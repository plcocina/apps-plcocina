import { Timestamp, type Firestore } from "firebase-admin/firestore";
import { describe, expect, it, vi } from "vitest";
import type { AdminPrincipal } from "../src/auth/require-super-admin.js";
import { UserControlService } from "../src/users/user-control-service.js";
import type { DirectoryUser, UserDirectory } from "../src/users/user-query-service.js";

class FakeSnapshot {
  constructor(readonly id: string, private readonly value?: Record<string, unknown>) {}
  get exists() { return this.value !== undefined; }
  data() { return this.value; }
}

class FakeReference {
  constructor(readonly collectionName: string, readonly id: string) {}
}

class FakeTransaction {
  private readonly writes: Array<() => void> = [];
  constructor(private readonly collections: Map<string, Map<string, Record<string, unknown>>>) {}
  async get(reference: FakeReference) {
    return new FakeSnapshot(reference.id, this.collections.get(reference.collectionName)?.get(reference.id));
  }
  create(reference: FakeReference, value: Record<string, unknown>) {
    this.writes.push(() => {
      const collection = this.collection(reference.collectionName);
      if (collection.has(reference.id)) throw new Error("already exists");
      collection.set(reference.id, value);
    });
  }
  update(reference: FakeReference, value: Record<string, unknown>) {
    this.writes.push(() => {
      const collection = this.collection(reference.collectionName);
      const current = collection.get(reference.id);
      if (!current) throw new Error("missing document");
      collection.set(reference.id, { ...current, ...value });
    });
  }
  set(reference: FakeReference, value: Record<string, unknown>) {
    this.writes.push(() => this.collection(reference.collectionName).set(reference.id, value));
  }
  commit() { for (const write of this.writes) write(); }
  private collection(name: string) {
    let collection = this.collections.get(name);
    if (!collection) { collection = new Map(); this.collections.set(name, collection); }
    return collection;
  }
}

class FakeFirestore {
  readonly collections = new Map<string, Map<string, Record<string, unknown>>>();
  private queue: Promise<void> = Promise.resolve();
  collection(name: string) {
    return { doc: (id: string) => new FakeReference(name, id) };
  }
  runTransaction<T>(callback: (transaction: FakeTransaction) => Promise<T>): Promise<T> {
    const result = this.queue.then(async () => {
      const transaction = new FakeTransaction(this.collections);
      const value = await callback(transaction);
      transaction.commit();
      return value;
    });
    this.queue = result.then(() => undefined, () => undefined);
    return result;
  }
  put(collection: string, id: string, value: Record<string, unknown>) {
    let records = this.collections.get(collection);
    if (!records) { records = new Map(); this.collections.set(collection, records); }
    records.set(id, value);
  }
  get(collection: string, id: string) { return this.collections.get(collection)?.get(id); }
  values(collection: string) { return [...(this.collections.get(collection)?.values() ?? [])]; }
}

const timestamp = Timestamp.fromDate(new Date("2026-10-22T18:00:00.000Z"));
const principal: AdminPrincipal = {
  uid: "admin-uid",
  email: "admin@plcocina.com",
  authTime: 1,
  issuedAt: 1,
  superAdmin: true
};

function profile(overrides: Record<string, unknown> = {}) {
  return {
    email: "user@plcocina.com",
    normalizedEmail: "user@plcocina.com",
    displayName: "Usuario",
    status: "active",
    authDisabled: false,
    invitationStatus: "accepted",
    createdAt: timestamp,
    createdBy: "admin-uid",
    updatedAt: timestamp,
    updatedBy: "admin-uid",
    revision: 1,
    pendingOperationId: null,
    version: 1,
    ...overrides
  };
}

function authUser(overrides: Partial<DirectoryUser> = {}): DirectoryUser {
  return {
    uid: "user-uid",
    email: "user@plcocina.com",
    displayName: "Usuario",
    emailVerified: true,
    disabled: false,
    metadata: { creationTime: "2026-10-01T00:00:00.000Z" },
    ...overrides
  };
}

function setup(user = authUser()) {
  const firestore = new FakeFirestore();
  firestore.put("users", user.uid, profile({ authDisabled: user.disabled }));
  const directory: UserDirectory = {
    listUsers: vi.fn(),
    getUser: vi.fn().mockResolvedValue(user),
    getUserByEmail: vi.fn(),
    getUsers: vi.fn(),
    updateUser: vi.fn().mockImplementation(async (_uid, properties) => ({ ...user, ...properties })),
    revokeRefreshTokens: vi.fn().mockResolvedValue(undefined),
    createUser: vi.fn()
  };
  const service = new UserControlService(directory, firestore as unknown as Firestore, "root-super-admin", () => timestamp);
  return { firestore, directory, service };
}

function execute(service: UserControlService, overrides: Record<string, unknown> = {}) {
  return service.execute({
    action: "suspend",
    uid: "user-uid",
    body: { expectedRevision: 1, reason: "Incidente de seguridad" },
    idempotencyKey: "11111111-1111-4111-8111-111111111111",
    principal,
    requestId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    ...overrides
  });
}

describe("administrative user control", () => {
  it("suspends, revokes sessions, updates the profile and appends one audit event", async () => {
    const { service, directory, firestore } = setup();
    const result = await execute(service);

    expect(result).toMatchObject({ uid: "user-uid", status: "disabled", authDisabled: true, sessionsRevoked: true, revision: 2 });
    expect(directory.updateUser).toHaveBeenCalledWith("user-uid", { disabled: true });
    expect(directory.revokeRefreshTokens).toHaveBeenCalledWith("user-uid");
    expect(firestore.get("users", "user-uid")).toMatchObject({ status: "disabled", authDisabled: true, revision: 2, pendingOperationId: null });
    expect(firestore.values("auditEvents")).toEqual([expect.objectContaining({ action: "user.suspended", result: "success", reason: "Incidente de seguridad" })]);
    expect(firestore.get("adminOperations", "11111111-1111-4111-8111-111111111111")).toMatchObject({ status: "completed" });
  });

  it("returns the stored result on an idempotent retry without repeating Auth or audit", async () => {
    const { service, directory, firestore } = setup();
    const first = await execute(service);
    const second = await execute(service, { requestId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" });
    expect(second).toEqual(first);
    expect(directory.updateUser).toHaveBeenCalledTimes(1);
    expect(directory.revokeRefreshTokens).toHaveBeenCalledTimes(1);
    expect(firestore.values("auditEvents")).toHaveLength(1);
  });

  it("rejects a concurrent retry while the first request owns the lease", async () => {
    const { service, directory } = setup();
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    vi.mocked(directory.updateUser).mockImplementationOnce(async () => { await gate; return authUser({ disabled: true }); });
    const first = execute(service);
    await vi.waitFor(() => expect(directory.updateUser).toHaveBeenCalledTimes(1));
    await expect(execute(service, { requestId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" }))
      .rejects.toMatchObject({ code: "OPERATION_IN_PROGRESS", status: 409 });
    release();
    await expect(first).resolves.toMatchObject({ revision: 2 });
  });

  it("recovers the same operation after an Authentication partial failure", async () => {
    const { service, directory, firestore } = setup();
    vi.mocked(directory.revokeRefreshTokens)
      .mockRejectedValueOnce(Object.assign(new Error("denied"), { code: "auth/insufficient-permission" }))
      .mockResolvedValueOnce(undefined);

    await expect(execute(service)).rejects.toMatchObject({ code: "INTERNAL_ERROR" });
    expect(firestore.get("adminOperations", "11111111-1111-4111-8111-111111111111")).toMatchObject({ status: "reconciliation_required" });
    await expect(execute(service, { requestId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" })).resolves.toMatchObject({ revision: 2 });
    expect(directory.updateUser).toHaveBeenCalledTimes(2);
    expect(firestore.values("auditEvents").map((event) => event.result)).toEqual(["failure", "success"]);
  });

  it("rejects stale revisions and never calls a mutable Authentication method", async () => {
    const { service, directory } = setup();
    await expect(execute(service, { body: { expectedRevision: 9, reason: "Cambio obsoleto" } }))
      .rejects.toMatchObject({ code: "REVISION_CONFLICT" });
    expect(directory.updateUser).not.toHaveBeenCalled();
    expect(directory.revokeRefreshTokens).not.toHaveBeenCalled();
  });

  it("rejects reused keys with different input and requires reasons where specified", async () => {
    const { service } = setup();
    await execute(service);
    await expect(execute(service, {
      requestId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      body: { expectedRevision: 1, reason: "Otro motivo" }
    })).rejects.toMatchObject({ code: "IDEMPOTENCY_CONFLICT" });

    const another = setup().service;
    await expect(execute(another, { body: { expectedRevision: 1 } }))
      .rejects.toMatchObject({ code: "VALIDATION_ERROR" });
  });

  it("reactivates without revoking sessions", async () => {
    const { firestore, directory } = setup(authUser({ disabled: true }));
    firestore.put("users", "user-uid", profile({ status: "disabled", authDisabled: true }));
    const service = new UserControlService(directory, firestore as unknown as Firestore, "root-super-admin", () => timestamp);
    await expect(execute(service, {
      action: "reactivate",
      body: { expectedRevision: 1 }
    })).resolves.toMatchObject({ status: "active", authDisabled: false, sessionsRevoked: false });
    expect(directory.updateUser).toHaveBeenCalledWith("user-uid", { disabled: false });
    expect(directory.revokeRefreshTokens).not.toHaveBeenCalled();
  });

  it.each([
    ["the actor", authUser({ uid: "admin-uid" }), "root-super-admin"],
    ["a claimed Super Admin", authUser({ customClaims: { super_admin: true } }), "root-super-admin"],
    ["the configured UID", authUser({ uid: "root-super-admin" }), "root-super-admin"]
  ])("protects %s", async (_label, user, protectedUid) => {
    const { firestore, directory } = setup(user);
    const service = new UserControlService(directory, firestore as unknown as Firestore, protectedUid, () => timestamp);
    await expect(execute(service, { uid: user.uid })).rejects.toMatchObject({ code: "PROTECTED_ACCOUNT" });
    expect(directory.updateUser).not.toHaveBeenCalled();
  });

  it("rejects an account without a profile and does not create one", async () => {
    const { service, directory, firestore } = setup();
    firestore.collections.get("users")?.delete("user-uid");
    await expect(execute(service)).rejects.toMatchObject({ code: "PROFILE_REQUIRED" });
    expect(directory.updateUser).not.toHaveBeenCalled();
    expect(firestore.get("users", "user-uid")).toBeUndefined();
  });

  it("revokes sessions with a required reason without exposing claims", async () => {
    const { service, directory } = setup(authUser({ customClaims: { internal: "secret" } }));
    const result = await execute(service, {
      action: "revoke-sessions",
      body: { expectedRevision: 1, reason: "Cierre preventivo" }
    });
    expect(result).toEqual({
      operationId: "11111111-1111-4111-8111-111111111111",
      uid: "user-uid",
      action: "revoke-sessions",
      status: "active",
      authDisabled: false,
      sessionsRevoked: true,
      revision: 2
    });
    expect(result).not.toHaveProperty("customClaims");
    expect(directory.updateUser).not.toHaveBeenCalled();
    expect(directory.revokeRefreshTokens).toHaveBeenCalledTimes(1);
  });
});
