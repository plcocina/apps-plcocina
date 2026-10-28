import type { DecodedIdToken } from "firebase-admin/auth";
import type { Firestore } from "firebase-admin/firestore";
import { Timestamp } from "firebase-admin/firestore";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { decideApplicationAccess } from "../src/access-grants/access-decision.js";
import { accessGrantId, AccessGrantService } from "../src/access-grants/access-grant-service.js";
import { createAdminApp } from "../src/app.js";
import type { AdminPrincipal } from "../src/auth/require-super-admin.js";
import type { ApplicationDocument, UserDocument } from "../src/models/admin-collections.js";
import type { DirectoryUser, UserDirectory } from "../src/users/user-query-service.js";

class FakeRef {
  constructor(readonly db: FakeFirestore, readonly path: string) {}
  get() { return Promise.resolve(this.db.snapshot(this.path)); }
}

class FakeQuery {
  private max = 500;
  constructor(private readonly db: FakeFirestore, private readonly collection: string, private readonly field: string, private readonly value: unknown) {}
  limit(value: number) { this.max = value; return this; }
  async get() {
    const docs = [...this.db.data.entries()]
      .filter(([path, value]) => path.startsWith(`${this.collection}/`) && value[this.field] === this.value)
      .slice(0, this.max)
      .map(([path]) => this.db.snapshot(path));
    return { docs };
  }
}

class FakeFirestore {
  readonly data = new Map<string, Record<string, unknown>>();
  collection(name: string) {
    return {
      doc: (id: string) => new FakeRef(this, `${name}/${id}`),
      where: (field: string, operator: string, value: unknown) => {
        if (operator !== "==") throw new Error("unsupported query");
        return new FakeQuery(this, name, field, value);
      }
    };
  }
  snapshot(path: string) {
    const value = this.data.get(path);
    return { id: path.split("/").at(-1)!, exists: value !== undefined, data: () => value };
  }
  async runTransaction<T>(work: (transaction: ReturnType<FakeFirestore["transaction"]>) => Promise<T>) { return work(this.transaction()); }
  transaction() {
    return {
      get: async (ref: FakeRef) => this.snapshot(ref.path),
      set: (ref: FakeRef, value: Record<string, unknown>) => { this.data.set(ref.path, value); },
      create: (ref: FakeRef, value: Record<string, unknown>) => {
        if (this.data.has(ref.path)) throw new Error("already exists");
        this.data.set(ref.path, value);
      }
    };
  }
}

const timestamp = Timestamp.fromDate(new Date("2026-10-27T16:00:00.000Z"));
const actor: AdminPrincipal = { uid: "admin", email: "admin@plcocina.com", authTime: 1, issuedAt: 1, superAdmin: true };
const profile: UserDocument = {
  email: "user@plcocina.com", normalizedEmail: "user@plcocina.com", displayName: "User",
  status: "active", authDisabled: false, invitationStatus: "accepted",
  createdAt: timestamp, createdBy: "admin", updatedAt: timestamp, updatedBy: "admin",
  revision: 1, pendingOperationId: null, version: 1
};
const authUser: DirectoryUser = {
  uid: "user-1", email: profile.email, displayName: profile.displayName, emailVerified: true,
  disabled: false, metadata: { creationTime: timestamp.toDate().toISOString() }
};
const application: ApplicationDocument = {
  appId: "private-app", slug: "private-app", name: "Private", normalizedName: "private",
  description: "", category: "Ops", normalizedCategory: "ops",
  launchUrl: "https://private.example.com/", normalizedLaunchUrl: "https://private.example.com/",
  status: "active", accessLevel: "private", iconKey: null, displayOrder: 0,
  createdAt: timestamp, createdBy: "admin", updatedAt: timestamp, updatedBy: "admin", revision: 1, version: 1
};

function directory(user = authUser): UserDirectory {
  return {
    getUser: async (uid) => {
      if (uid !== user.uid) throw Object.assign(new Error("missing"), { code: "auth/user-not-found" });
      return user;
    },
    listUsers: async () => ({ users: [user] }),
    getUserByEmail: async () => user,
    getUsers: async () => ({ users: [user] }),
    updateUser: async () => user,
    revokeRefreshTokens: async () => undefined,
    createUser: async () => user
  };
}

function setup(overrides: { user?: Partial<UserDocument>; auth?: Partial<DirectoryUser>; app?: Partial<ApplicationDocument> } = {}) {
  const db = new FakeFirestore();
  const currentUser = { ...authUser, ...overrides.auth };
  db.data.set(`users/${currentUser.uid}`, { ...profile, ...overrides.user });
  db.data.set(`applications/${application.appId}`, { ...application, ...overrides.app });
  return { db, service: new AccessGrantService(db as unknown as Firestore, directory(currentUser), () => timestamp) };
}

let sequence = 0;
function operation(action: "grant" | "revoke", expectedRevision: number, reason?: string) {
  sequence += 1;
  return {
    action, userId: authUser.uid, applicationId: application.appId,
    body: reason ? { expectedRevision, reason } : { expectedRevision },
    idempotencyKey: `00000000-0000-4000-8000-${String(sequence).padStart(12, "0")}`,
    principal: actor, requestId: `10000000-0000-4000-8000-${String(sequence).padStart(12, "0")}`
  };
}

describe("access grant service", () => {
  it("uses the frozen deterministic v1 grant ID", () => {
    expect(accessGrantId("user-1", "private-app")).toBe("a8706c00171b754f3e10ded3517932c6a5b850aa44da47fc468ea12605b67cda");
  });

  it("creates, revokes and reactivates a retained grant", async () => {
    const { db, service } = setup();
    const granted = await service.execute(operation("grant", 0));
    const revoked = await service.execute(operation("revoke", 1, "Access removed"));
    const reactivated = await service.execute(operation("grant", 2));
    expect([granted.status, revoked.status, reactivated.status]).toEqual(["active", "revoked", "active"]);
    expect([granted.revision, revoked.revision, reactivated.revision]).toEqual([1, 2, 3]);
    expect([...db.data.keys()].filter((key) => key.startsWith("accessGrants/"))).toHaveLength(1);
    expect([...db.data.keys()].filter((key) => key.startsWith("auditEvents/"))).toHaveLength(3);
  });

  it("records repeated grant and revoke as no-op operations without revision or audit", async () => {
    const { db, service } = setup();
    await service.execute(operation("grant", 0));
    const repeatedGrant = await service.execute(operation("grant", 1));
    await service.execute(operation("revoke", 1, "Access removed"));
    const repeatedRevoke = await service.execute(operation("revoke", 2, "Already removed"));
    expect(repeatedGrant).toMatchObject({ changed: false, revision: 1 });
    expect(repeatedRevoke).toMatchObject({ changed: false, revision: 2 });
    expect([...db.data.keys()].filter((key) => key.startsWith("adminOperations/"))).toHaveLength(4);
    expect([...db.data.keys()].filter((key) => key.startsWith("auditEvents/"))).toHaveLength(2);
  });

  it("replays the same idempotent request and rejects a conflicting reuse", async () => {
    const { service } = setup();
    const input = operation("grant", 0);
    const first = await service.execute(input);
    await expect(service.execute(input)).resolves.toEqual(first);
    await expect(service.execute({ ...input, body: { expectedRevision: 1 } })).rejects.toMatchObject({ code: "IDEMPOTENCY_CONFLICT" });
  });

  it("rejects revision conflicts", async () => {
    const { service } = setup();
    await service.execute(operation("grant", 0));
    await expect(service.execute(operation("revoke", 0, "Stale request"))).rejects.toMatchObject({ code: "REVISION_CONFLICT" });
  });

  it("rejects public and inactive applications and suspended users", async () => {
    await expect(setup({ app: { accessLevel: "public" } }).service.execute(operation("grant", 0))).rejects.toMatchObject({ code: "GRANT_NOT_REQUIRED" });
    await expect(setup({ app: { status: "inactive" } }).service.execute(operation("grant", 0))).rejects.toMatchObject({ code: "INVALID_STATE_TRANSITION" });
    await expect(setup({ app: { status: "archived" } }).service.execute(operation("grant", 0))).rejects.toMatchObject({ code: "INVALID_STATE_TRANSITION" });
    await expect(setup({ user: { status: "disabled", authDisabled: true }, auth: { disabled: true } }).service.execute(operation("grant", 0))).rejects.toMatchObject({ code: "INVALID_STATE_TRANSITION" });
  });
});

describe("access decision", () => {
  it("allows public apps but requires an explicit grant for private apps, including Super Admin", () => {
    const superAdmin = { ...authUser, customClaims: { super_admin: true } };
    expect(decideApplicationAccess({ authUser: superAdmin, user: profile, application: { ...application, accessLevel: "public" }, grant: null }).allowed).toBe(true);
    expect(decideApplicationAccess({ authUser: superAdmin, user: profile, application, grant: null })).toEqual({ allowed: false, reason: "GRANT_REQUIRED" });
    expect(decideApplicationAccess({
      authUser: superAdmin, user: profile, application,
      grant: {
        userId: authUser.uid, applicationId: application.appId, status: "active",
        createdAt: timestamp, createdBy: actor.uid, updatedAt: timestamp, updatedBy: actor.uid,
        revokedAt: null, revokedBy: null, revokeReason: null, revision: 1, version: 1
      }
    }).allowed).toBe(true);
  });
});

describe("access grant routes", () => {
  it("exposes grant and user-query routes to Super Admin", async () => {
    const { db } = setup();
    const decoded = { uid: actor.uid, email: actor.email, auth_time: 1, iat: 1, super_admin: true } as unknown as DecodedIdToken;
    const app = createAdminApp({
      verifyIdToken: async () => decoded, origins: new Set(["https://apps.plcocina.com"]),
      firestore: db as unknown as Firestore, userDirectory: directory()
    });
    const granted = await request(app).post("/api/admin/users/user-1/access-grants/private-app/grant")
      .set("Origin", "https://apps.plcocina.com").set("Authorization", "Bearer token")
      .set("Idempotency-Key", "00000000-0000-4000-8000-000000000098").send({ expectedRevision: 0 });
    expect(granted.status).toBe(200);
    expect(granted.body.data).toMatchObject({ status: "active", revision: 1, changed: true });
    const listed = await request(app).get("/api/admin/users/user-1/access-grants")
      .set("Origin", "https://apps.plcocina.com").set("Authorization", "Bearer token");
    expect(listed.status).toBe(200);
    expect(listed.body.data).toHaveLength(1);
  });

  it("rejects a non-admin before executing the operation", async () => {
    const { db } = setup();
    const decoded = { uid: "common", email: "common@plcocina.com", auth_time: 1, iat: 1, super_admin: false } as unknown as DecodedIdToken;
    const app = createAdminApp({
      verifyIdToken: async () => decoded, origins: new Set(["https://apps.plcocina.com"]),
      firestore: db as unknown as Firestore, userDirectory: directory()
    });
    const response = await request(app).post("/api/admin/users/user-1/access-grants/private-app/grant")
      .set("Origin", "https://apps.plcocina.com").set("Authorization", "Bearer token")
      .set("Idempotency-Key", "00000000-0000-4000-8000-000000000099").send({ expectedRevision: 0 });
    expect(response.status).toBe(403);
    expect(response.body.error.code).toBe("ADMIN_REQUIRED");
  });
});
