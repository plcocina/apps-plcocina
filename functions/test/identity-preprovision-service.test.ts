import { randomUUID } from "node:crypto";
import { Timestamp, type Firestore } from "firebase-admin/firestore";
import { describe, expect, it } from "vitest";
import type { AdminPrincipal } from "../src/auth/require-super-admin.js";
import {
  IdentityPreprovisionService,
  preprovisionedUid,
  type IdentityDirectory,
  type IdentityDirectoryUser
} from "../src/identities/identity-preprovision-service.js";
import { IdentityReservationService } from "../src/identities/identity-reservation-service.js";

const now = Timestamp.fromDate(new Date("2026-10-29T12:00:00.000Z"));
const pepper = Buffer.alloc(32, 0x5c);
const principal: AdminPrincipal = {
  uid: "protected-admin", email: "admin@example.test", authTime: 1, issuedAt: 1, superAdmin: true
};

class FakeRef {
  constructor(readonly db: FakeFirestore, readonly path: string) {}
  async get() { return { exists: this.db.data.has(this.path), data: () => this.db.data.get(this.path) }; }
  async update(value: Record<string, unknown>) {
    const current = this.db.data.get(this.path);
    if (!current) throw new Error("not found");
    this.db.data.set(this.path, { ...current, ...value });
  }
}

class FakeFirestore {
  readonly data = new Map<string, Record<string, unknown>>();
  transactionCount = 0;
  failTransactionNumber: number | null = null;
  collection(name: string) { return { doc: (id: string) => new FakeRef(this, `${name}/${id}`) }; }
  async runTransaction<T>(work: (transaction: ReturnType<FakeFirestore["transaction"]>) => Promise<T>) {
    this.transactionCount += 1;
    if (this.failTransactionNumber === this.transactionCount) throw new Error("firestore unavailable");
    return work(this.transaction());
  }
  transaction() {
    return {
      get: async (ref: FakeRef) => ({ exists: this.data.has(ref.path), data: () => this.data.get(ref.path) }),
      set: (ref: FakeRef, value: Record<string, unknown>) => this.data.set(ref.path, value),
      create: (ref: FakeRef, value: Record<string, unknown>) => {
        if (this.data.has(ref.path)) throw new Error("already exists");
        this.data.set(ref.path, value);
      },
      update: (ref: FakeRef, value: Record<string, unknown>) => {
        const current = this.data.get(ref.path);
        if (!current) throw new Error("not found");
        this.data.set(ref.path, { ...current, ...value });
      }
    };
  }
}

function notFound(): Error & { code: string } {
  return Object.assign(new Error("not found"), { code: "auth/user-not-found" });
}

class FakeDirectory implements IdentityDirectory {
  readonly users = new Map<string, IdentityDirectoryUser>();
  creates = 0;
  ambiguousCreate = false;

  async getUser(uid: string) { const user = this.users.get(uid); if (!user) throw notFound(); return user; }
  async getUserByEmail(email: string) {
    const user = [...this.users.values()].find((item) => item.email?.toLowerCase() === email.toLowerCase());
    if (!user) throw notFound(); return user;
  }
  async getUserByPhoneNumber(phone: string) {
    const user = [...this.users.values()].find((item) => item.phoneNumber === phone);
    if (!user) throw notFound(); return user;
  }
  async createUser(properties: Parameters<IdentityDirectory["createUser"]>[0]) {
    this.creates += 1;
    if (this.users.has(properties.uid)) throw Object.assign(new Error("uid exists"), { code: "auth/uid-already-exists" });
    const user: IdentityDirectoryUser = {
      uid: properties.uid, displayName: properties.displayName, disabled: true,
      email: properties.email ?? null, phoneNumber: properties.phoneNumber ?? null,
      emailVerified: false
    };
    this.users.set(user.uid, user);
    if (this.ambiguousCreate) throw new Error("transport response lost");
    return user;
  }
}

function setup(db = new FakeFirestore(), directory = new FakeDirectory()) {
  const reservations = new IdentityReservationService(db as unknown as Firestore, pepper, () => now);
  return { db, directory, service: new IdentityPreprovisionService(db as unknown as Firestore, directory, reservations, "protected-admin", () => now) };
}

describe("identity administrative preprovisioning", () => {
  it("creates an SMS-only disabled identity with the same Auth and Firestore UID", async () => {
    const { db, directory, service } = setup();
    const operationId = randomUUID();
    const result = await service.preprovision({
      operationId, requestId: randomUUID(), principal,
      body: { displayName: "Empleado SMS", authMethod: "sms", phoneE164: "+52 (81) 1234-5678" }
    });
    expect(result).toMatchObject({ uid: preprovisionedUid(operationId), authMethod: "sms", authDisabled: true, activationStatus: "pending" });
    expect(directory.users.get(result.uid)).toMatchObject({ uid: result.uid, phoneNumber: "+528112345678", email: null, disabled: true });
    expect(db.data.get(`users/${result.uid}`)).toMatchObject({ version: 2, email: null, authDisabled: true, activationStatus: "pending" });
    expect([...db.data.keys()].some((path) => path.startsWith("accessGrants/"))).toBe(false);
    expect(directory.users.get(result.uid)?.customClaims).toBeUndefined();
  });

  it("creates an Email Link identity without phone and leaves email unverified", async () => {
    const { db, directory, service } = setup();
    const result = await service.preprovision({
      operationId: randomUUID(), requestId: randomUUID(), principal,
      body: { displayName: "Empleado Email", authMethod: "email", email: " Employee@Example.TEST " }
    });
    expect(directory.users.get(result.uid)).toMatchObject({ email: "employee@example.test", phoneNumber: null, emailVerified: false, disabled: true });
    expect(db.data.get(`users/${result.uid}`)).toMatchObject({ normalizedEmail: "employee@example.test", phoneE164: null });
  });

  it("replays idempotently without duplicating Auth, profile or successful audit", async () => {
    const { db, directory, service } = setup();
    const operationId = randomUUID();
    const body = { displayName: "Empleado", authMethod: "sms", phoneE164: "+528112345679" };
    const first = await service.preprovision({ operationId, requestId: randomUUID(), principal, body });
    const replay = await service.preprovision({ operationId, requestId: randomUUID(), principal, body });
    expect(first.replayed).toBe(false);
    expect(replay).toMatchObject({ uid: first.uid, replayed: true });
    expect(directory.creates).toBe(1);
    expect([...db.data.entries()].filter(([path, value]) => path.startsWith("auditEvents/") && value.result === "success")).toHaveLength(1);
  });

  it("rejects duplicate identifiers and reuse of a key with changed input", async () => {
    const context = setup();
    await context.service.preprovision({
      operationId: randomUUID(), requestId: randomUUID(), principal,
      body: { displayName: "Primero", authMethod: "email", email: "same@example.test" }
    });
    await expect(context.service.preprovision({
      operationId: randomUUID(), requestId: randomUUID(), principal,
      body: { displayName: "Segundo", authMethod: "email", email: "SAME@example.test" }
    })).rejects.toMatchObject({ code: "IDENTIFIER_COLLISION" });
    const operationId = randomUUID();
    await context.service.preprovision({
      operationId, requestId: randomUUID(), principal,
      body: { displayName: "Tercero", authMethod: "sms", phoneE164: "+528112345680" }
    });
    await expect(context.service.preprovision({
      operationId, requestId: randomUUID(), principal,
      body: { displayName: "Cambiado", authMethod: "sms", phoneE164: "+528112345680" }
    })).rejects.toMatchObject({ code: "IDEMPOTENCY_CONFLICT" });
  });

  it("recovers an ambiguous Auth response only through the deterministic UID", async () => {
    const directory = new FakeDirectory();
    directory.ambiguousCreate = true;
    const { service } = setup(new FakeFirestore(), directory);
    const operationId = randomUUID();
    const result = await service.preprovision({
      operationId, requestId: randomUUID(), principal,
      body: { displayName: "Ambiguo", authMethod: "sms", phoneE164: "+528112345681" }
    });
    expect(result.uid).toBe(preprovisionedUid(operationId));
    expect(directory.users).toHaveLength(1);
    expect(directory.creates).toBe(1);
  });

  it("marks an Auth/Firestore partial failure and completes a retry with the same UID", async () => {
    const db = new FakeFirestore();
    db.failTransactionNumber = 3;
    const directory = new FakeDirectory();
    const { service } = setup(db, directory);
    const operationId = randomUUID();
    const body = { displayName: "Recuperable", authMethod: "sms", phoneE164: "+528112345682" };
    await expect(service.preprovision({ operationId, requestId: randomUUID(), principal, body }))
      .rejects.toMatchObject({ code: "RECONCILIATION_REQUIRED" });
    expect(db.data.get(`adminOperations/${operationId}`)?.status).toBe("reconciliation_required");
    expect(directory.users.has(preprovisionedUid(operationId))).toBe(true);
    const recovered = await service.preprovision({ operationId, requestId: randomUUID(), principal, body });
    expect(recovered.uid).toBe(preprovisionedUid(operationId));
    expect(directory.creates).toBe(1);
    expect(db.data.get(`adminOperations/${operationId}`)?.status).toBe("completed");
  });

  it("rejects callers without the Super Admin invariant", async () => {
    const { service } = setup();
    await expect(service.preprovision({
      operationId: randomUUID(), requestId: randomUUID(),
      principal: { ...principal, superAdmin: false } as unknown as AdminPrincipal,
      body: { displayName: "No autorizado", authMethod: "email", email: "blocked@example.test" }
    })).rejects.toMatchObject({ code: "ADMIN_REQUIRED" });
  });

  it("writes an audit projection without clear email or phone", async () => {
    const { db, service } = setup();
    await service.preprovision({
      operationId: randomUUID(), requestId: randomUUID(), principal,
      body: { displayName: "Privado", authMethod: "email", email: "private@example.test" }
    });
    const audit = [...db.data.entries()].find(([path, value]) => path.startsWith("auditEvents/") && value.result === "success")?.[1];
    expect(audit).toMatchObject({ action: "identity.preprovisioned", actorUid: principal.uid });
    expect(JSON.stringify(audit)).not.toContain("private@example.test");
  });

  it("reports v1 compatibility without rewriting the profile", async () => {
    const { db, directory, service } = setup();
    db.data.set("users/legacy-user", {
      email: "legacy@example.test", normalizedEmail: "legacy@example.test", displayName: "Legacy",
      status: "active", authDisabled: false, invitationStatus: "accepted", createdAt: now, createdBy: "protected-admin",
      updatedAt: now, updatedBy: "protected-admin", revision: 4, pendingOperationId: null, version: 1
    });
    directory.users.set("legacy-user", {
      uid: "legacy-user", email: "legacy@example.test", phoneNumber: null, displayName: "Legacy",
      emailVerified: true, disabled: false
    });
    await expect(service.getStatus("legacy-user")).resolves.toMatchObject({ profileVersion: 1, integrity: "linked", revision: 4 });
    expect(db.data.get("users/legacy-user")?.version).toBe(1);
  });
});
