import { randomUUID } from "node:crypto";
import { Timestamp, type Firestore } from "firebase-admin/firestore";
import { describe, expect, it } from "vitest";
import { identityCreateInputSchema } from "../src/identities/identity-contracts.js";
import {
  identifierKeyHash,
  identityIdentifierKeyDocumentSchema,
  normalizeIdentityEmail,
  normalizePhoneE164,
  userV2DocumentSchema
} from "../src/identities/identity-models.js";
import { IdentityReservationError, IdentityReservationService } from "../src/identities/identity-reservation-service.js";
import { assertIdentityTransition, canTransitionIdentity } from "../src/identities/identity-transitions.js";
import { accessGrantDocumentSchema, auditEventDocumentSchema, userDocumentSchema, userProfileDocumentSchema } from "../src/models/admin-collections.js";

const now = Timestamp.fromDate(new Date("2026-10-28T18:00:00.000Z"));
const pepper = Buffer.alloc(32, 0x4a);

function fixture(overrides: Record<string, unknown> = {}) {
  return {
    displayName: "Empleado",
    status: "invited",
    authDisabled: true,
    invitationStatus: "pending",
    authMethod: "sms",
    phoneE164: "+528112345678",
    normalizedPhone: "+528112345678",
    email: null,
    normalizedEmail: null,
    phoneVerifiedAt: null,
    emailVerifiedAt: null,
    activationStatus: "pending",
    credentialRevision: 1,
    authorizationRevision: 1,
    sessionValidAfter: now,
    createdAt: now,
    createdBy: "admin-uid",
    updatedAt: now,
    updatedBy: "admin-uid",
    revision: 1,
    pendingOperationId: null,
    version: 2,
    ...overrides
  };
}

class FakeRef { constructor(readonly path: string) {} }
class FakeFirestore {
  readonly data = new Map<string, Record<string, unknown>>();
  collection(name: string) { return { doc: (id: string) => new FakeRef(`${name}/${id}`) }; }
  async runTransaction<T>(work: (transaction: ReturnType<FakeFirestore["transaction"]>) => Promise<T>) { return work(this.transaction()); }
  transaction() {
    return {
      get: async (ref: FakeRef) => ({ exists: this.data.has(ref.path), data: () => this.data.get(ref.path) }),
      set: (ref: FakeRef, value: Record<string, unknown>) => this.data.set(ref.path, value),
      create: (ref: FakeRef, value: Record<string, unknown>) => {
        if (this.data.has(ref.path)) throw new Error("already exists");
        this.data.set(ref.path, value);
      }
    };
  }
}

describe("identity v2 models", () => {
  it("reads existing v1 profiles without changing their contract", () => {
    const v1 = userDocumentSchema.parse({
      email: "employee@example.test", normalizedEmail: "employee@example.test", displayName: "Empleado",
      status: "active", authDisabled: false, invitationStatus: "accepted", createdAt: now, createdBy: "admin-uid",
      updatedAt: now, updatedBy: "admin-uid", revision: 3, pendingOperationId: null, version: 1
    });
    expect(userProfileDocumentSchema.parse(v1).version).toBe(1);
  });

  it("accepts an SMS employee without email", () => {
    const user = userV2DocumentSchema.parse(fixture());
    expect(user.authMethod).toBe("sms");
    expect(user.email).toBeNull();
  });

  it("accepts an email employee without phone", () => {
    const user = userV2DocumentSchema.parse(fixture({
      authMethod: "email", phoneE164: null, normalizedPhone: null,
      email: "employee@example.test", normalizedEmail: "employee@example.test"
    }));
    expect(user.phoneE164).toBeNull();
  });

  it("requires the identifier selected by the authentication method", () => {
    expect(userV2DocumentSchema.safeParse(fixture({ phoneE164: null, normalizedPhone: null })).success).toBe(false);
    expect(userV2DocumentSchema.safeParse(fixture({ authMethod: "email" })).success).toBe(false);
    expect(identityCreateInputSchema.safeParse({ displayName: "Empleado", authMethod: "sms", phone: null, email: null }).success).toBe(false);
  });

  it("normalizes email and E.164 phone values consistently", () => {
    expect(normalizeIdentityEmail("  Employee@Example.TEST ")).toBe("employee@example.test");
    expect(normalizePhoneE164("+52 (81) 1234-5678")).toBe("+528112345678");
    expect(() => normalizePhoneE164("8112345678")).toThrow("INVALID_E164_PHONE");
    expect(userV2DocumentSchema.safeParse(fixture({ normalizedPhone: "+528100000000" })).success).toBe(false);
  });

  it("enforces activation invariants and positive revisions", () => {
    expect(userV2DocumentSchema.safeParse(fixture({ activationStatus: "active" })).success).toBe(false);
    expect(userV2DocumentSchema.safeParse(fixture({ activationStatus: "auth_enabled_pending_proof", authDisabled: false })).success).toBe(true);
    expect(userV2DocumentSchema.safeParse(fixture({ credentialRevision: 0 })).success).toBe(false);
    expect(userV2DocumentSchema.safeParse(fixture({ authorizationRevision: 0 })).success).toBe(false);
  });

  it("allows only reviewed activation transitions", () => {
    expect(canTransitionIdentity("pending", "auth_enabled_pending_proof")).toBe(true);
    expect(canTransitionIdentity("auth_enabled_pending_proof", "active")).toBe(true);
    expect(canTransitionIdentity("active", "pending")).toBe(false);
    expect(canTransitionIdentity("reconciliation_required", "active")).toBe(false);
    expect(() => assertIdentityTransition("active", "pending")).toThrow("IDENTITY_TRANSITION_REJECTED");
  });

  it("accepts a phone-only human audit actor and still requires its UID", () => {
    const base = {
      occurredAt: now, actorType: "user", actorUid: "phone-user", actorEmail: null, providerEventId: null,
      action: "identity.activated", resourceType: "user", resourceId: "phone-user", targetUid: "phone-user", appId: null,
      before: { activationStatus: "pending" }, after: { activationStatus: "active" }, reason: null,
      requestId: randomUUID(), source: "admin-api", result: "success", version: 1
    };
    expect(auditEventDocumentSchema.safeParse(base).success).toBe(true);
    expect(auditEventDocumentSchema.safeParse({ ...base, actorUid: null }).success).toBe(false);
  });

  it("keeps Access Grants UID-based and rejects administrative claims in the identity profile", () => {
    expect(accessGrantDocumentSchema.safeParse({
      userId: "stable-uid", applicationId: "private-app", status: "active",
      createdAt: now, createdBy: "admin-uid", updatedAt: now, updatedBy: "admin-uid",
      revokedAt: null, revokedBy: null, revokeReason: null, revision: 1, version: 1
    }).success).toBe(true);
    expect(userV2DocumentSchema.safeParse(fixture({ super_admin: true })).success).toBe(false);
  });
});

describe("identity identifier reservations", () => {
  it("stores only a keyed hash and replays an identical operation", async () => {
    const db = new FakeFirestore();
    const service = new IdentityReservationService(db as unknown as Firestore, pepper, () => now);
    const operationId = randomUUID();
    const first = await service.reserve({ operationId, uid: "stable-uid", kind: "email", value: " Employee@Example.test " });
    const replay = await service.reserve({ operationId, uid: "stable-uid", kind: "email", value: "employee@example.test" });
    expect(first.replayed).toBe(false);
    expect(replay.replayed).toBe(true);
    expect(replay.identifierHash).toBe(identifierKeyHash("email", "employee@example.test", pepper));
    const key = [...db.data.entries()].find(([path]) => path.startsWith("authIdentifierKeys/"))?.[1];
    expect(identityIdentifierKeyDocumentSchema.safeParse(key).success).toBe(true);
    expect(JSON.stringify(key)).not.toContain("employee@example.test");
  });

  it("rejects collisions and idempotency-key reuse with different data", async () => {
    const db = new FakeFirestore();
    const service = new IdentityReservationService(db as unknown as Firestore, pepper, () => now);
    const operationId = randomUUID();
    await service.reserve({ operationId, uid: "first-uid", kind: "phone", value: "+528112345678" });
    await expect(service.reserve({ operationId: randomUUID(), uid: "second-uid", kind: "phone", value: "+52 81 1234 5678" }))
      .rejects.toMatchObject({ code: "IDENTIFIER_COLLISION" } satisfies Partial<IdentityReservationError>);
    await expect(service.reserve({ operationId, uid: "first-uid", kind: "phone", value: "+528187654321" }))
      .rejects.toMatchObject({ code: "IDEMPOTENCY_CONFLICT" } satisfies Partial<IdentityReservationError>);
  });
});
