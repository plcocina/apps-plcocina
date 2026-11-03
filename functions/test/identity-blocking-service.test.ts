import { Timestamp } from "firebase-admin/firestore";
import { describe, expect, it } from "vitest";
import { createBeforeCreateHandler } from "../src/identities/identity-blocking-functions.js";
import {
  IdentityBlockingService,
  type BlockingAuthUser,
  type IdentityBlockingStore
} from "../src/identities/identity-blocking-service.js";
import { userV2DocumentSchema } from "../src/identities/identity-models.js";
import { userDocumentSchema, type UserProfileDocument } from "../src/models/admin-collections.js";

const now = Timestamp.fromDate(new Date("2026-10-29T20:00:00.000Z"));
const adminUid = "protected-admin";

function v2(overrides: Record<string, unknown> = {}) {
  return userV2DocumentSchema.parse({
    displayName: "Empleado", status: "active", authDisabled: false, invitationStatus: "accepted",
    authMethod: "sms", phoneE164: "+528112345678", normalizedPhone: "+528112345678",
    email: null, normalizedEmail: null, phoneVerifiedAt: now, emailVerifiedAt: null,
    activationStatus: "active", credentialRevision: 1, authorizationRevision: 1,
    sessionValidAfter: Timestamp.fromMillis(now.toMillis() - 60_000), createdAt: now, createdBy: adminUid,
    updatedAt: now, updatedBy: adminUid, revision: 1, pendingOperationId: null, version: 2,
    ...overrides
  });
}

function v1(overrides: Record<string, unknown> = {}) {
  return userDocumentSchema.parse({
    email: "legacy@example.test", normalizedEmail: "legacy@example.test", displayName: "Legacy",
    status: "active", authDisabled: false, invitationStatus: "accepted", createdAt: now, createdBy: adminUid,
    updatedAt: now, updatedBy: adminUid, revision: 2, pendingOperationId: null, version: 1,
    ...overrides
  });
}

class FakeStore implements IdentityBlockingStore {
  profile: UserProfileDocument | null = null;
  reconciliation = false;
  validInvitation = false;
  failRead = false;
  async getProfile() { if (this.failRead) throw new Error("unavailable"); return this.profile; }
  async hasReconciliation() { if (this.failRead) throw new Error("unavailable"); return this.reconciliation; }
  async hasValidV1Invitation() { if (this.failRead) throw new Error("unavailable"); return this.validInvitation; }
}

function smsUser(overrides: Partial<BlockingAuthUser> = {}): BlockingAuthUser {
  return { uid: "employee-sms", phoneNumber: "+528112345678", emailVerified: false, disabled: false, ...overrides };
}

describe("Identity Platform blocking policy", () => {
  it("rejects every public create without domain or country exceptions", () => {
    const store = new FakeStore();
    const service = new IdentityBlockingService(store, adminUid, () => now);
    expect(() => service.beforeCreate(smsUser())).toThrow(expect.objectContaining({ code: "CREATE_NOT_PREPROVISIONED" }));
    expect(() => service.beforeCreate(smsUser({ email: "person@plcocina.com", phoneNumber: "+5215512345678" })))
      .toThrow(expect.objectContaining({ code: "CREATE_NOT_PREPROVISIONED" }));
  });

  it("allows an active preprovisioned SMS identity only with phone", async () => {
    const store = new FakeStore(); store.profile = v2();
    const service = new IdentityBlockingService(store, adminUid, () => now);
    await expect(service.beforeSignIn(smsUser(), { signInMethod: "phone" })).resolves.toBeUndefined();
    await expect(service.beforeSignIn(smsUser(), { signInMethod: "emailLink" })).rejects.toMatchObject({ code: "METHOD_NOT_ALLOWED" });
  });

  it("allows an active preprovisioned Email Link identity without phone", async () => {
    const store = new FakeStore();
    store.profile = v2({
      authMethod: "email", phoneE164: null, normalizedPhone: null, phoneVerifiedAt: null,
      email: "employee@example.test", normalizedEmail: "employee@example.test", emailVerifiedAt: now
    });
    const service = new IdentityBlockingService(store, adminUid, () => now);
    await expect(service.beforeSignIn({
      uid: "employee-email", email: "Employee@Example.test", emailVerified: true, disabled: false
    }, { signInMethod: "emailLink" })).resolves.toBeUndefined();
    await expect(service.beforeSignIn({
      uid: "employee-email", email: "employee@example.test", emailVerified: false, disabled: false
    }, { signInMethod: "emailLink" })).rejects.toMatchObject({ code: "IDENTIFIER_MISMATCH" });
  });

  it("rejects nonexistent, suspended and inconsistent identities", async () => {
    const store = new FakeStore();
    const service = new IdentityBlockingService(store, adminUid, () => now);
    await expect(service.beforeSignIn(smsUser(), { signInMethod: "phone" })).rejects.toMatchObject({ code: "USER_NOT_AUTHORIZED" });
    store.profile = v2();
    await expect(service.beforeSignIn(smsUser({ disabled: true }), { signInMethod: "phone" })).rejects.toMatchObject({ code: "ACCOUNT_DISABLED" });
    store.profile = v2();
    await expect(service.beforeSignIn(smsUser({ phoneNumber: "+528100000000" }), { signInMethod: "phone" }))
      .rejects.toMatchObject({ code: "IDENTIFIER_MISMATCH" });
  });

  it("enforces the activation proof window", async () => {
    const store = new FakeStore();
    store.profile = v2({
      status: "invited", authDisabled: false, invitationStatus: "pending",
      activationStatus: "auth_enabled_pending_proof",
      sessionValidAfter: Timestamp.fromMillis(now.toMillis() - 14 * 60_000)
    });
    const service = new IdentityBlockingService(store, adminUid, () => now);
    await expect(service.beforeSignIn(smsUser(), { signInMethod: "phone" })).resolves.toBeUndefined();
    store.profile = v2({
      status: "invited", authDisabled: false, invitationStatus: "pending",
      activationStatus: "auth_enabled_pending_proof",
      sessionValidAfter: Timestamp.fromMillis(now.toMillis() - 16 * 60_000)
    });
    await expect(service.beforeSignIn(smsUser(), { signInMethod: "phone" })).rejects.toMatchObject({ code: "ACTIVATION_EXPIRED" });
  });

  it("fails closed for reconciliation and Firestore read failures", async () => {
    const store = new FakeStore(); store.profile = v2(); store.reconciliation = true;
    const service = new IdentityBlockingService(store, adminUid, () => now);
    await expect(service.beforeSignIn(smsUser(), { signInMethod: "phone" })).rejects.toMatchObject({ code: "RECONCILIATION_REQUIRED" });
    store.reconciliation = false; store.failRead = true;
    await expect(service.beforeSignIn(smsUser(), { signInMethod: "phone" })).rejects.toMatchObject({ code: "STATE_READ_FAILED" });
  });

  it("preserves only the protected Super Admin with verified password conditions", async () => {
    const service = new IdentityBlockingService(new FakeStore(), adminUid, () => now);
    const admin = { uid: adminUid, email: "admin@example.test", emailVerified: true, disabled: false, customClaims: { super_admin: true } };
    await expect(service.beforeSignIn(admin, { signInMethod: "password" })).resolves.toBeUndefined();
    await expect(service.beforeSignIn({ ...admin, emailVerified: false }, { signInMethod: "password" })).rejects.toMatchObject({ code: "SUPER_ADMIN_INVALID" });
    await expect(service.beforeSignIn(admin, { signInMethod: "emailLink" })).rejects.toMatchObject({ code: "SUPER_ADMIN_INVALID" });
  });

  it("never accepts an administrative claim for an employee", async () => {
    const store = new FakeStore(); store.profile = v2();
    const service = new IdentityBlockingService(store, adminUid, () => now);
    await expect(service.beforeSignIn(smsUser({ customClaims: { super_admin: true } }), { signInMethod: "phone" }))
      .rejects.toMatchObject({ code: "ADMIN_CLAIM_FORBIDDEN" });
  });

  it("keeps active v1 users and the invitation confirmation window compatible", async () => {
    const store = new FakeStore(); store.profile = v1();
    const service = new IdentityBlockingService(store, adminUid, () => now);
    const user = { uid: "legacy", email: "legacy@example.test", emailVerified: true, disabled: false };
    await expect(service.beforeSignIn(user, { signInMethod: "password" })).resolves.toBeUndefined();
    store.profile = v1({ status: "invited", authDisabled: true, invitationStatus: "pending" });
    store.validInvitation = true;
    await expect(service.beforeSignIn(user, { signInMethod: "password" })).resolves.toBeUndefined();
    store.validInvitation = false;
    await expect(service.beforeSignIn(user, { signInMethod: "password" })).rejects.toMatchObject({ code: "ACTIVATION_EXPIRED" });
  });

  it("returns generic blocking errors without leaking identifiers", async () => {
    const service = new IdentityBlockingService(new FakeStore(), adminUid, () => now);
    const handler = createBeforeCreateHandler(service);
    await expect(handler({
      data: { ...smsUser({ email: "private@example.test" }), metadata: {}, providerData: [] },
      ipAddress: "127.0.0.1", userAgent: "test"
    })).rejects.toMatchObject({ code: "permission-denied", message: "No fue posible autorizar la operación de identidad." });
  });

  it("is deterministic under controlled retries and creates no orphan state", async () => {
    const store = new FakeStore(); store.profile = v2();
    const service = new IdentityBlockingService(store, adminUid, () => now);
    await service.beforeSignIn(smsUser(), { signInMethod: "phone" });
    await service.beforeSignIn(smsUser(), { signInMethod: "phone" });
    expect(store.profile?.version).toBe(2);
  });
});
