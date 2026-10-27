import { randomUUID } from "node:crypto";
import { deleteApp, initializeApp } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import { getFirestore, Timestamp, type Firestore } from "firebase-admin/firestore";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import type { AdminPrincipal } from "../src/auth/require-super-admin.js";
import { DisabledInvitationEmailProvider, SimulatedInvitationEmailProvider, type InvitationEmailProvider } from "../src/invitations/invitation-email-provider.js";
import { InvitationService } from "../src/invitations/invitation-service.js";
import { InvitationAcceptanceService } from "../src/invitations/invitation-acceptance-service.js";
import { InvitationTokenKeyring } from "../src/invitations/invitation-token.js";
import { FirestoreWebhookReplayStore } from "../src/invitations/firestore-webhook-replay-store.js";
import { InvitationReconciliationService } from "../src/invitations/invitation-reconciliation-service.js";
import type { UserDirectory } from "../src/users/user-query-service.js";

const principal: AdminPrincipal = {
  uid: "integration-admin",
  email: "admin@plcocina.test",
  authTime: 1,
  issuedAt: 1,
  superAdmin: true
};

let firebaseApp: ReturnType<typeof initializeApp>;
let db: Firestore;
let directory: UserDirectory;

function setup(firestore: Firestore = db, now: () => Timestamp = () => Timestamp.now(), userDirectory: UserDirectory = directory) {
  const provider = new SimulatedInvitationEmailProvider(() => now().toDate());
  const tokens = new InvitationTokenKeyring(new Map([[1, Buffer.alloc(32, 7)]]), 1);
  return {
    provider,
    tokens,
    service: new InvitationService(userDirectory, firestore, tokens, provider, "protected-super-admin", now),
    acceptance: new InvitationAcceptanceService(userDirectory, firestore, tokens, "protected-super-admin", now)
  };
}

function create(service: InvitationService, email: string, key = randomUUID()) {
  return service.create({
    body: { displayName: "Usuario Invitado", email },
    idempotencyKey: key,
    principal,
    requestId: randomUUID()
  });
}

function resend(service: InvitationService, invitationId: string, expectedRevision: number, key = randomUUID()) {
  return service.resend({ invitationId, body: { expectedRevision }, idempotencyKey: key, principal, requestId: randomUUID() });
}

function revoke(service: InvitationService, invitationId: string, expectedRevision: number, key = randomUUID()) {
  return service.revoke({ invitationId, body: { expectedRevision, reason: "Acceso ya no requerido" }, idempotencyKey: key, principal, requestId: randomUUID() });
}

function establish(acceptance: InvitationAcceptanceService, invitationId: string, token: string, password = "C0ntraseña-segura-2026!", source = randomUUID()) {
  return acceptance.establishPassword({ invitationId, token, password }, source, randomUUID());
}

beforeAll(() => {
  if (!process.env.FIREBASE_AUTH_EMULATOR_HOST || !process.env.FIRESTORE_EMULATOR_HOST) {
    throw new Error("Esta prueba requiere Auth Emulator y Firestore Emulator.");
  }
  firebaseApp = initializeApp({ projectId: "demo-plcocina-apps" }, `invite-${randomUUID()}`);
  const auth = getAuth(firebaseApp);
  db = getFirestore(firebaseApp);
  directory = {
    listUsers: (maxResults, pageToken) => auth.listUsers(maxResults, pageToken),
    getUser: (uid) => auth.getUser(uid),
    getUserByEmail: (email) => auth.getUserByEmail(email),
    getUsers: (identifiers) => auth.getUsers(identifiers),
    updateUser: (uid, properties) => auth.updateUser(uid, properties),
    revokeRefreshTokens: (uid) => auth.revokeRefreshTokens(uid),
    createUser: (properties) => auth.createUser(properties)
  };
});

afterAll(async () => { await deleteApp(firebaseApp); });

describe("C1/C2 invitation provisioning with emulators", () => {
  it("creates a disabled passwordless account, profile and hashed-token invitation", async () => {
    const { service, provider } = setup();
    const email = `invite-${randomUUID()}@outside.example`;
    const result = await create(service, email);
    const [authUser, invitation, profile, grants] = await Promise.all([
      getAuth(firebaseApp).getUser(result.uid),
      db.collection("invitations").doc(result.invitationId).get(),
      db.collection("users").doc(result.uid).get(),
      db.collection("accessGrants").where("uid", "==", result.uid).get()
    ]);

    expect(authUser).toMatchObject({ uid: result.uid, email, disabled: true, emailVerified: false });
    expect(authUser.customClaims?.super_admin).not.toBe(true);
    expect(authUser.passwordHash).toBeUndefined();
    expect(profile.data()).toMatchObject({ status: "invited", authDisabled: true, invitationStatus: "pending" });
    expect(invitation.data()).toMatchObject({ status: "active", token: { hash: expect.stringMatching(/^[a-f0-9]{64}$/) } });
    expect(JSON.stringify(invitation.data())).not.toContain(provider.deliveries[0]?.message.token);
    expect(grants.empty).toBe(true);
    expect(provider.deliveries).toHaveLength(1);
    expect(provider.deliveries[0]?.message.tracking).toEqual({ opens: false, clicks: false });
  });

  it("returns the stored result for an idempotent retry without another account or email", async () => {
    const { service, provider } = setup();
    const key = randomUUID();
    const email = `idem-${randomUUID()}@example.net`;
    const first = await create(service, email, key);
    const second = await create(service, email, key);
    expect(second).toEqual(first);
    expect(provider.deliveries).toHaveLength(1);
    expect((await getAuth(firebaseApp).getUserByEmail(email)).uid).toBe(first.uid);
  });

  it("allows only one concurrent invitation for the same normalized email", async () => {
    const email = `race-${randomUUID()}@example.org`;
    const left = setup();
    const right = setup();
    const results = await Promise.allSettled([create(left.service, email), create(right.service, email.toUpperCase())]);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    const rejected = results.find((result) => result.status === "rejected");
    expect(rejected).toMatchObject({ reason: { code: "DUPLICATE_INVITATION", status: 409 } });
    expect(left.provider.deliveries.length + right.provider.deliveries.length).toBe(1);
  });

  it("recovers when Auth succeeds and the following Firestore transaction fails", async () => {
    let transactionCalls = 0;
    const failingFirestore = new Proxy(db, {
      get(target, property, receiver) {
        if (property === "runTransaction") {
          return async (...args: Parameters<Firestore["runTransaction"]>) => {
            transactionCalls += 1;
            if (transactionCalls === 2) throw new Error("SIMULATED_FIRESTORE_AFTER_AUTH_FAILURE");
            return target.runTransaction(...args);
          };
        }
        const value = Reflect.get(target, property, receiver);
        return typeof value === "function" ? value.bind(target) : value;
      }
    });
    const { service, provider } = setup(failingFirestore);
    const key = randomUUID();
    const email = `recover-${randomUUID()}@example.com`;

    await expect(create(service, email, key)).rejects.toMatchObject({ code: "INTERNAL_ERROR" });
    const created = await getAuth(firebaseApp).getUserByEmail(email);
    expect(created.disabled).toBe(true);
    await expect(create(service, email, key)).resolves.toMatchObject({ uid: created.uid, status: "active" });
    expect(provider.deliveries).toHaveLength(1);
  });

  it("rejects a pre-existing Authentication email outside recovery", async () => {
    const email = `existing-${randomUUID()}@example.com`;
    await getAuth(firebaseApp).createUser({ email, disabled: true });
    const { service, provider } = setup();
    await expect(create(service, email)).rejects.toMatchObject({ code: "DUPLICATE_INVITATION" });
    expect(provider.deliveries).toHaveLength(0);
  });
});

describe("C7 replay protection and reconciliation with emulators", () => {
  it("claims a Resend event exactly once under concurrent retries", async () => {
    const now = Timestamp.fromDate(new Date("2026-10-23T12:00:00.000Z"));
    const store = new FirestoreWebhookReplayStore(db, () => now);
    const eventId = `msg_${randomUUID().replaceAll("-", "")}`;
    const results = await Promise.all(Array.from({ length: 20 }, () => store.claim(eventId, new Date(now.toMillis() + 300_000))));
    expect(results.filter(Boolean)).toHaveLength(1);
    const records = await db.collection("webhookReplayEvents").get();
    const matching = records.docs.filter((document) => document.data().claimedAt.toMillis() === now.toMillis());
    expect(matching).toHaveLength(1);
    expect(JSON.stringify(matching[0]!.data())).not.toContain(eventId);
    expect(matching[0]!.data().expiresAt.toMillis()).toBe(now.toMillis() + 24 * 60 * 60_000);
    await store.release(eventId);
    await expect(store.claim(eventId, new Date(now.toMillis() + 300_000))).resolves.toBe(true);
    await store.complete(eventId);
    await expect(store.claim(eventId, new Date(now.toMillis() + 300_000))).resolves.toBe(false);
    expect((await matching[0]!.ref.get()).data()).toMatchObject({ status: "completed", attempts: 2 });
  });

  it("expires a pending invitation using server time without touching Authentication", async () => {
    const { service } = setup();
    const created = await create(service, `expire-reconcile-${randomUUID()}@example.net`);
    const past = Timestamp.fromMillis(Date.now() - 60_000);
    await db.collection("invitations").doc(created.invitationId).update({ expiresAt: past, "token.expiresAt": past });
    const updateUser = vi.fn(directory.updateUser);
    const reconciliation = new InvitationReconciliationService({ ...directory, updateUser }, db, "protected-super-admin");
    const result = await reconciliation.reconcileOnce();
    const [invitation, profile] = await Promise.all([
      db.collection("invitations").doc(created.invitationId).get(),
      db.collection("users").doc(created.uid).get()
    ]);
    expect(result.expired).toBeGreaterThanOrEqual(1);
    expect(invitation.data()).toMatchObject({ status: "expired", token: null });
    expect(profile.data()).toMatchObject({ status: "disabled", invitationStatus: "expired" });
    expect(updateUser).not.toHaveBeenCalled();
  });

  it("secures Auth after the confirmation window and completes the recovery checkpoint", async () => {
    const { service, acceptance, provider } = setup();
    const created = await create(service, `confirm-expire-${randomUUID()}@example.net`);
    await establish(acceptance, created.invitationId, provider.deliveries[0]!.message.token);
    const past = Timestamp.fromMillis(Date.now() - 60_000);
    await db.collection("invitations").doc(created.invitationId).update({ confirmationExpiresAt: past });
    const reconciliation = new InvitationReconciliationService(directory, db, "protected-super-admin");
    const result = await reconciliation.reconcileOnce();
    const [authUser, invitation, operations, grants] = await Promise.all([
      getAuth(firebaseApp).getUser(created.uid),
      db.collection("invitations").doc(created.invitationId).get(),
      db.collection("adminOperations").where("invitationId", "==", created.invitationId).get(),
      db.collection("accessGrants").where("uid", "==", created.uid).get()
    ]);
    expect(result.secured).toBeGreaterThanOrEqual(1);
    expect(authUser.disabled).toBe(true);
    expect(invitation.data()).toMatchObject({ status: "expired", token: null, pendingOperationId: null });
    expect(operations.docs.some((document) => document.data().type === "invitation.expire" && document.data().status === "completed")).toBe(true);
    expect(grants.empty).toBe(true);
  });

  it("allows only one concurrent reconciliation to own an ambiguous acceptance", async () => {
    const { service, acceptance, provider } = setup();
    const created = await create(service, `reconcile-race-${randomUUID()}@example.net`);
    await establish(acceptance, created.invitationId, provider.deliveries[0]!.message.token);
    await db.collection("invitations").doc(created.invitationId).update({ confirmationExpiresAt: Timestamp.fromMillis(Date.now() - 1) });
    const left = new InvitationReconciliationService(directory, db, "protected-super-admin");
    const right = new InvitationReconciliationService(directory, db, "protected-super-admin");
    const results = await Promise.all([left.reconcileOnce(), right.reconcileOnce()]);
    expect(results.reduce((total, result) => total + result.secured, 0)).toBe(1);
    const invitation = await db.collection("invitations").doc(created.invitationId).get();
    expect(invitation.data()?.status).toBe("expired");
  });
});

describe("C3 invitation lifecycle with emulators", () => {
  it("resends once, rotates the token and invalidates the previous generation", async () => {
    const { service, provider, tokens } = setup();
    const created = await create(service, `resend-${randomUUID()}@example.net`);
    const before = (await db.collection("invitations").doc(created.invitationId).get()).data()!;
    const oldToken = provider.deliveries[0]!.message.token;
    const result = await resend(service, created.invitationId, created.revision);
    const after = (await db.collection("invitations").doc(created.invitationId).get()).data()!;
    expect(result).toMatchObject({ status: "active", deliveryStatus: "accepted", revision: created.revision + 2 });
    expect(after.token.generation).toBe(before.token.generation + 1);
    expect(after.token.salt).not.toBe(before.token.salt);
    expect(tokens.verify(oldToken, after.token.hash)).toBe(false);
    expect(provider.deliveries).toHaveLength(2);
    expect(JSON.stringify(after)).not.toContain(provider.deliveries[1]!.message.token);
  });

  it("returns one delivery for an idempotent resend retry", async () => {
    const { service, provider } = setup();
    const created = await create(service, `retry-${randomUUID()}@example.net`);
    const key = randomUUID();
    const first = await resend(service, created.invitationId, created.revision, key);
    const second = await resend(service, created.invitationId, created.revision, key);
    expect(second).toEqual(first);
    expect(provider.deliveries).toHaveLength(2);
  });

  it("recovers a lost provider response without sending twice", async () => {
    const { service, provider } = setup();
    const created = await create(service, `lost-${randomUUID()}@example.net`);
    provider.queueOutcome("response_lost");
    const key = randomUUID();
    await expect(resend(service, created.invitationId, created.revision, key)).rejects.toMatchObject({ code: "INTERNAL_ERROR" });
    await expect(resend(service, created.invitationId, created.revision, key)).resolves.toMatchObject({ status: "active" });
    expect(provider.deliveries).toHaveLength(2);
  });

  it("recovers a definitive simulated delivery failure with the same generation", async () => {
    const { service, provider } = setup();
    const created = await create(service, `delivery-failure-${randomUUID()}@example.net`);
    provider.queueOutcome("network_error");
    const key = randomUUID();
    await expect(resend(service, created.invitationId, created.revision, key)).rejects.toMatchObject({ code: "INTERNAL_ERROR" });
    const failed = (await db.collection("invitations").doc(created.invitationId).get()).data()!;
    expect(failed).toMatchObject({ status: "reconciliation_required", delivery: { status: "failed", failureCode: "PROVIDER_NETWORK_ERROR" } });
    await expect(resend(service, created.invitationId, created.revision, key)).resolves.toMatchObject({ status: "active" });
    expect(provider.deliveries).toHaveLength(2);
  });

  it("allows only one concurrent generation", async () => {
    const left = setup();
    const right = setup();
    const created = await create(left.service, `resend-race-${randomUUID()}@example.net`);
    const results = await Promise.allSettled([
      resend(left.service, created.invitationId, created.revision),
      resend(right.service, created.invitationId, created.revision)
    ]);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((result) => result.status === "rejected")).toHaveLength(1);
  });

  it("revokes atomically before disabling Auth and remains idempotent", async () => {
    const { service } = setup();
    const created = await create(service, `revoke-${randomUUID()}@example.net`);
    const key = randomUUID();
    const first = await revoke(service, created.invitationId, created.revision, key);
    const second = await revoke(service, created.invitationId, created.revision, key);
    const [invitation, authUser, profile] = await Promise.all([
      db.collection("invitations").doc(created.invitationId).get(), getAuth(firebaseApp).getUser(created.uid), db.collection("users").doc(created.uid).get()
    ]);
    expect(second).toEqual(first);
    expect(first).toMatchObject({ status: "revoked" });
    expect(invitation.data()).toMatchObject({ status: "revoked", token: null, revokeReason: "Acceso ya no requerido" });
    expect(authUser.disabled).toBe(true);
    expect(profile.data()).toMatchObject({ status: "disabled", invitationStatus: "revoked" });
  });

  it("keeps create and resend closed but revokes safely without an email provider", async () => {
    const configured = setup();
    const email = `provider-disabled-${randomUUID()}@example.net`;
    const created = await create(configured.service, email);
    const originalToken = configured.provider.deliveries[0]!.message.token;
    const disabled = new InvitationService(directory, db, null, new DisabledInvitationEmailProvider(), "protected-super-admin", () => Timestamp.now());

    await expect(create(disabled, `blocked-${randomUUID()}@example.net`)).rejects.toMatchObject({ code: "INTERNAL_ERROR", status: 503 });
    await expect(resend(disabled, created.invitationId, created.revision)).rejects.toMatchObject({ code: "INTERNAL_ERROR", status: 503 });

    const key = randomUUID();
    const first = await revoke(disabled, created.invitationId, created.revision, key);
    const second = await revoke(disabled, created.invitationId, created.revision, key);
    expect(second).toEqual(first);
    expect(first).toMatchObject({ status: "revoked" });
    const [invitation, authUser, profile, audit] = await Promise.all([
      db.collection("invitations").doc(created.invitationId).get(),
      getAuth(firebaseApp).getUser(created.uid),
      db.collection("users").doc(created.uid).get(),
      db.collection("auditEvents").where("resourceId", "==", created.invitationId).get()
    ]);
    expect(invitation.data()).toMatchObject({ status: "revoked", token: null, revokeReason: "Acceso ya no requerido" });
    expect(authUser.disabled).toBe(true);
    expect(profile.data()).toMatchObject({ status: "disabled", invitationStatus: "revoked" });
    expect(audit.docs.some((doc) => doc.data().action === "invitation.revoked" && doc.data().result === "success")).toBe(true);
    await expect(configured.acceptance.validate({ invitationId: created.invitationId, token: originalToken }, randomUUID())).rejects.toMatchObject({ code: "INVITATION_INVALID" });
  });

  it("never calls an interrupted email provider while revoking", async () => {
    const configured = setup();
    const created = await create(configured.service, `provider-interruption-${randomUUID()}@example.net`);
    const send = vi.fn().mockRejectedValue(new Error("SIMULATED_PROVIDER_OUTAGE"));
    const interruptedProvider: InvitationEmailProvider = { name: "simulated", configured: true, send };
    const service = new InvitationService(directory, db, null, interruptedProvider, "protected-super-admin", () => Timestamp.now());
    await expect(revoke(service, created.invitationId, created.revision)).resolves.toMatchObject({ status: "revoked" });
    expect(send).not.toHaveBeenCalled();
  });

  it("keeps the token invalidated while recovering an Auth failure during revocation", async () => {
    let failOnce = true;
    const failingDirectory: UserDirectory = {
      ...directory,
      updateUser: async (uid, properties) => {
        if (failOnce) { failOnce = false; throw new Error("SIMULATED_AUTH_UPDATE_FAILURE"); }
        return directory.updateUser(uid, properties);
      }
    };
    const { service } = setup(db, () => Timestamp.now(), failingDirectory);
    const created = await create(service, `revoke-recovery-${randomUUID()}@example.net`);
    const key = randomUUID();
    await expect(revoke(service, created.invitationId, created.revision, key)).rejects.toMatchObject({ code: "INTERNAL_ERROR" });
    expect((await db.collection("invitations").doc(created.invitationId).get()).data()).toMatchObject({ status: "revoked", token: null });
    await expect(revoke(service, created.invitationId, created.revision, key)).resolves.toMatchObject({ status: "revoked" });
  });

  it("protects every account carrying super_admin", async () => {
    const { service } = setup();
    const created = await create(service, `protected-${randomUUID()}@example.net`);
    await getAuth(firebaseApp).setCustomUserClaims(created.uid, { super_admin: true });
    await expect(revoke(service, created.invitationId, created.revision)).rejects.toMatchObject({ code: "PROTECTED_ACCOUNT", status: 409 });
    expect((await db.collection("invitations").doc(created.invitationId).get()).data()).toMatchObject({ status: "active", token: expect.any(Object) });
  });

  it("requires explicit admin intervention after the 23 hour automatic retry window", async () => {
    let clock = Timestamp.fromDate(new Date("2026-10-23T00:00:00Z"));
    const { service, provider } = setup(db, () => clock);
    const created = await create(service, `retry-window-${randomUUID()}@example.net`);
    provider.queueOutcome("timeout");
    const oldKey = randomUUID();
    await expect(resend(service, created.invitationId, created.revision, oldKey)).rejects.toMatchObject({ code: "INTERNAL_ERROR" });
    clock = Timestamp.fromMillis(clock.toMillis() + 24 * 3_600_000);
    await expect(resend(service, created.invitationId, created.revision, oldKey)).rejects.toMatchObject({ code: "DELIVERY_RETRY_WINDOW_EXPIRED" });
    const pending = (await db.collection("invitations").doc(created.invitationId).get()).data()!;
    await expect(resend(service, created.invitationId, pending.revision)).resolves.toMatchObject({ status: "active" });
  });

  it("serializes concurrent resend and revoke operations", async () => {
    const left = setup();
    const right = setup();
    const created = await create(left.service, `mixed-race-${randomUUID()}@example.net`);
    const results = await Promise.allSettled([
      resend(left.service, created.invitationId, created.revision),
      revoke(right.service, created.invitationId, created.revision)
    ]);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((result) => result.status === "rejected")).toHaveLength(1);
  });

  it("materializes expiration with the server clock and removes token material", async () => {
    let clock = Timestamp.fromDate(new Date("2026-10-23T00:00:00Z"));
    const { service } = setup(db, () => clock);
    const created = await create(service, `expire-${randomUUID()}@example.net`);
    clock = Timestamp.fromMillis(clock.toMillis() + 73 * 3_600_000);
    const result = await service.reconcileExpired();
    const invitation = (await db.collection("invitations").doc(created.invitationId).get()).data();
    expect(result.expired).toBeGreaterThanOrEqual(1);
    expect(invitation).toMatchObject({ status: "expired", token: null, pendingOperationId: null });
  });

  it("reconciles an expiration whose Auth effect failed after token invalidation", async () => {
    let clock = Timestamp.fromDate(new Date("2026-11-01T00:00:00Z"));
    let failOnce = true;
    let targetUid = "";
    const failingDirectory: UserDirectory = {
      ...directory,
      updateUser: async (uid, properties) => {
        if (uid === targetUid && failOnce) { failOnce = false; throw new Error("SIMULATED_EXPIRATION_AUTH_FAILURE"); }
        return directory.updateUser(uid, properties);
      }
    };
    const { service } = setup(db, () => clock, failingDirectory);
    const created = await create(service, `expire-recovery-${randomUUID()}@example.net`);
    targetUid = created.uid;
    clock = Timestamp.fromMillis(clock.toMillis() + 73 * 3_600_000);
    const first = await service.reconcileExpired();
    expect(first.reconciliationRequired).toBeGreaterThanOrEqual(1);
    expect((await db.collection("invitations").doc(created.invitationId).get()).data()).toMatchObject({ status: "expired", token: null, pendingOperationId: expect.any(String) });
    const second = await service.reconcileExpired();
    expect(second).toMatchObject({ expired: expect.any(Number), reconciliationRequired: expect.any(Number) });
    expect(second.expired).toBeGreaterThanOrEqual(1);
    expect((await db.collection("invitations").doc(created.invitationId).get()).data()).toMatchObject({ status: "expired", token: null, pendingOperationId: null });
  });

  it("never persists clear tokens in invitations, operations or audit events", async () => {
    const { service, provider } = setup();
    const created = await create(service, `secret-${randomUUID()}@example.net`);
    await resend(service, created.invitationId, created.revision);
    const clearTokens = provider.deliveries.map((delivery) => delivery.message.token);
    const [invitations, operations, audits] = await Promise.all([
      db.collection("invitations").where("invitationId", "==", created.invitationId).get(),
      db.collection("adminOperations").where("invitationId", "==", created.invitationId).get(),
      db.collection("auditEvents").where("resourceId", "==", created.invitationId).get()
    ]);
    const persisted = JSON.stringify([...invitations.docs, ...operations.docs, ...audits.docs].map((doc) => doc.data()));
    for (const token of clearTokens) expect(persisted).not.toContain(token);
  });
});

describe("C4 invitation acceptance with emulators", () => {
  it("validates without consuming a current token and rejects unknown tokens uniformly", async () => {
    const { service, acceptance, provider } = setup();
    const created = await create(service, `validate-${randomUUID()}@example.net`);
    const token = provider.deliveries[0]!.message.token;
    await expect(acceptance.validate({ invitationId: created.invitationId, token }, "valid-source")).resolves.toEqual({ valid: true, expiresAt: created.expiresAt });
    await expect(acceptance.validate({ invitationId: created.invitationId, token: "A".repeat(43) }, "invalid-source")).rejects.toMatchObject({ code: "INVITATION_INVALID" });
    expect((await db.collection("invitations").doc(created.invitationId).get()).data()).toMatchObject({ status: "active", token: expect.any(Object) });
  });

  it("rejects expired, revoked and previous-generation tokens", async () => {
    let clock = Timestamp.fromDate(new Date("2026-12-01T00:00:00Z"));
    const expiring = setup(db, () => clock);
    const expired = await create(expiring.service, `expired-token-${randomUUID()}@example.net`);
    const expiredToken = expiring.provider.deliveries[0]!.message.token;
    clock = Timestamp.fromMillis(clock.toMillis() + 73 * 3_600_000);
    await expect(expiring.acceptance.validate({ invitationId: expired.invitationId, token: expiredToken }, randomUUID())).rejects.toMatchObject({ code: "INVITATION_INVALID" });

    const revokedSetup = setup();
    const revoked = await create(revokedSetup.service, `revoked-token-${randomUUID()}@example.net`);
    const revokedToken = revokedSetup.provider.deliveries[0]!.message.token;
    await revoke(revokedSetup.service, revoked.invitationId, revoked.revision);
    await expect(revokedSetup.acceptance.validate({ invitationId: revoked.invitationId, token: revokedToken }, randomUUID())).rejects.toMatchObject({ code: "INVITATION_INVALID" });

    const rotated = setup();
    const original = await create(rotated.service, `rotated-token-${randomUUID()}@example.net`);
    const oldToken = rotated.provider.deliveries[0]!.message.token;
    await resend(rotated.service, original.invitationId, original.revision);
    await expect(rotated.acceptance.validate({ invitationId: original.invitationId, token: oldToken }, randomUUID())).rejects.toMatchObject({ code: "INVITATION_INVALID" });
  });

  it("enforces the password policy without consuming the invitation", async () => {
    const { service, acceptance, provider } = setup();
    const created = await create(service, `password-policy-${randomUUID()}@example.net`);
    const token = provider.deliveries[0]!.message.token;
    await expect(establish(acceptance, created.invitationId, token, "short")).rejects.toMatchObject({ code: "VALIDATION_ERROR" });
    expect((await db.collection("invitations").doc(created.invitationId).get()).data()).toMatchObject({ status: "active", token: expect.any(Object) });
  });

  it("allows only one concurrent password establishment and grants no privileges", async () => {
    const { service, acceptance, provider } = setup();
    const created = await create(service, `consume-race-${randomUUID()}@example.net`);
    const token = provider.deliveries[0]!.message.token;
    const results = await Promise.allSettled([
      establish(acceptance, created.invitationId, token, "First-password-2026!"),
      establish(acceptance, created.invitationId, token, "Second-password-2026!")
    ]);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((result) => result.status === "rejected")).toHaveLength(1);
    const [invitation, authUser, grants] = await Promise.all([
      db.collection("invitations").doc(created.invitationId).get(), getAuth(firebaseApp).getUser(created.uid), db.collection("accessGrants").where("uid", "==", created.uid).get()
    ]);
    expect(invitation.data()).toMatchObject({ status: "password_set", token: null });
    expect(authUser.disabled).toBe(false);
    expect(authUser.customClaims?.super_admin).not.toBe(true);
    expect(grants.empty).toBe(true);
  });

  it("serializes password establishment against administrative revocation", async () => {
    const { service, acceptance, provider } = setup();
    const created = await create(service, `consume-revoke-race-${randomUUID()}@example.net`);
    const token = provider.deliveries[0]!.message.token;
    const results = await Promise.allSettled([
      establish(acceptance, created.invitationId, token),
      revoke(service, created.invitationId, created.revision)
    ]);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((result) => result.status === "rejected")).toHaveLength(1);
    const invitation = (await db.collection("invitations").doc(created.invitationId).get()).data()!;
    expect(["password_set", "revoked"]).toContain(invitation.status);
    expect(invitation.token).toBeNull();
  });

  it("lets server-clock expiration win before password establishment", async () => {
    let clock = Timestamp.fromDate(new Date("2027-01-01T00:00:00Z"));
    const { service, acceptance, provider } = setup(db, () => clock);
    const created = await create(service, `consume-expire-race-${randomUUID()}@example.net`);
    const token = provider.deliveries[0]!.message.token;
    clock = Timestamp.fromMillis(clock.toMillis() + 73 * 3_600_000);
    const results = await Promise.allSettled([
      establish(acceptance, created.invitationId, token),
      service.reconcileExpired()
    ]);
    expect(results[0]).toMatchObject({ status: "rejected", reason: { code: "INVITATION_INVALID" } });
    expect(results[1]).toMatchObject({ status: "fulfilled" });
    expect((await db.collection("invitations").doc(created.invitationId).get()).data()).toMatchObject({ status: "expired", token: null });
  });

  it("compensates a Firebase failure and requires a newly rotated invitation", async () => {
    const base = setup();
    const created = await create(base.service, `auth-failure-${randomUUID()}@example.net`);
    const token = base.provider.deliveries[0]!.message.token;
    const failingDirectory: UserDirectory = {
      ...directory,
      updateUser: async (uid, properties) => {
        if (properties.password) throw new Error("SIMULATED_AUTH_PASSWORD_FAILURE");
        return directory.updateUser(uid, properties);
      }
    };
    const acceptance = new InvitationAcceptanceService(failingDirectory, db, base.tokens, "protected-super-admin");
    await expect(establish(acceptance, created.invitationId, token)).rejects.toMatchObject({ code: "RECONCILIATION_REQUIRED" });
    const failed = (await db.collection("invitations").doc(created.invitationId).get()).data()!;
    expect(failed).toMatchObject({ status: "reconciliation_required", token: null, pendingOperationId: null });
    expect((await getAuth(firebaseApp).getUser(created.uid)).disabled).toBe(true);
    await expect(establish(acceptance, created.invitationId, token)).rejects.toMatchObject({ code: "INVITATION_INVALID" });
    await expect(resend(base.service, created.invitationId, failed.revision)).resolves.toMatchObject({ status: "active" });
  });

  it("does not repeat an ambiguous Auth update whose response was lost", async () => {
    const base = setup();
    const created = await create(base.service, `auth-response-lost-${randomUUID()}@example.net`);
    const token = base.provider.deliveries[0]!.message.token;
    let passwordUpdates = 0;
    const ambiguousDirectory: UserDirectory = {
      ...directory,
      updateUser: async (uid, properties) => {
        if (properties.password) {
          passwordUpdates += 1;
          await directory.updateUser(uid, properties);
          throw new Error("SIMULATED_AUTH_RESPONSE_LOST");
        }
        return directory.updateUser(uid, properties);
      }
    };
    const acceptance = new InvitationAcceptanceService(ambiguousDirectory, db, base.tokens, "protected-super-admin");
    await expect(establish(acceptance, created.invitationId, token)).rejects.toMatchObject({ code: "RECONCILIATION_REQUIRED" });
    expect(passwordUpdates).toBe(1);
    expect((await getAuth(firebaseApp).getUser(created.uid)).disabled).toBe(true);
    await expect(establish(acceptance, created.invitationId, token)).rejects.toMatchObject({ code: "INVITATION_INVALID" });
    expect(passwordUpdates).toBe(1);
  });

  it("disables the account when Firestore fails after the Authentication update", async () => {
    const base = setup();
    const created = await create(base.service, `firestore-after-auth-${randomUUID()}@example.net`);
    const token = base.provider.deliveries[0]!.message.token;
    let calls = 0;
    const failingFirestore = new Proxy(db, {
      get(target, property, receiver) {
        if (property === "runTransaction") return async (...args: Parameters<Firestore["runTransaction"]>) => {
          calls += 1;
          if (calls === 4) throw new Error("SIMULATED_FIRESTORE_AFTER_PASSWORD");
          return target.runTransaction(...args);
        };
        const value = Reflect.get(target, property, receiver);
        return typeof value === "function" ? value.bind(target) : value;
      }
    });
    const acceptance = new InvitationAcceptanceService(directory, failingFirestore, base.tokens, "protected-super-admin");
    await expect(establish(acceptance, created.invitationId, token)).rejects.toMatchObject({ code: "RECONCILIATION_REQUIRED" });
    expect((await getAuth(firebaseApp).getUser(created.uid)).disabled).toBe(true);
    expect((await db.collection("invitations").doc(created.invitationId).get()).data()).toMatchObject({ status: "reconciliation_required", token: null });
  });

  it("confirms the matching authenticated identity within ten minutes", async () => {
    let clock = Timestamp.fromDate(new Date("2026-12-10T00:00:00Z"));
    const { service, acceptance, provider } = setup(db, () => clock);
    const email = `confirm-${randomUUID()}@example.net`;
    const created = await create(service, email);
    const password = "Authenticated-user-2026!";
    await establish(acceptance, created.invitationId, provider.deliveries[0]!.message.token, password);
    const authHost = process.env.FIREBASE_AUTH_EMULATOR_HOST!;
    const signIn = await fetch(`http://${authHost}/identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=fake-api-key`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password, returnSecureToken: true })
    });
    expect(signIn.ok).toBe(true);
    expect(await signIn.json()).toMatchObject({ localId: created.uid, email });
    const result = await acceptance.confirm(created.invitationId, { uid: created.uid, email, superAdmin: false, decoded: {} as never }, randomUUID());
    const [profile, invitation, grants] = await Promise.all([
      db.collection("users").doc(created.uid).get(), db.collection("invitations").doc(created.invitationId).get(), db.collection("accessGrants").where("uid", "==", created.uid).get()
    ]);
    expect(result.status).toBe("accepted");
    expect(profile.data()).toMatchObject({ status: "active", authDisabled: false, invitationStatus: "accepted" });
    expect(invitation.data()).toMatchObject({ status: "accepted", token: null });
    expect(grants.empty).toBe(true);
  });

  it("rejects confirmation for another UID, after ten minutes, or for a Super Admin", async () => {
    let clock = Timestamp.fromDate(new Date("2026-12-15T00:00:00Z"));
    const first = setup(db, () => clock);
    const email = `confirm-reject-${randomUUID()}@example.net`;
    const created = await create(first.service, email);
    await establish(first.acceptance, created.invitationId, first.provider.deliveries[0]!.message.token);
    await expect(first.acceptance.confirm(created.invitationId, { uid: "wrong-uid", email, superAdmin: false, decoded: {} as never }, randomUUID())).rejects.toMatchObject({ code: "INVITATION_INVALID" });
    await expect(first.acceptance.confirm(created.invitationId, { uid: created.uid, email, superAdmin: true, decoded: {} as never }, randomUUID())).rejects.toMatchObject({ code: "INVITATION_INVALID" });
    clock = Timestamp.fromMillis(clock.toMillis() + 11 * 60_000);
    await expect(first.acceptance.confirm(created.invitationId, { uid: created.uid, email, superAdmin: false, decoded: {} as never }, randomUUID())).rejects.toMatchObject({ code: "INVITATION_INVALID" });
  });

  it("rejects password establishment for any account that becomes Super Admin", async () => {
    const { service, acceptance, provider } = setup();
    const created = await create(service, `admin-reject-${randomUUID()}@example.net`);
    await getAuth(firebaseApp).setCustomUserClaims(created.uid, { super_admin: true });
    await expect(establish(acceptance, created.invitationId, provider.deliveries[0]!.message.token)).rejects.toMatchObject({ code: "INVITATION_INVALID" });
    expect((await db.collection("invitations").doc(created.invitationId).get()).data()).toMatchObject({ status: "active", token: expect.any(Object) });
  });

  it("enforces a concurrent-safe per-invitation and source rate limit", async () => {
    const { service, acceptance, provider } = setup();
    const created = await create(service, `rate-${randomUUID()}@example.net`);
    const body = { invitationId: created.invitationId, token: provider.deliveries[0]!.message.token };
    for (let attempt = 0; attempt < 12; attempt += 1) await acceptance.validate(body, "same-origin");
    await expect(acceptance.validate(body, "same-origin")).rejects.toMatchObject({ code: "RATE_LIMITED", status: 429 });
  });
});
