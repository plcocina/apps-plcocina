import { randomUUID } from "node:crypto";
import { deleteApp, initializeApp } from "firebase-admin/app";
import { Timestamp, getFirestore, type Firestore } from "firebase-admin/firestore";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { GoogleIdentityLinkingService, readValidIdentityLinkAuthorization } from "../src/identities/identity-linking-service.js";
import { IdentityReservationService } from "../src/identities/identity-reservation-service.js";
import { AuthCoordinationPersistenceService } from "../src/identities/identity-auth-coordination-service.js";

let app: ReturnType<typeof initializeApp>;
let db: Firestore;
const pepper = Buffer.alloc(32, 0x4c);
const adminUid = "protected-admin";
const clock = Timestamp.fromDate(new Date("2026-11-04T20:00:00.000Z"));

beforeAll(() => {
  if (!process.env.FIRESTORE_EMULATOR_HOST) throw new Error("Esta prueba requiere Firestore Emulator.");
  app = initializeApp({ projectId: "demo-plcocina-apps" }, `identity-linking-${randomUUID()}`);
  db = getFirestore(app);
});

afterAll(async () => { await deleteApp(app); });

type Fixture = Awaited<ReturnType<typeof fixture>>;

async function fixture(overrides: { uid?: string; subject?: string; profile?: Record<string, unknown>; authorization?: Record<string, unknown>; persistAuthorization?: boolean } = {}) {
  const uid = overrides.uid ?? `google-user-${randomUUID()}`;
  const subject = overrides.subject ?? `google-subject-${randomUUID()}`;
  const operationId = randomUUID();
  const idempotencyKey = randomUUID();
  const authorizationId = randomUUID();
  const reservation = await new IdentityReservationService(db, pepper, () => clock).reserve({
    operationId: randomUUID(), uid, kind: "googleSubject", value: subject
  });
  const profile = {
    uid,
    displayName: "Empleado Workspace",
    status: "invited",
    authDisabled: true,
    invitationStatus: "accepted",
    authMethod: "googleWorkspace",
    phoneE164: null,
    normalizedPhone: null,
    email: `employee-${randomUUID()}@plcocina.com`,
    normalizedEmail: "",
    phoneVerifiedAt: null,
    emailVerifiedAt: clock,
    googleWorkspace: {
      authorizedDomain: "plcocina.com",
      subject,
      linkingStatus: "verified",
      verificationStatus: "verified",
      verifiedAt: clock,
      linkedAt: null,
      verificationRevision: 1,
      operationId: null
    },
    activationStatus: "recovery_required",
    credentialRevision: 1,
    authorizationRevision: 1,
    sessionValidAfter: clock,
    createdAt: clock,
    createdBy: adminUid,
    updatedAt: clock,
    updatedBy: adminUid,
    revision: 2,
    pendingOperationId: null,
    identityContractVersion: "2.1",
    version: 2,
    ...overrides.profile
  };
  profile.normalizedEmail = profile.email as string;
  await db.collection("users").doc(uid).set(profile);
  const authorization = {
    authorizationId,
    operation: "google.identity_link",
    operationId,
    idempotencyKey,
    targetUid: uid,
    googleSubjectHash: reservation.identifierHash,
    authorizedByUid: adminUid,
    expectedRevision: 2,
    reason: "Vinculación aprobada para prueba aislada",
    issuedAt: Timestamp.fromMillis(clock.toMillis() - 60_000),
    expiresAt: Timestamp.fromMillis(clock.toMillis() + 5 * 60_000),
    state: "pending",
    stateChangedAt: null,
    version: 1,
    ...overrides.authorization
  };
  const service = new GoogleIdentityLinkingService(db, pepper, adminUid, () => clock);
  if (overrides.persistAuthorization !== false) await service.persistAuthorization(authorization);
  const request = {
    authorizationId,
    operation: "google.identity_link",
    operationId,
    idempotencyKey,
    targetUid: uid,
    googleSubjectHash: reservation.identifierHash,
    expectedRevision: 2,
    requestedActivationStatus: "linked_pending_activation"
  };
  const verifiedIdentity = {
    subject,
    verifiedAt: clock,
    validUntil: Timestamp.fromMillis(clock.toMillis() + 5 * 60_000),
    verificationId: randomUUID()
  };
  return { uid, subject, reservation, authorization, request, verifiedIdentity, service };
}

async function link(value: Fixture) {
  return value.service.linkVerifiedIdentity({
    trustedTargetUid: value.uid,
    trustedAdministratorUid: adminUid,
    request: value.request,
    verifiedIdentity: value.verifiedIdentity
  });
}

async function expectRejected(work: Promise<unknown>, code: string) {
  await expect(work).rejects.toMatchObject({ code });
}

function invitationRecord(uid: string, overrides: {
  status?: "active" | "revoked";
  expiresAt?: Timestamp;
  token?: Record<string, unknown> | null;
} = {}) {
  const invitationId = randomUUID();
  const email = `invitation-${randomUUID()}@plcocina.com`;
  const expiresAt = overrides.expiresAt ?? Timestamp.fromMillis(clock.toMillis() + 60 * 60_000);
  const issuedAt = Timestamp.fromMillis(clock.toMillis() - 60_000);
  return {
    invitationId,
    email,
    normalizedEmail: email,
    displayName: "Empleado invitado",
    uid,
    status: overrides.status ?? "active",
    token: overrides.token === null ? null : overrides.token ?? {
      hash: "a".repeat(64), generation: 1, salt: "A".repeat(22), keyVersion: 1, issuedAt, expiresAt
    },
    delivery: {
      provider: "simulated" as const, status: "accepted" as const, idempotencyKey: randomUUID(),
      providerMessageId: null, templateVersion: 1, firstAttemptAt: issuedAt, retryUntil: expiresAt,
      sentAt: issuedAt, deliveredAt: issuedAt, failureCode: null
    },
    expiresAt,
    createdAt: issuedAt,
    createdBy: adminUid,
    updatedAt: issuedAt,
    updatedBy: adminUid,
    pendingOperationId: null,
    consumeOperationId: null,
    consumeLeaseExpiresAt: null,
    passwordSetAt: null,
    confirmationExpiresAt: null,
    deliveredAt: issuedAt,
    acceptedAt: null,
    revokedAt: null,
    revokedBy: null,
    revokeReason: null,
    expiredAt: null,
    resendCount: 0,
    lastSentAt: issuedAt,
    revision: 1,
    version: 2 as const
  };
}

const authenticatedAdmin = {
  uid: adminUid, email: "admin@plcocina.com", authTime: 1_799_999_000, issuedAt: 1_799_999_000, superAdmin: true as const
};

async function persistInvitationBinding(value: Fixture, invitation = invitationRecord(value.uid)) {
  await db.collection("invitations").doc(invitation.invitationId).set(invitation);
  const authorization = { ...value.authorization, invitationId: invitation.invitationId };
  const result = await value.service.persistEmployeeInvitationAuthorization(authorization, authenticatedAdmin);
  return { authorization, invitation, result };
}

describe("E4B2 invitation-bound authorization persistence", () => {
  it("persists an active invitation binding to the target UID", async () => {
    const value = await fixture({ persistAuthorization: false });
    const linked = await persistInvitationBinding(value);
    expect(linked.result).toMatchObject({
      authorizationId: value.authorization.authorizationId, operationId: value.authorization.operationId,
      targetUid: value.uid, invitationId: linked.invitation.invitationId
    });
    expect((await db.collection("identityLinkAuthorizations").doc(value.authorization.authorizationId).get()).data())
      .toMatchObject({ targetUid: value.uid, operationId: value.authorization.operationId, invitationId: linked.invitation.invitationId });
  });

  it.each([
    ["expired", { expiresAt: clock }, "INVITATION_NOT_ACTIVE"],
    ["revoked", { status: "revoked" as const, token: null }, "INVITATION_NOT_ACTIVE"],
    ["another UID", { uid: "different-employee" }, "INVITATION_UID_MISMATCH"]
  ])("rejects an %s invitation without writing an authorization", async (_label, overrides, code) => {
    const value = await fixture({ persistAuthorization: false });
    const invitation = invitationRecord(overrides.uid ?? value.uid, overrides);
    const invitationRef = db.collection("invitations").doc(invitation.invitationId);
    await invitationRef.set(invitation);
    const before = (await invitationRef.get()).data();
    await expectRejected(value.service.persistEmployeeInvitationAuthorization(
      { ...value.authorization, invitationId: invitation.invitationId }, authenticatedAdmin
    ), code);
    expect((await db.collection("identityLinkAuthorizations").doc(value.authorization.authorizationId).get()).exists).toBe(false);
    expect((await invitationRef.get()).data()).toEqual(before);
  });

  it("rejects a missing invitation without a partial authorization write", async () => {
    const value = await fixture({ persistAuthorization: false });
    const invitationId = randomUUID();
    await expectRejected(value.service.persistEmployeeInvitationAuthorization(
      { ...value.authorization, invitationId }, authenticatedAdmin
    ), "INVITATION_NOT_FOUND");
    expect((await db.collection("identityLinkAuthorizations").doc(value.authorization.authorizationId).get()).exists).toBe(false);
  });

  it("returns the same authorization for an equivalent retry", async () => {
    const value = await fixture({ persistAuthorization: false });
    const invitation = invitationRecord(value.uid);
    await db.collection("invitations").doc(invitation.invitationId).set(invitation);
    const authorization = { ...value.authorization, invitationId: invitation.invitationId };
    const first = await value.service.persistEmployeeInvitationAuthorization(authorization, authenticatedAdmin);
    const second = await value.service.persistEmployeeInvitationAuthorization(authorization, authenticatedAdmin);
    expect(second).toEqual(first);
  });

  it("resolves target UID and Google subject only from completed E4B2 records", async () => {
    const value = await fixture();
    await link(value);
    const authorizationRef = db.collection("identityLinkAuthorizations").doc(value.authorization.authorizationId);
    await authorizationRef.update({ state: "pending", stateChangedAt: null });
    const profileSnapshot = await db.collection("users").doc(value.uid).get();
    const linkedProfile = profileSnapshot.data()!;
    const expiresAt = Timestamp.fromMillis(clock.toMillis() + 5 * 60_000);
    const coordinationId = randomUUID();
    await new AuthCoordinationPersistenceService(db, adminUid, () => clock).create({
      trustedAdministratorUid: adminUid,
      document: {
        operationId: coordinationId, operation: "google.firebase_provider_link",
        expectedFirebaseUid: value.uid, expectedInternalUid: value.uid,
        googleSubjectHash: value.reservation.identifierHash, state: "not_started",
        expectedProfileRevision: linkedProfile.revision, currentProfileRevision: linkedProfile.revision,
        idempotencyKey: randomUUID(), authorizationId: value.authorization.authorizationId, challengeId: null,
        evidence: {
          authorization: { authorizationId: value.authorization.authorizationId, operation: "google.identity_link",
            validatedBy: "identity-link-authorization", validatedAt: clock, validUntil: expiresAt },
          firestoreLink: { linkOperationId: value.authorization.operationId,
            observedBy: "identity-linking-service", linkedAt: clock, profileRevision: linkedProfile.revision,
            activationStatus: "linked_pending_activation", authDisabled: true },
          challenge: null, googleVerification: null, firebaseSession: null, firebaseProvider: null, postflight: null
        },
        conflictReason: null, revision: 1, lastEvent: null, createdAt: clock, updatedAt: clock, expiresAt,
        localActivationStatus: "linked_pending_activation", localAuthDisabled: true, version: 1
      }
    });
    const invitation = invitationRecord(value.uid);
    await db.collection("invitations").doc(invitation.invitationId).set(invitation);
    const result = await value.service.bindEmployeeInvitationAuthorization({
      authorizationId: value.authorization.authorizationId, invitationId: invitation.invitationId,
      principal: authenticatedAdmin
    });
    expect(result).toMatchObject({
      authorizationId: value.authorization.authorizationId, operationId: value.authorization.operationId,
      targetUid: value.uid, googleSubjectHash: value.reservation.identifierHash,
      invitationId: invitation.invitationId, state: "pending"
    });
  });

  it("rejects another invitation for the same UID without replacing the original binding", async () => {
    const value = await fixture({ persistAuthorization: false });
    const firstInvitation = invitationRecord(value.uid);
    const secondInvitation = invitationRecord(value.uid);
    await db.collection("invitations").doc(firstInvitation.invitationId).set(firstInvitation);
    await db.collection("invitations").doc(secondInvitation.invitationId).set(secondInvitation);
    const authorizationRef = db.collection("identityLinkAuthorizations").doc(value.authorization.authorizationId);
    await value.service.persistEmployeeInvitationAuthorization(
      { ...value.authorization, invitationId: firstInvitation.invitationId }, authenticatedAdmin
    );
    const before = (await authorizationRef.get()).data();
    const secondBefore = (await db.collection("invitations").doc(secondInvitation.invitationId).get()).data();
    await expectRejected(value.service.persistEmployeeInvitationAuthorization(
      { ...value.authorization, invitationId: secondInvitation.invitationId }, authenticatedAdmin
    ), "AUTHORIZATION_INVITATION_CONFLICT");
    expect((await authorizationRef.get()).data()).toEqual(before);
    expect((await db.collection("invitations").doc(secondInvitation.invitationId).get()).data()).toEqual(secondBefore);
  });

  it("keeps legacy E4B2 authorizations without an invitation binding", async () => {
    const value = await fixture();
    const stored = (await db.collection("identityLinkAuthorizations").doc(value.authorization.authorizationId).get()).data();
    expect(stored).toBeDefined();
    expect(stored).not.toHaveProperty("invitationId");
  });
});

describe("transactional E4B2 authorization reader", () => {
  it("reads a valid authorization through the supplied Firestore transaction without writing", async () => {
    const value = await fixture();
    const ref = db.collection("identityLinkAuthorizations").doc(value.authorization.authorizationId);
    const before = (await ref.get()).data();
    const result = await db.runTransaction(async (transaction) => readValidIdentityLinkAuthorization({
      db, transaction, authorizationId: value.authorization.authorizationId,
      expected: { operationId: value.authorization.operationId, targetUid: value.uid,
        googleSubjectHash: value.reservation.identifierHash, expectedRevision: 2 }, now: clock
    }));
    expect(result).toMatchObject({ authorizationId: value.authorization.authorizationId, state: "pending" });
    expect((await ref.get()).data()).toEqual(before);
  });

  it.each([
    ["missing", null, "AUTHORIZATION_NOT_FOUND"],
    ["expired", { state: "expired", stateChangedAt: clock }, "AUTHORIZATION_EXPIRED"],
    ["revoked", { state: "revoked", stateChangedAt: clock }, "AUTHORIZATION_REVOKED"],
    ["consumed", { state: "consumed", stateChangedAt: clock }, "AUTHORIZATION_CONSUMED"],
    ["wrong user", { targetUid: "someone-else" }, "AUTHORIZATION_MISMATCH"],
    ["wrong operation", { operation: "google.other_operation" }, "AUTHORIZATION_MISMATCH"],
    ["wrong subject", { googleSubjectHash: "f".repeat(64) }, "AUTHORIZATION_MISMATCH"],
    ["wrong revision", { expectedRevision: 9 }, "AUTHORIZATION_MISMATCH"]
  ])("rejects %s through the provided transaction", async (_label, override, code) => {
    const value = await fixture();
    const ref = db.collection("identityLinkAuthorizations").doc(value.authorization.authorizationId);
    if (override) await ref.set({ ...value.authorization, ...(override as Record<string, unknown>) });
    const before = (await ref.get()).data();
    const txDb = new Proxy(db, { get(target, key) {
      if (key === "runTransaction") return () => { throw new Error("nested transaction"); };
      const result = Reflect.get(target, key, target) as unknown;
      return typeof result === "function" ? result.bind(target) : result;
    } });
    await expect(db.runTransaction(async (transaction) => readValidIdentityLinkAuthorization({
      db: txDb, transaction, authorizationId: override ? value.authorization.authorizationId : randomUUID(),
      expected: { operationId: value.authorization.operationId, targetUid: value.uid,
        googleSubjectHash: value.reservation.identifierHash, expectedRevision: 2 }, now: clock
    }))).rejects.toMatchObject({ code });
    expect((await ref.get()).data()).toEqual(before);
  });
});

describe("transactional Google Workspace identity linking", () => {
  it("links a verified identity to the existing UID", async () => {
    const value = await fixture();
    const result = await link(value);
    expect(result).toMatchObject({ uid: value.uid, revision: 3, replayed: false });
    expect((await db.collection("users").doc(value.uid).get()).id).toBe(value.uid);
  });

  it("persists only linked_pending_activation with Authentication disabled", async () => {
    const value = await fixture();
    await link(value);
    expect((await db.collection("users").doc(value.uid).get()).data()).toMatchObject({
      status: "invited", authDisabled: true, activationStatus: "linked_pending_activation",
      googleWorkspace: { linkingStatus: "linked", verificationStatus: "verified", subject: value.subject }
    });
  });

  it("consumes the authorization exactly once and writes one audit", async () => {
    const value = await fixture();
    await link(value);
    expect((await db.collection("identityLinkAuthorizations").doc(value.authorization.authorizationId).get()).data()).toMatchObject({ state: "consumed" });
    expect((await db.collection("auditEvents").where("targetUid", "==", value.uid).get()).size).toBe(1);
  });

  it("replays exactly without revision or audit changes", async () => {
    const value = await fixture();
    const first = await link(value);
    const second = await link(value);
    expect(second).toEqual({ ...first, replayed: true });
    expect((await db.collection("users").doc(value.uid).get()).data()?.revision).toBe(3);
    expect((await db.collection("auditEvents").where("targetUid", "==", value.uid).get()).size).toBe(1);
  });

  it("coalesces two equivalent concurrent requests", async () => {
    const value = await fixture();
    const results = await Promise.all([link(value), link(value)]);
    expect(results.map((result) => result.replayed).sort()).toEqual([false, true]);
    expect((await db.collection("auditEvents").where("targetUid", "==", value.uid).get()).size).toBe(1);
  });

  it("rejects a second UID for the reserved subject", async () => {
    const owner = await fixture();
    const contender = await fixture();
    contender.subject = owner.subject;
    contender.verifiedIdentity.subject = owner.subject;
    contender.request.googleSubjectHash = owner.reservation.identifierHash;
    await db.collection("users").doc(contender.uid).update({ "googleWorkspace.subject": owner.subject });
    await db.collection("identityLinkAuthorizations").doc(contender.authorization.authorizationId).update({
      googleSubjectHash: owner.reservation.identifierHash
    });
    await expectRejected(link(contender), "RESERVATION_CONFLICT");
    expect((await db.collection("users").doc(contender.uid).get()).data()?.revision).toBe(2);
  });

  it("allows at most one incompatible subject for one UID", async () => {
    const first = await fixture();
    const second = await fixture({ uid: first.uid });
    const results = await Promise.allSettled([link(first), link(second)]);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect((await db.collection("users").doc(first.uid).get()).data()?.revision).toBe(3);
  });

  it("rejects an expired authorization without consuming it", async () => {
    const value = await fixture({ authorization: { expiresAt: clock } });
    await expectRejected(link(value), "AUTHORIZATION_EXPIRED");
    expect((await db.collection("identityLinkAuthorizations").doc(value.authorization.authorizationId).get()).data()?.state).toBe("pending");
  });

  it("rejects a revoked authorization", async () => {
    const value = await fixture({ authorization: { state: "revoked", stateChangedAt: clock } });
    await expectRejected(link(value), "AUTHORIZATION_REVOKED");
  });

  it("rejects an obsolete revision", async () => {
    const value = await fixture();
    await db.collection("users").doc(value.uid).update({ revision: 3 });
    await expectRejected(link(value), "REVISION_CONFLICT");
  });

  it("rejects a verified subject different from the authorization", async () => {
    const value = await fixture();
    value.verifiedIdentity.subject = `different-${randomUUID()}`;
    await expectRejected(link(value), "SUBJECT_CONFLICT");
  });

  it("rejects an absent reservation", async () => {
    const value = await fixture();
    await db.collection("authIdentifierKeys").doc(value.reservation.identifierHash).delete();
    await expectRejected(link(value), "RESERVATION_REQUIRED");
  });

  it("rejects a reservation owned by another UID", async () => {
    const value = await fixture();
    await db.collection("authIdentifierKeys").doc(value.reservation.identifierHash).update({ uid: `other-${randomUUID()}` });
    await expectRejected(link(value), "RESERVATION_CONFLICT");
  });

  it("rejects a suspended user", async () => {
    const value = await fixture({ profile: { status: "disabled" } });
    await expectRejected(link(value), "IDENTITY_STATE_INVALID");
  });

  it("protects the Super Admin destination", async () => {
    const value = await fixture({ uid: adminUid });
    await expectRejected(link(value), "SUPER_ADMIN_LINK_FORBIDDEN");
  });

  it("rejects an invalid transition from declared", async () => {
    const value = await fixture();
    await db.collection("users").doc(value.uid).update({
      "googleWorkspace.linkingStatus": "declared", "googleWorkspace.verificationStatus": "unverified",
      "googleWorkspace.subject": null, "googleWorkspace.verifiedAt": null, emailVerifiedAt: null, activationStatus: "pending"
    });
    await expectRejected(link(value), "IDENTITY_STATE_INVALID");
  });

  it("rejects expired verified evidence", async () => {
    const value = await fixture();
    value.verifiedIdentity.verifiedAt = Timestamp.fromMillis(clock.toMillis() - 120_000);
    value.verifiedIdentity.validUntil = Timestamp.fromMillis(clock.toMillis() - 60_000);
    await expectRejected(link(value), "VERIFICATION_EXPIRED");
  });

  it("rejects reuse of an idempotency key with different parameters", async () => {
    const value = await fixture();
    await link(value);
    value.request.operationId = randomUUID();
    await expectRejected(link(value), "IDEMPOTENCY_CONFLICT");
  });

  it("rejects reuse of a consumed authorization outside its exact replay", async () => {
    const value = await fixture();
    await link(value);
    await db.collection("identityLinkOperations").doc(value.request.idempotencyKey).delete();
    await expectRejected(link(value), "AUTHORIZATION_CONSUMED");
  });

  it("aborts every write when the final deterministic audit conflicts", async () => {
    const value = await fixture();
    await db.collection("auditEvents").doc(`google-link-${value.request.operationId}`).set({ occupied: true });
    await expect(link(value)).rejects.toBeTruthy();
    expect((await db.collection("users").doc(value.uid).get()).data()?.revision).toBe(2);
    expect((await db.collection("identityLinkAuthorizations").doc(value.authorization.authorizationId).get()).data()?.state).toBe("pending");
    expect((await db.collection("identityLinkOperations").doc(value.request.idempotencyKey).get()).exists).toBe(false);
  });

  it("does not create Access Grants, custom claims or active profiles", async () => {
    const value = await fixture();
    await link(value);
    expect((await db.collection("accessGrants").where("userId", "==", value.uid).get()).empty).toBe(true);
    expect((await db.collection("customClaims").doc(value.uid).get()).exists).toBe(false);
    expect((await db.collection("users").doc(value.uid).get()).data()?.status).not.toBe("active");
  });

  it("leaves SMS and Email Link profiles outside the Google transaction", async () => {
    const value = await fixture();
    await db.collection("users").doc(value.uid).set({
      displayName: "SMS", status: "invited", authDisabled: true, invitationStatus: "pending",
      authMethod: "sms", phoneE164: "+528112345678", normalizedPhone: "+528112345678",
      email: null, normalizedEmail: null, phoneVerifiedAt: null, emailVerifiedAt: null,
      activationStatus: "pending", credentialRevision: 1, authorizationRevision: 1,
      sessionValidAfter: clock, createdAt: clock, createdBy: adminUid, updatedAt: clock, updatedBy: adminUid,
      revision: 2, pendingOperationId: null, version: 2
    });
    await expectRejected(link(value), "IDENTITY_STATE_INVALID");
    expect((await db.collection("users").doc(value.uid).get()).data()?.authMethod).toBe("sms");
  });
});
