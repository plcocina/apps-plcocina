import { randomUUID } from "node:crypto";
import { deleteApp, initializeApp } from "firebase-admin/app";
import { Timestamp, getFirestore, type Firestore } from "firebase-admin/firestore";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createTrustedAuthChallengeContext } from "../src/identities/identity-auth-challenge-contracts.js";
import { AuthChallengePersistenceService } from "../src/identities/identity-auth-challenge-service.js";
import { createTrustedAuthCoordinationEvent } from "../src/identities/identity-auth-coordination-contracts.js";
import { AuthCoordinationPersistenceService } from "../src/identities/identity-auth-coordination-service.js";
import { IdentityAuthOrchestrationPersistenceService,
  type AuthOrchestrationPersistenceRequest } from "../src/identities/identity-auth-orchestration-service.js";
import { GoogleIdentityLinkingService } from "../src/identities/identity-linking-service.js";
import { IdentityReservationService } from "../src/identities/identity-reservation-service.js";

let app: ReturnType<typeof initializeApp>;
let db: Firestore;
const pepper = Buffer.alloc(32, 0x5d);
const adminUid = "protected-admin";
const clock = Timestamp.fromDate(new Date("2026-11-09T18:00:00.000Z"));
const orchestrationTime = Timestamp.fromMillis(clock.toMillis() + 2_000);

beforeAll(() => {
  if (!process.env.FIRESTORE_EMULATOR_HOST) throw new Error("Esta prueba requiere Firestore Emulator.");
  app = initializeApp({ projectId: "demo-plcocina-apps" }, `auth-orchestration-${randomUUID()}`);
  db = getFirestore(app);
});

afterAll(async () => { await deleteApp(app); });

type Setup = Awaited<ReturnType<typeof setup>>;

async function setup() {
  const uid = `orchestration-user-${randomUUID()}`;
  const subject = `orchestration-subject-${randomUUID()}`;
  const linkOperationId = randomUUID();
  const linkIdempotencyKey = randomUUID();
  const authorizationId = randomUUID();
  const reservation = await new IdentityReservationService(db, pepper, () => clock).reserve({
    operationId: randomUUID(), uid, kind: "googleSubject", value: subject
  });
  const profile = {
    uid, displayName: "Empleado Orquestación", status: "invited", authDisabled: true,
    invitationStatus: "accepted", authMethod: "googleWorkspace", phoneE164: null, normalizedPhone: null,
    email: `orchestration-${randomUUID()}@plcocina.com`, normalizedEmail: "", phoneVerifiedAt: null,
    emailVerifiedAt: clock,
    googleWorkspace: { authorizedDomain: "plcocina.com", subject, linkingStatus: "verified",
      verificationStatus: "verified", verifiedAt: clock, linkedAt: null, verificationRevision: 1, operationId: null },
    activationStatus: "recovery_required", credentialRevision: 1, authorizationRevision: 1,
    sessionValidAfter: clock, createdAt: clock, createdBy: adminUid, updatedAt: clock, updatedBy: adminUid,
    revision: 2, pendingOperationId: null, identityContractVersion: "2.1", version: 2
  };
  profile.normalizedEmail = profile.email;
  await db.collection("users").doc(uid).set(profile);
  const authorization = {
    authorizationId, operation: "google.identity_link", operationId: linkOperationId,
    idempotencyKey: linkIdempotencyKey, targetUid: uid, googleSubjectHash: reservation.identifierHash,
    authorizedByUid: adminUid, expectedRevision: 2, reason: "Vinculación aprobada para orquestación",
    issuedAt: Timestamp.fromMillis(clock.toMillis() - 60_000),
    expiresAt: Timestamp.fromMillis(clock.toMillis() + 10 * 60_000), state: "pending", stateChangedAt: null,
    version: 1
  };
  const linking = new GoogleIdentityLinkingService(db, pepper, adminUid, () => clock);
  await linking.persistAuthorization(authorization);
  await linking.linkVerifiedIdentity({ trustedTargetUid: uid, trustedAdministratorUid: adminUid,
    request: { authorizationId, operation: "google.identity_link", operationId: linkOperationId,
      idempotencyKey: linkIdempotencyKey, targetUid: uid, googleSubjectHash: reservation.identifierHash,
      expectedRevision: 2, requestedActivationStatus: "linked_pending_activation" },
    verifiedIdentity: { subject, verifiedAt: clock, validUntil: authorization.expiresAt, verificationId: randomUUID() } });

  const operationId = randomUUID();
  const coordinationService = new AuthCoordinationPersistenceService(db, adminUid, () => clock);
  const coordination = {
    operationId, operation: "google.firebase_provider_link", expectedFirebaseUid: uid, expectedInternalUid: uid,
    googleSubjectHash: reservation.identifierHash, state: "not_started", expectedProfileRevision: 3,
    currentProfileRevision: 3, idempotencyKey: randomUUID(), authorizationId, challengeId: null,
    evidence: {
      authorization: { authorizationId, operation: "google.identity_link", validatedBy: "identity-link-authorization",
        validatedAt: clock, validUntil: authorization.expiresAt },
      firestoreLink: { linkOperationId, observedBy: "identity-linking-service", linkedAt: clock,
        profileRevision: 3, activationStatus: "linked_pending_activation", authDisabled: true },
      challenge: null, googleVerification: null, firebaseSession: null, firebaseProvider: null, postflight: null
    },
    conflictReason: null, revision: 1, lastEvent: null, createdAt: clock, updatedAt: clock,
    expiresAt: Timestamp.fromMillis(clock.toMillis() + 15 * 60_000),
    localActivationStatus: "linked_pending_activation", localAuthDisabled: true, version: 1
  };
  await coordinationService.create({ trustedAdministratorUid: adminUid, document: coordination });
  const challengeService = new AuthChallengePersistenceService(db, adminUid, () => clock);
  const challenge = await challengeService.create({ trustedOperatorUid: adminUid, expectedInternalUid: uid,
    expectedFirebaseUid: uid, coordinationOperationId: operationId, authorizationId,
    googleSubjectHash: reservation.identifierHash, trustedSessionId: `session-${randomUUID()}`, lifetimeMs: 300_000 });
  await coordinationService.transition({ trustedAdministratorUid: adminUid, operationId, expectedRevision: 1,
    event: createTrustedAuthCoordinationEvent({ type: "challenge_issued", operationId, idempotencyKey: randomUUID(),
      expectedFirebaseUid: uid, expectedInternalUid: uid, googleSubjectHash: reservation.identifierHash,
      expectedCoordinationRevision: 1, expectedProfileRevision: 3,
      challenge: { challengeId: challenge.document.challengeId, issuedBy: "identity-challenge-service",
        issuedAt: challenge.document.issuedAt, expiresAt: challenge.document.expiresAt } }) });
  const request: AuthOrchestrationPersistenceRequest = {
    trustedAdministratorUid: adminUid, operationId, challengeId: challenge.document.challengeId, authorizationId,
    trustedSessionId: challenge.document.trustedSessionId, idempotencyKey: randomUUID(), verificationId: randomUUID(),
    expectedCoordinationRevision: 2, expectedChallengeRevision: 1, googleIdToken: `synthetic-${randomUUID()}`,
    nonce: challenge.oneTimeSecrets.nonce, state: challenge.oneTimeSecrets.state
  };
  return { uid, subject, authorization, reservation, coordinationService, challengeService, challenge, request };
}

function service(value: Setup, subject = value.subject) {
  return new IdentityAuthOrchestrationPersistenceService(db, {
    verify: async () => ({ issuer: "https://accounts.google.com", audience: "approved-client",
      authorizedParty: "approved-client", subject, email: "employee@plcocina.com", emailVerified: true,
      hostedDomain: "plcocina.com", issuedAt: new Date(clock.toMillis() - 1_000),
      expiresAt: new Date(clock.toMillis() + 5 * 60_000), nonceVerified: true })
  }, pepper, adminUid, () => orchestrationTime);
}

async function rejected(work: Promise<unknown>, code: string) {
  await expect(work).rejects.toMatchObject({ code });
}

async function persisted(value: Setup) {
  const [challenge, coordination, audits] = await Promise.all([
    db.collection("identityAuthChallenges").doc(value.request.challengeId).get(),
    db.collection("identityAuthCoordinations").doc(value.request.operationId).get(),
    db.collection("auditEvents").where("resourceId", "==", value.uid).get()
  ]);
  return { challenge: challenge.data(), coordination: coordination.data(), audits };
}

describe("persistent atomic auth orchestration", () => {
  it("atomically consumes one challenge and records one coordination transition", async () => {
    const value = await setup();
    expect(await service(value).verifyConsumeAndRecord(value.request)).toMatchObject({
      replayed: false, state: "google_proof_verified", coordinationRevision: 3, challengeRevision: 2,
      automaticActivation: false
    });
    const stored = await persisted(value);
    expect(stored.challenge).toMatchObject({ state: "consumed", revision: 2 });
    expect(stored.coordination).toMatchObject({ state: "google_proof_verified", revision: 3,
      localActivationStatus: "linked_pending_activation", localAuthDisabled: true });
    expect(stored.audits.size).toBe(4);
  });

  it("coalesces two equivalent simultaneous orchestrations", async () => {
    const value = await setup();
    const results = await Promise.all([service(value).verifyConsumeAndRecord(value.request),
      service(value).verifyConsumeAndRecord(value.request)]);
    expect(results.map((result) => result.replayed).sort()).toEqual([false, true]);
    expect((await persisted(value)).coordination).toMatchObject({ state: "google_proof_verified", revision: 3 });
  });

  it("permits exactly one of two conflicting simultaneous orchestrations", async () => {
    const value = await setup();
    const conflict = { ...value.request, verificationId: randomUUID() };
    const results = await Promise.allSettled([service(value).verifyConsumeAndRecord(value.request),
      service(value).verifyConsumeAndRecord(conflict)]);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect((await persisted(value)).challenge).toMatchObject({ state: "consumed", revision: 2 });
  });

  it("rejects a second idempotency key after challenge consumption", async () => {
    const value = await setup();
    await service(value).verifyConsumeAndRecord(value.request);
    await expect(service(value).verifyConsumeAndRecord({ ...value.request, idempotencyKey: randomUUID() })).rejects.toBeTruthy();
    expect((await persisted(value)).coordination).toMatchObject({ revision: 3 });
  });

  it("rejects stale coordination revision without changing documents", async () => {
    const value = await setup();
    await rejected(service(value).verifyConsumeAndRecord({ ...value.request, expectedCoordinationRevision: 1 }), "REVISION_CONFLICT");
    expect(await persisted(value)).toMatchObject({ challenge: { state: "issued", revision: 1 },
      coordination: { state: "challenge_issued", revision: 2 } });
  });

  it("returns a durable replay for an operation already completed", async () => {
    const value = await setup();
    await service(value).verifyConsumeAndRecord(value.request);
    const replay = await service(value).verifyConsumeAndRecord(value.request);
    expect(replay).toMatchObject({ replayed: true, challengeConsumedAgain: false, challengeRevision: 2,
      coordinationRevision: 3 });
  });

  it("rejects a challenge consumed outside the atomic operation", async () => {
    const value = await setup();
    await value.challengeService.consume({ trustedOperatorUid: adminUid, challengeId: value.request.challengeId,
      context: createTrustedAuthChallengeContext({ expectedInternalUid: value.uid, expectedFirebaseUid: value.uid,
        coordinationOperationId: value.request.operationId, authorizationId: value.request.authorizationId,
        trustedSessionId: value.request.trustedSessionId, nonce: value.request.nonce, state: value.request.state,
        expectedRevision: 1, verifiedGoogleIdentity: { subject: value.subject, nonceVerified: true,
          googleSubjectHash: value.reservation.identifierHash } }) });
    await expect(service(value).verifyConsumeAndRecord(value.request)).rejects.toBeTruthy();
    expect((await persisted(value)).coordination).toMatchObject({ state: "challenge_issued", revision: 2 });
  });

  it("rejects an expired challenge", async () => {
    const value = await setup();
    await db.collection("identityAuthChallenges").doc(value.request.challengeId).update({ expiresAt: orchestrationTime });
    await rejected(service(value).verifyConsumeAndRecord(value.request), "CHALLENGE_EXPIRED");
    expect((await persisted(value)).coordination).toMatchObject({ revision: 2 });
  });

  it("rejects a revoked challenge", async () => {
    const value = await setup();
    await db.collection("identityAuthChallenges").doc(value.request.challengeId).update({
      state: "revoked", stateChangedAt: orchestrationTime
    });
    await rejected(service(value).verifyConsumeAndRecord(value.request), "CHALLENGE_REVOKED");
    expect((await persisted(value)).coordination).toMatchObject({ revision: 2 });
  });

  it("rejects a revoked authorization", async () => {
    const value = await setup();
    await db.collection("identityLinkAuthorizations").doc(value.request.authorizationId).update({
      state: "revoked", stateChangedAt: orchestrationTime
    });
    await rejected(service(value).verifyConsumeAndRecord(value.request), "AUTHORIZATION_INVALID");
    expect((await persisted(value)).challenge).toMatchObject({ state: "issued" });
  });

  it("blocks a suspended user", async () => {
    const value = await setup();
    await db.collection("users").doc(value.uid).update({ status: "disabled" });
    await rejected(service(value).verifyConsumeAndRecord(value.request), "PROFILE_BLOCKED");
    expect((await persisted(value)).challenge).toMatchObject({ state: "issued" });
  });

  it("rejects a reservation owned by another UID", async () => {
    const value = await setup();
    await db.collection("authIdentifierKeys").doc(value.reservation.identifierHash).update({ uid: `other-${randomUUID()}` });
    await rejected(service(value).verifyConsumeAndRecord(value.request), "RESERVATION_CONFLICT");
    expect((await persisted(value)).coordination).toMatchObject({ revision: 2 });
  });

  it("rejects when the E4B2 profile link is not confirmed", async () => {
    const value = await setup();
    await db.collection("users").doc(value.uid).update({ "googleWorkspace.linkingStatus": "verified" });
    await rejected(service(value).verifyConsumeAndRecord(value.request), "E4_LINK_NOT_CONFIRMED");
    expect((await persisted(value)).challenge).toMatchObject({ state: "issued" });
  });

  it("rejects a blocked coordination state", async () => {
    const value = await setup();
    await value.coordinationService.transition({ trustedAdministratorUid: adminUid,
      operationId: value.request.operationId, expectedRevision: 2,
      event: createTrustedAuthCoordinationEvent({ type: "provider_result_unknown", operationId: value.request.operationId,
        idempotencyKey: randomUUID(), expectedFirebaseUid: value.uid, expectedInternalUid: value.uid,
        googleSubjectHash: value.reservation.identifierHash, expectedCoordinationRevision: 2,
        expectedProfileRevision: 3 }) });
    await expect(service(value).verifyConsumeAndRecord({ ...value.request, expectedCoordinationRevision: 3 })).rejects.toBeTruthy();
    expect((await persisted(value)).challenge).toMatchObject({ state: "issued" });
  });

  it("treats an unknown external result as blocked", async () => {
    const value = await setup();
    await db.collection("identityAuthCoordinations").doc(value.request.operationId).update({
      state: "auth_state_unknown", conflictReason: "PROVIDER_RESULT_UNKNOWN"
    });
    await expect(service(value).verifyConsumeAndRecord(value.request)).rejects.toBeTruthy();
    expect((await persisted(value)).challenge).toMatchObject({ state: "issued" });
  });

  it("rolls back challenge, coordination, locks, and idempotency when audit creation fails", async () => {
    const value = await setup();
    await db.collection("auditEvents").doc(`auth-coordination-${value.request.operationId}-3`).set({ occupied: true });
    await expect(service(value).verifyConsumeAndRecord(value.request)).rejects.toBeTruthy();
    const stored = await persisted(value);
    expect(stored.challenge).toMatchObject({ state: "issued", revision: 1 });
    expect(stored.coordination).toMatchObject({ state: "challenge_issued", revision: 2 });
    expect((await db.collection("identityAuthCoordinationIdempotency").doc(value.request.idempotencyKey).get()).exists).toBe(false);
  });

  it("can retry safely after an aborted validation", async () => {
    const value = await setup();
    await expect(service(value).verifyConsumeAndRecord({ ...value.request, state: value.request.nonce })).rejects.toBeTruthy();
    expect(await service(value).verifyConsumeAndRecord(value.request)).toMatchObject({ replayed: false, coordinationRevision: 3 });
  });

  it("leaves no partial writes after a conflicting subject", async () => {
    const value = await setup();
    await rejected(service(value, `different-${randomUUID()}`).verifyConsumeAndRecord(value.request),
      "COORDINATION_CONTEXT_MISMATCH");
    expect(await persisted(value)).toMatchObject({ challenge: { state: "issued", revision: 1 },
      coordination: { state: "challenge_issued", revision: 2 } });
  });

  it("creates one transition audit and no duplicate on replay", async () => {
    const value = await setup();
    const before = (await persisted(value)).audits.size;
    await service(value).verifyConsumeAndRecord(value.request);
    await service(value).verifyConsumeAndRecord(value.request);
    expect((await persisted(value)).audits.size).toBe(before + 1);
  });

  it("does not activate, grant, claim, create, or privilege users", async () => {
    const value = await setup();
    await service(value).verifyConsumeAndRecord(value.request);
    const profile = (await db.collection("users").doc(value.uid).get()).data();
    expect(profile).toMatchObject({ activationStatus: "linked_pending_activation", authDisabled: true });
    expect((await db.collection("accessGrants").where("userId", "==", value.uid).get()).empty).toBe(true);
    expect((await persisted(value)).coordination).toMatchObject({ localActivationStatus: "linked_pending_activation",
      localAuthDisabled: true });
  });
});
