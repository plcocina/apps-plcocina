import { generateKeyPairSync, randomUUID, sign } from "node:crypto";
import { deleteApp, initializeApp } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import { Timestamp, getFirestore, type Firestore } from "firebase-admin/firestore";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { AdminPrincipal } from "../src/auth/require-super-admin.js";
import { InvitationTokenKeyring } from "../src/invitations/invitation-token.js";
import { GoogleAuthLibraryJwtCryptographicVerifier, GoogleIdentityTokenVerifier, type GoogleCertificateSource,
  type GoogleTokenVerifierConfig } from "../src/identities/google-token-verifier.js";
import { createInternalGoogleBootstrapComposition } from "../src/identities/identity-google-bootstrap-composition.js";
import { AuthCoordinationPersistenceService } from "../src/identities/identity-auth-coordination-service.js";
import { GoogleIdentityLinkingService } from "../src/identities/identity-linking-service.js";
import { IdentityReservationService } from "../src/identities/identity-reservation-service.js";
import { InvitationGoogleProofService } from "../src/identities/identity-invitation-google-proof-service.js";
import { GoogleBootstrapPreparationService } from "../src/identities/identity-google-bootstrap-preparation-service.js";
import { identifierKeyHash } from "../src/identities/identity-models.js";

let app: ReturnType<typeof initializeApp>; let db: Firestore;
const now = new Date(); const clock = () => Timestamp.fromDate(now); const adminUid = "protected-admin";
const principal: AdminPrincipal = { uid: adminUid, email: "admin@plcocina.com", authTime: Math.floor(now.getTime() / 1000),
  issuedAt: Math.floor(now.getTime() / 1000), superAdmin: true };
const pepper = Buffer.alloc(32, 0x6b);
const invitationTokens = new InvitationTokenKeyring(new Map([[1, Buffer.alloc(32, 0x51)]]), 1);
const keyId = "local-rsa-preparation-key"; const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
const verifierConfig: GoogleTokenVerifierConfig = { allowedIssuers: ["accounts.google.com", "https://accounts.google.com"],
  allowedAudiences: ["local-client.apps.googleusercontent.com"], allowedAuthorizedParties: ["local-client.apps.googleusercontent.com"],
  allowedWorkspaceDomains: ["plcocina.com"], requireAuthorizedParty: true, clockSkewSeconds: 60, maxTokenLifetimeSeconds: 3600 };
class LocalCertificates implements GoogleCertificateSource { async getCertificates() { return { [keyId]: publicKeyPem }; } }
beforeAll(() => {
  if (!process.env.FIRESTORE_EMULATOR_HOST || !process.env.FIREBASE_AUTH_EMULATOR_HOST) throw new Error("Requiere Auth y Firestore Emulator.");
  app = initializeApp({ projectId: "demo-plcocina-apps" }, `bootstrap-preparation-${randomUUID()}`); db = getFirestore(app);
});
afterAll(async () => { await deleteApp(app); });
function encode(value: unknown) { return Buffer.from(JSON.stringify(value)).toString("base64url"); }
function googleToken(subject: string, email: string, nonce: string) {
  const issuedAt = Math.floor(now.getTime() / 1000); const header = encode({ alg: "RS256", typ: "JWT", kid: keyId });
  const payload = encode({ iss: "https://accounts.google.com", aud: "local-client.apps.googleusercontent.com",
    azp: "local-client.apps.googleusercontent.com", sub: subject, email, email_verified: true, hd: "plcocina.com",
    nonce, iat: issuedAt, exp: issuedAt + 600 });
  return `${header}.${payload}.${sign("RSA-SHA256", Buffer.from(`${header}.${payload}`), privateKey).toString("base64url")}`;
}
async function fixture() {
  const invitationId = randomUUID(); const uid = `preprovisioned-${randomUUID()}`;
  const email = `empleado-${randomUUID()}@plcocina.com`; const issuedAt = clock();
  const expiresAt = Timestamp.fromMillis(issuedAt.toMillis() + 3_600_000); const token = invitationTokens.issue(invitationId, 1);
  await getAuth(app).createUser({ uid, email, disabled: true });
  await db.collection("users").doc(uid).set({ displayName: "Empleado", status: "invited", authDisabled: true,
    invitationStatus: "pending", authMethod: "email", phoneE164: null, normalizedPhone: null, email, normalizedEmail: email,
    phoneVerifiedAt: null, emailVerifiedAt: null, activationStatus: "pending", credentialRevision: 1, authorizationRevision: 1,
    sessionValidAfter: issuedAt, createdAt: issuedAt, createdBy: adminUid, updatedAt: issuedAt, updatedBy: adminUid,
    revision: 1, pendingOperationId: null, version: 2 });
  await db.collection("invitations").doc(invitationId).set({ invitationId, email, normalizedEmail: email, displayName: "Empleado", uid,
    status: "active", token: { hash: token.hash, generation: 1, salt: token.salt, keyVersion: token.keyVersion, issuedAt, expiresAt },
    delivery: { provider: "simulated", status: "accepted", idempotencyKey: `invitation/${invitationId}/generation/1`, providerMessageId: null,
      templateVersion: 1, firstAttemptAt: issuedAt, retryUntil: null, sentAt: issuedAt, deliveredAt: issuedAt, failureCode: null },
    expiresAt, createdAt: issuedAt, createdBy: adminUid, updatedAt: issuedAt, updatedBy: adminUid,
    pendingOperationId: null, consumeOperationId: null, consumeLeaseExpiresAt: null, passwordSetAt: null, confirmationExpiresAt: null,
    deliveredAt: issuedAt, acceptedAt: null, revokedAt: null, revokedBy: null, revokeReason: null, expiredAt: null,
    resendCount: 0, lastSentAt: issuedAt, revision: 1, version: 2 });
  const verifier = new GoogleIdentityTokenVerifier(verifierConfig, new LocalCertificates(), new GoogleAuthLibraryJwtCryptographicVerifier(), () => now);
  const proofService = new InvitationGoogleProofService(db, invitationTokens, verifier, clock);
  const proofChallenge = await proofService.start({ invitationId, token: token.token });
  const proof = await proofService.verify({ invitationId, token: token.token, challengeId: proofChallenge.challengeId,
    nonce: proofChallenge.nonce, googleIdToken: googleToken(`google-sub-${randomUUID()}`, email, proofChallenge.nonce) });
  return { invitationId, invitationToken: token, uid, email, proofId: proof.proofId };
}
function service(options: { failLinkOnce?: { value: boolean } } = {}) {
  const reservation = new IdentityReservationService(db, pepper, clock);
  const linking = new GoogleIdentityLinkingService(db, pepper, adminUid, clock);
  const coordination = new AuthCoordinationPersistenceService(db, adminUid, clock);
  const realLink = linking.linkVerifiedIdentity.bind(linking);
  return new GoogleBootstrapPreparationService(db, pepper, adminUid, clock, {
    reserve: reservation.reserve.bind(reservation),
    persistEmployeeInvitationAuthorization: linking.persistEmployeeInvitationAuthorization.bind(linking),
    linkVerifiedIdentity: async (input) => {
      if (options.failLinkOnce?.value) { options.failLinkOnce.value = false; throw new Error("SIMULATED_INTERRUPTION"); }
      return realLink(input);
    },
    createCoordination: coordination.create.bind(coordination)
  });
}
function bootstrapComposition() {
  return createInternalGoogleBootstrapComposition(db, { googleTokenVerifier: verifierConfig, identifierPepper: pepper,
    protectedSuperAdminUid: adminUid }, { certificates: new LocalCertificates(),
    cryptographicVerifier: new GoogleAuthLibraryJwtCryptographicVerifier(), now: () => now });
}
async function prepareAndIssue(proofId: string) {
  const prepared = await service().prepare(prepareInput(proofId), principal);
  const issued = await bootstrapComposition().issue({ principal, authorizationId: prepared.authorizationId, idempotencyKey: randomUUID(), lifetimeMs: 300_000 });
  return { prepared, issued };
}
const prepareInput = (proofId: string) => ({ proofId });

describe("E5 preparation from B5-B4 verified evidence", () => {
  it("prepares reservation, invitation-bound E4B2 and E5B2, then issues through existing B4", async () => {
    const f = await fixture();
    const proof = (await db.collection("identityVerifiedGoogleProofs").doc(f.proofId).get()).data()!;
    const subjectHash = identifierKeyHash("googleSubject", String(proof.subject), pepper);
    expect((await db.collection("authIdentifierKeys").doc(subjectHash).get()).exists).toBe(false);
    expect((await db.collection("identityLinkAuthorizations").where("targetUid", "==", f.uid).get()).empty).toBe(true);
    expect((await db.collection("identityAuthCoordinations").where("expectedFirebaseUid", "==", f.uid).get()).empty).toBe(true);
    const result = await service().prepare(prepareInput(f.proofId), principal);
    expect(result).toMatchObject({ uid: f.uid, state: "not_started" });
    const authorization = (await db.collection("identityLinkAuthorizations").doc(result.authorizationId).get()).data()!;
    expect(authorization).toMatchObject({ invitationId: f.invitationId, targetUid: f.uid, state: "consumed" });
    expect((await db.collection("identityAuthCoordinations").doc(result.coordinationOperationId).get()).data()).toMatchObject({
      authorizationId: result.authorizationId, expectedFirebaseUid: f.uid, state: "not_started"
    });
    expect((await db.collection("users").doc(f.uid).get()).data()).toMatchObject({ authDisabled: true, status: "invited",
      activationStatus: "linked_pending_activation", googleWorkspace: { subject: (await db.collection("identityVerifiedGoogleProofs").doc(f.proofId).get()).data()?.subject } });
    expect((await getAuth(app).getUser(f.uid)).disabled).toBe(true);
    const bootstrap = bootstrapComposition();
    const challenge = await bootstrap.issue({ principal, authorizationId: result.authorizationId, idempotencyKey: randomUUID(), lifetimeMs: 300_000 });
    expect(challenge.nonce.length).toBeGreaterThan(16);
    expect((await db.collection("identityAuthCoordinations").doc(result.coordinationOperationId).get()).data()).toMatchObject({ state: "challenge_issued" });
    const consumeInput = { challengeId: challenge.challengeId, idempotencyKey: randomUUID(), nonce: challenge.nonce, state: challenge.state,
      googleIdToken: googleToken(String(proof.subject), f.email, challenge.nonce) };
    await expect(bootstrap.verifyAndConsume(consumeInput)).resolves.toMatchObject({ state: "google_proof_verified",
      replayed: false, automaticActivation: false });
    const challengeAfter = await db.collection("identityAuthChallenges").doc(challenge.challengeId).get();
    const coordinationAfter = await db.collection("identityAuthCoordinations").doc(result.coordinationOperationId).get();
    expect(challengeAfter.data()).toMatchObject({ state: "consumed", revision: 2 });
    expect(coordinationAfter.data()).toMatchObject({ state: "google_proof_verified", revision: 3, localAuthDisabled: true,
      evidence: { googleVerification: { nonceVerified: true } } });
    expect((await db.collection("users").doc(f.uid).get()).data()).toMatchObject({ authDisabled: true, status: "invited",
      activationStatus: "linked_pending_activation" });
    expect((await getAuth(app).getUser(f.uid)).disabled).toBe(true);
    await expect(bootstrap.verifyAndConsume(consumeInput)).resolves.toMatchObject({ state: "google_proof_verified", replayed: true });
    expect((await db.collection("identityAuthChallenges").doc(challenge.challengeId).get()).data()).toEqual(challengeAfter.data());
    expect((await getAuth(app).getUser(f.uid)).disabled).toBe(true);
  });

  it("rejects a consumed E4B2 authorization whose completed link binding is incompatible without consuming E5D2", async () => {
    const f = await fixture(); const { prepared, issued } = await prepareAndIssue(f.proofId);
    const operationRef = db.collection("identityLinkOperations").doc((await db.collection("identityLinkAuthorizations")
      .doc(prepared.authorizationId).get()).data()?.idempotencyKey);
    await operationRef.update({ operationId: randomUUID() });
    const challengeRef = db.collection("identityAuthChallenges").doc(issued.challengeId);
    const coordinationRef = db.collection("identityAuthCoordinations").doc(prepared.coordinationOperationId);
    const challengeBefore = await challengeRef.get(); const coordinationBefore = await coordinationRef.get();
    const proof = (await db.collection("identityVerifiedGoogleProofs").doc(f.proofId).get()).data()!;
    await expect(bootstrapComposition().verifyAndConsume({ challengeId: issued.challengeId, idempotencyKey: randomUUID(),
      nonce: issued.nonce, state: issued.state, googleIdToken: googleToken(String(proof.subject), f.email, issued.nonce) })).rejects.toMatchObject({
      code: "AUTHORIZATION_MISMATCH"
    });
    expect((await challengeRef.get()).data()).toEqual(challengeBefore.data());
    expect((await coordinationRef.get()).data()).toEqual(coordinationBefore.data());
  });

  it("rejects a missing proof without creating preparation records", async () => {
    const proofId = randomUUID();
    await expect(service().prepare(prepareInput(proofId), principal)).rejects.toMatchObject({ code: "PROOF_NOT_FOUND" });
    expect((await db.collection("identityGoogleBootstrapPreparations").doc(proofId).get()).exists).toBe(false);
  });

  it.each(["revoked", "resent"] as const)("rejects an invitation that was %s after proof issuance", async (change) => {
    const f = await fixture(); const ref = db.collection("invitations").doc(f.invitationId);
    if (change === "revoked") await ref.update({ status: "revoked", revokedAt: clock(), revokedBy: adminUid, revokeReason: "Prueba", revision: 2 });
    else {
      const next = invitationTokens.issue(f.invitationId, 2); const expiresAt = Timestamp.fromMillis(clock().toMillis() + 3_600_000);
      await ref.update({ token: { hash: next.hash, generation: 2, salt: next.salt, keyVersion: next.keyVersion, issuedAt: clock(), expiresAt },
        expiresAt, resendCount: 1, revision: 2 });
    }
    await expect(service().prepare(prepareInput(f.proofId), principal)).rejects.toMatchObject({ code: "INVITATION_INVALID" });
    expect((await db.collection("identityLinkAuthorizations").get()).docs.every((doc) => doc.data().targetUid !== f.uid)).toBe(true);
  });

  it("rejects a subject reserved for another UID without mutating the employee", async () => {
    const f = await fixture(); const proof = (await db.collection("identityVerifiedGoogleProofs").doc(f.proofId).get()).data()!;
    const foreignUid = `other-${randomUUID()}`;
    await new IdentityReservationService(db, pepper, clock).reserve({ operationId: randomUUID(), uid: foreignUid,
      kind: "googleSubject", value: String(proof.subject) });
    await expect(service().prepare(prepareInput(f.proofId), principal)).rejects.toMatchObject({ code: "RESERVATION_CONFLICT" });
    expect((await db.collection("users").doc(f.uid).get()).data()).toMatchObject({ revision: 1, authDisabled: true });
    expect((await db.collection("identityLinkAuthorizations").where("targetUid", "==", f.uid).get()).empty).toBe(true);
    expect((await db.collection("identityAuthCoordinations").where("expectedFirebaseUid", "==", f.uid).get()).empty).toBe(true);
  });

  it("retries with the same identifiers and records", async () => {
    const f = await fixture(); const prep = service();
    const first = await prep.prepare(prepareInput(f.proofId), principal);
    const profileBefore = (await db.collection("users").doc(f.uid).get()).data();
    const second = await prep.prepare(prepareInput(f.proofId), principal);
    expect(second).toMatchObject({ authorizationId: first.authorizationId, operationId: first.operationId,
      coordinationOperationId: first.coordinationOperationId, state: first.state, replayed: true });
    expect((await db.collection("users").doc(f.uid).get()).data()).toEqual(profileBefore);
    expect((await db.collection("identityLinkOperations").where("targetUid", "==", f.uid).get()).size).toBe(1);
    expect((await db.collection("identityAuthCoordinations").where("expectedFirebaseUid", "==", f.uid).get()).size).toBe(1);
  });

  it("recovers the same plan after interruption following authorization persistence", async () => {
    const f = await fixture(); const failure = { value: true }; const prep = service({ failLinkOnce: failure });
    await expect(prep.prepare(prepareInput(f.proofId), principal)).rejects.toThrow("SIMULATED_INTERRUPTION");
    expect((await db.collection("authIdentifierKeys").where("uid", "==", f.uid).get()).size).toBe(1);
    expect((await db.collection("identityLinkAuthorizations").where("targetUid", "==", f.uid).get()).size).toBe(1);
    expect((await db.collection("identityAuthCoordinations").where("expectedFirebaseUid", "==", f.uid).get()).empty).toBe(true);
    const recovered = await prep.prepare(prepareInput(f.proofId), principal);
    expect(recovered).toMatchObject({ uid: f.uid, state: "not_started" });
    expect((await db.collection("identityAuthCoordinations").where("expectedFirebaseUid", "==", f.uid).get()).size).toBe(1);
  });
});
