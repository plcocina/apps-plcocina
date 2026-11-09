import { generateKeyPairSync, randomUUID, sign } from "node:crypto";
import { deleteApp, initializeApp } from "firebase-admin/app";
import { Timestamp, getFirestore, type Firestore } from "firebase-admin/firestore";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createTrustedAuthCoordinationEvent } from "../src/identities/identity-auth-coordination-contracts.js";
import { AuthCoordinationPersistenceService } from "../src/identities/identity-auth-coordination-service.js";
import { AuthChallengePersistenceService } from "../src/identities/identity-auth-challenge-service.js";
import { createInternalAuthOrchestrationService } from "../src/identities/identity-auth-orchestration-composition.js";
import { GoogleIdentityLinkingService } from "../src/identities/identity-linking-service.js";
import { IdentityReservationService } from "../src/identities/identity-reservation-service.js";
import { GoogleAuthLibraryJwtCryptographicVerifier, type GoogleCertificateSource,
  type GoogleTokenVerifierConfig } from "../src/identities/google-token-verifier.js";

let app: ReturnType<typeof initializeApp>;
let db: Firestore;
const pepper = Buffer.alloc(32, 0x6e);
const adminUid = "protected-admin";
const now = new Date();
const clock = Timestamp.fromDate(now);
const keyId = "controlled-composition-key";
const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
const verifierConfig: GoogleTokenVerifierConfig = {
  allowedIssuers: ["accounts.google.com", "https://accounts.google.com"],
  allowedAudiences: ["approved-client.apps.googleusercontent.com"],
  allowedAuthorizedParties: ["approved-client.apps.googleusercontent.com"],
  allowedWorkspaceDomains: ["plcocina.com"],
  requireAuthorizedParty: true,
  clockSkewSeconds: 60,
  maxTokenLifetimeSeconds: 3_600
};

class StaticCertificateSource implements GoogleCertificateSource {
  async getCertificates(): Promise<Readonly<Record<string, string>>> {
    return { [keyId]: publicKeyPem };
  }
}

beforeAll(() => {
  if (!process.env.FIRESTORE_EMULATOR_HOST) throw new Error("Esta prueba requiere Firestore Emulator.");
  app = initializeApp({ projectId: "demo-plcocina-apps" }, `auth-composition-${randomUUID()}`);
  db = getFirestore(app);
});

afterAll(async () => { await deleteApp(app); });

function encode(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function token(payload: Record<string, unknown>, alterSignature = false): string {
  const header = encode({ alg: "RS256", typ: "JWT", kid: keyId });
  const body = encode(payload);
  const signature = sign("RSA-SHA256", Buffer.from(`${header}.${body}`), privateKey).toString("base64url");
  return `${header}.${body}.${alterSignature ? `${signature.slice(0, -2)}aa` : signature}`;
}

function service(config: GoogleTokenVerifierConfig = verifierConfig) {
  return createInternalAuthOrchestrationService(db, {
    googleTokenVerifier: config,
    identifierPepper: pepper,
    protectedSuperAdminUid: adminUid
  }, {
    certificates: new StaticCertificateSource(),
    cryptographicVerifier: new GoogleAuthLibraryJwtCryptographicVerifier(),
    now: () => now
  });
}

type Setup = Awaited<ReturnType<typeof setup>>;

async function setup() {
  const uid = `composition-user-${randomUUID()}`;
  const subject = `composition-subject-${randomUUID()}`;
  const authorizationId = randomUUID();
  const linkOperationId = randomUUID();
  const linkIdempotencyKey = randomUUID();
  const reservation = await new IdentityReservationService(db, pepper, () => clock).reserve({
    operationId: randomUUID(), uid, kind: "googleSubject", value: subject
  });
  const email = `composition-${randomUUID()}@plcocina.com`;
  await db.collection("users").doc(uid).set({
    uid, displayName: "Empleado Composición", status: "invited", authDisabled: true,
    invitationStatus: "accepted", authMethod: "googleWorkspace", phoneE164: null, normalizedPhone: null,
    email, normalizedEmail: email, phoneVerifiedAt: null, emailVerifiedAt: clock,
    googleWorkspace: { authorizedDomain: "plcocina.com", subject, linkingStatus: "verified",
      verificationStatus: "verified", verifiedAt: clock, linkedAt: null, verificationRevision: 1, operationId: null },
    activationStatus: "recovery_required", credentialRevision: 1, authorizationRevision: 1,
    sessionValidAfter: clock, createdAt: clock, createdBy: adminUid, updatedAt: clock, updatedBy: adminUid,
    revision: 2, pendingOperationId: null, identityContractVersion: "2.1", version: 2
  });
  const expiresAt = Timestamp.fromMillis(clock.toMillis() + 600_000);
  const linking = new GoogleIdentityLinkingService(db, pepper, adminUid, () => clock);
  await linking.persistAuthorization({ authorizationId, operation: "google.identity_link", operationId: linkOperationId,
    idempotencyKey: linkIdempotencyKey, targetUid: uid, googleSubjectHash: reservation.identifierHash,
    authorizedByUid: adminUid, expectedRevision: 2, reason: "Composición E3B E5D2",
    issuedAt: Timestamp.fromMillis(clock.toMillis() - 60_000), expiresAt, state: "pending",
    stateChangedAt: null, version: 1 });
  await linking.linkVerifiedIdentity({ trustedTargetUid: uid, trustedAdministratorUid: adminUid,
    request: { authorizationId, operation: "google.identity_link", operationId: linkOperationId,
      idempotencyKey: linkIdempotencyKey, targetUid: uid, googleSubjectHash: reservation.identifierHash,
      expectedRevision: 2, requestedActivationStatus: "linked_pending_activation" },
    verifiedIdentity: { subject, verifiedAt: clock, validUntil: expiresAt, verificationId: randomUUID() } });

  const operationId = randomUUID();
  const coordination = new AuthCoordinationPersistenceService(db, adminUid, () => clock);
  await coordination.create({ trustedAdministratorUid: adminUid, document: {
    operationId, operation: "google.firebase_provider_link", expectedFirebaseUid: uid, expectedInternalUid: uid,
    googleSubjectHash: reservation.identifierHash, state: "not_started", expectedProfileRevision: 3,
    currentProfileRevision: 3, idempotencyKey: randomUUID(), authorizationId, challengeId: null,
    evidence: { authorization: { authorizationId, operation: "google.identity_link",
      validatedBy: "identity-link-authorization", validatedAt: clock, validUntil: expiresAt },
      firestoreLink: { linkOperationId, observedBy: "identity-linking-service", linkedAt: clock,
        profileRevision: 3, activationStatus: "linked_pending_activation", authDisabled: true },
      challenge: null, googleVerification: null, firebaseSession: null, firebaseProvider: null, postflight: null },
    conflictReason: null, revision: 1, lastEvent: null, createdAt: clock, updatedAt: clock,
    expiresAt, localActivationStatus: "linked_pending_activation", localAuthDisabled: true, version: 1
  } });
  const challengeService = new AuthChallengePersistenceService(db, adminUid, () => clock);
  const challenge = await challengeService.create({ trustedOperatorUid: adminUid, expectedInternalUid: uid,
    expectedFirebaseUid: uid, coordinationOperationId: operationId, authorizationId,
    googleSubjectHash: reservation.identifierHash, trustedSessionId: `session-${randomUUID()}`, lifetimeMs: 300_000 });
  await coordination.transition({ trustedAdministratorUid: adminUid, operationId, expectedRevision: 1,
    event: createTrustedAuthCoordinationEvent({ type: "challenge_issued", operationId,
      idempotencyKey: randomUUID(), expectedFirebaseUid: uid, expectedInternalUid: uid,
      googleSubjectHash: reservation.identifierHash, expectedCoordinationRevision: 1, expectedProfileRevision: 3,
      challenge: { challengeId: challenge.document.challengeId, issuedBy: "identity-challenge-service",
        issuedAt: challenge.document.issuedAt, expiresAt: challenge.document.expiresAt } }) });
  const payload = { iss: "https://accounts.google.com", aud: verifierConfig.allowedAudiences[0],
    azp: verifierConfig.allowedAuthorizedParties[0], sub: subject, email, email_verified: true, hd: "plcocina.com",
    iat: Math.floor(now.getTime() / 1000) - 30, exp: Math.floor(now.getTime() / 1000) + 900,
    nonce: challenge.oneTimeSecrets.nonce };
  const request = { trustedAdministratorUid: adminUid, operationId,
    challengeId: challenge.document.challengeId, authorizationId,
    trustedSessionId: challenge.document.trustedSessionId, idempotencyKey: randomUUID(), verificationId: randomUUID(),
    expectedCoordinationRevision: 2, expectedChallengeRevision: 1, googleIdToken: token(payload),
    nonce: challenge.oneTimeSecrets.nonce, state: challenge.oneTimeSecrets.state };
  return { uid, subject, operationId, challenge, payload, request };
}

async function state(value: Setup) {
  const [challenge, coordination, audits, grants] = await Promise.all([
    db.collection("identityAuthChallenges").doc(value.request.challengeId).get(),
    db.collection("identityAuthCoordinations").doc(value.operationId).get(),
    db.collection("auditEvents").where("resourceId", "==", value.uid).get(),
    db.collection("accessGrants").where("userId", "==", value.uid).get()
  ]);
  return { challenge: challenge.data(), coordination: coordination.data(), audits: audits.size, grants: grants.size };
}

async function rejectWithoutWrites(value: Setup, googleIdToken: string, code: string) {
  const before = await state(value);
  await expect(service().verifyConsumeAndRecord({ ...value.request, googleIdToken })).rejects.toMatchObject({ code });
  expect(await state(value)).toEqual(before);
}

describe("internal E3B to E5D2 composition", () => {
  it("verifies a controlled RSA token before atomically recording google proof", async () => {
    const value = await setup();
    await expect(service().verifyConsumeAndRecord(value.request)).resolves.toMatchObject({
      state: "google_proof_verified", replayed: false, automaticActivation: false
    });
    expect(await state(value)).toMatchObject({ challenge: { state: "consumed", revision: 2 },
      coordination: { state: "google_proof_verified", revision: 3,
        localActivationStatus: "linked_pending_activation", localAuthDisabled: true }, grants: 0 });
  });

  it.each([
    ["signature", (value: Setup) => token(value.payload, true), "SIGNATURE_INVALID"],
    ["issuer", (value: Setup) => token({ ...value.payload, iss: "https://securetoken.google.com/demo" }), "ISSUER_NOT_ALLOWED"],
    ["audience", (value: Setup) => token({ ...value.payload, aud: "attacker.apps.googleusercontent.com" }), "AUDIENCE_NOT_ALLOWED"],
    ["authorized party", (value: Setup) => token({ ...value.payload, azp: "attacker.apps.googleusercontent.com" }), "AUTHORIZED_PARTY_NOT_ALLOWED"],
    ["Workspace domain", (value: Setup) => token({ ...value.payload, hd: "attacker.example" }), "HOSTED_DOMAIN_NOT_ALLOWED"],
    ["nonce", (value: Setup) => token({ ...value.payload, nonce: "different-controlled-nonce" }), "NONCE_INVALID"],
    ["expiration", (value: Setup) => token({ ...value.payload,
      iat: Math.floor(now.getTime() / 1000) - 900, exp: Math.floor(now.getTime() / 1000) - 300 }), "TOKEN_EXPIRED"]
  ])("rejects invalid %s through real E3B before any orchestration write", async (_name, makeToken, code) => {
    const value = await setup();
    await rejectWithoutWrites(value, makeToken(value), code);
  });

  it("rejects a cryptographically valid conflicting subject without writes", async () => {
    const value = await setup();
    await rejectWithoutWrites(value, token({ ...value.payload, sub: `different-${randomUUID()}` }),
      "COORDINATION_CONTEXT_MISMATCH");
  });

  it("fails closed while constructing incomplete or invalid server configuration", () => {
    expect(() => service({ ...verifierConfig, allowedAudiences: [] })).toThrow();
    expect(() => createInternalAuthOrchestrationService(db, undefined as never)).toThrow(
      "AUTH_ORCHESTRATION_CONFIGURATION_INVALID");
    expect(() => createInternalAuthOrchestrationService(db, {
      googleTokenVerifier: verifierConfig, identifierPepper: Buffer.alloc(8), protectedSuperAdminUid: adminUid
    })).toThrow("IDENTIFIER_PEPPER_TOO_SHORT");
  });

  it("returns an equivalent replay without a second consumption or audit", async () => {
    const value = await setup();
    const composed = service();
    await composed.verifyConsumeAndRecord(value.request);
    const afterFirst = await state(value);
    await expect(composed.verifyConsumeAndRecord(value.request)).resolves.toMatchObject({
      replayed: true, challengeConsumedAgain: false
    });
    expect(await state(value)).toEqual(afterFirst);
  });
});
