import { generateKeyPairSync, randomUUID, sign } from "node:crypto";
import { deleteApp, initializeApp } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import { Timestamp, getFirestore, type Firestore } from "firebase-admin/firestore";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { InvitationTokenKeyring } from "../src/invitations/invitation-token.js";
import { GoogleAuthLibraryJwtCryptographicVerifier, type GoogleCertificateSource, type GoogleTokenVerifierConfig } from "../src/identities/google-token-verifier.js";
import { InvitationGoogleProofService } from "../src/identities/identity-invitation-google-proof-service.js";

let app: ReturnType<typeof initializeApp>; let db: Firestore;
const now = new Date(); const clock = () => Timestamp.fromDate(now);
const keyId = "local-rsa-proof-key"; const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
const config: GoogleTokenVerifierConfig = { allowedIssuers: ["accounts.google.com", "https://accounts.google.com"],
  allowedAudiences: ["local-client.apps.googleusercontent.com"], allowedAuthorizedParties: ["local-client.apps.googleusercontent.com"],
  allowedWorkspaceDomains: ["plcocina.com"], requireAuthorizedParty: true, clockSkewSeconds: 60, maxTokenLifetimeSeconds: 3600 };
class LocalCertificates implements GoogleCertificateSource { async getCertificates() { return { [keyId]: publicKeyPem }; } }
const tokens = new InvitationTokenKeyring(new Map([[1, Buffer.alloc(32, 0x41)]]), 1);
beforeAll(() => { if (!process.env.FIRESTORE_EMULATOR_HOST) throw new Error("Requiere Firestore Emulator."); app = initializeApp({ projectId: "demo-plcocina-apps" }, `initial-google-proof-${randomUUID()}`); db = getFirestore(app); });
afterAll(async () => { await deleteApp(app); });
function encode(value: unknown) { return Buffer.from(JSON.stringify(value)).toString("base64url"); }
function jwt(subject: string, email: string, nonce: string) {
  const iat = Math.floor(now.getTime() / 1000); const head = encode({ alg: "RS256", typ: "JWT", kid: keyId });
  const body = encode({ iss: "https://accounts.google.com", aud: "local-client.apps.googleusercontent.com", azp: "local-client.apps.googleusercontent.com",
    sub: subject, email, email_verified: true, hd: "plcocina.com", nonce, iat, exp: iat + 600 });
  return `${head}.${body}.${sign("RSA-SHA256", Buffer.from(`${head}.${body}`), privateKey).toString("base64url")}`;
}
async function fixture(email = `empleado-${randomUUID()}@plcocina.com`, corporateEmail = true) {
  const invitationId = randomUUID(); const uid = `preprovisioned-${randomUUID()}`; const material = tokens.issue(invitationId, 1);
  await getAuth(app).createUser({ uid, email: corporateEmail ? email : undefined, disabled: true });
  const stamp = clock(); const expiresAt = Timestamp.fromMillis(stamp.toMillis() + 3_600_000);
  await db.collection("invitations").doc(invitationId).set({ invitationId, email, normalizedEmail: email.toLowerCase(), displayName: "Empleado", uid,
    status: "active", token: { hash: material.hash, generation: 1, salt: material.salt, keyVersion: material.keyVersion, issuedAt: stamp, expiresAt },
    delivery: { provider: "simulated", status: "accepted", idempotencyKey: `invitation/${invitationId}/generation/1`, providerMessageId: null,
      templateVersion: 1, firstAttemptAt: stamp, retryUntil: null, sentAt: stamp, deliveredAt: stamp, failureCode: null },
    expiresAt, createdAt: stamp, createdBy: "admin", updatedAt: stamp, updatedBy: "admin", pendingOperationId: null, consumeOperationId: null,
    consumeLeaseExpiresAt: null, passwordSetAt: null, confirmationExpiresAt: null, deliveredAt: stamp, acceptedAt: null, revokedAt: null, revokedBy: null,
    revokeReason: null, expiredAt: null, resendCount: 0, lastSentAt: stamp, revision: 1, version: 2 });
  await db.collection("users").doc(uid).set({ displayName: "Empleado", status: "invited", authDisabled: true, invitationStatus: "pending", authMethod: corporateEmail ? "email" : "sms",
    phoneE164: corporateEmail ? null : "+15551234567", normalizedPhone: corporateEmail ? null : "+15551234567", email: corporateEmail ? email : null,
    normalizedEmail: corporateEmail ? email.toLowerCase() : null, phoneVerifiedAt: null, emailVerifiedAt: null, activationStatus: "pending",
    credentialRevision: 1, authorizationRevision: 1, sessionValidAfter: stamp, createdAt: stamp, createdBy: "admin", updatedAt: stamp, updatedBy: "admin",
    revision: 1, pendingOperationId: null, version: 2 });
  const service = new InvitationGoogleProofService(db, tokens, {
    verify: async (input) => new (await import("../src/identities/google-token-verifier.js")).GoogleIdentityTokenVerifier(config, new LocalCertificates(),
      new GoogleAuthLibraryJwtCryptographicVerifier(), () => now).verify(input)
  }, clock);
  return { invitationId, uid, email, token: material.token, service };
}

describe("invitation-bound initial Google proof", () => {
  it("verifies with E3B, records trusted subject evidence, and leaves profile disabled", async () => {
    const f = await fixture(); const start = await f.service.start({ invitationId: f.invitationId, token: f.token });
    const result = await f.service.verify({ invitationId: f.invitationId, token: f.token, challengeId: start.challengeId, nonce: start.nonce,
      googleIdToken: jwt("google-subject-1", f.email, start.nonce) });
    expect(result).toMatchObject({ uid: f.uid, state: "verified" });
    expect((await db.collection("identityVerifiedGoogleProofs").doc(start.challengeId).get()).data()).toMatchObject({ subject: "google-subject-1", nonceVerified: true });
    expect((await db.collection("users").doc(f.uid).get()).data()).toMatchObject({ authDisabled: true, status: "invited", revision: 1 });
    expect((await getAuth(app).getUser(f.uid)).disabled).toBe(true);
  });
  it("rejects another Google account in the same Workspace domain", async () => {
    const f = await fixture(); const start = await f.service.start({ invitationId: f.invitationId, token: f.token });
    await expect(f.service.verify({ invitationId: f.invitationId, token: f.token, challengeId: start.challengeId, nonce: start.nonce,
      googleIdToken: jwt("different-subject", `other-${randomUUID()}@plcocina.com`, start.nonce) })).rejects.toMatchObject({ code: "GOOGLE_EMAIL_MISMATCH" });
  });
  it("rejects a wrong nonce", async () => {
    const f = await fixture(); const start = await f.service.start({ invitationId: f.invitationId, token: f.token });
    await expect(f.service.verify({ invitationId: f.invitationId, token: f.token, challengeId: start.challengeId, nonce: start.nonce,
      googleIdToken: jwt("google-subject", f.email, "a-different-server-nonce-value") })).rejects.toMatchObject({ code: "NONCE_INVALID" });
  });
  it("rejects a preprovisioned profile without a trusted corporate email", async () => {
    const f = await fixture(undefined, false);
    await expect(f.service.start({ invitationId: f.invitationId, token: f.token })).rejects.toMatchObject({ code: "CORPORATE_EMAIL_REQUIRED" });
  });
  it("rejects a revoked invitation", async () => {
    const f = await fixture(); const start = await f.service.start({ invitationId: f.invitationId, token: f.token });
    await db.collection("invitations").doc(f.invitationId).update({ status: "revoked", revokedAt: clock(), revokedBy: "admin", revokeReason: "Cancelada", revision: 2 });
    await expect(f.service.verify({ invitationId: f.invitationId, token: f.token, challengeId: start.challengeId, nonce: start.nonce,
      googleIdToken: jwt("google-subject", f.email, start.nonce) })).rejects.toMatchObject({ code: "INVITATION_INVALID" });
  });
  it("rejects an expired invitation before issuing a proof challenge", async () => {
    const f = await fixture();
    await db.collection("invitations").doc(f.invitationId).update({ expiresAt: clock(), "token.expiresAt": clock() });
    await expect(f.service.start({ invitationId: f.invitationId, token: f.token })).rejects.toMatchObject({ code: "INVITATION_INVALID" });
    expect((await db.collection("identityInvitationGoogleProofChallenges").get()).docs
      .some((document) => document.data().invitationId === f.invitationId)).toBe(false);
  });
  it("invalidates the earlier proof attempt after credential resend", async () => {
    const f = await fixture(); const start = await f.service.start({ invitationId: f.invitationId, token: f.token });
    const next = tokens.issue(f.invitationId, 2); const expiresAt = Timestamp.fromMillis(clock().toMillis() + 3_600_000);
    await db.collection("invitations").doc(f.invitationId).update({ token: { hash: next.hash, generation: 2, salt: next.salt, keyVersion: next.keyVersion,
      issuedAt: clock(), expiresAt }, expiresAt, revision: 2 });
    await expect(f.service.verify({ invitationId: f.invitationId, token: next.token, challengeId: start.challengeId, nonce: start.nonce,
      googleIdToken: jwt("google-subject", f.email, start.nonce) })).rejects.toMatchObject({ code: "CHALLENGE_INVALID" });
  });
  it("consumes the nonce and proof only once", async () => {
    const f = await fixture(); const start = await f.service.start({ invitationId: f.invitationId, token: f.token });
    const input = { invitationId: f.invitationId, token: f.token, challengeId: start.challengeId, nonce: start.nonce,
      googleIdToken: jwt("google-subject", f.email, start.nonce) };
    await f.service.verify(input);
    await expect(f.service.verify(input)).rejects.toMatchObject({ code: "CHALLENGE_CONSUMED" });
    expect((await db.collection("identityVerifiedGoogleProofs").where("uid", "==", f.uid).get()).size).toBe(1);
  });
});
