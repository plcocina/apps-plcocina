import { createHash, randomBytes, randomUUID } from "node:crypto";
import { Timestamp, type Firestore } from "firebase-admin/firestore";
import { z } from "zod";
import { invitationDocumentSchema } from "../models/admin-collections.js";
import { effectiveInvitationStatus } from "../invitations/invitation-transitions.js";
import { InvitationTokenKeyring } from "../invitations/invitation-token.js";
import { createTrustedNonceContext, type VerifiedGoogleIdentity, type VerifyGoogleIdTokenInput } from "./google-token-verifier.js";
import { normalizeIdentityEmail, normalizeGoogleSubject, userV2DocumentSchema } from "./identity-models.js";

const inputSchema = z.object({ invitationId: z.string().uuid(), token: z.string().regex(/^[A-Za-z0-9_-]{43}$/) }).strict();
const verifySchema = inputSchema.extend({ challengeId: z.string().uuid(), nonce: z.string().min(16).max(512), googleIdToken: z.string().min(1).max(20_000) }).strict();
export const identityVerifiedGoogleProofSchema = z.object({ proofId: z.string().uuid(), invitationId: z.string().uuid(), uid: z.string().min(1),
  credentialGeneration: z.number().int().positive(), subject: z.string().min(1).max(255), normalizedEmail: z.string().email(),
  verificationId: z.string().uuid(), verifiedAt: z.instanceof(Timestamp), validUntil: z.instanceof(Timestamp),
  nonceVerified: z.literal(true), state: z.literal("verified"), version: z.literal(1) }).strict().superRefine((proof, context) => {
    if (proof.proofId !== proof.verificationId || proof.validUntil.toMillis() <= proof.verifiedAt.toMillis()) {
      context.addIssue({ code: "custom", path: ["verificationId"], message: "La evidencia Google verificada no es coherente" });
    }
  });
const challengeSchema = z.object({ challengeId: z.string().uuid(), invitationId: z.string().uuid(), uid: z.string().min(1),
  credentialGeneration: z.number().int().positive(), credentialHash: z.string().regex(/^[a-f0-9]{64}$/), nonceHash: z.string().regex(/^[a-f0-9]{64}$/),
  expectedEmail: z.string().email(), issuedAt: z.instanceof(Timestamp), expiresAt: z.instanceof(Timestamp), consumedAt: z.instanceof(Timestamp).nullable(), version: z.literal(1) }).strict();

export type InternalGoogleIdentityVerifier = { verify(input: VerifyGoogleIdTokenInput): Promise<VerifiedGoogleIdentity> };
export class InvitationGoogleProofError extends Error {
  constructor(readonly code: "INVITATION_INVALID" | "PROFILE_INVALID" | "CORPORATE_EMAIL_REQUIRED" | "GOOGLE_EMAIL_MISMATCH" | "CHALLENGE_INVALID" | "CHALLENGE_EXPIRED" | "CHALLENGE_CONSUMED") {
    super("Invitation Google proof rejected"); this.name = "InvitationGoogleProofError";
  }
}
const digest = (value: string) => createHash("sha256").update(value).digest("hex");

/** Server-only bootstrap proof; never logs credentials, nonce, or token material. */
export class InvitationGoogleProofService {
  constructor(private readonly db: Firestore, private readonly tokens: InvitationTokenKeyring,
    private readonly verifier: InternalGoogleIdentityVerifier, private readonly now: () => Timestamp = () => Timestamp.now(),
    private readonly lifetimeMs = 5 * 60_000) {}

  async start(input: unknown) {
    const value = inputSchema.parse(input);
    const invitationRef = this.db.collection("invitations").doc(value.invitationId);
    const initial = await invitationRef.get();
    if (!initial.exists) throw new InvitationGoogleProofError("INVITATION_INVALID");
    const invitation = invitationDocumentSchema.safeParse(initial.data());
    if (!invitation.success || !this.validInvitation(invitation.data, value.token)) throw new InvitationGoogleProofError("INVITATION_INVALID");
    const profileRef = this.db.collection("users").doc(invitation.data.uid);
    const profileSnapshotByUid = await profileRef.get();
    const profile = userV2DocumentSchema.safeParse(profileSnapshotByUid.data());
    if (!profileSnapshotByUid.exists || !profile.success || profile.data.authDisabled !== true || profile.data.status !== "invited") {
      throw new InvitationGoogleProofError("PROFILE_INVALID");
    }
    const expectedEmail = profile.data.normalizedEmail;
    if (!expectedEmail) throw new InvitationGoogleProofError("CORPORATE_EMAIL_REQUIRED");
    if (normalizeIdentityEmail(expectedEmail) !== invitation.data.normalizedEmail) throw new InvitationGoogleProofError("PROFILE_INVALID");
    const issuedAt = this.now(); const expiresAt = Timestamp.fromMillis(issuedAt.toMillis() + this.lifetimeMs);
    const challengeId = randomUUID(); const nonce = randomBytes(32).toString("base64url");
    const challenge = challengeSchema.parse({ challengeId, invitationId: value.invitationId, uid: invitation.data.uid,
      credentialGeneration: invitation.data.token!.generation, credentialHash: invitation.data.token!.hash,
      nonceHash: digest(nonce), expectedEmail, issuedAt, expiresAt, consumedAt: null, version: 1 });
    await this.db.runTransaction(async (transaction) => {
      const [currentInvitation, currentProfile] = await Promise.all([transaction.get(invitationRef), transaction.get(profileRef)]);
      const parsedInvitation = invitationDocumentSchema.safeParse(currentInvitation.data());
      const parsedProfile = userV2DocumentSchema.safeParse(currentProfile.data());
      if (!currentInvitation.exists || !parsedInvitation.success || !this.validInvitation(parsedInvitation.data, value.token)
        || parsedInvitation.data.uid !== challenge.uid || parsedInvitation.data.token?.generation !== challenge.credentialGeneration
        || parsedInvitation.data.token?.hash !== challenge.credentialHash || !currentProfile.exists || !parsedProfile.success
        || parsedProfile.data.normalizedEmail !== expectedEmail || parsedProfile.data.authDisabled !== true || parsedProfile.data.status !== "invited") {
        throw new InvitationGoogleProofError("INVITATION_INVALID");
      }
      transaction.create(this.db.collection("identityInvitationGoogleProofChallenges").doc(challengeId), challenge);
    });
    return Object.freeze({ challengeId, nonce, expiresAt });
  }

  async verify(input: unknown) {
    const value = verifySchema.parse(input);
    const invitationRef = this.db.collection("invitations").doc(value.invitationId);
    const challengeRef = this.db.collection("identityInvitationGoogleProofChallenges").doc(value.challengeId);
    const invitationSnapshot = await invitationRef.get(); const challengeSnapshot = await challengeRef.get();
    const invitation = invitationDocumentSchema.safeParse(invitationSnapshot.data());
    const challenge = challengeSchema.safeParse(challengeSnapshot.data());
    if (!invitationSnapshot.exists || !invitation.success || !this.validInvitation(invitation.data, value.token)) {
      throw new InvitationGoogleProofError("INVITATION_INVALID");
    }
    if (!challengeSnapshot.exists || !challenge.success || challenge.data.invitationId !== value.invitationId
      || challenge.data.uid !== invitation.data.uid || challenge.data.credentialGeneration !== invitation.data.token?.generation
      || challenge.data.credentialHash !== invitation.data.token?.hash || challenge.data.nonceHash !== digest(value.nonce)) {
      throw new InvitationGoogleProofError("CHALLENGE_INVALID");
    }
    const profileRef = this.db.collection("users").doc(invitation.data.uid);
    const profileSnapshot = await profileRef.get(); const profile = userV2DocumentSchema.safeParse(profileSnapshot.data());
    if (!profileSnapshot.exists || !profile.success || !profile.data.normalizedEmail || profile.data.normalizedEmail !== challenge.data.expectedEmail
      || profile.data.authDisabled !== true || profile.data.status !== "invited") throw new InvitationGoogleProofError("PROFILE_INVALID");
    if (challenge.data.expiresAt.toMillis() <= this.now().toMillis()) throw new InvitationGoogleProofError("CHALLENGE_EXPIRED");
    if (challenge.data.consumedAt) throw new InvitationGoogleProofError("CHALLENGE_CONSUMED");

    const identity = await this.verifier.verify({ idToken: value.googleIdToken, nonceContext: createTrustedNonceContext(value.nonce) });
    if (normalizeIdentityEmail(identity.email) !== challenge.data.expectedEmail) throw new InvitationGoogleProofError("GOOGLE_EMAIL_MISMATCH");
    const subject = normalizeGoogleSubject(identity.subject);
    const verifiedAt = Timestamp.fromDate(identity.issuedAt); const validUntil = Timestamp.fromDate(identity.expiresAt);
    const proof = identityVerifiedGoogleProofSchema.parse({ proofId: value.challengeId, invitationId: value.invitationId, uid: challenge.data.uid,
      credentialGeneration: challenge.data.credentialGeneration, subject, normalizedEmail: challenge.data.expectedEmail,
      verificationId: value.challengeId, verifiedAt, validUntil, nonceVerified: true, state: "verified", version: 1 });
    await this.db.runTransaction(async (transaction) => {
      const [currentInvitation, currentChallenge, currentProfile] = await Promise.all([
        transaction.get(invitationRef), transaction.get(challengeRef), transaction.get(profileRef)
      ]);
      const parsedInvitation = invitationDocumentSchema.safeParse(currentInvitation.data());
      const parsedChallenge = challengeSchema.safeParse(currentChallenge.data()); const parsedProfile = userV2DocumentSchema.safeParse(currentProfile.data());
      if (!currentInvitation.exists || !parsedInvitation.success || !this.validInvitation(parsedInvitation.data, value.token)
        || parsedInvitation.data.uid !== proof.uid || parsedInvitation.data.token?.generation !== proof.credentialGeneration
        || parsedInvitation.data.token?.hash !== challenge.data!.credentialHash || !currentChallenge.exists || !parsedChallenge.success
        || parsedChallenge.data.nonceHash !== digest(value.nonce) || parsedChallenge.data.consumedAt
        || parsedChallenge.data.expiresAt.toMillis() <= this.now().toMillis() || !currentProfile.exists || !parsedProfile.success
        || parsedProfile.data.normalizedEmail !== proof.normalizedEmail || parsedProfile.data.authDisabled !== true || parsedProfile.data.status !== "invited") {
        throw new InvitationGoogleProofError("CHALLENGE_INVALID");
      }
      transaction.update(challengeRef, { consumedAt: this.now() });
      transaction.create(this.db.collection("identityVerifiedGoogleProofs").doc(proof.proofId), proof);
    });
    return Object.freeze({ proofId: proof.proofId, uid: proof.uid, state: proof.state, verifiedAt: proof.verifiedAt });
  }

  private validInvitation(invitation: z.infer<typeof invitationDocumentSchema>, token: string) {
    const now = this.now().toMillis();
    return invitation.token !== null && effectiveInvitationStatus(invitation, now) === "active"
      && invitation.token.expiresAt.toMillis() > now && invitation.expiresAt.toMillis() > now
      && this.tokens.verify(token, invitation.token.hash)
      && invitation.verificationMethod === "googleWorkspace";
  }
}
