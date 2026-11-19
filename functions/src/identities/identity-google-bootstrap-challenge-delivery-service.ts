import { createHash } from "node:crypto";
import { Timestamp, type Firestore, type Transaction } from "firebase-admin/firestore";
import { z } from "zod";
import { invitationDocumentSchema } from "../models/admin-collections.js";
import { effectiveInvitationStatus } from "../invitations/invitation-transitions.js";
import { InvitationTokenKeyring } from "../invitations/invitation-token.js";
import { authChallengeDocumentSchema } from "./identity-auth-challenge-contracts.js";
import { verifyAuthChallengeSecret } from "./identity-auth-challenge-crypto.js";
import { authCoordinationDocumentSchema } from "./identity-auth-coordination-contracts.js";
import { deriveGoogleBootstrapChallengeKey, type InternalGoogleBootstrapComposition } from "./identity-google-bootstrap-composition.js";
import { deriveGoogleBootstrapChallengeSecrets } from "./identity-google-bootstrap-challenge-coordinator.js";
import { GoogleIdentityLinkError, readValidIdentityLinkAuthorization } from "./identity-linking-service.js";
import { identityVerifiedGoogleProofSchema } from "./identity-invitation-google-proof-service.js";
import { hashIdentityVerifiedGoogleProof, identityGoogleBootstrapPreparationPlanSchema } from "./identity-google-bootstrap-preparation-service.js";
import { googleWorkspaceUserV21DocumentSchema, identityIdentifierKeyDocumentSchema,
  normalizeGoogleSubject, normalizeIdentityEmail } from "./identity-models.js";
import type { AuthOrchestrationTransactionValidator } from "./identity-auth-orchestration-service.js";

const invitationInputSchema = z.object({ invitationId: z.string().uuid(), token: z.string().regex(/^[A-Za-z0-9_-]{43}$/) }).strict();
const finalizationInputSchema = invitationInputSchema.extend({ challengeId: z.string().uuid(),
  state: z.string().regex(/^[A-Za-z0-9_-]{43}$/), googleIdToken: z.string().min(1).max(20_000) }).strict();
type Proof = z.infer<typeof identityVerifiedGoogleProofSchema>;
type Plan = z.infer<typeof identityGoogleBootstrapPreparationPlanSchema>;
type Challenge = z.infer<typeof authChallengeDocumentSchema>;
type BindingMode = "delivery" | "consume";
type BindingInput = { invitationId: string; token: string; mode: BindingMode; challengeId?: string;
  state?: string; idempotencyKey?: string; now?: Timestamp; verifiedIdentity?: {
    subject: string; email: string; emailVerified: true; nonceVerified: boolean; googleSubjectHash: string;
  } };
type Binding = { proof: Proof; plan: Plan; challenge: Challenge; nonce: string; state: string;
  coordination: z.infer<typeof authCoordinationDocumentSchema> };

export class GoogleBootstrapChallengeDeliveryError extends Error {
  constructor(readonly code: "INVITATION_INVALID" | "PROOF_NOT_FOUND" | "PROOF_EXPIRED" | "PREPARATION_NOT_FOUND"
    | "PREPARATION_INVALID" | "AUTHORIZATION_INVALID" | "COORDINATION_INVALID" | "PROFILE_INVALID"
    | "RESERVATION_INVALID" | "CHALLENGE_NOT_FOUND" | "CHALLENGE_EXPIRED" | "CHALLENGE_CONSUMED"
    | "CHALLENGE_AMBIGUOUS" | "CHALLENGE_STATE_INVALID" | "GOOGLE_IDENTITY_INVALID" | "VERIFICATION_UNAVAILABLE"
    | "FINALIZATION_REJECTED") {
    super("Google bootstrap challenge delivery rejected");
    this.name = "GoogleBootstrapChallengeDeliveryError";
  }
}

export type GoogleBootstrapChallengeDelivery = Readonly<{
  challengeId: string;
  nonce: string;
  state: string;
  expiresAt: Timestamp;
}>;

function finalizationIdempotencyKey(challengeId: string, invitationId: string): string {
  const bytes = Buffer.from(createHash("sha256")
    .update(`apps-pl-cocina/b5-c5/finalization/v1\0${invitationId}\0${challengeId}`).digest().subarray(0, 16));
  bytes[6] = (bytes[6]! & 0x0f) | 0x50;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** Invitation-scoped recovery and finalization for an already issued B4 challenge. */
export class GoogleBootstrapChallengeDeliveryService {
  private readonly challengeKey: Buffer;

  constructor(private readonly db: Firestore, identifierPepper: Buffer,
    private readonly invitationTokens: InvitationTokenKeyring, private readonly protectedSuperAdminUid: string,
    private readonly now: () => Timestamp = () => Timestamp.now()) {
    this.challengeKey = deriveGoogleBootstrapChallengeKey(identifierPepper);
  }

  async recover(input: unknown): Promise<GoogleBootstrapChallengeDelivery> {
    const value = invitationInputSchema.parse(input);
    const binding = await this.db.runTransaction((transaction) => this.validateBinding(transaction,
      { ...value, mode: "delivery" }));
    return Object.freeze({ challengeId: binding.challenge.challengeId, nonce: binding.nonce,
      state: binding.state, expiresAt: binding.challenge.expiresAt });
  }

  async verifyAndConsume(input: unknown, composition: InternalGoogleBootstrapComposition): Promise<{
    state: "google_proof_verified"; replayed: boolean;
  }> {
    const value = finalizationInputSchema.parse(input);
    const idempotencyKey = finalizationIdempotencyKey(value.challengeId, value.invitationId);
    const preflight = await this.db.runTransaction((transaction) => this.validateBinding(transaction,
      { ...value, mode: "consume", idempotencyKey }));
    const validateTransaction: AuthOrchestrationTransactionValidator = async (context) => {
      const current = await this.validateBinding(context.transaction, { ...value, mode: "consume", idempotencyKey,
        now: context.now, verifiedIdentity: { subject: context.identity.subject, email: context.identity.email,
          emailVerified: context.identity.emailVerified, nonceVerified: context.identity.nonceVerified,
          googleSubjectHash: context.googleSubjectHash } });
      if (current.nonce !== preflight.nonce || current.challenge.challengeId !== context.challengeId
        || current.plan.coordinationOperationId !== context.operationId
        || current.plan.authorizationId !== context.authorizationId) {
        throw new GoogleBootstrapChallengeDeliveryError("CHALLENGE_NOT_FOUND");
      }
    };

    try {
      const result = await composition.verifyAndConsume({ challengeId: value.challengeId, idempotencyKey,
        googleIdToken: value.googleIdToken, nonce: preflight.nonce, state: value.state }, { validateTransaction });
      return Object.freeze({ state: result.state, replayed: result.replayed });
    } catch (error) {
      if (error instanceof GoogleBootstrapChallengeDeliveryError) throw error;
      const code = typeof error === "object" && error !== null && "code" in error ? String(error.code) : "";
      if (["KEY_FETCH_FAILED", "KEY_SET_INVALID", "VERIFICATION_UNAVAILABLE", "VERIFIER_MISCONFIGURED"].includes(code)) {
        throw new GoogleBootstrapChallengeDeliveryError("VERIFICATION_UNAVAILABLE");
      }
      if (["NONCE_INVALID", "NONCE_REQUIRED", "SIGNATURE_INVALID", "ALGORITHM_NOT_ALLOWED", "KEY_ID_UNKNOWN",
        "ISSUER_NOT_ALLOWED", "AUDIENCE_NOT_ALLOWED", "AUTHORIZED_PARTY_NOT_ALLOWED", "TOKEN_EXPIRED", "TOKEN_MALFORMED",
        "TOKEN_TOO_LARGE", "EMAIL_INVALID", "EMAIL_NOT_VERIFIED", "HOSTED_DOMAIN_MISSING", "HOSTED_DOMAIN_NOT_ALLOWED",
        "IDENTITY_CLAIMS_INCONSISTENT", "SUBJECT_INVALID", "ISSUED_AT_INVALID", "CHALLENGE_CONTEXT_INVALID"].includes(code)) {
        throw new GoogleBootstrapChallengeDeliveryError("GOOGLE_IDENTITY_INVALID");
      }
      if (error instanceof Error && error.name === "GoogleBootstrapChallengeDeliveryError") throw error;
      throw new GoogleBootstrapChallengeDeliveryError("FINALIZATION_REJECTED");
    }
  }

  private async validateBinding(transaction: Transaction, input: BindingInput): Promise<Binding> {
    const now = input.now ?? this.now();
    const invitationRef = this.db.collection("invitations").doc(input.invitationId);
    const proofQuery = this.db.collection("identityVerifiedGoogleProofs").where("invitationId", "==", input.invitationId).limit(21);
    const [invitationSnapshot, proofSnapshots] = await Promise.all([
      transaction.get(invitationRef), transaction.get(proofQuery)
    ]);
    const invitation = invitationDocumentSchema.safeParse(invitationSnapshot.data());
    if (!invitationSnapshot.exists || !invitation.success || !this.validInvitation(invitation.data, input.invitationId, input.token, now)) {
      throw new GoogleBootstrapChallengeDeliveryError("INVITATION_INVALID");
    }
    if (proofSnapshots.size > 20) throw new GoogleBootstrapChallengeDeliveryError("CHALLENGE_AMBIGUOUS");

    const proofs: Proof[] = [];
    let proofExpired = false;
    for (const snapshot of proofSnapshots.docs) {
      const proof = identityVerifiedGoogleProofSchema.safeParse(snapshot.data());
      if (!proof.success || proof.data.proofId !== snapshot.id) throw new GoogleBootstrapChallengeDeliveryError("PREPARATION_INVALID");
      if (proof.data.invitationId !== invitation.data.invitationId || proof.data.uid !== invitation.data.uid
        || proof.data.normalizedEmail !== invitation.data.normalizedEmail
        || proof.data.credentialGeneration !== invitation.data.token!.generation || proof.data.state !== "verified"
        || proof.data.nonceVerified !== true) continue;
      if (proof.data.validUntil.toMillis() <= now.toMillis()) { proofExpired = true; continue; }
      proofs.push(proof.data);
    }
    if (proofs.length === 0) throw new GoogleBootstrapChallengeDeliveryError(proofExpired ? "PROOF_EXPIRED" : "PROOF_NOT_FOUND");

    const planSnapshots = await Promise.all(proofs.map((proof) => transaction.get(
      this.db.collection("identityGoogleBootstrapPreparations").doc(proof.proofId))));
    const preparedPlans: Plan[] = [];
    for (let index = 0; index < planSnapshots.length; index += 1) {
      const snapshot = planSnapshots[index]!;
      if (!snapshot.exists) continue;
      const plan = identityGoogleBootstrapPreparationPlanSchema.safeParse(snapshot.data());
      if (!plan.success) throw new GoogleBootstrapChallengeDeliveryError("PREPARATION_INVALID");
      const proof = proofs[index]!;
      if (plan.data.proofId !== proof.proofId || plan.data.proofHash !== hashIdentityVerifiedGoogleProof(proof)
        || plan.data.invitationId !== invitation.data.invitationId || plan.data.uid !== invitation.data.uid
        || plan.data.credentialGeneration !== invitation.data.token!.generation
        || plan.data.normalizedEmail !== invitation.data.normalizedEmail) {
        throw new GoogleBootstrapChallengeDeliveryError("PREPARATION_INVALID");
      }
      if (plan.data.state === "prepared") {
        if (plan.data.preparedAt === null) throw new GoogleBootstrapChallengeDeliveryError("PREPARATION_INVALID");
        preparedPlans.push(plan.data);
      }
    }
    if (preparedPlans.length === 0) throw new GoogleBootstrapChallengeDeliveryError("PREPARATION_NOT_FOUND");

    const challengeSnapshots = await Promise.all(preparedPlans.map((plan) => transaction.get(
      this.db.collection("identityAuthChallenges").doc(plan.authorizationId))));
    const candidates: Array<{ plan: Plan; proof: Proof; challenge: Challenge }> = [];
    let expired = false; let consumed = false;
    for (let index = 0; index < challengeSnapshots.length; index += 1) {
      const snapshot = challengeSnapshots[index]!;
      if (!snapshot.exists) continue;
      const challenge = authChallengeDocumentSchema.safeParse(snapshot.data());
      if (!challenge.success) throw new GoogleBootstrapChallengeDeliveryError("CHALLENGE_NOT_FOUND");
      const plan = preparedPlans[index]!;
      if (input.challengeId && challenge.data.challengeId !== input.challengeId) continue;
      if (challenge.data.challengeId !== plan.authorizationId || challenge.data.authorizationId !== plan.authorizationId
        || challenge.data.coordinationOperationId !== plan.coordinationOperationId
        || challenge.data.contextType !== "google_bootstrap" || challenge.data.trustedSessionId !== undefined
        || !challenge.data.issuanceIdempotencyKey || challenge.data.expectedFirebaseUid !== plan.uid
        || challenge.data.expectedInternalUid !== plan.uid || challenge.data.googleSubjectHash !== plan.subjectHash) {
        throw new GoogleBootstrapChallengeDeliveryError("CHALLENGE_NOT_FOUND");
      }
      if (challenge.data.state === "consumed") { consumed = true; }
      else if (challenge.data.state === "expired" || challenge.data.expiresAt.toMillis() <= now.toMillis()) { expired = true; continue; }
      else if (challenge.data.state !== "issued") continue;
      if (input.mode === "delivery" && challenge.data.state !== "issued") continue;
      if (challenge.data.issuedAt.toMillis() > now.toMillis()) throw new GoogleBootstrapChallengeDeliveryError("CHALLENGE_NOT_FOUND");
      const proof = proofs.find((candidate) => candidate.proofId === plan.proofId)!;
      candidates.push({ plan, proof, challenge: challenge.data });
    }
    if (candidates.length > 1) throw new GoogleBootstrapChallengeDeliveryError("CHALLENGE_AMBIGUOUS");
    if (candidates.length === 0) {
      if (consumed) throw new GoogleBootstrapChallengeDeliveryError("CHALLENGE_CONSUMED");
      if (expired) throw new GoogleBootstrapChallengeDeliveryError("CHALLENGE_EXPIRED");
      throw new GoogleBootstrapChallengeDeliveryError("CHALLENGE_NOT_FOUND");
    }

    const { plan, proof, challenge } = candidates[0]!;
    const [profileSnapshot, reservationSnapshot, coordinationSnapshot] = await Promise.all([
      transaction.get(this.db.collection("users").doc(plan.uid)),
      transaction.get(this.db.collection("authIdentifierKeys").doc(plan.subjectHash)),
      transaction.get(this.db.collection("identityAuthCoordinations").doc(plan.coordinationOperationId))
    ]);
    const profile = googleWorkspaceUserV21DocumentSchema.safeParse(profileSnapshot.data());
    const reservation = identityIdentifierKeyDocumentSchema.safeParse(reservationSnapshot.data());
    const coordination = authCoordinationDocumentSchema.safeParse(coordinationSnapshot.data());
    if (!profileSnapshot.exists || !profile.success || profile.data.uid !== plan.uid || profile.data.status !== "invited"
      || profile.data.authDisabled !== true || profile.data.activationStatus !== "linked_pending_activation"
      || profile.data.normalizedEmail !== proof.normalizedEmail || profile.data.googleWorkspace.subject !== proof.subject
      || profile.data.googleWorkspace.linkingStatus !== "linked" || profile.data.googleWorkspace.verificationStatus !== "verified"
      || profile.data.revision !== plan.verifiedProfileRevision + 1) {
      throw new GoogleBootstrapChallengeDeliveryError("PROFILE_INVALID");
    }
    if (!reservationSnapshot.exists || !reservation.success || reservation.data.kind !== "googleSubject"
      || reservation.data.identifierHash !== plan.subjectHash || reservation.data.uid !== plan.uid
      || reservation.data.state !== "reserved") throw new GoogleBootstrapChallengeDeliveryError("RESERVATION_INVALID");
    const expectedCoordinationState = challenge.state === "consumed" ? "google_proof_verified" : "challenge_issued";
    if (!coordinationSnapshot.exists || !coordination.success || coordination.data.operationId !== plan.coordinationOperationId
      || coordination.data.authorizationId !== plan.authorizationId || coordination.data.expectedFirebaseUid !== plan.uid
      || coordination.data.expectedInternalUid !== plan.uid || coordination.data.googleSubjectHash !== plan.subjectHash
      || coordination.data.challengeId !== challenge.challengeId || coordination.data.state !== expectedCoordinationState
      || coordination.data.evidence.challenge?.challengeId !== challenge.challengeId
      || coordination.data.evidence.challenge.issuedAt.toMillis() !== challenge.issuedAt.toMillis()
      || coordination.data.evidence.challenge.expiresAt.toMillis() !== challenge.expiresAt.toMillis()
      || coordination.data.evidence.firestoreLink.linkOperationId !== plan.linkOperationId
      || coordination.data.currentProfileRevision !== profile.data.revision
      || coordination.data.expiresAt.toMillis() <= now.toMillis()) {
      throw new GoogleBootstrapChallengeDeliveryError("COORDINATION_INVALID");
    }

    if (challenge.state === "consumed") {
      const replayKey = input.idempotencyKey;
      if (input.mode !== "consume" || !replayKey) throw new GoogleBootstrapChallengeDeliveryError("CHALLENGE_CONSUMED");
      const replaySnapshot = await transaction.get(this.db.collection("identityAuthCoordinationIdempotency").doc(replayKey));
      const replay = replaySnapshot.data();
      if (!replaySnapshot.exists || replay?.operationId !== plan.coordinationOperationId || replay?.kind !== "transition"
        || replay?.resultingRevision !== coordination.data.revision || typeof replay?.inputHash !== "string"
        || replay.version !== 1) throw new GoogleBootstrapChallengeDeliveryError("CHALLENGE_CONSUMED");
    } else if (input.mode === "consume" && input.idempotencyKey) {
      const replaySnapshot = await transaction.get(this.db.collection("identityAuthCoordinationIdempotency").doc(input.idempotencyKey));
      if (replaySnapshot.exists) throw new GoogleBootstrapChallengeDeliveryError("COORDINATION_INVALID");
    }

    let authorization;
    try {
      authorization = await readValidIdentityLinkAuthorization({ db: this.db, transaction,
        authorizationId: plan.authorizationId,
        expected: { operationId: plan.linkOperationId, targetUid: plan.uid,
          googleSubjectHash: plan.subjectHash, expectedRevision: plan.verifiedProfileRevision },
        now, allowConsumedLink: true });
    } catch (error) {
      if (error instanceof GoogleIdentityLinkError) throw new GoogleBootstrapChallengeDeliveryError("AUTHORIZATION_INVALID");
      throw error;
    }
    if (authorization.invitationId !== invitation.data.invitationId || authorization.targetUid !== invitation.data.uid
      || authorization.authorizedByUid !== this.protectedSuperAdminUid
      || authorization.state !== "consumed" || authorization.expiresAt.toMillis() <= now.toMillis()) {
      throw new GoogleBootstrapChallengeDeliveryError("AUTHORIZATION_INVALID");
    }

    const secrets = deriveGoogleBootstrapChallengeSecrets(this.challengeKey, challenge.authorizationId,
      challenge.issuanceIdempotencyKey!);
    try {
      if (!verifyAuthChallengeSecret(secrets.nonce, challenge.nonceHash)
        || !verifyAuthChallengeSecret(secrets.state, challenge.stateHash)) {
        throw new GoogleBootstrapChallengeDeliveryError("CHALLENGE_NOT_FOUND");
      }
    } catch {
      throw new GoogleBootstrapChallengeDeliveryError("CHALLENGE_NOT_FOUND");
    }
    if (input.state !== undefined) {
      let stateMatches = false;
      try { stateMatches = verifyAuthChallengeSecret(input.state, challenge.stateHash); } catch { /* Treat malformed state as a mismatch. */ }
      if (!stateMatches) throw new GoogleBootstrapChallengeDeliveryError("CHALLENGE_STATE_INVALID");
    }
    if (input.verifiedIdentity && (normalizeGoogleSubject(input.verifiedIdentity.subject) !== proof.subject
      || normalizeIdentityEmail(input.verifiedIdentity.email) !== proof.normalizedEmail
      || input.verifiedIdentity.emailVerified !== true || input.verifiedIdentity.nonceVerified !== true
      || input.verifiedIdentity.googleSubjectHash !== plan.subjectHash)) {
      throw new GoogleBootstrapChallengeDeliveryError("GOOGLE_IDENTITY_INVALID");
    }
    return { proof, plan, challenge, nonce: secrets.nonce, state: secrets.state, coordination: coordination.data };
  }

  private validInvitation(invitation: z.infer<typeof invitationDocumentSchema>, invitationId: string,
    token: string, now: Timestamp): boolean {
    return invitation.invitationId === invitationId && invitation.token !== null
      && effectiveInvitationStatus(invitation, now.toMillis()) === "active"
      && invitation.token.expiresAt.toMillis() > now.toMillis() && invitation.expiresAt.toMillis() > now.toMillis()
      && this.invitationTokens.verify(token, invitation.token.hash);
  }
}
