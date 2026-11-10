import { createHash } from "node:crypto";
import { Timestamp, type Firestore } from "firebase-admin/firestore";
import { z } from "zod";
import type { VerifiedGoogleIdentity, VerifyGoogleIdTokenInput } from "./google-token-verifier.js";
import { createTrustedNonceContext } from "./google-token-verifier.js";
import { authChallengeDocumentSchema, createTrustedAuthBootstrapChallengeContext,
  createTrustedAuthChallengeContext } from "./identity-auth-challenge-contracts.js";
import { prepareAuthChallengeConsumption } from "./identity-auth-challenge-service.js";
import { createTrustedAuthCoordinationEvent } from "./identity-auth-coordination-contracts.js";
import { AuthCoordinationPersistenceService, prepareAuthCoordinationTransition } from "./identity-auth-coordination-service.js";
import {
  createTrustedAdministrativeOrchestrationEvidence,
  createTrustedChallengeOrchestrationEvidence,
  createTrustedCoordinationOrchestrationEvidence,
  createTrustedGoogleOrchestrationEvidence,
  type AuthOrchestrationInput
} from "./identity-auth-orchestration-contracts.js";
import { evaluateAuthOrchestration } from "./identity-auth-orchestration-policy.js";
import { identityLinkAuthorizationSchema } from "./identity-linking-contracts.js";
import { readValidIdentityLinkAuthorization } from "./identity-linking-service.js";
import { googleWorkspaceUserV21DocumentSchema, identifierKeyHash,
  identityIdentifierKeyDocumentSchema } from "./identity-models.js";

const uidSchema = z.string().min(1).max(128).refine((value) => !value.includes("/"));
const uuidSchema = z.string().uuid();
const sessionSchema = z.string().min(16).max(256).regex(/^[A-Za-z0-9._~-]+$/);

const orchestrationRequestSchema = z.object({
  trustedAdministratorUid: uidSchema,
  contextType: z.enum(["trusted_session", "google_bootstrap"]).default("trusted_session"),
  operationId: uuidSchema,
  challengeId: uuidSchema,
  authorizationId: uuidSchema,
  trustedSessionId: sessionSchema.optional(),
  idempotencyKey: uuidSchema,
  verificationId: uuidSchema,
  expectedCoordinationRevision: z.number().int().positive(),
  expectedChallengeRevision: z.number().int().positive(),
  googleIdToken: z.string().min(1).max(20_000),
  nonce: z.string().min(1).max(512),
  state: z.string().min(1).max(512)
}).strict().superRefine((request, context) => {
  if (request.contextType === "trusted_session" && !request.trustedSessionId) {
    context.addIssue({ code: "custom", path: ["trustedSessionId"], message: "trusted_session requiere sesión" });
  }
  if (request.contextType === "google_bootstrap" && request.trustedSessionId !== undefined) {
    context.addIssue({ code: "custom", path: ["trustedSessionId"], message: "google_bootstrap no admite sesión" });
  }
});

export type AuthOrchestrationPersistenceRequest = z.input<typeof orchestrationRequestSchema>;

export interface InternalGoogleIdentityVerifier {
  verify(input: VerifyGoogleIdTokenInput): Promise<VerifiedGoogleIdentity>;
}

export type AuthOrchestrationPersistenceErrorCode = "TRUSTED_CONTEXT_MISMATCH" | "SUPER_ADMIN_FORBIDDEN"
  | "COORDINATION_CONTEXT_MISMATCH" | "E4_LINK_NOT_CONFIRMED" | "AUTHORIZATION_INVALID"
  | "PROFILE_BLOCKED" | "RESERVATION_CONFLICT" | "POLICY_REJECTED" | "REPLAY_STATE_INVALID";

export class AuthOrchestrationPersistenceError extends Error {
  constructor(readonly code: AuthOrchestrationPersistenceErrorCode) {
    super("Auth orchestration persistence rejected");
    this.name = "AuthOrchestrationPersistenceError";
  }
}

export type AuthOrchestrationPersistenceResult = Readonly<{
  operationId: string;
  challengeId: string;
  coordinationRevision: number;
  challengeRevision: number;
  state: "google_proof_verified";
  replayed: boolean;
  challengeConsumedAgain: false;
  automaticActivation: false;
}>;

function stableRequestHash(value: {
  operationId: string; challengeId: string; authorizationId: string; contextType: "trusted_session" | "google_bootstrap";
  trustedSessionId?: string;
  idempotencyKey: string; verificationId: string; expectedCoordinationRevision: number; expectedChallengeRevision: number;
  googleSubjectHash: string;
}): string {
  const canonical = {
    operationId: value.operationId,
    challengeId: value.challengeId,
    authorizationId: value.authorizationId,
    ...(value.trustedSessionId === undefined ? {} : { trustedSessionId: value.trustedSessionId }),
    idempotencyKey: value.idempotencyKey,
    verificationId: value.verificationId,
    expectedCoordinationRevision: value.expectedCoordinationRevision,
    expectedChallengeRevision: value.expectedChallengeRevision,
    googleSubjectHash: value.googleSubjectHash,
    ...(value.contextType === "google_bootstrap" ? { contextType: value.contextType } : {})
  };
  return createHash("sha256").update(JSON.stringify(canonical)).digest("hex");
}

export class IdentityAuthOrchestrationPersistenceService {
  constructor(
    private readonly db: Firestore,
    private readonly googleVerifier: InternalGoogleIdentityVerifier,
    private readonly identifierPepper: Buffer,
    private readonly protectedSuperAdminUid: string,
    private readonly now: () => Timestamp = () => Timestamp.now()
  ) {
    if (identifierPepper.length < 32) throw new Error("IDENTIFIER_PEPPER_TOO_SHORT");
    uidSchema.parse(protectedSuperAdminUid);
  }

  async verifyConsumeAndRecord(input: AuthOrchestrationPersistenceRequest): Promise<AuthOrchestrationPersistenceResult> {
    const request = orchestrationRequestSchema.parse(input);
    if (request.trustedAdministratorUid !== this.protectedSuperAdminUid) {
      throw new AuthOrchestrationPersistenceError("TRUSTED_CONTEXT_MISMATCH");
    }
    const coordination = await new AuthCoordinationPersistenceService(this.db, this.protectedSuperAdminUid, this.now)
      .get(request.operationId);
    if (coordination.expectedFirebaseUid === this.protectedSuperAdminUid) {
      throw new AuthOrchestrationPersistenceError("SUPER_ADMIN_FORBIDDEN");
    }
    if (coordination.expectedFirebaseUid !== coordination.expectedInternalUid
      || coordination.challengeId !== request.challengeId
      || coordination.authorizationId !== request.authorizationId) {
      throw new AuthOrchestrationPersistenceError("COORDINATION_CONTEXT_MISMATCH");
    }

    const identity = await this.googleVerifier.verify({
      idToken: request.googleIdToken,
      nonceContext: createTrustedNonceContext(request.nonce)
    });
    const googleSubjectHash = identifierKeyHash("googleSubject", identity.subject, this.identifierPepper);
    if (googleSubjectHash !== coordination.googleSubjectHash || identity.nonceVerified !== true) {
      throw new AuthOrchestrationPersistenceError("COORDINATION_CONTEXT_MISMATCH");
    }
    const evidenceTime = Timestamp.fromDate(identity.issuedAt);
    const validUntil = Timestamp.fromDate(identity.expiresAt);
    const event = createTrustedAuthCoordinationEvent({
      type: "google_proof_verified",
      operationId: request.operationId,
      idempotencyKey: request.idempotencyKey,
      expectedFirebaseUid: coordination.expectedFirebaseUid,
      expectedInternalUid: coordination.expectedInternalUid,
      googleSubjectHash,
      expectedCoordinationRevision: request.expectedCoordinationRevision,
      expectedProfileRevision: coordination.currentProfileRevision,
      verification: { verificationId: request.verificationId, verifiedBy: "google-token-verifier", googleSubjectHash,
        verifiedAt: evidenceTime, validUntil, nonceVerified: true }
    });

    return this.db.runTransaction(async (transaction) => {
      const timestamp = this.now();
      const preparedCoordination = await prepareAuthCoordinationTransition({ db: this.db, transaction,
        trustedAdministratorUid: request.trustedAdministratorUid, protectedSuperAdminUid: this.protectedSuperAdminUid,
        operationId: request.operationId, expectedRevision: request.expectedCoordinationRevision, event, now: timestamp });

      if (preparedCoordination.result.replayed) {
        const challengeSnapshot = await transaction.get(this.db.collection("identityAuthChallenges").doc(request.challengeId));
        const challenge = authChallengeDocumentSchema.safeParse(challengeSnapshot.data());
        if (!challengeSnapshot.exists || !challenge.success || challenge.data.state !== "consumed"
          || challenge.data.coordinationOperationId !== request.operationId
          || challenge.data.authorizationId !== request.authorizationId
          || (challenge.data.contextType ?? "trusted_session") !== request.contextType
          || request.contextType === "trusted_session" && challenge.data.trustedSessionId !== request.trustedSessionId
          || request.contextType === "google_bootstrap" && challenge.data.trustedSessionId !== undefined
          || challenge.data.googleSubjectHash !== googleSubjectHash) {
          throw new AuthOrchestrationPersistenceError("REPLAY_STATE_INVALID");
        }
        if (request.contextType === "google_bootstrap") {
          const current = preparedCoordination.result.document;
          const authorization = await readValidIdentityLinkAuthorization({ db: this.db, transaction,
            authorizationId: request.authorizationId,
            expected: { operationId: current.evidence.firestoreLink.linkOperationId,
              targetUid: current.expectedFirebaseUid, googleSubjectHash,
              expectedRevision: current.evidence.firestoreLink.profileRevision - 1 }, now: timestamp });
          if (authorization.authorizedByUid !== request.trustedAdministratorUid) {
            throw new AuthOrchestrationPersistenceError("AUTHORIZATION_INVALID");
          }
        }
        return Object.freeze({ operationId: request.operationId, challengeId: request.challengeId,
          coordinationRevision: preparedCoordination.result.document.revision, challengeRevision: challenge.data.revision,
          state: "google_proof_verified" as const, replayed: true, challengeConsumedAgain: false as const,
          automaticActivation: false as const });
      }

      const current = preparedCoordination.previousDocument;
      if (current.state !== "challenge_issued" || current.revision !== request.expectedCoordinationRevision
        || current.challengeId !== request.challengeId || current.authorizationId !== request.authorizationId) {
        throw new AuthOrchestrationPersistenceError("COORDINATION_CONTEXT_MISMATCH");
      }
      const profileRef = this.db.collection("users").doc(current.expectedFirebaseUid);
      const reservationRef = this.db.collection("authIdentifierKeys").doc(googleSubjectHash);
      const [profileSnapshot, reservationSnapshot] = await Promise.all([
        transaction.get(profileRef), transaction.get(reservationRef)
      ]);
      if (profileSnapshot.data()?.status === "disabled") {
        throw new AuthOrchestrationPersistenceError("PROFILE_BLOCKED");
      }
      const profile = googleWorkspaceUserV21DocumentSchema.safeParse(profileSnapshot.data());
      if (!profileSnapshot.exists || !profile.success || profile.data.uid !== current.expectedFirebaseUid
        || profile.data.status === "disabled" || profile.data.activationStatus !== "linked_pending_activation"
        || profile.data.authDisabled !== true || profile.data.googleWorkspace.linkingStatus !== "linked"
        || profile.data.googleWorkspace.subject !== identity.subject
        || profile.data.revision !== current.currentProfileRevision) {
        throw new AuthOrchestrationPersistenceError("E4_LINK_NOT_CONFIRMED");
      }
      const reservation = identityIdentifierKeyDocumentSchema.safeParse(reservationSnapshot.data());
      if (!reservationSnapshot.exists || !reservation.success || reservation.data.kind !== "googleSubject"
        || reservation.data.identifierHash !== googleSubjectHash || reservation.data.state !== "reserved"
        || reservation.data.uid !== current.expectedFirebaseUid) {
        throw new AuthOrchestrationPersistenceError("RESERVATION_CONFLICT");
      }
      let authorizationData: z.infer<typeof identityLinkAuthorizationSchema>;
      if (request.contextType === "google_bootstrap") {
        authorizationData = await readValidIdentityLinkAuthorization({ db: this.db, transaction,
          authorizationId: request.authorizationId,
          expected: { operationId: current.evidence.firestoreLink.linkOperationId,
            targetUid: current.expectedFirebaseUid, googleSubjectHash,
            expectedRevision: current.evidence.firestoreLink.profileRevision - 1 }, now: timestamp });
        if (authorizationData.authorizedByUid !== request.trustedAdministratorUid) {
          throw new AuthOrchestrationPersistenceError("AUTHORIZATION_INVALID");
        }
      } else {
        const authorizationRef = this.db.collection("identityLinkAuthorizations").doc(request.authorizationId);
        const authorizationSnapshot = await transaction.get(authorizationRef);
        const authorization = identityLinkAuthorizationSchema.safeParse(authorizationSnapshot.data());
        if (!authorizationSnapshot.exists || !authorization.success || authorization.data.state !== "consumed"
          || authorization.data.authorizationId !== request.authorizationId
          || authorization.data.operationId !== current.evidence.firestoreLink.linkOperationId
          || authorization.data.targetUid !== current.expectedFirebaseUid
          || authorization.data.googleSubjectHash !== googleSubjectHash
          || authorization.data.authorizedByUid !== request.trustedAdministratorUid
          || timestamp.toMillis() >= authorization.data.expiresAt.toMillis()) {
          throw new AuthOrchestrationPersistenceError("AUTHORIZATION_INVALID");
        }
        authorizationData = authorization.data;
      }

      const challengeContext = request.contextType === "google_bootstrap"
        ? createTrustedAuthBootstrapChallengeContext({
          contextType: "google_bootstrap",
          expectedInternalUid: current.expectedInternalUid,
          expectedFirebaseUid: current.expectedFirebaseUid,
          coordinationOperationId: request.operationId,
          authorizationId: request.authorizationId,
          nonce: request.nonce,
          state: request.state,
          expectedRevision: request.expectedChallengeRevision,
          verifiedGoogleIdentity: { subject: identity.subject, nonceVerified: true, googleSubjectHash }
        })
        : createTrustedAuthChallengeContext({
          expectedInternalUid: current.expectedInternalUid,
          expectedFirebaseUid: current.expectedFirebaseUid,
          coordinationOperationId: request.operationId,
          authorizationId: request.authorizationId,
          trustedSessionId: request.trustedSessionId!,
          nonce: request.nonce,
          state: request.state,
          expectedRevision: request.expectedChallengeRevision,
          verifiedGoogleIdentity: { subject: identity.subject, nonceVerified: true, googleSubjectHash }
        });
      const preparedChallenge = await prepareAuthChallengeConsumption({ db: this.db, transaction,
        challengeId: request.challengeId, context: challengeContext, now: timestamp });

      const requestHash = stableRequestHash({ operationId: request.operationId, challengeId: request.challengeId,
        authorizationId: request.authorizationId, contextType: request.contextType,
        ...(request.trustedSessionId === undefined ? {} : { trustedSessionId: request.trustedSessionId }),
        idempotencyKey: request.idempotencyKey, verificationId: request.verificationId,
        expectedCoordinationRevision: request.expectedCoordinationRevision,
        expectedChallengeRevision: request.expectedChallengeRevision, googleSubjectHash });
      const policyInput: AuthOrchestrationInput = {
        contextType: request.contextType,
        operationId: request.operationId,
        expectedFirebaseUid: current.expectedFirebaseUid,
        expectedInternalUid: current.expectedInternalUid,
        googleSubjectHash,
        challengeId: request.challengeId,
        authorizationId: request.authorizationId,
        ...(request.trustedSessionId === undefined ? {} : { trustedSessionId: request.trustedSessionId }),
        idempotencyKey: request.idempotencyKey,
        requestHash,
        expectedCoordinationState: "challenge_issued",
        expectedCoordinationRevision: request.expectedCoordinationRevision,
        requestedAction: "consume_challenge_and_record_google_proof",
        contextTime: timestamp,
        evidence: {
          google: createTrustedGoogleOrchestrationEvidence({ verificationId: request.verificationId,
            identity, googleSubjectHash, verifiedAt: evidenceTime }),
          challenge: createTrustedChallengeOrchestrationEvidence({
            challengeId: request.challengeId, verifiedBy: "identity-auth-challenge-service",
            operationId: request.operationId, expectedFirebaseUid: current.expectedFirebaseUid,
            expectedInternalUid: current.expectedInternalUid, authorizationId: request.authorizationId,
            contextType: request.contextType,
            ...(request.trustedSessionId === undefined ? {} : { trustedSessionId: request.trustedSessionId }),
            googleSubjectHash, status: "validated",
            revision: request.expectedChallengeRevision, validatedAt: timestamp, consumedAt: null,
            validUntil: preparedChallenge.document.expiresAt
          }),
          administrative: createTrustedAdministrativeOrchestrationEvidence({
            authorizationId: request.authorizationId, verifiedBy: "identity-link-authorization",
            operationId: request.operationId, targetUid: current.expectedFirebaseUid, googleSubjectHash,
            profileRevision: profile.data.revision, state: "authorized", profileStatus: "linked_pending_activation",
            authDisabled: true, verifiedAt: timestamp, validUntil: authorizationData.expiresAt
          }),
          coordination: createTrustedCoordinationOrchestrationEvidence({
            operationId: request.operationId, verifiedBy: "identity-auth-coordination-service",
            expectedFirebaseUid: current.expectedFirebaseUid, expectedInternalUid: current.expectedInternalUid,
            googleSubjectHash, authorizationId: request.authorizationId, challengeId: request.challengeId,
            state: current.state, revision: current.revision, conflictReason: current.conflictReason,
            lastIdempotencyKey: null, lastRequestHash: null, lastOutcome: null, observedAt: timestamp
          }),
          partialState: null
        },
        activationRequested: false,
        version: 1
      };
      const decision = evaluateAuthOrchestration(policyInput, this.protectedSuperAdminUid);
      if (decision.decision !== "proceed" || decision.nextStep !== "atomic_consume_and_record") {
        throw new AuthOrchestrationPersistenceError("POLICY_REJECTED");
      }
      preparedChallenge.apply();
      preparedCoordination.apply();
      return Object.freeze({ operationId: request.operationId, challengeId: request.challengeId,
        coordinationRevision: preparedCoordination.result.document.revision,
        challengeRevision: preparedChallenge.document.revision, state: "google_proof_verified" as const,
        replayed: false, challengeConsumedAgain: false as const, automaticActivation: false as const });
    });
  }
}
