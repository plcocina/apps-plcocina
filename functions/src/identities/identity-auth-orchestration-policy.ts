import { authOrchestrationInputSchema, hasTrustedOrchestrationEvidence,
  type AuthOrchestrationInput } from "./identity-auth-orchestration-contracts.js";

export type AuthOrchestrationRejectionCode = "CONTRACT_INVALID" | "UNTRUSTED_EVIDENCE" | "EVIDENCE_MISSING"
  | "UID_MISMATCH" | "SUBJECT_MISMATCH" | "CHALLENGE_MISMATCH" | "SESSION_MISMATCH"
  | "AUTHORIZATION_MISMATCH" | "AUTHORIZATION_EXPIRED" | "AUTHORIZATION_REVOKED"
  | "GOOGLE_EVIDENCE_EXPIRED" | "CHALLENGE_EXPIRED" | "CHALLENGE_ALREADY_CONSUMED" | "CHALLENGE_NOT_CONSUMED"
  | "COORDINATION_STATE_INVALID" | "REVISION_CONFLICT" | "IDEMPOTENCY_CONFLICT"
  | "OPERATION_BLOCKED" | "SUPER_ADMIN_FORBIDDEN" | "AUTOMATIC_ACTIVATION_FORBIDDEN";

export type AuthOrchestrationDecision =
  | { decision: "proceed"; nextStep: "atomic_consume_and_record" | "prepare_firebase_provider_link"
    | "confirm_firebase_provider_link";
    requiresAtomicPersistence: true; automaticActivation: false }
  | { decision: "proceed"; nextStep: "record_consumed_challenge_result"; requiresAtomicPersistence: false;
    consumeChallengeAgain: false; automaticActivation: false }
  | { decision: "replay"; outcome: "confirmed" | "pending" | "blocked" | "unknown" | "reconciliation_required";
    consumeChallengeAgain: false }
  | { decision: "pending"; reason: "FIRESTORE_LINK_PENDING" | "FIREBASE_AUTH_PENDING" | "POSTFLIGHT_PENDING";
    retry: "observe_then_resume"; consumeChallengeAgain: false }
  | { decision: "blocked"; reason: "AUTHORIZATION_REVOKED" | "OPERATION_BLOCKED"; intervention: "administrative" }
  | { decision: "reconciliation_required"; reason: "COORDINATION_WITHOUT_CHALLENGE_CONSUMPTION"
    | "RESERVATION_UID_CONFLICT" | "EXTERNAL_RESULT_UNKNOWN"; retry: "forbidden_until_observed" }
  | { decision: "reject"; code: AuthOrchestrationRejectionCode };

const blockedStates = new Set(["provider_conflict", "auth_state_unknown", "revocation_pending",
  "reconciliation_required", "cancelled", "activation_pending", "active"]);

function reject(code: AuthOrchestrationRejectionCode): AuthOrchestrationDecision {
  return { decision: "reject", code };
}

export function evaluateAuthOrchestration(input: AuthOrchestrationInput,
  protectedSuperAdminUid: string): AuthOrchestrationDecision {
  const parsed = authOrchestrationInputSchema.safeParse(input);
  if (!parsed.success) return reject((input as { activationRequested?: unknown }).activationRequested === true
    ? "AUTOMATIC_ACTIVATION_FORBIDDEN" : "CONTRACT_INVALID");
  if (!hasTrustedOrchestrationEvidence(input)) return reject("UNTRUSTED_EVIDENCE");
  const value = parsed.data;
  const { google, challenge, administrative, coordination, partialState } = input.evidence;

  if (value.expectedFirebaseUid !== value.expectedInternalUid) return reject("UID_MISMATCH");
  if (value.expectedFirebaseUid === protectedSuperAdminUid) return reject("SUPER_ADMIN_FORBIDDEN");
  if (!google || !challenge || !administrative || !coordination) return reject("EVIDENCE_MISSING");

  if (coordination.lastIdempotencyKey === value.idempotencyKey) {
    if (coordination.lastRequestHash !== value.requestHash || coordination.lastOutcome === null) {
      return reject("IDEMPOTENCY_CONFLICT");
    }
    return { decision: "replay", outcome: coordination.lastOutcome, consumeChallengeAgain: false };
  }

  if (partialState === "coordination_updated_challenge_pending") {
    return { decision: "reconciliation_required", reason: "COORDINATION_WITHOUT_CHALLENGE_CONSUMPTION",
      retry: "forbidden_until_observed" };
  }
  if (partialState === "reservation_owned_by_other_uid") {
    return { decision: "reconciliation_required", reason: "RESERVATION_UID_CONFLICT", retry: "forbidden_until_observed" };
  }
  if (partialState === "external_result_unknown") {
    return { decision: "reconciliation_required", reason: "EXTERNAL_RESULT_UNKNOWN", retry: "forbidden_until_observed" };
  }
  if (partialState === "authorization_revoked_during_operation") {
    return { decision: "blocked", reason: "AUTHORIZATION_REVOKED", intervention: "administrative" };
  }
  if (partialState === "firestore_link_pending") {
    return { decision: "pending", reason: "FIRESTORE_LINK_PENDING", retry: "observe_then_resume", consumeChallengeAgain: false };
  }
  if (partialState === "firestore_linked_firebase_auth_pending") {
    return { decision: "pending", reason: "FIREBASE_AUTH_PENDING", retry: "observe_then_resume", consumeChallengeAgain: false };
  }
  if (partialState === "postflight_pending") {
    return { decision: "pending", reason: "POSTFLIGHT_PENDING", retry: "observe_then_resume", consumeChallengeAgain: false };
  }

  if (google.googleSubjectHash !== value.googleSubjectHash
    || administrative.googleSubjectHash !== value.googleSubjectHash
    || challenge.googleSubjectHash !== value.googleSubjectHash
    || coordination.googleSubjectHash !== value.googleSubjectHash) return reject("SUBJECT_MISMATCH");
  if (challenge.challengeId !== value.challengeId || coordination.challengeId !== value.challengeId
    || challenge.operationId !== value.operationId) return reject("CHALLENGE_MISMATCH");
  if (challenge.trustedSessionId !== value.trustedSessionId) return reject("SESSION_MISMATCH");
  if ([challenge.expectedFirebaseUid, challenge.expectedInternalUid, administrative.targetUid,
    coordination.expectedFirebaseUid, coordination.expectedInternalUid].some((uid) => uid !== value.expectedFirebaseUid)) {
    return reject("UID_MISMATCH");
  }
  if (administrative.authorizationId !== value.authorizationId || challenge.authorizationId !== value.authorizationId
    || coordination.authorizationId !== value.authorizationId || administrative.operationId !== value.operationId
    || coordination.operationId !== value.operationId) return reject("AUTHORIZATION_MISMATCH");
  if (administrative.state === "revoked") return reject("AUTHORIZATION_REVOKED");
  if (administrative.state === "expired" || value.contextTime.toMillis() >= administrative.validUntil.toMillis()) {
    return reject("AUTHORIZATION_EXPIRED");
  }
  if (administrative.profileStatus === "suspended" || administrative.profileStatus === "reconciliation_required") {
    return { decision: "blocked", reason: "OPERATION_BLOCKED", intervention: "administrative" };
  }
  if (value.contextTime.toMillis() >= google.validUntil.toMillis()) return reject("GOOGLE_EVIDENCE_EXPIRED");
  if (value.contextTime.toMillis() >= challenge.validUntil.toMillis()) return reject("CHALLENGE_EXPIRED");
  if (coordination.revision !== value.expectedCoordinationRevision) return reject("REVISION_CONFLICT");
  if (coordination.state !== value.expectedCoordinationState) return reject("COORDINATION_STATE_INVALID");
  if (blockedStates.has(coordination.state) || coordination.conflictReason !== null) {
    return { decision: "blocked", reason: "OPERATION_BLOCKED", intervention: "administrative" };
  }

  if (value.requestedAction === "consume_challenge_and_record_google_proof") {
    if (coordination.state !== "challenge_issued") return reject("COORDINATION_STATE_INVALID");
    if (challenge.status === "consumed" && partialState === "challenge_consumed_coordination_pending") {
      return { decision: "proceed", nextStep: "record_consumed_challenge_result", requiresAtomicPersistence: false,
        consumeChallengeAgain: false, automaticActivation: false };
    }
    if (challenge.status === "consumed" && partialState !== "challenge_consumed_coordination_pending") {
      return reject("CHALLENGE_ALREADY_CONSUMED");
    }
    return { decision: "proceed", nextStep: "atomic_consume_and_record", requiresAtomicPersistence: true,
      automaticActivation: false };
  }
  if (challenge.status !== "consumed") return reject("CHALLENGE_NOT_CONSUMED");
  if (value.requestedAction === "prepare_firebase_provider_link") {
    if (coordination.state !== "google_proof_verified") return reject("COORDINATION_STATE_INVALID");
    return { decision: "proceed", nextStep: "prepare_firebase_provider_link", requiresAtomicPersistence: true,
      automaticActivation: false };
  }
  if (coordination.state !== "provider_link_pending") return reject("COORDINATION_STATE_INVALID");
  return { decision: "proceed", nextStep: "confirm_firebase_provider_link", requiresAtomicPersistence: true,
    automaticActivation: false };
}
