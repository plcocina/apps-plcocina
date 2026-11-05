import { createHash } from "node:crypto";
import { Timestamp } from "firebase-admin/firestore";
import {
  authCoordinationDocumentSchema,
  isTrustedAuthCoordinationEvent,
  type AuthCoordinationConflictReason,
  type AuthCoordinationDocument,
  type AuthCoordinationEvent,
  type AuthCoordinationState,
  type TrustedAuthCoordinationEvent
} from "./identity-auth-coordination-contracts.js";

export type AuthCoordinationTransitionErrorCode =
  | "UNTRUSTED_EVIDENCE"
  | "SUPER_ADMIN_FORBIDDEN"
  | "UID_MISMATCH"
  | "SUBJECT_MISMATCH"
  | "REVISION_CONFLICT"
  | "IDEMPOTENCY_CONFLICT"
  | "EVENT_OUT_OF_ORDER"
  | "OPERATION_BLOCKED"
  | "OPERATION_EXPIRED"
  | "AUTHORIZATION_EXPIRED"
  | "CHALLENGE_EXPIRED"
  | "GOOGLE_PROOF_EXPIRED"
  | "ACTIVATION_OUT_OF_SCOPE";

export class AuthCoordinationTransitionError extends Error {
  constructor(readonly code: AuthCoordinationTransitionErrorCode) {
    super("Auth coordination transition rejected");
    this.name = "AuthCoordinationTransitionError";
  }
}

export type AuthCoordinationTransitionResult = {
  decision: "transition" | "replay";
  document: AuthCoordinationDocument;
  replayed: boolean;
};

const normalTransitions: Readonly<Record<string, { from: AuthCoordinationState; to: AuthCoordinationState }>> = {
  challenge_issued: { from: "not_started", to: "challenge_issued" },
  google_proof_verified: { from: "challenge_issued", to: "google_proof_verified" },
  provider_link_requested: { from: "google_proof_verified", to: "provider_link_pending" },
  postflight_verified: { from: "provider_link_pending", to: "provider_link_confirmed" },
  activation_prepared: { from: "provider_link_confirmed", to: "activation_pending" }
};

const blockedStates = new Set<AuthCoordinationState>([
  "provider_conflict", "auth_state_unknown", "revocation_pending", "reconciliation_required", "cancelled"
]);

function canonical(value: unknown): unknown {
  if (value instanceof Timestamp) return { seconds: value.seconds, nanoseconds: value.nanoseconds };
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => [key, canonical(item)]));
  }
  return value;
}

function eventHash(event: AuthCoordinationEvent): string {
  return createHash("sha256").update(JSON.stringify(canonical(event))).digest("hex");
}

function eventConflict(event: AuthCoordinationEvent): { state: AuthCoordinationState; reason: AuthCoordinationConflictReason } | null {
  switch (event.type) {
    case "authorization_revoked": return { state: "cancelled", reason: "AUTHORIZATION_REVOKED" };
    case "user_suspended": return { state: "revocation_pending", reason: "USER_SUSPENDED" };
    case "challenge_expired": return { state: "cancelled", reason: "CHALLENGE_EXPIRED" };
    case "provider_credential_conflict": return { state: "provider_conflict", reason: "PROVIDER_CREDENTIAL_IN_USE" };
    case "provider_result_unknown": return { state: "auth_state_unknown", reason: "PROVIDER_RESULT_UNKNOWN" };
    case "firestore_inconsistent": return { state: "reconciliation_required", reason: "FIRESTORE_INCONSISTENT" };
    case "postflight_failed": return { state: "reconciliation_required", reason: "POSTFLIGHT_FAILED" };
    default: return null;
  }
}

export function evaluateAuthCoordinationTransition(input: {
  document: unknown;
  event: TrustedAuthCoordinationEvent;
  now: Timestamp;
  protectedSuperAdminUid: string;
}): AuthCoordinationTransitionResult {
  const document = authCoordinationDocumentSchema.parse(input.document);
  if (!isTrustedAuthCoordinationEvent(input.event)) throw new AuthCoordinationTransitionError("UNTRUSTED_EVIDENCE");
  const event = input.event;

  if (document.expectedInternalUid === input.protectedSuperAdminUid) {
    throw new AuthCoordinationTransitionError("SUPER_ADMIN_FORBIDDEN");
  }
  if (event.operationId !== document.operationId
    || event.expectedFirebaseUid !== document.expectedFirebaseUid
    || event.expectedInternalUid !== document.expectedInternalUid
    || event.expectedFirebaseUid !== event.expectedInternalUid) {
    throw new AuthCoordinationTransitionError("UID_MISMATCH");
  }
  if (event.googleSubjectHash !== document.googleSubjectHash) {
    throw new AuthCoordinationTransitionError("SUBJECT_MISMATCH");
  }

  const inputHash = eventHash(event);
  if (document.lastEvent?.idempotencyKey === event.idempotencyKey) {
    if (document.lastEvent.inputHash !== inputHash || document.lastEvent.eventType !== event.type) {
      throw new AuthCoordinationTransitionError("IDEMPOTENCY_CONFLICT");
    }
    return { decision: "replay", document, replayed: true };
  }
  if (event.idempotencyKey === document.idempotencyKey) {
    throw new AuthCoordinationTransitionError("IDEMPOTENCY_CONFLICT");
  }
  if (event.expectedCoordinationRevision !== document.revision
    || event.expectedProfileRevision !== document.currentProfileRevision) {
    throw new AuthCoordinationTransitionError("REVISION_CONFLICT");
  }
  if (document.state === "active" || event.type === "activation_completed") {
    throw new AuthCoordinationTransitionError("ACTIVATION_OUT_OF_SCOPE");
  }
  if (blockedStates.has(document.state) || document.state === "activation_pending") {
    throw new AuthCoordinationTransitionError("OPERATION_BLOCKED");
  }
  if (input.now.toMillis() >= document.expiresAt.toMillis()) {
    throw new AuthCoordinationTransitionError("OPERATION_EXPIRED");
  }

  const conflict = eventConflict(event);
  let nextState: AuthCoordinationState;
  let conflictReason: AuthCoordinationConflictReason | null = null;
  if (conflict) {
    nextState = conflict.state;
    conflictReason = conflict.reason;
  } else {
    const transition = normalTransitions[event.type];
    if (!transition || transition.from !== document.state) {
      throw new AuthCoordinationTransitionError("EVENT_OUT_OF_ORDER");
    }
    nextState = transition.to;
  }

  if (input.now.toMillis() >= document.evidence.authorization.validUntil.toMillis()) {
    throw new AuthCoordinationTransitionError("AUTHORIZATION_EXPIRED");
  }

  const evidence = { ...document.evidence };
  let challengeId = document.challengeId;
  if (event.type === "challenge_issued") {
    if (input.now.toMillis() >= event.challenge.expiresAt.toMillis()) throw new AuthCoordinationTransitionError("CHALLENGE_EXPIRED");
    evidence.challenge = event.challenge;
    challengeId = event.challenge.challengeId;
  }
  if (event.type === "google_proof_verified") {
    if (!document.evidence.challenge || input.now.toMillis() >= document.evidence.challenge.expiresAt.toMillis()) {
      throw new AuthCoordinationTransitionError("CHALLENGE_EXPIRED");
    }
    if (event.verification.googleSubjectHash !== document.googleSubjectHash) {
      throw new AuthCoordinationTransitionError("SUBJECT_MISMATCH");
    }
    if (input.now.toMillis() >= event.verification.validUntil.toMillis()) {
      throw new AuthCoordinationTransitionError("GOOGLE_PROOF_EXPIRED");
    }
    evidence.googleVerification = event.verification;
  }
  if (event.type === "provider_link_requested") {
    if (!document.evidence.googleVerification
      || input.now.toMillis() >= document.evidence.googleVerification.validUntil.toMillis()) {
      throw new AuthCoordinationTransitionError("GOOGLE_PROOF_EXPIRED");
    }
    if (event.session.firebaseUid !== document.expectedFirebaseUid) throw new AuthCoordinationTransitionError("UID_MISMATCH");
    evidence.firebaseSession = event.session;
  }
  if (event.type === "postflight_verified") {
    if (event.provider.firebaseUid !== document.expectedFirebaseUid
      || event.postflight.firebaseUid !== document.expectedFirebaseUid) {
      throw new AuthCoordinationTransitionError("UID_MISMATCH");
    }
    if (event.provider.providerUidHash !== document.googleSubjectHash
      || event.postflight.providerUidHash !== document.googleSubjectHash) {
      throw new AuthCoordinationTransitionError("SUBJECT_MISMATCH");
    }
    evidence.firebaseProvider = event.provider;
    evidence.postflight = event.postflight;
  }

  const revision = document.revision + 1;
  const next = authCoordinationDocumentSchema.parse({
    ...document,
    state: nextState,
    challengeId,
    evidence,
    conflictReason,
    revision,
    lastEvent: {
      eventType: event.type,
      idempotencyKey: event.idempotencyKey,
      inputHash,
      resultingState: nextState,
      resultingRevision: revision
    },
    updatedAt: input.now
  });
  return { decision: "transition", document: next, replayed: false };
}
