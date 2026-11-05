import { Timestamp } from "firebase-admin/firestore";
import { z } from "zod";

const uidSchema = z.string().min(1).max(128).refine((value) => !value.includes("/"));
const uuidSchema = z.string().uuid();
const hashSchema = z.string().regex(/^[a-f0-9]{64}$/);
const timestampSchema = z.instanceof(Timestamp);

export const authCoordinationStateSchema = z.enum([
  "not_started",
  "challenge_issued",
  "google_proof_verified",
  "provider_link_pending",
  "provider_link_confirmed",
  "activation_pending",
  "active",
  "provider_conflict",
  "auth_state_unknown",
  "revocation_pending",
  "reconciliation_required",
  "cancelled"
]);

export const authCoordinationConflictReasonSchema = z.enum([
  "UID_MISMATCH",
  "SUBJECT_MISMATCH",
  "PROVIDER_CREDENTIAL_IN_USE",
  "AUTHORIZATION_REVOKED",
  "USER_SUSPENDED",
  "CHALLENGE_EXPIRED",
  "POSTFLIGHT_FAILED",
  "PROVIDER_RESULT_UNKNOWN",
  "FIRESTORE_INCONSISTENT",
  "REVISION_CONFLICT"
]);

export const authorizationValidatedEvidenceSchema = z.object({
  authorizationId: uuidSchema,
  operation: z.literal("google.identity_link"),
  validatedBy: z.literal("identity-link-authorization"),
  validatedAt: timestampSchema,
  validUntil: timestampSchema
}).strict().superRefine((evidence, context) => {
  if (evidence.validUntil.toMillis() <= evidence.validatedAt.toMillis()) {
    context.addIssue({ code: "custom", path: ["validUntil"], message: "La autorización requiere vigencia positiva" });
  }
});

export const firestoreLinkedEvidenceSchema = z.object({
  linkOperationId: uuidSchema,
  observedBy: z.literal("identity-linking-service"),
  linkedAt: timestampSchema,
  profileRevision: z.number().int().positive(),
  activationStatus: z.literal("linked_pending_activation"),
  authDisabled: z.literal(true)
}).strict();

export const challengeEvidenceSchema = z.object({
  challengeId: uuidSchema,
  issuedBy: z.literal("identity-challenge-service"),
  issuedAt: timestampSchema,
  expiresAt: timestampSchema
}).strict().superRefine((evidence, context) => {
  if (evidence.expiresAt.toMillis() <= evidence.issuedAt.toMillis()) {
    context.addIssue({ code: "custom", path: ["expiresAt"], message: "El desafío requiere vigencia positiva" });
  }
});

export const googleVerificationEvidenceSchema = z.object({
  verificationId: uuidSchema,
  verifiedBy: z.literal("google-token-verifier"),
  googleSubjectHash: hashSchema,
  verifiedAt: timestampSchema,
  validUntil: timestampSchema,
  nonceVerified: z.literal(true)
}).strict().superRefine((evidence, context) => {
  if (evidence.validUntil.toMillis() <= evidence.verifiedAt.toMillis()) {
    context.addIssue({ code: "custom", path: ["validUntil"], message: "La evidencia Google requiere vigencia positiva" });
  }
});

export const firebaseSessionEvidenceSchema = z.object({
  sessionVerificationId: uuidSchema,
  verifiedBy: z.literal("firebase-session-verifier"),
  firebaseUid: uidSchema,
  verifiedAt: timestampSchema,
  authTime: timestampSchema,
  revoked: z.literal(false),
  disabled: z.literal(false)
}).strict();

export const firebaseProviderObservationSchema = z.object({
  observationId: uuidSchema,
  observedBy: z.literal("firebase-admin-postflight"),
  firebaseUid: uidSchema,
  providerId: z.literal("google.com"),
  providerUidHash: hashSchema,
  observedAt: timestampSchema
}).strict();

export const postflightEvidenceSchema = z.object({
  postflightId: uuidSchema,
  verifiedBy: z.literal("firebase-admin-postflight"),
  firebaseUid: uidSchema,
  providerUidHash: hashSchema,
  authRecordDisabled: z.boolean(),
  verifiedAt: timestampSchema
}).strict();

export const authCoordinationEvidenceSchema = z.object({
  authorization: authorizationValidatedEvidenceSchema,
  firestoreLink: firestoreLinkedEvidenceSchema,
  challenge: challengeEvidenceSchema.nullable(),
  googleVerification: googleVerificationEvidenceSchema.nullable(),
  firebaseSession: firebaseSessionEvidenceSchema.nullable(),
  firebaseProvider: firebaseProviderObservationSchema.nullable(),
  postflight: postflightEvidenceSchema.nullable()
}).strict();

export const authCoordinationLastEventSchema = z.object({
  eventType: z.string().min(1).max(80),
  idempotencyKey: uuidSchema,
  inputHash: hashSchema,
  resultingState: authCoordinationStateSchema,
  resultingRevision: z.number().int().positive()
}).strict();

export const authCoordinationDocumentSchema = z.object({
  operationId: uuidSchema,
  operation: z.literal("google.firebase_provider_link"),
  expectedFirebaseUid: uidSchema,
  expectedInternalUid: uidSchema,
  googleSubjectHash: hashSchema,
  state: authCoordinationStateSchema,
  expectedProfileRevision: z.number().int().positive(),
  currentProfileRevision: z.number().int().positive(),
  idempotencyKey: uuidSchema,
  authorizationId: uuidSchema,
  challengeId: uuidSchema.nullable(),
  evidence: authCoordinationEvidenceSchema,
  conflictReason: authCoordinationConflictReasonSchema.nullable(),
  revision: z.number().int().positive(),
  lastEvent: authCoordinationLastEventSchema.nullable(),
  createdAt: timestampSchema,
  updatedAt: timestampSchema,
  expiresAt: timestampSchema,
  localActivationStatus: z.literal("linked_pending_activation"),
  localAuthDisabled: z.literal(true),
  version: z.literal(1)
}).strict().superRefine((document, context) => {
  if (document.expectedFirebaseUid !== document.expectedInternalUid) {
    context.addIssue({ code: "custom", path: ["expectedInternalUid"], message: "Los UID Firebase e interno deben coincidir" });
  }
  if (document.authorizationId !== document.evidence.authorization.authorizationId) {
    context.addIssue({ code: "custom", path: ["authorizationId"], message: "La referencia de autorización no coincide" });
  }
  if (document.currentProfileRevision !== document.expectedProfileRevision
    || document.evidence.firestoreLink.profileRevision !== document.currentProfileRevision) {
    context.addIssue({ code: "custom", path: ["currentProfileRevision"], message: "La revisión debe coincidir con el vínculo Firestore" });
  }
  if ((document.challengeId === null) !== (document.evidence.challenge === null)) {
    context.addIssue({ code: "custom", path: ["challengeId"], message: "La referencia y evidencia de desafío deben existir juntas" });
  }
  if (document.challengeId !== null && document.evidence.challenge?.challengeId !== document.challengeId) {
    context.addIssue({ code: "custom", path: ["challengeId"], message: "El desafío no coincide" });
  }
  if (document.evidence.googleVerification
    && document.evidence.googleVerification.googleSubjectHash !== document.googleSubjectHash) {
    context.addIssue({ code: "custom", path: ["googleSubjectHash"], message: "La prueba Google pertenece a otro subject" });
  }
  for (const uid of [
    document.evidence.firebaseSession?.firebaseUid,
    document.evidence.firebaseProvider?.firebaseUid,
    document.evidence.postflight?.firebaseUid
  ]) {
    if (uid !== undefined && uid !== document.expectedFirebaseUid) {
      context.addIssue({ code: "custom", path: ["expectedFirebaseUid"], message: "La evidencia Firebase pertenece a otro UID" });
    }
  }
  for (const hash of [document.evidence.firebaseProvider?.providerUidHash, document.evidence.postflight?.providerUidHash]) {
    if (hash !== undefined && hash !== document.googleSubjectHash) {
      context.addIssue({ code: "custom", path: ["googleSubjectHash"], message: "La evidencia del provider pertenece a otro subject" });
    }
  }
  if (document.expiresAt.toMillis() <= document.createdAt.toMillis()
    || document.updatedAt.toMillis() < document.createdAt.toMillis()) {
    context.addIssue({ code: "custom", path: ["expiresAt"], message: "Las marcas temporales son inconsistentes" });
  }
  const blocked = new Set(["provider_conflict", "auth_state_unknown", "revocation_pending", "reconciliation_required", "cancelled"]);
  if (blocked.has(document.state) !== (document.conflictReason !== null)) {
    context.addIssue({ code: "custom", path: ["conflictReason"], message: "Sólo un estado bloqueado requiere motivo" });
  }
  if (document.state === "active") {
    context.addIssue({ code: "custom", path: ["state"], message: "E5B1 no representa activación completada" });
  }
});

const eventBindingSchema = z.object({
  operationId: uuidSchema,
  idempotencyKey: uuidSchema,
  expectedFirebaseUid: uidSchema,
  expectedInternalUid: uidSchema,
  googleSubjectHash: hashSchema,
  expectedCoordinationRevision: z.number().int().positive(),
  expectedProfileRevision: z.number().int().positive()
}).strict();

export const authCoordinationEventSchema = z.discriminatedUnion("type", [
  eventBindingSchema.extend({ type: z.literal("challenge_issued"), challenge: challengeEvidenceSchema }).strict(),
  eventBindingSchema.extend({ type: z.literal("google_proof_verified"), verification: googleVerificationEvidenceSchema }).strict(),
  eventBindingSchema.extend({ type: z.literal("provider_link_requested"), session: firebaseSessionEvidenceSchema }).strict(),
  eventBindingSchema.extend({
    type: z.literal("postflight_verified"),
    provider: firebaseProviderObservationSchema,
    postflight: postflightEvidenceSchema
  }).strict(),
  eventBindingSchema.extend({ type: z.literal("activation_prepared") }).strict(),
  eventBindingSchema.extend({ type: z.literal("activation_completed") }).strict(),
  eventBindingSchema.extend({ type: z.literal("authorization_revoked") }).strict(),
  eventBindingSchema.extend({ type: z.literal("user_suspended") }).strict(),
  eventBindingSchema.extend({ type: z.literal("challenge_expired") }).strict(),
  eventBindingSchema.extend({ type: z.literal("provider_credential_conflict") }).strict(),
  eventBindingSchema.extend({ type: z.literal("provider_result_unknown") }).strict(),
  eventBindingSchema.extend({ type: z.literal("firestore_inconsistent") }).strict(),
  eventBindingSchema.extend({ type: z.literal("postflight_failed") }).strict()
]);

const trustedEventMarker: unique symbol = Symbol("trusted-auth-coordination-event");
export type AuthCoordinationEvent = z.infer<typeof authCoordinationEventSchema>;
export type TrustedAuthCoordinationEvent = AuthCoordinationEvent & { readonly [trustedEventMarker]: true };

export function createTrustedAuthCoordinationEvent(input: unknown): TrustedAuthCoordinationEvent {
  const event = authCoordinationEventSchema.parse(input);
  return Object.freeze({ ...event, [trustedEventMarker]: true as const }) as TrustedAuthCoordinationEvent;
}

export function isTrustedAuthCoordinationEvent(event: TrustedAuthCoordinationEvent): boolean {
  return event[trustedEventMarker] === true;
}

export type AuthCoordinationState = z.infer<typeof authCoordinationStateSchema>;
export type AuthCoordinationConflictReason = z.infer<typeof authCoordinationConflictReasonSchema>;
export type AuthCoordinationDocument = z.infer<typeof authCoordinationDocumentSchema>;
