import { Timestamp } from "firebase-admin/firestore";
import { z } from "zod";
import type { VerifiedGoogleIdentity } from "./google-token-verifier.js";
import { authCoordinationStateSchema } from "./identity-auth-coordination-contracts.js";

const uidSchema = z.string().min(1).max(128).refine((value) => !value.includes("/"));
const uuidSchema = z.string().uuid();
const hashSchema = z.string().regex(/^[a-f0-9]{64}$/);
const timestampSchema = z.instanceof(Timestamp);
const sessionSchema = z.string().min(16).max(256).regex(/^[A-Za-z0-9._~-]+$/);

export const orchestrationActionSchema = z.enum([
  "consume_challenge_and_record_google_proof",
  "prepare_firebase_provider_link",
  "confirm_firebase_provider_link"
]);

export const orchestrationPartialStateSchema = z.enum([
  "challenge_consumed_coordination_pending",
  "coordination_updated_challenge_pending",
  "authorization_revoked_during_operation",
  "reservation_owned_by_other_uid",
  "firestore_link_pending",
  "firestore_linked_firebase_auth_pending",
  "external_result_unknown",
  "postflight_pending"
]);

const googleEvidenceSchema = z.object({
  verificationId: uuidSchema,
  verifiedBy: z.literal("google-token-verifier"),
  issuerVerified: z.literal(true),
  audienceVerified: z.literal(true),
  signatureVerified: z.literal(true),
  tokenCurrent: z.literal(true),
  workspaceDomainVerified: z.literal(true),
  nonceVerified: z.literal(true),
  subject: z.string().min(1).max(255),
  googleSubjectHash: hashSchema,
  verifiedAt: timestampSchema,
  validUntil: timestampSchema
}).strict();

const challengeEvidenceSchema = z.object({
  challengeId: uuidSchema,
  verifiedBy: z.literal("identity-auth-challenge-service"),
  operationId: uuidSchema,
  expectedFirebaseUid: uidSchema,
  expectedInternalUid: uidSchema,
  authorizationId: uuidSchema,
  trustedSessionId: sessionSchema,
  googleSubjectHash: hashSchema,
  status: z.enum(["validated", "consumed"]),
  revision: z.number().int().positive(),
  validatedAt: timestampSchema,
  consumedAt: timestampSchema.nullable(),
  validUntil: timestampSchema
}).strict().superRefine((value, context) => {
  if ((value.status === "consumed") !== (value.consumedAt !== null)) {
    context.addIssue({ code: "custom", path: ["consumedAt"], message: "El consumo requiere sello inequívoco" });
  }
});

const administrativeEvidenceSchema = z.object({
  authorizationId: uuidSchema,
  verifiedBy: z.literal("identity-link-authorization"),
  operationId: uuidSchema,
  targetUid: uidSchema,
  googleSubjectHash: hashSchema,
  profileRevision: z.number().int().nonnegative(),
  state: z.enum(["authorized", "revoked", "expired"]),
  profileStatus: z.enum(["linked_pending_activation", "suspended", "reconciliation_required"]),
  authDisabled: z.literal(true),
  verifiedAt: timestampSchema,
  validUntil: timestampSchema
}).strict();

const coordinationEvidenceSchema = z.object({
  operationId: uuidSchema,
  verifiedBy: z.literal("identity-auth-coordination-service"),
  expectedFirebaseUid: uidSchema,
  expectedInternalUid: uidSchema,
  googleSubjectHash: hashSchema,
  authorizationId: uuidSchema,
  challengeId: uuidSchema,
  state: authCoordinationStateSchema,
  revision: z.number().int().positive(),
  conflictReason: z.string().min(1).max(80).nullable(),
  lastIdempotencyKey: uuidSchema.nullable(),
  lastRequestHash: hashSchema.nullable(),
  lastOutcome: z.enum(["confirmed", "pending", "blocked", "unknown", "reconciliation_required"]).nullable(),
  observedAt: timestampSchema
}).strict().superRefine((value, context) => {
  const lastValues = [value.lastIdempotencyKey, value.lastRequestHash, value.lastOutcome];
  if (lastValues.some((item) => item === null) && !lastValues.every((item) => item === null)) {
    context.addIssue({ code: "custom", path: ["lastIdempotencyKey"], message: "La evidencia idempotente debe estar completa" });
  }
});

const googleMarker: unique symbol = Symbol("trusted-google-orchestration-evidence");
const challengeMarker: unique symbol = Symbol("trusted-challenge-orchestration-evidence");
const administrativeMarker: unique symbol = Symbol("trusted-administrative-orchestration-evidence");
const coordinationMarker: unique symbol = Symbol("trusted-coordination-orchestration-evidence");

export type TrustedGoogleOrchestrationEvidence = z.infer<typeof googleEvidenceSchema> & { readonly [googleMarker]: true };
export type TrustedChallengeOrchestrationEvidence = z.infer<typeof challengeEvidenceSchema> & { readonly [challengeMarker]: true };
export type TrustedAdministrativeOrchestrationEvidence = z.infer<typeof administrativeEvidenceSchema>
  & { readonly [administrativeMarker]: true };
export type TrustedCoordinationOrchestrationEvidence = z.infer<typeof coordinationEvidenceSchema>
  & { readonly [coordinationMarker]: true };

export function createTrustedGoogleOrchestrationEvidence(input: {
  verificationId: string;
  identity: VerifiedGoogleIdentity;
  googleSubjectHash: string;
  verifiedAt: Timestamp;
}): TrustedGoogleOrchestrationEvidence {
  const value = googleEvidenceSchema.parse({
    verificationId: input.verificationId,
    verifiedBy: "google-token-verifier",
    issuerVerified: true,
    audienceVerified: true,
    signatureVerified: true,
    tokenCurrent: input.verifiedAt.toMillis() < input.identity.expiresAt.getTime(),
    workspaceDomainVerified: true,
    nonceVerified: input.identity.nonceVerified,
    subject: input.identity.subject,
    googleSubjectHash: input.googleSubjectHash,
    verifiedAt: input.verifiedAt,
    validUntil: Timestamp.fromDate(input.identity.expiresAt)
  });
  return Object.freeze({ ...value, [googleMarker]: true as const }) as TrustedGoogleOrchestrationEvidence;
}

export function createTrustedChallengeOrchestrationEvidence(input: unknown): TrustedChallengeOrchestrationEvidence {
  const value = challengeEvidenceSchema.parse(input);
  return Object.freeze({ ...value, [challengeMarker]: true as const }) as TrustedChallengeOrchestrationEvidence;
}

export function createTrustedAdministrativeOrchestrationEvidence(input: unknown): TrustedAdministrativeOrchestrationEvidence {
  const value = administrativeEvidenceSchema.parse(input);
  return Object.freeze({ ...value, [administrativeMarker]: true as const }) as TrustedAdministrativeOrchestrationEvidence;
}

export function createTrustedCoordinationOrchestrationEvidence(input: unknown): TrustedCoordinationOrchestrationEvidence {
  const value = coordinationEvidenceSchema.parse(input);
  return Object.freeze({ ...value, [coordinationMarker]: true as const }) as TrustedCoordinationOrchestrationEvidence;
}

export const authOrchestrationInputSchema = z.object({
  operationId: uuidSchema,
  expectedFirebaseUid: uidSchema,
  expectedInternalUid: uidSchema,
  googleSubjectHash: hashSchema,
  challengeId: uuidSchema,
  authorizationId: uuidSchema,
  trustedSessionId: sessionSchema,
  idempotencyKey: uuidSchema,
  requestHash: hashSchema,
  expectedCoordinationState: authCoordinationStateSchema,
  expectedCoordinationRevision: z.number().int().positive(),
  requestedAction: orchestrationActionSchema,
  contextTime: timestampSchema,
  evidence: z.object({
    google: googleEvidenceSchema.nullable(),
    challenge: challengeEvidenceSchema.nullable(),
    administrative: administrativeEvidenceSchema.nullable(),
    coordination: coordinationEvidenceSchema.nullable(),
    partialState: orchestrationPartialStateSchema.nullable()
  }).strict(),
  activationRequested: z.literal(false),
  version: z.literal(1)
}).strict();

export type AuthOrchestrationInput = Omit<z.infer<typeof authOrchestrationInputSchema>, "evidence"> & {
  evidence: {
    google: TrustedGoogleOrchestrationEvidence | null;
    challenge: TrustedChallengeOrchestrationEvidence | null;
    administrative: TrustedAdministrativeOrchestrationEvidence | null;
    coordination: TrustedCoordinationOrchestrationEvidence | null;
    partialState: z.infer<typeof orchestrationPartialStateSchema> | null;
  };
};

export function hasTrustedOrchestrationEvidence(input: AuthOrchestrationInput): boolean {
  return (input.evidence.google === null || input.evidence.google[googleMarker] === true)
    && (input.evidence.challenge === null || input.evidence.challenge[challengeMarker] === true)
    && (input.evidence.administrative === null || input.evidence.administrative[administrativeMarker] === true)
    && (input.evidence.coordination === null || input.evidence.coordination[coordinationMarker] === true);
}
