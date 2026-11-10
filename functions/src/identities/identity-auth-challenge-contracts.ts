import { Timestamp } from "firebase-admin/firestore";
import { z } from "zod";
import type { VerifiedGoogleIdentity } from "./google-token-verifier.js";
import { verifyAuthChallengeSecret } from "./identity-auth-challenge-crypto.js";

const uidSchema = z.string().min(1).max(128).refine((value) => !value.includes("/"));
const uuidSchema = z.string().uuid();
const hashSchema = z.string().regex(/^[a-f0-9]{64}$/);
const timestampSchema = z.instanceof(Timestamp);
const trustedSessionIdSchema = z.string().min(16).max(256).regex(/^[A-Za-z0-9._~-]+$/);
const MAX_CHALLENGE_LIFETIME_MS = 15 * 60 * 1000;

export const authChallengeStateSchema = z.enum(["issued", "consumed", "expired", "revoked"]);
export const authChallengeContextTypeSchema = z.enum(["trusted_session", "google_bootstrap"]);

export const authChallengeDocumentSchema = z.object({
  challengeId: uuidSchema,
  expectedInternalUid: uidSchema,
  expectedFirebaseUid: uidSchema,
  coordinationOperationId: uuidSchema,
  authorizationId: uuidSchema,
  googleSubjectHash: hashSchema.nullable(),
  contextType: authChallengeContextTypeSchema.optional(),
  trustedSessionId: trustedSessionIdSchema.optional(),
  nonceHash: hashSchema,
  stateHash: hashSchema,
  issuedAt: timestampSchema,
  expiresAt: timestampSchema,
  state: authChallengeStateSchema,
  stateChangedAt: timestampSchema.nullable(),
  revision: z.number().int().positive(),
  version: z.literal(1)
}).strict().superRefine((challenge, context) => {
  const contextType = challenge.contextType ?? "trusted_session";
  if (contextType === "trusted_session" && !challenge.trustedSessionId) {
    context.addIssue({ code: "custom", path: ["trustedSessionId"], message: "trusted_session requiere sesión" });
  }
  if (contextType === "google_bootstrap" && challenge.trustedSessionId !== undefined) {
    context.addIssue({ code: "custom", path: ["trustedSessionId"], message: "google_bootstrap no admite sesión Firebase" });
  }
  if (challenge.expectedInternalUid !== challenge.expectedFirebaseUid) {
    context.addIssue({ code: "custom", path: ["expectedFirebaseUid"], message: "Los UID interno y Firebase deben coincidir" });
  }
  const lifetime = challenge.expiresAt.toMillis() - challenge.issuedAt.toMillis();
  if (lifetime <= 0 || lifetime > MAX_CHALLENGE_LIFETIME_MS) {
    context.addIssue({ code: "custom", path: ["expiresAt"], message: "La vigencia debe ser positiva y acotada" });
  }
  if ((challenge.state === "issued") !== (challenge.stateChangedAt === null)) {
    context.addIssue({ code: "custom", path: ["stateChangedAt"], message: "Sólo un challenge issued carece de sello de transición" });
  }
  if (challenge.stateChangedAt && challenge.stateChangedAt.toMillis() < challenge.issuedAt.toMillis()) {
    context.addIssue({ code: "custom", path: ["stateChangedAt"], message: "La transición no puede anteceder a la emisión" });
  }
});

export type VerifiedGoogleChallengeBinding = Readonly<Pick<VerifiedGoogleIdentity, "subject" | "nonceVerified"> & {
  googleSubjectHash: string;
}>;

const trustedContextSchema = z.object({
  expectedInternalUid: uidSchema,
  expectedFirebaseUid: uidSchema,
  coordinationOperationId: uuidSchema,
  authorizationId: uuidSchema,
  contextType: z.literal("trusted_session").optional(),
  trustedSessionId: trustedSessionIdSchema,
  nonce: z.string(),
  state: z.string(),
  expectedRevision: z.number().int().positive(),
  verifiedGoogleIdentity: z.object({
    subject: z.string().min(1).max(255),
    nonceVerified: z.literal(true),
    googleSubjectHash: hashSchema
  }).strict().nullable()
}).strict();

const trustedContextMarker: unique symbol = Symbol("trusted-auth-challenge-context");
export type AuthChallengeTrustedContext = z.infer<typeof trustedContextSchema> & { readonly [trustedContextMarker]: true };

export function createTrustedAuthChallengeContext(input: unknown): AuthChallengeTrustedContext {
  const context = trustedContextSchema.parse(input);
  if (context.expectedInternalUid !== context.expectedFirebaseUid) {
    throw new AuthChallengeValidationError("UID_MISMATCH");
  }
  return Object.freeze({ ...context, [trustedContextMarker]: true as const }) as AuthChallengeTrustedContext;
}

export type AuthChallengeValidationErrorCode = "UNTRUSTED_CONTEXT" | "CHALLENGE_EXPIRED" | "CHALLENGE_REVOKED"
  | "CHALLENGE_CONSUMED" | "REPLAY_DETECTED" | "UID_MISMATCH" | "OPERATION_MISMATCH"
  | "AUTHORIZATION_MISMATCH" | "SESSION_MISMATCH" | "NONCE_MISMATCH" | "STATE_MISMATCH"
  | "REVISION_CONFLICT" | "SUBJECT_MISMATCH" | "GOOGLE_PROOF_REQUIRED" | "CONTEXT_TYPE_MISMATCH";

export class AuthChallengeValidationError extends Error {
  constructor(readonly code: AuthChallengeValidationErrorCode) {
    super("Auth challenge validation rejected");
    this.name = "AuthChallengeValidationError";
  }
}

export type AuthChallengeValidationResult = Readonly<{
  decision: "valid";
  challengeId: string;
  revision: number;
  nonceVerified: true;
  stateVerified: true;
  consumed: false;
}>;

export function evaluateAuthChallenge(input: {
  challenge: unknown;
  context: AuthChallengeTrustedContext;
  now: Timestamp;
}): AuthChallengeValidationResult {
  const challenge = authChallengeDocumentSchema.parse(input.challenge);
  if (input.context[trustedContextMarker] !== true) throw new AuthChallengeValidationError("UNTRUSTED_CONTEXT");
  const context = input.context;
  if (challenge.state === "consumed") throw new AuthChallengeValidationError("REPLAY_DETECTED");
  if (challenge.state === "revoked") throw new AuthChallengeValidationError("CHALLENGE_REVOKED");
  if (challenge.state === "expired" || input.now.toMillis() >= challenge.expiresAt.toMillis()) {
    throw new AuthChallengeValidationError("CHALLENGE_EXPIRED");
  }
  if (context.expectedInternalUid !== challenge.expectedInternalUid
    || context.expectedFirebaseUid !== challenge.expectedFirebaseUid) throw new AuthChallengeValidationError("UID_MISMATCH");
  if (context.coordinationOperationId !== challenge.coordinationOperationId) {
    throw new AuthChallengeValidationError("OPERATION_MISMATCH");
  }
  if (context.authorizationId !== challenge.authorizationId) throw new AuthChallengeValidationError("AUTHORIZATION_MISMATCH");
  if ((challenge.contextType ?? "trusted_session") !== "trusted_session") {
    throw new AuthChallengeValidationError("CONTEXT_TYPE_MISMATCH");
  }
  if (context.trustedSessionId !== challenge.trustedSessionId) throw new AuthChallengeValidationError("SESSION_MISMATCH");
  if (context.expectedRevision !== challenge.revision) throw new AuthChallengeValidationError("REVISION_CONFLICT");
  if (!verifyAuthChallengeSecret(context.nonce, challenge.nonceHash)) throw new AuthChallengeValidationError("NONCE_MISMATCH");
  if (!verifyAuthChallengeSecret(context.state, challenge.stateHash)) throw new AuthChallengeValidationError("STATE_MISMATCH");
  if (challenge.googleSubjectHash !== null) {
    if (!context.verifiedGoogleIdentity) throw new AuthChallengeValidationError("GOOGLE_PROOF_REQUIRED");
    if (!context.verifiedGoogleIdentity.nonceVerified
      || context.verifiedGoogleIdentity.googleSubjectHash !== challenge.googleSubjectHash) {
      throw new AuthChallengeValidationError("SUBJECT_MISMATCH");
    }
  }
  return Object.freeze({ decision: "valid", challengeId: challenge.challengeId, revision: challenge.revision,
    nonceVerified: true, stateVerified: true, consumed: false });
}

export type AuthChallengeDocument = z.infer<typeof authChallengeDocumentSchema>;
export type AuthChallengeState = z.infer<typeof authChallengeStateSchema>;
