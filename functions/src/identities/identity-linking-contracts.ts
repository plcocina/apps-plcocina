import { Timestamp } from "firebase-admin/firestore";
import { z } from "zod";

const uidSchema = z.string().min(1).max(128).refine((value) => !value.includes("/"));
const uuidSchema = z.string().uuid();
const subjectHashSchema = z.string().regex(/^[a-f0-9]{64}$/);
const timestampSchema = z.instanceof(Timestamp);
const MAX_AUTHORIZATION_LIFETIME_MS = 15 * 60 * 1000;

export const identityLinkAuthorizationStateSchema = z.enum([
  "pending",
  "consumed",
  "revoked",
  "expired"
]);

export const identityLinkAuthorizationSchema = z.object({
  authorizationId: uuidSchema,
  operation: z.literal("google.identity_link"),
  operationId: uuidSchema,
  idempotencyKey: uuidSchema,
  targetUid: uidSchema,
  googleSubjectHash: subjectHashSchema,
  authorizedByUid: uidSchema,
  expectedRevision: z.number().int().nonnegative(),
  reason: z.string().trim().min(3).max(500),
  issuedAt: timestampSchema,
  expiresAt: timestampSchema,
  state: identityLinkAuthorizationStateSchema,
  stateChangedAt: timestampSchema.nullable(),
  version: z.literal(1)
}).strict().superRefine((authorization, context) => {
  const lifetime = authorization.expiresAt.toMillis() - authorization.issuedAt.toMillis();
  if (lifetime <= 0 || lifetime > MAX_AUTHORIZATION_LIFETIME_MS) {
    context.addIssue({ code: "custom", path: ["expiresAt"], message: "La autorización debe tener una vigencia positiva y acotada" });
  }
  if ((authorization.state === "pending") !== (authorization.stateChangedAt === null)) {
    context.addIssue({ code: "custom", path: ["stateChangedAt"], message: "Sólo una autorización pendiente carece de sello de transición" });
  }
});

export const linkGoogleIdentityRequestSchema = z.object({
  authorizationId: uuidSchema,
  operation: z.literal("google.identity_link"),
  operationId: uuidSchema,
  idempotencyKey: uuidSchema,
  targetUid: uidSchema,
  googleSubjectHash: subjectHashSchema,
  expectedRevision: z.number().int().nonnegative(),
  requestedActivationStatus: z.literal("linked_pending_activation")
}).strict();

export const completedIdentityLinkOperationSchema = linkGoogleIdentityRequestSchema.extend({
  status: z.literal("completed"),
  resultingRevision: z.number().int().positive()
}).strict();

export type IdentityLinkAuthorization = z.infer<typeof identityLinkAuthorizationSchema>;
export type LinkGoogleIdentityRequest = z.infer<typeof linkGoogleIdentityRequestSchema>;
export type CompletedIdentityLinkOperation = z.infer<typeof completedIdentityLinkOperationSchema>;

export type IdentityLinkingDecision =
  | {
    decision: "link";
    uid: string;
    googleSubjectHash: string;
    nextLinkingStatus: "linked";
    nextActivationStatus: "linked_pending_activation";
    nextAuthDisabled: true;
    nextRevision: number;
    replayed: false;
  }
  | {
    decision: "replay";
    uid: string;
    googleSubjectHash: string;
    nextLinkingStatus: "linked";
    nextActivationStatus: "linked_pending_activation";
    nextAuthDisabled: true;
    nextRevision: number;
    replayed: true;
  }
  | {
    decision: "reconciliation_required";
    uid: string;
    googleSubjectHash: string;
    reason: "RESERVATION_MISSING" | "RESERVATION_UID_CONFLICT";
    replayed: false;
  };

export type IdentityLinkingErrorCode =
  | "AUTHORIZATION_EXPIRED"
  | "AUTHORIZATION_REVOKED"
  | "AUTHORIZATION_CONSUMED"
  | "AUTHORIZATION_MISMATCH"
  | "REVISION_CONFLICT"
  | "UID_CONFLICT"
  | "SUBJECT_CONFLICT"
  | "IDEMPOTENCY_CONFLICT"
  | "IDENTITY_STATE_INVALID"
  | "SUPER_ADMIN_LINK_FORBIDDEN";

export class IdentityLinkingContractError extends Error {
  constructor(readonly code: IdentityLinkingErrorCode) {
    super("Google identity linking contract rejected");
    this.name = "IdentityLinkingContractError";
  }
}

export function evaluateIdentityLinkAuthorization(
  authorizationInput: unknown,
  now: Timestamp
): "valid" {
  const authorization = identityLinkAuthorizationSchema.parse(authorizationInput);
  if (authorization.state === "revoked") throw new IdentityLinkingContractError("AUTHORIZATION_REVOKED");
  if (authorization.state === "consumed") throw new IdentityLinkingContractError("AUTHORIZATION_CONSUMED");
  if (authorization.state === "expired" || now.toMillis() >= authorization.expiresAt.toMillis()) {
    throw new IdentityLinkingContractError("AUTHORIZATION_EXPIRED");
  }
  return "valid";
}

export type EvaluateGoogleIdentityLinkInput = {
  request: unknown;
  authorization: unknown;
  now: Timestamp;
  protectedSuperAdminUid: string;
  currentProfile: {
    uid: string;
    revision: number;
    linkingStatus: "declared" | "verified" | "linked" | "reconciliation_required";
    activationStatus: string;
    authDisabled: boolean;
  };
  verifiedGoogleSubjectHash: string;
  reservationOwnerUid: string | null;
  completedOperation?: unknown;
};

function sameCompletedOperation(
  operation: CompletedIdentityLinkOperation,
  request: LinkGoogleIdentityRequest
): boolean {
  return operation.authorizationId === request.authorizationId
    && operation.operation === request.operation
    && operation.operationId === request.operationId
    && operation.idempotencyKey === request.idempotencyKey
    && operation.targetUid === request.targetUid
    && operation.googleSubjectHash === request.googleSubjectHash
    && operation.expectedRevision === request.expectedRevision
    && operation.requestedActivationStatus === request.requestedActivationStatus;
}

export function evaluateGoogleIdentityLink(
  input: EvaluateGoogleIdentityLinkInput
): IdentityLinkingDecision {
  const request = linkGoogleIdentityRequestSchema.parse(input.request);
  const authorization = identityLinkAuthorizationSchema.parse(input.authorization);
  const verifiedHash = subjectHashSchema.parse(input.verifiedGoogleSubjectHash);
  const protectedUid = uidSchema.parse(input.protectedSuperAdminUid);

  if (request.targetUid === protectedUid) throw new IdentityLinkingContractError("SUPER_ADMIN_LINK_FORBIDDEN");
  if (input.completedOperation !== undefined) {
    const completed = completedIdentityLinkOperationSchema.parse(input.completedOperation);
    if (!sameCompletedOperation(completed, request)) throw new IdentityLinkingContractError("IDEMPOTENCY_CONFLICT");
    return {
      decision: "replay",
      uid: request.targetUid,
      googleSubjectHash: request.googleSubjectHash,
      nextLinkingStatus: "linked",
      nextActivationStatus: "linked_pending_activation",
      nextAuthDisabled: true,
      nextRevision: completed.resultingRevision,
      replayed: true
    };
  }

  if (input.currentProfile.uid !== request.targetUid) throw new IdentityLinkingContractError("UID_CONFLICT");
  if (input.currentProfile.revision !== request.expectedRevision) throw new IdentityLinkingContractError("REVISION_CONFLICT");
  if (input.currentProfile.linkingStatus !== "verified"
    || input.currentProfile.activationStatus === "active"
    || input.currentProfile.authDisabled !== true) {
    throw new IdentityLinkingContractError("IDENTITY_STATE_INVALID");
  }
  if (verifiedHash !== request.googleSubjectHash) throw new IdentityLinkingContractError("SUBJECT_CONFLICT");
  if (authorization.authorizationId !== request.authorizationId
    || authorization.operation !== request.operation
    || authorization.operationId !== request.operationId
    || authorization.idempotencyKey !== request.idempotencyKey
    || authorization.targetUid !== request.targetUid
    || authorization.googleSubjectHash !== request.googleSubjectHash
    || authorization.expectedRevision !== request.expectedRevision) {
    throw new IdentityLinkingContractError("AUTHORIZATION_MISMATCH");
  }
  evaluateIdentityLinkAuthorization(authorization, input.now);

  if (input.reservationOwnerUid === null) {
    return {
      decision: "reconciliation_required",
      uid: request.targetUid,
      googleSubjectHash: request.googleSubjectHash,
      reason: "RESERVATION_MISSING",
      replayed: false
    };
  }
  if (input.reservationOwnerUid !== request.targetUid) {
    return {
      decision: "reconciliation_required",
      uid: request.targetUid,
      googleSubjectHash: request.googleSubjectHash,
      reason: "RESERVATION_UID_CONFLICT",
      replayed: false
    };
  }

  return {
    decision: "link",
    uid: request.targetUid,
    googleSubjectHash: request.googleSubjectHash,
    nextLinkingStatus: "linked",
    nextActivationStatus: "linked_pending_activation",
    nextAuthDisabled: true,
    nextRevision: request.expectedRevision + 1,
    replayed: false
  };
}
