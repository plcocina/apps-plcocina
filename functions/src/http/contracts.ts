import { z } from "zod";

const requestIdSchema = z.string().uuid();

export const errorCodeSchema = z.enum([
  "AUTH_REQUIRED",
  "TOKEN_INVALID",
  "TOKEN_EXPIRED",
  "TOKEN_REVOKED",
  "ADMIN_REQUIRED",
  "ORIGIN_FORBIDDEN",
  "NOT_FOUND",
  "METHOD_NOT_ALLOWED",
  "VALIDATION_ERROR",
  "DUPLICATE_APPLICATION",
  "DUPLICATE_INVITATION",
  "GRANT_NOT_REQUIRED",
  "REVISION_CONFLICT",
  "IDEMPOTENCY_REQUIRED",
  "IDEMPOTENCY_CONFLICT",
  "OPERATION_IN_PROGRESS",
  "DELIVERY_RETRY_WINDOW_EXPIRED",
  "INVITATION_INVALID",
  "RATE_LIMITED",
  "RECONCILIATION_REQUIRED",
  "PROTECTED_ACCOUNT",
  "PROFILE_REQUIRED",
  "PROFILE_INCONSISTENT",
  "INVALID_STATE_TRANSITION",
  "INTERNAL_ERROR"
]);

export const errorResponseSchema = z.object({
  ok: z.literal(false),
  error: z.object({
    code: errorCodeSchema,
    message: z.string().min(1).max(240)
  }).strict(),
  requestId: requestIdSchema
}).strict();

export const healthResponseSchema = z.object({
  ok: z.literal(true),
  data: z.object({
    status: z.literal("ok"),
    service: z.literal("admin-api"),
    version: z.string().min(1),
    region: z.string().min(1),
    checkedAt: z.string().datetime()
  }).strict(),
  requestId: requestIdSchema
}).strict();

export const meResponseSchema = z.object({
  ok: z.literal(true),
  data: z.object({
    uid: z.string().min(1).max(128),
    email: z.string().email().nullable(),
    superAdmin: z.literal(true),
    authTime: z.number().int().nonnegative(),
    issuedAt: z.number().int().nonnegative()
  }).strict(),
  requestId: requestIdSchema
}).strict();

const publicUserSchema = z.object({
  uid: z.string().min(1).max(128),
  email: z.string().email().nullable(),
  displayName: z.string().min(1).max(160).nullable(),
  emailVerified: z.boolean().nullable(),
  disabled: z.boolean().nullable(),
  authCreatedAt: z.string().nullable(),
  lastSignInAt: z.string().nullable(),
  isProtected: z.boolean(),
  integrity: z.enum(["linked", "missing_profile", "orphan_profile", "profile_mismatch", "invalid_profile"]),
  profile: z.object({
    status: z.enum(["invited", "active", "disabled"]),
    authDisabled: z.boolean(),
    invitationStatus: z.enum(["pending", "accepted", "expired", "revoked"]),
    createdAt: z.string().datetime(),
    updatedAt: z.string().datetime(),
    revision: z.number().int().positive(),
    version: z.literal(1)
  }).strict().nullable()
}).strict();

export const usersListResponseSchema = z.object({
  ok: z.literal(true),
  data: z.object({
    users: z.array(publicUserSchema),
    nextPageToken: z.string().nullable()
  }).strict(),
  requestId: requestIdSchema
}).strict();

export const userResponseSchema = z.object({
  ok: z.literal(true),
  data: publicUserSchema,
  requestId: requestIdSchema
}).strict();

export const userOperationResponseSchema = z.object({
  ok: z.literal(true),
  data: z.object({
    operationId: z.string().uuid(),
    uid: z.string().min(1).max(128),
    action: z.enum(["suspend", "reactivate", "revoke-sessions"]),
    status: z.enum(["invited", "active", "disabled"]),
    authDisabled: z.boolean(),
    sessionsRevoked: z.boolean(),
    revision: z.number().int().positive()
  }).strict(),
  requestId: requestIdSchema
}).strict();

export const invitationResponseSchema = z.object({
  ok: z.literal(true),
  data: z.object({
    invitationId: z.string().uuid(),
    uid: z.string().min(1).max(128),
    email: z.string().email(),
    displayName: z.string().min(1).max(160),
    status: z.enum(["active", "expired", "revoked", "reconciliation_required"]),
    deliveryStatus: z.enum(["pending", "accepted", "delivered", "delayed", "bounced", "complained", "failed", "unknown"]),
    expiresAt: z.string().datetime(),
    revision: z.number().int().positive()
  }).strict(),
  requestId: requestIdSchema
}).strict();

const administrativeInvitationSchema = z.object({
  invitationId: z.string().uuid(),
  email: z.string().email(),
  displayName: z.string().min(1).max(160),
  status: z.enum(["provisioning", "pending_delivery", "active", "accepting", "password_set", "accepted", "expired", "revoked", "reconciliation_required"]),
  deliveryStatus: z.enum(["pending", "accepted", "delivered", "delayed", "bounced", "complained", "failed", "unknown"]),
  createdAt: z.string().datetime(),
  expiresAt: z.string().datetime(),
  acceptedAt: z.string().datetime().nullable(),
  revision: z.number().int().positive()
}).strict();

export const invitationsListResponseSchema = z.object({
  ok: z.literal(true),
  data: z.object({
    invitations: z.array(administrativeInvitationSchema),
    nextPageToken: z.string().nullable()
  }).strict(),
  requestId: requestIdSchema
}).strict();

export const invitationDetailResponseSchema = z.object({
  ok: z.literal(true),
  data: administrativeInvitationSchema,
  requestId: requestIdSchema
}).strict();

export const invitationValidationResponseSchema = z.object({
  ok: z.literal(true),
  data: z.object({ valid: z.literal(true), expiresAt: z.string().datetime() }).strict(),
  requestId: requestIdSchema
}).strict();

export const passwordEstablishmentResponseSchema = z.object({
  ok: z.literal(true),
  data: z.object({ status: z.literal("password_set"), confirmationExpiresAt: z.string().datetime() }).strict(),
  requestId: requestIdSchema
}).strict();

export const invitationConfirmationResponseSchema = z.object({
  ok: z.literal(true),
  data: z.object({ status: z.literal("accepted"), acceptedAt: z.string().datetime() }).strict(),
  requestId: requestIdSchema
}).strict();

export type ErrorCode = z.infer<typeof errorCodeSchema>;
