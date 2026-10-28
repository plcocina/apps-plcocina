import { Timestamp } from "firebase-admin/firestore";
import { z } from "zod";

const timestampSchema = z.instanceof(Timestamp);
const uidSchema = z.string().min(1).max(128).refine((value) => !value.includes("/"));
const documentIdSchema = z.string().regex(/^[a-zA-Z0-9_-]{1,128}$/);
const normalizedEmailSchema = z.string().email().transform((value) => value.toLowerCase());
const httpsUrlSchema = z.string().url().refine(
  (value) => new URL(value).protocol === "https:",
  "La URL debe usar HTTPS"
);

export const userDocumentSchema = z.object({
  email: z.string().email(),
  normalizedEmail: normalizedEmailSchema,
  displayName: z.string().trim().min(1).max(160),
  status: z.enum(["invited", "active", "disabled"]),
  authDisabled: z.boolean(),
  invitationStatus: z.enum(["pending", "accepted", "expired", "revoked"]),
  createdAt: timestampSchema,
  createdBy: uidSchema,
  updatedAt: timestampSchema,
  updatedBy: uidSchema,
  revision: z.number().int().positive().default(1),
  pendingOperationId: z.string().uuid().nullable().default(null),
  version: z.literal(1)
}).strict().superRefine((user, context) => {
  if (user.normalizedEmail !== user.email.toLowerCase()) {
    context.addIssue({
      code: "custom",
      path: ["normalizedEmail"],
      message: "El correo normalizado debe corresponder al correo principal"
    });
  }
});

export const applicationDocumentSchema = z.object({
  appId: documentIdSchema,
  slug: z.string().regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/).max(80),
  name: z.string().trim().min(1).max(120),
  normalizedName: z.string().min(1).max(120),
  description: z.string().trim().max(500),
  category: z.string().trim().min(1).max(80),
  normalizedCategory: z.string().min(1).max(80),
  launchUrl: httpsUrlSchema,
  normalizedLaunchUrl: httpsUrlSchema,
  status: z.enum(["draft", "active", "inactive", "archived"]),
  accessLevel: z.enum(["public", "private"]),
  iconKey: z.string().trim().min(1).max(64).nullable(),
  displayOrder: z.number().int().min(0).max(10000),
  createdAt: timestampSchema,
  createdBy: uidSchema,
  updatedAt: timestampSchema,
  updatedBy: uidSchema,
  revision: z.number().int().positive(),
  version: z.literal(1)
}).strict();

export const applicationUniqueKeyDocumentSchema = z.object({
  kind: z.enum(["slug", "url", "categoryName"]),
  value: z.string().min(1).max(2048),
  appId: documentIdSchema,
  createdAt: timestampSchema,
  version: z.literal(1)
}).strict();

export const accessGrantDocumentSchema = z.object({
  userId: uidSchema,
  applicationId: documentIdSchema,
  status: z.enum(["active", "revoked"]),
  createdAt: timestampSchema,
  createdBy: uidSchema,
  updatedAt: timestampSchema,
  updatedBy: uidSchema,
  revokedAt: timestampSchema.nullable(),
  revokedBy: uidSchema.nullable(),
  revokeReason: z.string().trim().min(3).max(500).nullable(),
  revision: z.number().int().positive(),
  version: z.literal(1)
}).strict().superRefine((grant, context) => {
  if (grant.status === "revoked" && (!grant.revokedAt || !grant.revokedBy || !grant.revokeReason)) {
    context.addIssue({
      code: "custom",
      message: "Un permiso revocado requiere fecha, autor y motivo de revocación"
    });
  }
  if (grant.status !== "revoked" && (grant.revokedAt || grant.revokedBy || grant.revokeReason)) {
    context.addIssue({
      code: "custom",
      message: "Un permiso no revocado no puede contener metadatos de revocación"
    });
  }
});

export const invitationDocumentSchema = z.object({
  invitationId: z.string().uuid(),
  email: z.string().email(),
  normalizedEmail: normalizedEmailSchema,
  displayName: z.string().trim().min(1).max(160),
  uid: uidSchema,
  status: z.enum(["provisioning", "pending_delivery", "active", "accepting", "password_set", "accepted", "expired", "revoked", "reconciliation_required"]),
  token: z.object({
    hash: z.string().regex(/^[a-f0-9]{64}$/),
    generation: z.number().int().positive(),
    salt: z.string().regex(/^[A-Za-z0-9_-]{22}$/),
    keyVersion: z.number().int().positive(),
    issuedAt: timestampSchema,
    expiresAt: timestampSchema
  }).strict().nullable(),
  delivery: z.object({
    provider: z.enum(["simulated", "resend"]),
    status: z.enum(["pending", "accepted", "delivered", "delayed", "bounced", "complained", "failed", "unknown"]),
    idempotencyKey: z.string().min(1).max(256),
    providerMessageId: z.string().max(256).nullable(),
    templateVersion: z.number().int().positive(),
    firstAttemptAt: timestampSchema.nullable(),
    retryUntil: timestampSchema.nullable(),
    sentAt: timestampSchema.nullable(),
    deliveredAt: timestampSchema.nullable(),
    failureCode: z.string().max(80).nullable()
  }).strict(),
  expiresAt: timestampSchema,
  createdAt: timestampSchema,
  createdBy: uidSchema,
  updatedAt: timestampSchema,
  updatedBy: uidSchema,
  pendingOperationId: z.string().uuid().nullable(),
  consumeOperationId: z.string().uuid().nullable(),
  consumeLeaseExpiresAt: timestampSchema.nullable(),
  passwordSetAt: timestampSchema.nullable(),
  confirmationExpiresAt: timestampSchema.nullable(),
  deliveredAt: timestampSchema.nullable(),
  acceptedAt: timestampSchema.nullable(),
  revokedAt: timestampSchema.nullable(),
  revokedBy: uidSchema.nullable(),
  revokeReason: z.string().trim().min(3).max(500).nullable(),
  expiredAt: timestampSchema.nullable(),
  resendCount: z.number().int().nonnegative(),
  lastSentAt: timestampSchema.nullable(),
  revision: z.number().int().positive(),
  version: z.literal(2)
}).strict().superRefine((invitation, context) => {
  if (invitation.normalizedEmail !== invitation.email.toLowerCase()) {
    context.addIssue({ code: "custom", path: ["normalizedEmail"], message: "El correo normalizado no coincide" });
  }
  if (invitation.token && invitation.token.expiresAt.toMillis() !== invitation.expiresAt.toMillis()) {
    context.addIssue({ code: "custom", path: ["token", "expiresAt"], message: "La vigencia del token no coincide" });
  }
});

export const invitationUniqueKeyDocumentSchema = z.object({
  normalizedEmailHash: z.string().regex(/^[a-f0-9]{64}$/),
  invitationId: z.string().uuid(),
  uid: uidSchema,
  state: z.enum(["reserved", "active", "accepted", "released"]),
  createdAt: timestampSchema,
  updatedAt: timestampSchema,
  version: z.literal(1)
}).strict();

export const auditEventDocumentSchema = z.object({
  occurredAt: timestampSchema,
  actorType: z.enum(["admin", "user", "system", "provider"]).default("admin"),
  actorUid: uidSchema.nullable(),
  actorEmail: z.string().email().nullable(),
  providerEventId: z.string().max(256).nullable().default(null),
  action: z.string().regex(/^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$/).max(100),
  resourceType: z.enum(["user", "application", "accessGrant", "invitation"]),
  resourceId: uidSchema,
  targetUid: uidSchema.nullable(),
  appId: documentIdSchema.nullable(),
  before: z.record(z.string(), z.unknown()).nullable(),
  after: z.record(z.string(), z.unknown()).nullable(),
  reason: z.string().trim().min(1).max(500).nullable(),
  requestId: z.string().uuid(),
  source: z.literal("admin-api"),
  result: z.enum(["success", "failure"]),
  version: z.literal(1)
}).strict().superRefine((event, context) => {
  if ((event.actorType === "admin" || event.actorType === "user") && (!event.actorUid || !event.actorEmail)) {
    context.addIssue({ code: "custom", message: "Un actor humano requiere UID y correo" });
  }
  if (event.actorType === "provider" && !event.providerEventId) {
    context.addIssue({ code: "custom", path: ["providerEventId"], message: "Un evento de proveedor requiere identificador" });
  }
});

export const adminOperationDocumentSchema = z.object({
  operationId: z.string().uuid(),
  type: z.enum(["user.suspend", "user.reactivate", "user.revoke_sessions", "invitation.create", "invitation.resend", "invitation.revoke", "invitation.accept", "invitation.expire", "access_grant.grant", "access_grant.revoke"]),
  targetUid: uidSchema,
  appId: documentIdSchema.nullable().default(null),
  invitationId: z.string().uuid().nullable().default(null),
  actorUid: uidSchema,
  inputHash: z.string().regex(/^[a-f0-9]{64}$/),
  expectedRevision: z.number().int().nonnegative().nullable(),
  status: z.enum(["pending", "auth_applied", "completed", "reconciliation_required"]),
  checkpoint: z.enum(["reserved", "auth_created", "profile_created", "email_requested", "email_accepted", "password_applied", "completed"]).default("reserved"),
  requestId: z.string().uuid(),
  leaseOwner: z.string().uuid(),
  leaseExpiresAt: timestampSchema,
  attempts: z.number().int().positive(),
  result: z.record(z.string(), z.unknown()).nullable(),
  failureCode: z.string().regex(/^[A-Z0-9_]{1,80}$/).nullable(),
  createdAt: timestampSchema,
  updatedAt: timestampSchema,
  completedAt: timestampSchema.nullable(),
  version: z.literal(1)
}).strict().superRefine((operation, context) => {
  if (operation.status === "completed" && (!operation.result || !operation.completedAt)) {
    context.addIssue({ code: "custom", message: "Una operación completada requiere resultado y fecha de finalización" });
  }
  if (operation.status !== "completed" && operation.completedAt) {
    context.addIssue({ code: "custom", path: ["completedAt"], message: "Sólo una operación completada puede tener fecha de finalización" });
  }
});

export const webhookReplayEventDocumentSchema = z.object({
  eventIdHash: z.string().regex(/^[a-f0-9]{64}$/),
  provider: z.literal("resend"),
  status: z.enum(["processing", "completed", "retryable"]),
  attempts: z.number().int().positive(),
  claimedAt: timestampSchema,
  updatedAt: timestampSchema,
  leaseExpiresAt: timestampSchema,
  completedAt: timestampSchema.nullable(),
  expiresAt: timestampSchema,
  version: z.literal(1)
}).strict().superRefine((event, context) => {
  if (event.expiresAt.toMillis() <= event.claimedAt.toMillis()) {
    context.addIssue({ code: "custom", path: ["expiresAt"], message: "La expiración debe ser posterior a la reserva" });
  }
  if ((event.status === "completed") !== (event.completedAt !== null)) {
    context.addIssue({ code: "custom", path: ["completedAt"], message: "El estado completado requiere fecha final" });
  }
});

export type UserDocument = z.infer<typeof userDocumentSchema>;
export type ApplicationDocument = z.infer<typeof applicationDocumentSchema>;
export type ApplicationUniqueKeyDocument = z.infer<typeof applicationUniqueKeyDocumentSchema>;
export type AccessGrantDocument = z.infer<typeof accessGrantDocumentSchema>;
export type InvitationDocument = z.infer<typeof invitationDocumentSchema>;
export type InvitationUniqueKeyDocument = z.infer<typeof invitationUniqueKeyDocumentSchema>;
export type AuditEventDocument = z.infer<typeof auditEventDocumentSchema>;
export type AdminOperationDocument = z.infer<typeof adminOperationDocumentSchema>;
export type WebhookReplayEventDocument = z.infer<typeof webhookReplayEventDocumentSchema>;
