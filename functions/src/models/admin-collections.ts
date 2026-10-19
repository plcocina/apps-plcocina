import { Timestamp } from "firebase-admin/firestore";
import { z } from "zod";

const timestampSchema = z.instanceof(Timestamp);
const uidSchema = z.string().min(1).max(128);
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
  slug: z.string().regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/).max(80),
  name: z.string().trim().min(1).max(120),
  description: z.string().trim().max(500),
  launchUrl: httpsUrlSchema,
  status: z.enum(["draft", "active", "disabled", "archived"]),
  accessMode: z.enum(["public", "restricted"]),
  iconKey: z.string().trim().min(1).max(64),
  displayOrder: z.number().int().min(0).max(10000),
  createdAt: timestampSchema,
  createdBy: uidSchema,
  updatedAt: timestampSchema,
  updatedBy: uidSchema,
  version: z.literal(1)
}).strict();

export const accessGrantDocumentSchema = z.object({
  uid: uidSchema,
  appId: documentIdSchema,
  status: z.enum(["active", "suspended", "revoked", "expired"]),
  grantedAt: timestampSchema,
  grantedBy: uidSchema,
  validFrom: timestampSchema,
  validUntil: timestampSchema.nullable(),
  revokedAt: timestampSchema.nullable(),
  revokedBy: uidSchema.nullable(),
  revokeReason: z.string().trim().min(1).max(500).nullable(),
  updatedAt: timestampSchema,
  version: z.literal(1)
}).strict().superRefine((grant, context) => {
  if (grant.validUntil && grant.validUntil.toMillis() <= grant.validFrom.toMillis()) {
    context.addIssue({
      code: "custom",
      path: ["validUntil"],
      message: "La vigencia final debe ser posterior a la vigencia inicial"
    });
  }
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
  normalizedEmail: normalizedEmailSchema,
  uid: uidSchema,
  status: z.enum(["pending", "delivered", "accepted", "expired", "revoked"]),
  expiresAt: timestampSchema,
  createdAt: timestampSchema,
  createdBy: uidSchema,
  deliveredAt: timestampSchema.nullable(),
  acceptedAt: timestampSchema.nullable(),
  revokedAt: timestampSchema.nullable(),
  version: z.literal(1)
}).strict();

export const auditEventDocumentSchema = z.object({
  occurredAt: timestampSchema,
  actorUid: uidSchema,
  actorEmail: z.string().email(),
  action: z.string().regex(/^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$/).max(100),
  resourceType: z.enum(["user", "application", "accessGrant", "invitation"]),
  resourceId: documentIdSchema,
  targetUid: uidSchema.nullable(),
  appId: documentIdSchema.nullable(),
  before: z.record(z.string(), z.unknown()).nullable(),
  after: z.record(z.string(), z.unknown()).nullable(),
  reason: z.string().trim().min(1).max(500).nullable(),
  requestId: z.string().uuid(),
  source: z.literal("admin-api"),
  result: z.enum(["success", "failure"]),
  version: z.literal(1)
}).strict();

export type UserDocument = z.infer<typeof userDocumentSchema>;
export type ApplicationDocument = z.infer<typeof applicationDocumentSchema>;
export type AccessGrantDocument = z.infer<typeof accessGrantDocumentSchema>;
export type InvitationDocument = z.infer<typeof invitationDocumentSchema>;
export type AuditEventDocument = z.infer<typeof auditEventDocumentSchema>;
