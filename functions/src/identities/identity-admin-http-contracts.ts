import { z } from "zod";
import { activationStatusSchema, authMethodSchema } from "./identity-models.js";

const uidSchema = z.string().min(1).max(128).refine((value) => !value.includes("/"));

export const identityPreprovisionRequestSchema = z.discriminatedUnion("authMethod", [
  z.object({
    displayName: z.string().trim().min(1).max(160),
    authMethod: z.literal("sms"),
    phoneE164: z.string().min(1).max(32)
  }).strict(),
  z.object({
    displayName: z.string().trim().min(1).max(160),
    authMethod: z.literal("email"),
    email: z.string().trim().email().max(254)
  }).strict()
]);

export const identityPreprovisionResponseSchema = z.object({
  operationId: z.string().uuid(),
  uid: uidSchema,
  authMethod: authMethodSchema,
  activationStatus: z.literal("pending"),
  authDisabled: z.literal(true),
  revision: z.literal(1),
  replayed: z.boolean()
}).strict();

export const identityStatusResponseSchema = z.object({
  uid: uidSchema,
  profileVersion: z.union([z.literal(1), z.literal(2)]),
  authMethod: authMethodSchema.nullable(),
  activationStatus: activationStatusSchema.nullable(),
  authDisabled: z.boolean(),
  authRecordPresent: z.boolean(),
  integrity: z.enum(["linked", "missing_auth", "missing_profile", "mismatch", "invalid_profile"]),
  revision: z.number().int().positive().nullable()
}).strict();

// Diseño solamente: este módulo no se importa desde app.ts ni index.ts.
export const proposedIdentityAdminRoutes = Object.freeze({
  preprovision: { method: "POST", path: "/api/admin/identities", requiresSuperAdmin: true, requiresIdempotencyKey: true, requiresExpectedRevision: false },
  getStatus: { method: "GET", path: "/api/admin/identities/:uid", requiresSuperAdmin: true, requiresIdempotencyKey: false, requiresExpectedRevision: false }
});

export type IdentityPreprovisionRequest = z.infer<typeof identityPreprovisionRequestSchema>;
export type IdentityPreprovisionResponse = z.infer<typeof identityPreprovisionResponseSchema>;
export type IdentityStatusResponse = z.infer<typeof identityStatusResponseSchema>;
