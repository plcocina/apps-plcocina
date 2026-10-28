import { z } from "zod";
import { activationStatusSchema, authMethodSchema } from "./identity-models.js";

export const identityCreateInputSchema = z.object({
  displayName: z.string().trim().min(1).max(160),
  authMethod: authMethodSchema,
  phone: z.string().trim().min(1).max(32).nullable().default(null),
  email: z.string().trim().min(1).max(254).nullable().default(null)
}).strict().superRefine((input, context) => {
  if (input.authMethod === "sms" && !input.phone) {
    context.addIssue({ code: "custom", path: ["phone"], message: "El método SMS requiere teléfono" });
  }
  if (input.authMethod === "email" && !input.email) {
    context.addIssue({ code: "custom", path: ["email"], message: "El método email requiere correo" });
  }
});

export const identityUpdateInputSchema = z.object({
  expectedRevision: z.number().int().positive(),
  reason: z.string().trim().min(3).max(500),
  authMethod: authMethodSchema.optional(),
  phone: z.string().trim().min(1).max(32).nullable().optional(),
  email: z.string().trim().min(1).max(254).nullable().optional()
}).strict().refine(
  (input) => input.authMethod !== undefined || input.phone !== undefined || input.email !== undefined,
  "La operación no contiene cambios de identidad"
);

export const identityActivationTransitionInputSchema = z.object({
  expectedRevision: z.number().int().positive(),
  from: activationStatusSchema,
  to: activationStatusSchema,
  reason: z.string().trim().min(3).max(500)
}).strict();

export type IdentityCreateInput = z.infer<typeof identityCreateInputSchema>;
export type IdentityUpdateInput = z.infer<typeof identityUpdateInputSchema>;
