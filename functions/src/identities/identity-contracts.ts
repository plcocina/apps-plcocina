import { z } from "zod";
import {
  activationStatusSchema,
  authMethodV21Schema,
  normalizeIdentityEmail,
  normalizeWorkspaceDomain
} from "./identity-models.js";

const workspaceDomainInputSchema = z.string().trim().min(1).max(253).transform((value, context) => {
  try {
    return normalizeWorkspaceDomain(value);
  } catch {
    context.addIssue({ code: "custom", message: "El dominio Workspace no es válido" });
    return z.NEVER;
  }
});

export const identityCreateInputSchema = z.discriminatedUnion("authMethod", [
  z.object({
    displayName: z.string().trim().min(1).max(160),
    authMethod: z.literal("sms"),
    phone: z.string().trim().min(1).max(32),
    email: z.null().default(null)
  }).strict(),
  z.object({
    displayName: z.string().trim().min(1).max(160),
    authMethod: z.literal("email"),
    phone: z.null().default(null),
    email: z.string().trim().email().max(254)
  }).strict(),
  z.object({
    displayName: z.string().trim().min(1).max(160),
    authMethod: z.literal("googleWorkspace"),
    phone: z.null().default(null),
    email: z.string().trim().email().max(254).transform(normalizeIdentityEmail),
    workspaceDomain: workspaceDomainInputSchema
  }).strict().superRefine((input, context) => {
    if (!input.email.endsWith(`@${input.workspaceDomain}`)) {
      context.addIssue({ code: "custom", path: ["workspaceDomain"], message: "El correo declarado no pertenece al dominio Workspace" });
    }
  })
]);

export const identityUpdateInputSchema = z.object({
  expectedRevision: z.number().int().positive(),
  reason: z.string().trim().min(3).max(500),
  authMethod: authMethodV21Schema.optional(),
  phone: z.string().trim().min(1).max(32).nullable().optional(),
  email: z.string().trim().min(1).max(254).nullable().optional(),
  workspaceDomain: z.string().trim().min(1).max(253).nullable().optional()
}).strict().refine(
  (input) => input.authMethod !== undefined || input.phone !== undefined || input.email !== undefined || input.workspaceDomain !== undefined,
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
