import { createHmac } from "node:crypto";
import { Timestamp } from "firebase-admin/firestore";
import { z } from "zod";

const timestampSchema = z.instanceof(Timestamp);
const uidSchema = z.string().min(1).max(128).refine((value) => !value.includes("/"));
const operationIdSchema = z.string().uuid();

export const authMethodSchema = z.enum(["sms", "email"]);
export const activationStatusSchema = z.enum([
  "pending",
  "auth_enabled_pending_proof",
  "active",
  "recovery_required",
  "reconciliation_required"
]);
export const identityIdentifierKindSchema = z.enum(["phone", "email"]);

export function normalizeIdentityEmail(value: string): string {
  const normalized = value.normalize("NFKC").trim().toLowerCase();
  return z.string().email().max(254).parse(normalized);
}

export function normalizePhoneE164(value: string): string {
  const normalized = value.normalize("NFKC").replace(/[\s()-]/g, "");
  if (!/^\+[1-9]\d{7,14}$/.test(normalized)) {
    throw new Error("INVALID_E164_PHONE");
  }
  return normalized;
}

export function identifierKeyHash(
  kind: z.infer<typeof identityIdentifierKindSchema>,
  normalizedValue: string,
  pepper: Buffer
): string {
  if (pepper.length < 32) throw new Error("IDENTIFIER_PEPPER_TOO_SHORT");
  return createHmac("sha256", pepper).update(`plcocina-identity-v1\0${kind}\0${normalizedValue}`).digest("hex");
}

export const userV2DocumentSchema = z.object({
  displayName: z.string().trim().min(1).max(160),
  status: z.enum(["invited", "active", "disabled"]),
  authDisabled: z.boolean(),
  invitationStatus: z.enum(["pending", "accepted", "expired", "revoked"]),
  authMethod: authMethodSchema,
  phoneE164: z.string().nullable(),
  normalizedPhone: z.string().nullable(),
  email: z.string().nullable(),
  normalizedEmail: z.string().nullable(),
  phoneVerifiedAt: timestampSchema.nullable(),
  emailVerifiedAt: timestampSchema.nullable(),
  activationStatus: activationStatusSchema,
  credentialRevision: z.number().int().positive(),
  authorizationRevision: z.number().int().positive(),
  sessionValidAfter: timestampSchema,
  createdAt: timestampSchema,
  createdBy: uidSchema,
  updatedAt: timestampSchema,
  updatedBy: uidSchema,
  revision: z.number().int().positive().default(1),
  pendingOperationId: operationIdSchema.nullable().default(null),
  version: z.literal(2)
}).strict().superRefine((user, context) => {
  if ((user.email === null) !== (user.normalizedEmail === null)) {
    context.addIssue({ code: "custom", path: ["normalizedEmail"], message: "El correo y su valor normalizado deben existir juntos" });
  } else if (user.email !== null) {
    try {
      if (normalizeIdentityEmail(user.email) !== user.normalizedEmail) throw new Error("mismatch");
    } catch {
      context.addIssue({ code: "custom", path: ["normalizedEmail"], message: "El correo normalizado no coincide" });
    }
  }

  if ((user.phoneE164 === null) !== (user.normalizedPhone === null)) {
    context.addIssue({ code: "custom", path: ["normalizedPhone"], message: "El teléfono y su valor normalizado deben existir juntos" });
  } else if (user.phoneE164 !== null) {
    try {
      const normalized = normalizePhoneE164(user.phoneE164);
      if (normalized !== user.phoneE164 || normalized !== user.normalizedPhone) throw new Error("mismatch");
    } catch {
      context.addIssue({ code: "custom", path: ["normalizedPhone"], message: "El teléfono debe usar el formato E.164 canónico" });
    }
  }

  if (user.authMethod === "sms" && !user.normalizedPhone) {
    context.addIssue({ code: "custom", path: ["phoneE164"], message: "El método SMS requiere teléfono" });
  }
  if (user.authMethod === "email" && !user.normalizedEmail) {
    context.addIssue({ code: "custom", path: ["email"], message: "El método email requiere correo" });
  }
  if (user.phoneVerifiedAt && !user.phoneE164) {
    context.addIssue({ code: "custom", path: ["phoneVerifiedAt"], message: "No puede verificarse un teléfono ausente" });
  }
  if (user.emailVerifiedAt && !user.email) {
    context.addIssue({ code: "custom", path: ["emailVerifiedAt"], message: "No puede verificarse un correo ausente" });
  }

  if (user.activationStatus === "active" && (user.status !== "active" || user.authDisabled)) {
    context.addIssue({ code: "custom", path: ["activationStatus"], message: "Una identidad activa requiere perfil activo y Authentication habilitado" });
  }
  if (user.activationStatus === "auth_enabled_pending_proof" && (user.status !== "invited" || user.authDisabled)) {
    context.addIssue({ code: "custom", path: ["activationStatus"], message: "La prueba pendiente requiere perfil invitado y Authentication habilitado" });
  }
  if (user.activationStatus === "pending" && (user.status !== "invited" || !user.authDisabled)) {
    context.addIssue({ code: "custom", path: ["activationStatus"], message: "Una identidad pendiente debe permanecer invitada y deshabilitada" });
  }
});

export const identityIdentifierKeyDocumentSchema = z.object({
  kind: identityIdentifierKindSchema,
  identifierHash: z.string().regex(/^[a-f0-9]{64}$/),
  uid: uidSchema,
  state: z.enum(["reserved", "active", "released"]),
  operationId: operationIdSchema,
  createdAt: timestampSchema,
  updatedAt: timestampSchema,
  releasedAt: timestampSchema.nullable(),
  version: z.literal(1)
}).strict().superRefine((key, context) => {
  if ((key.state === "released") !== (key.releasedAt !== null)) {
    context.addIssue({ code: "custom", path: ["releasedAt"], message: "Sólo una reserva liberada requiere fecha de liberación" });
  }
});

export const identityReservationOperationSchema = z.object({
  operationId: operationIdSchema,
  type: z.literal("identity.identifier_reserve"),
  uid: uidSchema,
  kind: identityIdentifierKindSchema,
  identifierHash: z.string().regex(/^[a-f0-9]{64}$/),
  inputHash: z.string().regex(/^[a-f0-9]{64}$/),
  status: z.literal("completed"),
  result: z.object({
    identifierHash: z.string().regex(/^[a-f0-9]{64}$/),
    state: z.literal("reserved")
  }).strict(),
  createdAt: timestampSchema,
  completedAt: timestampSchema,
  version: z.literal(1)
}).strict();

export type UserV2Document = z.infer<typeof userV2DocumentSchema>;
export type AuthMethod = z.infer<typeof authMethodSchema>;
export type ActivationStatus = z.infer<typeof activationStatusSchema>;
export type IdentityIdentifierKind = z.infer<typeof identityIdentifierKindSchema>;
export type IdentityIdentifierKeyDocument = z.infer<typeof identityIdentifierKeyDocumentSchema>;
