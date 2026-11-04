import { createHmac } from "node:crypto";
import { Timestamp } from "firebase-admin/firestore";
import { z } from "zod";

const timestampSchema = z.instanceof(Timestamp);
const uidSchema = z.string().min(1).max(128).refine((value) => !value.includes("/"));
const operationIdSchema = z.string().uuid();

export const authMethodSchema = z.enum(["sms", "email"]);
export const authMethodV21Schema = z.enum(["sms", "email", "googleWorkspace"]);
export const activationStatusSchema = z.enum([
  "pending",
  "auth_enabled_pending_proof",
  "active",
  "recovery_required",
  "reconciliation_required"
]);
export const googleWorkspaceActivationStatusSchema = z.union([
  activationStatusSchema,
  z.literal("linked_pending_activation")
]);
export const identityIdentifierKindSchema = z.enum(["phone", "email", "googleSubject"]);

export const googleWorkspaceLinkingStatusSchema = z.enum([
  "declared",
  "verified",
  "linked",
  "reconciliation_required"
]);
export const googleWorkspaceVerificationStatusSchema = z.enum([
  "unverified",
  "verified",
  "reconciliation_required"
]);

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

export function normalizeWorkspaceDomain(value: string): string {
  const normalized = value.normalize("NFKC").trim().toLowerCase();
  if (normalized.length > 253
    || !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(normalized)) {
    throw new Error("INVALID_WORKSPACE_DOMAIN");
  }
  return normalized;
}

export function normalizeGoogleSubject(value: string): string {
  const normalized = value.normalize("NFKC").trim();
  if (!/^[A-Za-z0-9._~-]{1,255}$/.test(normalized)) {
    throw new Error("INVALID_GOOGLE_SUBJECT");
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

export const googleWorkspaceIdentitySchema = z.object({
  authorizedDomain: z.string().min(1).max(253),
  subject: z.string().min(1).max(255).nullable(),
  linkingStatus: googleWorkspaceLinkingStatusSchema,
  verificationStatus: googleWorkspaceVerificationStatusSchema,
  verifiedAt: timestampSchema.nullable(),
  linkedAt: timestampSchema.nullable(),
  verificationRevision: z.number().int().positive(),
  operationId: operationIdSchema.nullable()
}).strict().superRefine((identity, context) => {
  try {
    if (normalizeWorkspaceDomain(identity.authorizedDomain) !== identity.authorizedDomain) throw new Error("mismatch");
  } catch {
    context.addIssue({ code: "custom", path: ["authorizedDomain"], message: "El dominio Workspace debe ser canónico" });
  }
  if (identity.subject !== null) {
    try {
      if (normalizeGoogleSubject(identity.subject) !== identity.subject) throw new Error("mismatch");
    } catch {
      context.addIssue({ code: "custom", path: ["subject"], message: "El sub de Google no es válido" });
    }
  }

  if (identity.linkingStatus === "declared") {
    if (identity.subject !== null || identity.verificationStatus !== "unverified" || identity.verifiedAt !== null || identity.linkedAt !== null) {
      context.addIssue({ code: "custom", message: "Una identidad declarada todavía no puede estar verificada ni vinculada" });
    }
  }
  if (identity.linkingStatus === "verified") {
    if (!identity.subject || identity.verificationStatus !== "verified" || !identity.verifiedAt || identity.linkedAt !== null) {
      context.addIssue({ code: "custom", message: "Una identidad verificada requiere sub y sello de verificación, pero no vínculo" });
    }
  }
  if (identity.linkingStatus === "linked") {
    if (!identity.subject || identity.verificationStatus !== "verified" || !identity.verifiedAt || !identity.linkedAt) {
      context.addIssue({ code: "custom", message: "Una identidad vinculada requiere verificación y sub" });
    }
  }
  if (identity.linkingStatus === "reconciliation_required"
    && (identity.verificationStatus !== "reconciliation_required" || identity.operationId === null)) {
    context.addIssue({ code: "custom", path: ["verificationStatus"], message: "La conciliación debe bloquear la verificación y conservar su operación" });
  }
  if (identity.linkingStatus !== "reconciliation_required" && identity.operationId !== null) {
    context.addIssue({ code: "custom", path: ["operationId"], message: "Sólo una conciliación puede conservar una operación pendiente" });
  }
}).describe("Estado declarado, verificado o vinculado de una identidad Google Workspace");

export const googleWorkspaceUserV21DocumentSchema = z.object({
  uid: uidSchema,
  displayName: z.string().trim().min(1).max(160),
  status: z.enum(["invited", "active", "disabled"]),
  authDisabled: z.boolean(),
  invitationStatus: z.enum(["pending", "accepted", "expired", "revoked"]),
  authMethod: z.literal("googleWorkspace"),
  phoneE164: z.null(),
  normalizedPhone: z.null(),
  email: z.string().email().max(254),
  normalizedEmail: z.string().email().max(254),
  phoneVerifiedAt: z.null(),
  emailVerifiedAt: timestampSchema.nullable(),
  googleWorkspace: googleWorkspaceIdentitySchema,
  activationStatus: googleWorkspaceActivationStatusSchema,
  credentialRevision: z.number().int().positive(),
  authorizationRevision: z.number().int().positive(),
  sessionValidAfter: timestampSchema,
  createdAt: timestampSchema,
  createdBy: uidSchema,
  updatedAt: timestampSchema,
  updatedBy: uidSchema,
  revision: z.number().int().positive(),
  pendingOperationId: operationIdSchema.nullable(),
  identityContractVersion: z.literal("2.1"),
  version: z.literal(2)
}).strict().superRefine((user, context) => {
  try {
    if (normalizeIdentityEmail(user.email) !== user.normalizedEmail) throw new Error("mismatch");
  } catch {
    context.addIssue({ code: "custom", path: ["normalizedEmail"], message: "El correo normalizado no coincide" });
  }

  const domain = user.normalizedEmail.slice(user.normalizedEmail.lastIndexOf("@") + 1);
  if (domain !== user.googleWorkspace.authorizedDomain) {
    context.addIssue({ code: "custom", path: ["googleWorkspace", "authorizedDomain"], message: "El correo declarado no pertenece al dominio Workspace autorizado" });
  }

  const linkedAndVerified = user.googleWorkspace.linkingStatus === "linked"
    && user.googleWorkspace.verificationStatus === "verified"
    && user.googleWorkspace.subject !== null
    && user.googleWorkspace.verifiedAt !== null
    && user.googleWorkspace.linkedAt !== null
    && user.emailVerifiedAt !== null;
  if ((user.googleWorkspace.verificationStatus === "unverified" && user.emailVerifiedAt !== null)
    || (user.googleWorkspace.verificationStatus === "verified" && user.emailVerifiedAt === null)) {
    context.addIssue({ code: "custom", path: ["emailVerifiedAt"], message: "El sello de correo debe coincidir con el estado de verificación Google" });
  }
  if (user.activationStatus === "active" && (!linkedAndVerified || user.status !== "active" || user.authDisabled)) {
    context.addIssue({ code: "custom", path: ["activationStatus"], message: "Una identidad Google activa debe estar verificada y vinculada" });
  }
  if (user.activationStatus === "linked_pending_activation"
    && (!linkedAndVerified || user.status !== "invited" || !user.authDisabled)) {
    context.addIssue({
      code: "custom",
      path: ["activationStatus"],
      message: "Una identidad vinculada pendiente de activación debe permanecer invitada y deshabilitada"
    });
  }
  if (user.activationStatus === "pending" && (user.status !== "invited" || !user.authDisabled || user.googleWorkspace.linkingStatus !== "declared")) {
    context.addIssue({ code: "custom", path: ["activationStatus"], message: "Una identidad Google pendiente debe permanecer declarada, invitada y deshabilitada" });
  }
  if (user.activationStatus === "auth_enabled_pending_proof"
    && (user.status !== "invited" || user.authDisabled || user.googleWorkspace.linkingStatus === "linked")) {
    context.addIssue({ code: "custom", path: ["activationStatus"], message: "La prueba pendiente no puede considerarse ya vinculada" });
  }
  if ((user.activationStatus === "reconciliation_required")
    !== (user.googleWorkspace.linkingStatus === "reconciliation_required")) {
    context.addIssue({ code: "custom", path: ["activationStatus"], message: "La conciliación del perfil y de Google debe coincidir" });
  }
  if (user.googleWorkspace.linkingStatus === "linked"
    && user.activationStatus !== "active"
    && user.activationStatus !== "linked_pending_activation") {
    context.addIssue({ code: "custom", path: ["activationStatus"], message: "Una identidad vinculada debe estar activa o pendiente de activación" });
  }
});

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

// Contrato aislado: no forma parte todavía de userProfileDocumentSchema ni de 3C-C.
export const userV21DocumentSchema = z.union([userV2DocumentSchema, googleWorkspaceUserV21DocumentSchema]);

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
export type AuthMethodV21 = z.infer<typeof authMethodV21Schema>;
export type ActivationStatus = z.infer<typeof activationStatusSchema>;
export type GoogleWorkspaceActivationStatus = z.infer<typeof googleWorkspaceActivationStatusSchema>;
export type IdentityIdentifierKind = z.infer<typeof identityIdentifierKindSchema>;
export type IdentityIdentifierKeyDocument = z.infer<typeof identityIdentifierKeyDocumentSchema>;
export type GoogleWorkspaceIdentity = z.infer<typeof googleWorkspaceIdentitySchema>;
export type GoogleWorkspaceUserV21Document = z.infer<typeof googleWorkspaceUserV21DocumentSchema>;
