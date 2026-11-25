import { createHash } from "node:crypto";
import { Timestamp, type Firestore, type Transaction } from "firebase-admin/firestore";
import { z } from "zod";
import type { AdminPrincipal } from "../auth/require-super-admin.js";
import { auditEventDocumentSchema, invitationDocumentSchema } from "../models/admin-collections.js";
import { effectiveInvitationStatus } from "../invitations/invitation-transitions.js";
import { authCoordinationDocumentSchema } from "./identity-auth-coordination-contracts.js";
import {
  completedIdentityLinkOperationSchema,
  employeeInvitationLinkAuthorizationSchema,
  identityLinkAuthorizationSchema,
  evaluateIdentityLinkAuthorization,
  linkGoogleIdentityRequestSchema,
  type IdentityLinkAuthorization,
  type LinkGoogleIdentityRequest
} from "./identity-linking-contracts.js";
import {
  googleWorkspaceUserV21DocumentSchema,
  identifierKeyHash,
  identityIdentifierKeyDocumentSchema,
  normalizeGoogleSubject
} from "./identity-models.js";

const uidSchema = z.string().min(1).max(128).refine((value) => !value.includes("/"));
const timestampSchema = z.instanceof(Timestamp);

const verifiedGoogleIdentitySchema = z.object({
  subject: z.string().min(1).max(255),
  verifiedAt: timestampSchema,
  validUntil: timestampSchema,
  verificationId: z.string().uuid()
}).strict().superRefine((identity, context) => {
  try {
    if (normalizeGoogleSubject(identity.subject) !== identity.subject) throw new Error("mismatch");
  } catch {
    context.addIssue({ code: "custom", path: ["subject"], message: "La identidad verificada requiere un subject canónico" });
  }
  if (identity.validUntil.toMillis() <= identity.verifiedAt.toMillis()) {
    context.addIssue({ code: "custom", path: ["validUntil"], message: "La evidencia verificada requiere vigencia positiva" });
  }
});

const persistedLinkOperationSchema = completedIdentityLinkOperationSchema.extend({
  inputHash: z.string().regex(/^[a-f0-9]{64}$/),
  subjectHash: z.string().regex(/^[a-f0-9]{64}$/),
  authorizationId: z.string().uuid(),
  completedAt: timestampSchema,
  result: z.object({
    operationId: z.string().uuid(),
    uid: uidSchema,
    googleSubjectHash: z.string().regex(/^[a-f0-9]{64}$/),
    revision: z.number().int().positive()
  }).strict(),
  version: z.literal(1)
}).strict();

export type VerifiedGoogleIdentityEvidence = z.infer<typeof verifiedGoogleIdentitySchema>;
export type GoogleIdentityLinkResult = {
  operationId: string;
  uid: string;
  googleSubjectHash: string;
  revision: number;
  replayed: boolean;
};

export type GoogleIdentityLinkErrorCode =
  | "TRUSTED_CONTEXT_MISMATCH"
  | "SUPER_ADMIN_LINK_FORBIDDEN"
  | "PROFILE_NOT_FOUND"
  | "IDENTITY_STATE_INVALID"
  | "REVISION_CONFLICT"
  | "SUBJECT_CONFLICT"
  | "RESERVATION_REQUIRED"
  | "RESERVATION_CONFLICT"
  | "AUTHORIZATION_NOT_FOUND"
  | "AUTHORIZATION_EXPIRED"
  | "AUTHORIZATION_REVOKED"
  | "AUTHORIZATION_CONSUMED"
  | "AUTHORIZATION_MISMATCH"
  | "AUTHORIZATION_INVITATION_CONFLICT"
  | "INVITATION_NOT_FOUND"
  | "INVITATION_NOT_ACTIVE"
  | "INVITATION_UID_MISMATCH"
  | "AUTHORIZATION_NOT_FOUND"
  | "COORDINATION_NOT_FOUND"
  | "COORDINATION_AMBIGUOUS"
  | "COORDINATION_CONTEXT_INVALID"
  | "PROFILE_NOT_FOUND"
  | "RESERVATION_REQUIRED"
  | "RESERVATION_CONFLICT"
  | "LINK_OPERATION_NOT_FOUND"
  | "VERIFICATION_EXPIRED"
  | "IDEMPOTENCY_CONFLICT";

export class GoogleIdentityLinkError extends Error {
  constructor(readonly code: GoogleIdentityLinkErrorCode, message: string) {
    super(message);
    this.name = "GoogleIdentityLinkError";
  }
}

export async function readValidIdentityLinkAuthorization(input: {
  db: Firestore;
  transaction: Transaction;
  authorizationId: string;
  expected: Pick<IdentityLinkAuthorization, "operationId" | "targetUid" | "googleSubjectHash" | "expectedRevision">;
  now: Timestamp;
  allowConsumedLink?: boolean;
}): Promise<IdentityLinkAuthorization> {
  const reference = input.db.collection("identityLinkAuthorizations").doc(input.authorizationId);
  const snapshot = await input.transaction.get(reference);
  if (!snapshot.exists) throw new GoogleIdentityLinkError("AUTHORIZATION_NOT_FOUND", "La autorización requerida no existe.");
  const parsed = identityLinkAuthorizationSchema.safeParse(snapshot.data());
  if (!parsed.success || parsed.data.authorizationId !== input.authorizationId
    || parsed.data.operationId !== input.expected.operationId
    || parsed.data.operation !== "google.identity_link"
    || parsed.data.targetUid !== input.expected.targetUid
    || parsed.data.googleSubjectHash !== input.expected.googleSubjectHash
    || parsed.data.expectedRevision !== input.expected.expectedRevision) {
    throw new GoogleIdentityLinkError("AUTHORIZATION_MISMATCH", "La autorización no corresponde a esta operación.");
  }
  if (parsed.data.state === "consumed" && input.allowConsumedLink === true) {
    if (!parsed.data.invitationId) {
      throw new GoogleIdentityLinkError("AUTHORIZATION_CONSUMED", "La autorización ya fue consumida.");
    }
    if (input.now.toMillis() >= parsed.data.expiresAt.toMillis()) {
      throw new GoogleIdentityLinkError("AUTHORIZATION_EXPIRED", "La autorización vinculada no está vigente.");
    }
    const operationSnapshot = await input.transaction.get(input.db.collection("identityLinkOperations").doc(parsed.data.idempotencyKey));
    const operation = persistedLinkOperationSchema.safeParse(operationSnapshot.data());
    if (!operationSnapshot.exists || !operation.success || operation.data.authorizationId !== parsed.data.authorizationId
      || operation.data.idempotencyKey !== parsed.data.idempotencyKey || operation.data.operationId !== parsed.data.operationId
      || operation.data.targetUid !== parsed.data.targetUid
      || operation.data.googleSubjectHash !== parsed.data.googleSubjectHash || operation.data.subjectHash !== parsed.data.googleSubjectHash
      || operation.data.expectedRevision !== parsed.data.expectedRevision || operation.data.resultingRevision !== parsed.data.expectedRevision + 1
      || operation.data.requestedActivationStatus !== "linked_pending_activation"
      || operation.data.result.operationId !== parsed.data.operationId || operation.data.result.uid !== parsed.data.targetUid
      || operation.data.result.googleSubjectHash !== parsed.data.googleSubjectHash
      || operation.data.result.revision !== operation.data.resultingRevision
      || operation.data.completedAt.toMillis() !== parsed.data.stateChangedAt?.toMillis()) {
      throw new GoogleIdentityLinkError("AUTHORIZATION_MISMATCH", "La autorización consumida no tiene un vínculo E4B2 completado válido.");
    }
    return parsed.data;
  }
  try { evaluateIdentityLinkAuthorization(parsed.data, input.now); }
  catch (error) {
    const code = error instanceof Error && "code" in error ? String(error.code) : "AUTHORIZATION_MISMATCH";
    throw new GoogleIdentityLinkError(code as GoogleIdentityLinkErrorCode, "La autorización no está vigente.");
  }
  return parsed.data;
}

function canonicalHash(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function sameRequest(operation: z.infer<typeof persistedLinkOperationSchema>, request: LinkGoogleIdentityRequest, inputHash: string): boolean {
  return operation.inputHash === inputHash
    && operation.operationId === request.operationId
    && operation.idempotencyKey === request.idempotencyKey
    && operation.authorizationId === request.authorizationId
    && operation.targetUid === request.targetUid
    && operation.subjectHash === request.googleSubjectHash
    && operation.expectedRevision === request.expectedRevision;
}

export class GoogleIdentityLinkingService {
  constructor(
    private readonly db: Firestore,
    private readonly identifierPepper: Buffer,
    private readonly protectedSuperAdminUid: string,
    private readonly now: () => Timestamp = () => Timestamp.now()
  ) {
    if (identifierPepper.length < 32) throw new Error("IDENTIFIER_PEPPER_TOO_SHORT");
    uidSchema.parse(protectedSuperAdminUid);
  }

  /** Internal-only persistence hook. Authentication/approval of the administrator remains upstream. */
  async persistAuthorization(input: unknown): Promise<IdentityLinkAuthorization> {
    const authorization = identityLinkAuthorizationSchema.parse(input);
    if (authorization.invitationId !== undefined) {
      throw new GoogleIdentityLinkError("AUTHORIZATION_MISMATCH", "Use la variante de autorización vinculada a invitación.");
    }
    if (authorization.authorizedByUid !== this.protectedSuperAdminUid) {
      throw new GoogleIdentityLinkError("TRUSTED_CONTEXT_MISMATCH", "La autorización no proviene del administrador protegido.");
    }
    const reference = this.db.collection("identityLinkAuthorizations").doc(authorization.authorizationId);
    await this.persistAuthorizationTransaction(reference, authorization);
    return authorization;
  }

  /** Persists the employee invitation binding from a verified Super Admin request context. */
  async persistEmployeeInvitationAuthorization(input: unknown, principal: AdminPrincipal): Promise<IdentityLinkAuthorization> {
    const authorization = employeeInvitationLinkAuthorizationSchema.parse(input);
    if (principal?.superAdmin !== true || principal.uid !== this.protectedSuperAdminUid
      || authorization.authorizedByUid !== principal.uid) {
      throw new GoogleIdentityLinkError("TRUSTED_CONTEXT_MISMATCH", "La autorización no proviene del administrador autenticado.");
    }
    const reference = this.db.collection("identityLinkAuthorizations").doc(authorization.authorizationId);
    const invitationReference = this.db.collection("invitations").doc(authorization.invitationId);
    await this.db.runTransaction(async (transaction) => {
      const [snapshot, invitationSnapshot] = await Promise.all([
        transaction.get(reference), transaction.get(invitationReference)
      ]);
      if (!invitationSnapshot.exists) {
        throw new GoogleIdentityLinkError("INVITATION_NOT_FOUND", "La invitación no existe.");
      }
      const invitation = invitationDocumentSchema.safeParse(invitationSnapshot.data());
      if (!invitation.success || invitation.data.invitationId !== authorization.invitationId
        || !invitation.data.token || effectiveInvitationStatus(invitation.data, this.now().toMillis()) !== "active"
        || invitation.data.token.expiresAt.toMillis() <= this.now().toMillis()) {
        throw new GoogleIdentityLinkError("INVITATION_NOT_ACTIVE", "La invitación no está activa y vigente.");
      }
      if (invitation.data.uid !== authorization.targetUid) {
        throw new GoogleIdentityLinkError("INVITATION_UID_MISMATCH", "La invitación no corresponde al usuario objetivo.");
      }
      if (snapshot.exists) {
        const existing = identityLinkAuthorizationSchema.safeParse(snapshot.data());
        if (!existing.success) {
          throw new GoogleIdentityLinkError("IDEMPOTENCY_CONFLICT", "El identificador de autorización ya tiene otros parámetros.");
        }
        if (existing.data.invitationId === authorization.invitationId) {
          if (canonicalHash(existing.data) !== canonicalHash(authorization)) {
            throw new GoogleIdentityLinkError("IDEMPOTENCY_CONFLICT", "El identificador de autorización ya tiene otros parámetros.");
          }
          return;
        }
        if (existing.data.invitationId !== undefined) {
          throw new GoogleIdentityLinkError("AUTHORIZATION_INVITATION_CONFLICT", "La autorización ya está vinculada a otra invitación.");
        }
        const { invitationId: _oldInvitationId, ...existingAuthorization } = existing.data;
        const { invitationId: _newInvitationId, ...requestedAuthorization } = authorization;
        if (canonicalHash(existingAuthorization) !== canonicalHash(requestedAuthorization)) {
          throw new GoogleIdentityLinkError("IDEMPOTENCY_CONFLICT", "El identificador de autorización ya tiene otros parámetros.");
        }
        transaction.update(reference, { invitationId: authorization.invitationId });
        return;
      }
      transaction.create(reference, authorization);
    });
    return authorization;
  }

  /** Resolves trusted E4B2 evidence from storage, then binds the referenced active invitation. */
  async bindEmployeeInvitationAuthorization(input: {
    authorizationId: string;
    invitationId: string;
    principal: AdminPrincipal;
  }): Promise<IdentityLinkAuthorization> {
    const authorizationId = z.string().uuid().parse(input.authorizationId);
    const invitationId = z.string().uuid().parse(input.invitationId);
    if (input.principal?.superAdmin !== true || input.principal.uid !== this.protectedSuperAdminUid) {
      throw new GoogleIdentityLinkError("TRUSTED_CONTEXT_MISMATCH", "Se requiere el Super Admin protegido autenticado.");
    }

    const authorizationSnapshot = await this.db.collection("identityLinkAuthorizations").doc(authorizationId).get();
    if (!authorizationSnapshot.exists) throw new GoogleIdentityLinkError("AUTHORIZATION_NOT_FOUND", "La autorización E4B2 no existe.");
    const authorization = identityLinkAuthorizationSchema.safeParse(authorizationSnapshot.data());
    if (!authorization.success || authorization.data.authorizationId !== authorizationId
      || authorization.data.authorizedByUid !== input.principal.uid) {
      throw new GoogleIdentityLinkError("AUTHORIZATION_MISMATCH", "La autorización E4B2 no corresponde al administrador autenticado.");
    }

    const profileRef = this.db.collection("users").doc(authorization.data.targetUid);
    const reservationRef = this.db.collection("authIdentifierKeys").doc(authorization.data.googleSubjectHash);
    const linkOperationRef = this.db.collection("identityLinkOperations").doc(authorization.data.idempotencyKey);
    const [profileSnapshot, reservationSnapshot, linkOperationSnapshot, coordinationSnapshots] = await Promise.all([
      profileRef.get(), reservationRef.get(), linkOperationRef.get(),
      this.db.collection("identityAuthCoordinations").where("authorizationId", "==", authorizationId).limit(2).get()
    ]);

    if (!profileSnapshot.exists) throw new GoogleIdentityLinkError("PROFILE_NOT_FOUND", "No existe el perfil interno del UID autorizado.");
    const profile = googleWorkspaceUserV21DocumentSchema.safeParse(profileSnapshot.data());
    if (!profile.success || profile.data.uid !== authorization.data.targetUid
      || profile.data.googleWorkspace.subject === null
      || profile.data.googleWorkspace.linkingStatus !== "linked"
      || profile.data.googleWorkspace.verificationStatus !== "verified"
      || profile.data.authDisabled !== true
      || profile.data.activationStatus !== "linked_pending_activation") {
      throw new GoogleIdentityLinkError("IDENTITY_STATE_INVALID", "El perfil no contiene la identidad Google vinculada esperada.");
    }
    const subjectHash = identifierKeyHash("googleSubject", normalizeGoogleSubject(profile.data.googleWorkspace.subject), this.identifierPepper);
    if (subjectHash !== authorization.data.googleSubjectHash) {
      throw new GoogleIdentityLinkError("SUBJECT_CONFLICT", "El subject del perfil no coincide con la autorización.");
    }

    if (!reservationSnapshot.exists) throw new GoogleIdentityLinkError("RESERVATION_REQUIRED", "Falta la reserva de la identidad Google.");
    const reservation = identityIdentifierKeyDocumentSchema.safeParse(reservationSnapshot.data());
    if (!reservation.success || reservation.data.kind !== "googleSubject"
      || reservation.data.identifierHash !== subjectHash || reservation.data.uid !== authorization.data.targetUid
      || reservation.data.state !== "reserved") {
      throw new GoogleIdentityLinkError("RESERVATION_CONFLICT", "La reserva Google no corresponde al UID autorizado.");
    }

    if (!linkOperationSnapshot.exists) throw new GoogleIdentityLinkError("LINK_OPERATION_NOT_FOUND", "Falta la operación E4B2 completada.");
    const linkOperation = persistedLinkOperationSchema.safeParse(linkOperationSnapshot.data());
    if (!linkOperation.success || linkOperation.data.authorizationId !== authorizationId
      || linkOperation.data.operationId !== authorization.data.operationId
      || linkOperation.data.targetUid !== authorization.data.targetUid
      || linkOperation.data.subjectHash !== subjectHash
      || linkOperation.data.googleSubjectHash !== subjectHash
      || linkOperation.data.expectedRevision !== authorization.data.expectedRevision
      || linkOperation.data.resultingRevision !== profile.data.revision) {
      throw new GoogleIdentityLinkError("AUTHORIZATION_MISMATCH", "La operación E4B2 no coincide con el perfil ni la autorización.");
    }

    if (coordinationSnapshots.empty) throw new GoogleIdentityLinkError("COORDINATION_NOT_FOUND", "Falta la coordinación de autenticación asociada.");
    if (coordinationSnapshots.size !== 1) throw new GoogleIdentityLinkError("COORDINATION_AMBIGUOUS", "Hay más de una coordinación para la autorización.");
    const coordination = authCoordinationDocumentSchema.safeParse(coordinationSnapshots.docs[0]!.data());
    if (!coordination.success || coordination.data.authorizationId !== authorizationId
      || coordination.data.expectedFirebaseUid !== authorization.data.targetUid
      || coordination.data.expectedInternalUid !== authorization.data.targetUid
      || coordination.data.googleSubjectHash !== subjectHash
      || coordination.data.evidence.firestoreLink.linkOperationId !== authorization.data.operationId
      || coordination.data.evidence.firestoreLink.profileRevision !== profile.data.revision
      || coordination.data.currentProfileRevision !== profile.data.revision
      || !["not_started", "challenge_issued"].includes(coordination.data.state)
      || coordination.data.expiresAt.toMillis() <= this.now().toMillis()) {
      throw new GoogleIdentityLinkError("COORDINATION_CONTEXT_INVALID", "La coordinación no coincide con la identidad E4B2.");
    }

    return this.persistEmployeeInvitationAuthorization({ ...authorization.data, invitationId }, input.principal);
  }

  private async persistAuthorizationTransaction(
    reference: FirebaseFirestore.DocumentReference,
    authorization: IdentityLinkAuthorization
  ): Promise<void> {
    await this.db.runTransaction(async (transaction) => {
      const snapshot = await transaction.get(reference);
      if (snapshot.exists) {
        const existing = identityLinkAuthorizationSchema.safeParse(snapshot.data());
        if (!existing.success || canonicalHash(existing.data) !== canonicalHash(authorization)) {
          throw new GoogleIdentityLinkError("IDEMPOTENCY_CONFLICT", "El identificador de autorización ya tiene otros parámetros.");
        }
        return;
      }
      transaction.create(reference, authorization);
    });
  }

  async linkVerifiedIdentity(input: {
    trustedTargetUid: string;
    trustedAdministratorUid: string;
    request: unknown;
    verifiedIdentity: unknown;
  }): Promise<GoogleIdentityLinkResult> {
    const trustedTargetUid = uidSchema.parse(input.trustedTargetUid);
    const trustedAdministratorUid = uidSchema.parse(input.trustedAdministratorUid);
    const request = linkGoogleIdentityRequestSchema.parse(input.request);
    const verifiedIdentity = verifiedGoogleIdentitySchema.parse(input.verifiedIdentity);
    if (trustedTargetUid !== request.targetUid || trustedAdministratorUid !== this.protectedSuperAdminUid) {
      throw new GoogleIdentityLinkError("TRUSTED_CONTEXT_MISMATCH", "El UID o actor no coincide con el contexto interno confiable.");
    }
    if (trustedTargetUid === this.protectedSuperAdminUid) {
      throw new GoogleIdentityLinkError("SUPER_ADMIN_LINK_FORBIDDEN", "El Super Admin protegido no admite vinculación Google.");
    }

    const subjectHash = identifierKeyHash("googleSubject", verifiedIdentity.subject, this.identifierPepper);
    if (subjectHash !== request.googleSubjectHash) {
      throw new GoogleIdentityLinkError("SUBJECT_CONFLICT", "La identidad verificada no coincide con la solicitud.");
    }
    const inputHash = canonicalHash({
      request,
      verificationId: verifiedIdentity.verificationId,
      verifiedAt: verifiedIdentity.verifiedAt.toMillis(),
      validUntil: verifiedIdentity.validUntil.toMillis()
    });

    const profileRef = this.db.collection("users").doc(trustedTargetUid);
    const reservationRef = this.db.collection("authIdentifierKeys").doc(subjectHash);
    const authorizationRef = this.db.collection("identityLinkAuthorizations").doc(request.authorizationId);
    const operationRef = this.db.collection("identityLinkOperations").doc(request.idempotencyKey);
    const auditRef = this.db.collection("auditEvents").doc(`google-link-${request.operationId}`);

    return this.db.runTransaction(async (transaction) => {
      const [profileSnapshot, reservationSnapshot, authorizationSnapshot, operationSnapshot] = await Promise.all([
        transaction.get(profileRef), transaction.get(reservationRef), transaction.get(authorizationRef), transaction.get(operationRef)
      ]);

      if (operationSnapshot.exists) {
        const operation = persistedLinkOperationSchema.safeParse(operationSnapshot.data());
        if (!operation.success || !sameRequest(operation.data, request, inputHash)) {
          throw new GoogleIdentityLinkError("IDEMPOTENCY_CONFLICT", "La clave idempotente ya fue utilizada con otros parámetros.");
        }
        return { ...operation.data.result, replayed: true };
      }

      const timestamp = this.now();
      if (timestamp.toMillis() >= verifiedIdentity.validUntil.toMillis()) {
        throw new GoogleIdentityLinkError("VERIFICATION_EXPIRED", "La evidencia Google ya no está vigente.");
      }
      if (!authorizationSnapshot.exists) throw new GoogleIdentityLinkError("AUTHORIZATION_NOT_FOUND", "La autorización requerida no existe.");
      const authorization = identityLinkAuthorizationSchema.safeParse(authorizationSnapshot.data());
      if (!authorization.success
        || authorization.data.operation !== request.operation
        || authorization.data.operationId !== request.operationId
        || authorization.data.idempotencyKey !== request.idempotencyKey
        || authorization.data.targetUid !== trustedTargetUid
        || authorization.data.googleSubjectHash !== subjectHash
        || authorization.data.expectedRevision !== request.expectedRevision
        || authorization.data.authorizedByUid !== trustedAdministratorUid) {
        throw new GoogleIdentityLinkError("AUTHORIZATION_MISMATCH", "La autorización no corresponde a esta operación.");
      }
      if (authorization.data.state === "revoked") throw new GoogleIdentityLinkError("AUTHORIZATION_REVOKED", "La autorización fue revocada.");
      if (authorization.data.state === "consumed") throw new GoogleIdentityLinkError("AUTHORIZATION_CONSUMED", "La autorización ya fue consumida.");
      if (authorization.data.state === "expired" || timestamp.toMillis() >= authorization.data.expiresAt.toMillis()) {
        throw new GoogleIdentityLinkError("AUTHORIZATION_EXPIRED", "La autorización expiró.");
      }
      if (!profileSnapshot.exists) throw new GoogleIdentityLinkError("PROFILE_NOT_FOUND", "El UID objetivo no existe.");
      const profile = googleWorkspaceUserV21DocumentSchema.safeParse(profileSnapshot.data());
      if (!profile.success || profile.data.uid !== trustedTargetUid) {
        throw new GoogleIdentityLinkError("IDENTITY_STATE_INVALID", "El perfil no satisface el contrato Google v2.1.");
      }
      const alreadyLinked = profile.data.googleWorkspace.linkingStatus === "linked"
        && profile.data.activationStatus === "linked_pending_activation";
      if (profile.data.status === "disabled"
        || profile.data.activationStatus === "reconciliation_required"
        || (profile.data.googleWorkspace.linkingStatus !== "verified" && !alreadyLinked)
        || profile.data.googleWorkspace.verificationStatus !== "verified"
        || profile.data.authDisabled !== true) {
        throw new GoogleIdentityLinkError("IDENTITY_STATE_INVALID", "El estado actual no permite vinculación.");
      }
      if (profile.data.revision !== request.expectedRevision) {
        throw new GoogleIdentityLinkError("REVISION_CONFLICT", "La revisión esperada está obsoleta.");
      }
      if (profile.data.googleWorkspace.subject !== verifiedIdentity.subject) {
        throw new GoogleIdentityLinkError("SUBJECT_CONFLICT", "El subject verificado difiere del perfil.");
      }

      if (!reservationSnapshot.exists) throw new GoogleIdentityLinkError("RESERVATION_REQUIRED", "La reserva googleSubject es obligatoria.");
      const reservation = identityIdentifierKeyDocumentSchema.safeParse(reservationSnapshot.data());
      if (!reservation.success
        || reservation.data.kind !== "googleSubject"
        || reservation.data.identifierHash !== subjectHash
        || reservation.data.state !== "reserved"
        || reservation.data.uid !== trustedTargetUid) {
        throw new GoogleIdentityLinkError("RESERVATION_CONFLICT", "La reserva googleSubject no pertenece al UID objetivo.");
      }

      const revision = profile.data.revision + 1;
      const linkedProfile = googleWorkspaceUserV21DocumentSchema.parse({
        ...profile.data,
        authDisabled: true,
        activationStatus: "linked_pending_activation",
        googleWorkspace: {
          ...profile.data.googleWorkspace,
          linkingStatus: "linked",
          linkedAt: alreadyLinked ? profile.data.googleWorkspace.linkedAt : timestamp,
          operationId: null
        },
        credentialRevision: alreadyLinked ? profile.data.credentialRevision : profile.data.credentialRevision + 1,
        updatedAt: timestamp,
        updatedBy: trustedAdministratorUid,
        revision,
        pendingOperationId: null
      });
      const result = { operationId: request.operationId, uid: trustedTargetUid, googleSubjectHash: subjectHash, revision };
      const operation = persistedLinkOperationSchema.parse({
        ...request,
        status: "completed",
        resultingRevision: revision,
        inputHash,
        subjectHash,
        completedAt: timestamp,
        result,
        version: 1
      });
      const audit = auditEventDocumentSchema.parse({
        occurredAt: timestamp,
        actorType: "admin",
        actorUid: trustedAdministratorUid,
        actorEmail: null,
        providerEventId: null,
        action: alreadyLinked ? "google.identity_link_reconfirmed" : "google.identity_linked",
        resourceType: "user",
        resourceId: trustedTargetUid,
        targetUid: trustedTargetUid,
        appId: null,
        before: { linkingStatus: profile.data.googleWorkspace.linkingStatus, revision: profile.data.revision },
        after: { linkingStatus: "linked", activationStatus: "linked_pending_activation", authDisabled: true, revision, googleSubjectHash: subjectHash },
        reason: authorization.data.reason,
        requestId: request.operationId,
        source: "admin-api",
        result: "success",
        version: 1
      });

      transaction.set(profileRef, linkedProfile);
      transaction.update(authorizationRef, { state: "consumed", stateChangedAt: timestamp });
      transaction.create(operationRef, operation);
      transaction.create(auditRef, audit);
      return { ...result, replayed: false };
    });
  }
}
