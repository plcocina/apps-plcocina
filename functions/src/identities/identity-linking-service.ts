import { createHash } from "node:crypto";
import { Timestamp, type Firestore } from "firebase-admin/firestore";
import { z } from "zod";
import { auditEventDocumentSchema } from "../models/admin-collections.js";
import {
  completedIdentityLinkOperationSchema,
  identityLinkAuthorizationSchema,
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
  | "VERIFICATION_EXPIRED"
  | "IDEMPOTENCY_CONFLICT";

export class GoogleIdentityLinkError extends Error {
  constructor(readonly code: GoogleIdentityLinkErrorCode, message: string) {
    super(message);
    this.name = "GoogleIdentityLinkError";
  }
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
    if (authorization.authorizedByUid !== this.protectedSuperAdminUid) {
      throw new GoogleIdentityLinkError("TRUSTED_CONTEXT_MISMATCH", "La autorización no proviene del administrador protegido.");
    }
    const reference = this.db.collection("identityLinkAuthorizations").doc(authorization.authorizationId);
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
    return authorization;
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
      if (profile.data.status === "disabled"
        || profile.data.activationStatus === "reconciliation_required"
        || profile.data.googleWorkspace.linkingStatus !== "verified"
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
          linkedAt: timestamp,
          operationId: null
        },
        credentialRevision: profile.data.credentialRevision + 1,
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
        action: "google.identity_linked",
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
