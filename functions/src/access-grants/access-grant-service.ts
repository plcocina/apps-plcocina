import { createHash, randomUUID } from "node:crypto";
import { Timestamp, type Firestore, type QueryDocumentSnapshot } from "firebase-admin/firestore";
import { z } from "zod";
import type { AdminPrincipal } from "../auth/require-super-admin.js";
import { ApiError } from "../http/errors.js";
import {
  accessGrantDocumentSchema,
  adminOperationDocumentSchema,
  applicationDocumentSchema,
  auditEventDocumentSchema,
  userDocumentSchema,
  type AccessGrantDocument,
  type ApplicationDocument,
  type UserDocument
} from "../models/admin-collections.js";
import type { DirectoryUser, UserDirectory } from "../users/user-query-service.js";

const userIdSchema = z.string().trim().min(1).max(128).refine((value) => !value.includes("/"));
const applicationIdSchema = z.string().regex(/^[a-zA-Z0-9_-]{1,128}$/);
const mutationSchema = z.object({
  expectedRevision: z.number().int().nonnegative(),
  reason: z.string().trim().min(3).max(500).optional()
}).strict();
const idempotencyKeySchema = z.string().uuid();

type Action = "grant" | "revoke";
export type AccessGrantResult = {
  operationId: string;
  grantId: string;
  userId: string;
  applicationId: string;
  status: AccessGrantDocument["status"];
  revision: number;
  changed: boolean;
};

function parse<T>(schema: z.ZodType<T>, value: unknown, message: string): T {
  const result = schema.safeParse(value);
  if (!result.success) throw new ApiError(400, "VALIDATION_ERROR", message);
  return result.data;
}

function authCode(error: unknown): string | undefined {
  return typeof error === "object" && error !== null && "code" in error ? String(error.code) : undefined;
}

export function accessGrantId(userIdInput: string, applicationIdInput: string): string {
  const userId = parse(userIdSchema, userIdInput, "El identificador de usuario no es válido.");
  const applicationId = parse(applicationIdSchema, applicationIdInput, "El identificador de aplicación no es válido.");
  return createHash("sha256").update(`v1\0${userId}\0${applicationId}`).digest("hex");
}

function inputHash(action: Action, userId: string, applicationId: string, expectedRevision: number, reason: string | null): string {
  return createHash("sha256").update(JSON.stringify({ action, userId, applicationId, expectedRevision, reason })).digest("hex");
}

function publicGrant(grantId: string, grant: AccessGrantDocument) {
  return {
    grantId,
    userId: grant.userId,
    applicationId: grant.applicationId,
    status: grant.status,
    createdAt: grant.createdAt.toDate().toISOString(),
    updatedAt: grant.updatedAt.toDate().toISOString(),
    revokedAt: grant.revokedAt?.toDate().toISOString() ?? null,
    revision: grant.revision
  };
}

export class AccessGrantService {
  constructor(
    private readonly db: Firestore,
    private readonly directory: UserDirectory,
    private readonly now = () => Timestamp.now()
  ) {}

  async listForUser(userIdInput: string) {
    const userId = parse(userIdSchema, userIdInput, "El identificador de usuario no es válido.");
    await this.validUser(userId);
    const snapshot = await this.db.collection("accessGrants").where("userId", "==", userId).limit(500).get();
    return this.sorted(snapshot.docs);
  }

  async listForApplication(applicationIdInput: string) {
    const applicationId = parse(applicationIdSchema, applicationIdInput, "El identificador de aplicación no es válido.");
    await this.validApplication(applicationId);
    const snapshot = await this.db.collection("accessGrants").where("applicationId", "==", applicationId).limit(500).get();
    return this.sorted(snapshot.docs);
  }

  async execute(input: {
    action: Action;
    userId: string;
    applicationId: string;
    body: unknown;
    idempotencyKey: string | undefined;
    principal: AdminPrincipal;
    requestId: string;
  }): Promise<AccessGrantResult> {
    const userId = parse(userIdSchema, input.userId, "El identificador de usuario no es válido.");
    const applicationId = parse(applicationIdSchema, input.applicationId, "El identificador de aplicación no es válido.");
    const body = parse(mutationSchema, input.body, "Los datos de la operación no son válidos.");
    if (input.action === "revoke" && !body.reason) throw new ApiError(400, "VALIDATION_ERROR", "Indica el motivo de la revocación.");
    if (!input.idempotencyKey) throw new ApiError(400, "IDEMPOTENCY_REQUIRED", "Se requiere una clave de idempotencia UUID.");
    const operationId = parse(idempotencyKeySchema, input.idempotencyKey, "La clave de idempotencia no es válida.");
    const hash = inputHash(input.action, userId, applicationId, body.expectedRevision, body.reason ?? null);
    const operationRef = this.db.collection("adminOperations").doc(operationId);
    const existing = await operationRef.get();
    if (existing.exists) return this.replay(existing.data(), input.action, userId, applicationId, input.principal.uid, hash);

    const authUser = await this.validUser(userId);
    return this.db.runTransaction(async (transaction) => {
      const grantId = accessGrantId(userId, applicationId);
      const grantRef = this.db.collection("accessGrants").doc(grantId);
      const userRef = this.db.collection("users").doc(userId);
      const applicationRef = this.db.collection("applications").doc(applicationId);
      const [operationSnapshot, grantSnapshot, userSnapshot, applicationSnapshot] = await Promise.all([
        transaction.get(operationRef), transaction.get(grantRef), transaction.get(userRef), transaction.get(applicationRef)
      ]);
      if (operationSnapshot.exists) return this.replay(operationSnapshot.data(), input.action, userId, applicationId, input.principal.uid, hash);

      this.parseUser(userSnapshot.data(), authUser);
      const application = this.parseApplication(applicationSnapshot.data());
      if (application.appId !== applicationId) throw new ApiError(409, "PROFILE_INCONSISTENT", "La aplicación no corresponde al recurso solicitado.");
      if (application.accessLevel === "public") throw new ApiError(409, "GRANT_NOT_REQUIRED", "La aplicación pública no requiere permisos individuales.");
      if (input.action === "grant" && application.status !== "active") {
        throw new ApiError(409, "INVALID_STATE_TRANSITION", "No se puede conceder acceso a una aplicación inactiva o archivada.");
      }
      const current = grantSnapshot.exists
        ? accessGrantDocumentSchema.parse(grantSnapshot.data())
        : null;
      if (current && (current.userId !== userId || current.applicationId !== applicationId)) {
        throw new ApiError(409, "PROFILE_INCONSISTENT", "El permiso almacenado no corresponde al recurso solicitado.");
      }
      const currentRevision = current?.revision ?? 0;
      if (body.expectedRevision !== currentRevision) throw new ApiError(409, "REVISION_CONFLICT", "El permiso cambió. Recarga los datos.");
      if (input.action === "revoke" && !current) throw new ApiError(404, "NOT_FOUND", "El permiso no existe.");

      const timestamp = this.now();
      const changed = input.action === "grant" ? current?.status !== "active" : current?.status !== "revoked";
      let grant: AccessGrantDocument;
      if (!changed) {
        grant = current!;
      } else if (input.action === "grant") {
        grant = accessGrantDocumentSchema.parse({
          userId, applicationId, status: "active",
          createdAt: current?.createdAt ?? timestamp, createdBy: current?.createdBy ?? input.principal.uid,
          updatedAt: timestamp, updatedBy: input.principal.uid,
          revokedAt: null, revokedBy: null, revokeReason: null,
          revision: currentRevision + 1, version: 1
        });
      } else {
        grant = accessGrantDocumentSchema.parse({
          ...current!, status: "revoked", updatedAt: timestamp, updatedBy: input.principal.uid,
          revokedAt: timestamp, revokedBy: input.principal.uid, revokeReason: body.reason,
          revision: currentRevision + 1
        });
      }

      const result: AccessGrantResult = {
        operationId, grantId, userId, applicationId, status: grant.status, revision: grant.revision, changed
      };
      if (changed) {
        transaction.set(grantRef, grant);
        transaction.create(this.db.collection("auditEvents").doc(randomUUID()), auditEventDocumentSchema.parse({
          occurredAt: timestamp, actorType: "admin", actorUid: input.principal.uid,
          actorEmail: input.principal.email ?? "unknown@plcocina.invalid", providerEventId: null,
          action: `access_grant.${input.action === "grant" ? "granted" : "revoked"}`,
          resourceType: "accessGrant", resourceId: grantId, targetUid: userId, appId: applicationId,
          before: current, after: grant, reason: body.reason ?? null, requestId: input.requestId,
          source: "admin-api", result: "success", version: 1
        }));
      }
      transaction.create(operationRef, adminOperationDocumentSchema.parse({
        operationId, type: `access_grant.${input.action}`, targetUid: userId, appId: applicationId,
        invitationId: null, actorUid: input.principal.uid, inputHash: hash,
        expectedRevision: body.expectedRevision, status: "completed", checkpoint: "completed",
        requestId: input.requestId, leaseOwner: input.requestId, leaseExpiresAt: timestamp,
        attempts: 1, result, failureCode: null, createdAt: timestamp, updatedAt: timestamp,
        completedAt: timestamp, version: 1
      }));
      return result;
    });
  }

  private sorted(docs: QueryDocumentSnapshot[]) {
    return docs.map((snapshot) => publicGrant(snapshot.id, accessGrantDocumentSchema.parse(snapshot.data())))
      .sort((left, right) => right.updatedAt.localeCompare(left.updatedAt));
  }

  private async validUser(userId: string): Promise<DirectoryUser> {
    const authUser = await this.directory.getUser(userId).catch((error) => {
      if (authCode(error) === "auth/user-not-found") throw new ApiError(404, "NOT_FOUND", "El usuario no existe.");
      throw error;
    });
    const profile = await this.db.collection("users").doc(userId).get();
    this.parseUser(profile.data(), authUser);
    return authUser;
  }

  private parseUser(data: unknown, authUser: DirectoryUser): UserDocument {
    const parsed = userDocumentSchema.safeParse(data);
    if (!parsed.success) throw new ApiError(409, data ? "PROFILE_INCONSISTENT" : "PROFILE_REQUIRED", "El perfil del usuario no está listo para administrar permisos.");
    const user = parsed.data;
    if (authUser.disabled || user.authDisabled || user.status !== "active") {
      throw new ApiError(409, "INVALID_STATE_TRANSITION", "El usuario está suspendido o no está activo.");
    }
    if (!authUser.email || user.normalizedEmail !== authUser.email.toLowerCase()) {
      throw new ApiError(409, "PROFILE_INCONSISTENT", "El perfil no coincide con Firebase Authentication.");
    }
    return user;
  }

  private async validApplication(applicationId: string): Promise<ApplicationDocument> {
    const snapshot = await this.db.collection("applications").doc(applicationId).get();
    const application = this.parseApplication(snapshot.data());
    if (application.appId !== applicationId) throw new ApiError(409, "PROFILE_INCONSISTENT", "La aplicación no corresponde al recurso solicitado.");
    return application;
  }

  private parseApplication(data: unknown): ApplicationDocument {
    if (!data) throw new ApiError(404, "NOT_FOUND", "La aplicación no existe.");
    const parsed = applicationDocumentSchema.safeParse(data);
    if (!parsed.success) throw new ApiError(409, "PROFILE_INCONSISTENT", "La aplicación tiene una configuración inconsistente.");
    return parsed.data;
  }

  private replay(data: unknown, action: Action, userId: string, applicationId: string, actorUid: string, hash: string): AccessGrantResult {
    const operation = adminOperationDocumentSchema.safeParse(data);
    if (!operation.success
      || operation.data.type !== `access_grant.${action}`
      || operation.data.targetUid !== userId
      || operation.data.appId !== applicationId
      || operation.data.actorUid !== actorUid
      || operation.data.inputHash !== hash) {
      throw new ApiError(409, "IDEMPOTENCY_CONFLICT", "La clave de idempotencia ya fue usada con otros datos.");
    }
    if (operation.data.status !== "completed" || !operation.data.result) {
      throw new ApiError(409, "OPERATION_IN_PROGRESS", "La operación todavía está en proceso.");
    }
    return operation.data.result as AccessGrantResult;
  }
}
