import { createHash, randomUUID } from "node:crypto";
import { Timestamp, type Firestore } from "firebase-admin/firestore";
import { z } from "zod";
import type { AdminPrincipal } from "../auth/require-super-admin.js";
import { ApiError } from "../http/errors.js";
import {
  adminOperationDocumentSchema,
  auditEventDocumentSchema,
  userDocumentSchema,
  type UserDocument
} from "../models/admin-collections.js";
import type { DirectoryUser, UserDirectory } from "./user-query-service.js";

export type UserControlAction = "suspend" | "reactivate" | "revoke-sessions";

const uidSchema = z.string().trim().min(1).max(128).refine((value) => !value.includes("/"));
const idempotencyKeySchema = z.string().uuid();
const baseActionSchema = z.object({
  expectedRevision: z.number().int().positive(),
  reason: z.string().trim().min(3).max(500).optional()
}).strict();

export type UserOperationResult = {
  operationId: string;
  uid: string;
  action: UserControlAction;
  status: "invited" | "active" | "disabled";
  authDisabled: boolean;
  sessionsRevoked: boolean;
  revision: number;
};

function parseInput(action: UserControlAction, value: unknown) {
  const result = baseActionSchema.safeParse(value);
  if (!result.success) {
    throw new ApiError(400, "VALIDATION_ERROR", result.error.issues[0]?.message ?? "Datos no válidos.");
  }
  if ((action === "suspend" || action === "revoke-sessions") && !result.data.reason) {
    throw new ApiError(400, "VALIDATION_ERROR", "Se requiere un motivo de al menos 3 caracteres.");
  }
  return result.data;
}

function operationType(action: UserControlAction) {
  return action === "suspend" ? "user.suspend" as const :
    action === "reactivate" ? "user.reactivate" as const : "user.revoke_sessions" as const;
}

function auditAction(action: UserControlAction) {
  return action === "suspend" ? "user.suspended" :
    action === "reactivate" ? "user.reactivated" : "user.sessions_revoked";
}

function inputHash(action: UserControlAction, uid: string, expectedRevision: number, reason?: string) {
  return createHash("sha256")
    .update(JSON.stringify({ action, uid, expectedRevision, reason: reason ?? null }))
    .digest("hex");
}

function profileProjection(value: UserDocument) {
  return {
    status: value.status,
    authDisabled: value.authDisabled,
    revision: value.revision
  };
}

function authCode(error: unknown) {
  return typeof error === "object" && error !== null && "code" in error ? String(error.code) : "AUTH_OPERATION_FAILED";
}

export class UserControlService {
  constructor(
    private readonly directory: UserDirectory,
    private readonly db: Firestore,
    private readonly protectedUid: string | null,
    private readonly now: () => Timestamp = () => Timestamp.now()
  ) {}

  async execute(input: {
    action: UserControlAction;
    uid: string;
    body: unknown;
    idempotencyKey: string | undefined;
    principal: AdminPrincipal;
    requestId: string;
  }): Promise<UserOperationResult> {
    const uid = uidSchema.safeParse(input.uid);
    if (!uid.success) throw new ApiError(400, "VALIDATION_ERROR", "El identificador de usuario no es válido.");
    const key = idempotencyKeySchema.safeParse(input.idempotencyKey);
    if (!key.success) throw new ApiError(400, "IDEMPOTENCY_REQUIRED", "Se requiere un encabezado Idempotency-Key UUID válido.");
    if (!this.protectedUid) {
      throw new ApiError(503, "INTERNAL_ERROR", "El control de cuentas no está configurado de forma segura.");
    }
    if (!input.principal.email) {
      throw new ApiError(403, "ADMIN_REQUIRED", "La cuenta administrativa requiere un correo válido.");
    }

    const body = parseInput(input.action, input.body);
    const target = await this.directory.getUser(uid.data).catch((error) => {
      if (authCode(error) === "auth/user-not-found") {
        throw new ApiError(404, "NOT_FOUND", "El usuario no existe en Authentication.");
      }
      throw error;
    });
    this.assertMutableTarget(target, input.principal.uid);

    const operationRef = this.db.collection("adminOperations").doc(key.data);
    const profileRef = this.db.collection("users").doc(uid.data);
    const hash = inputHash(input.action, uid.data, body.expectedRevision, body.reason);
    const now = this.now();
    const leaseExpiresAt = Timestamp.fromMillis(now.toMillis() + 60_000);

    const reservation = await this.db.runTransaction(async (transaction) => {
      const [operationSnapshot, profileSnapshot] = await Promise.all([
        transaction.get(operationRef),
        transaction.get(profileRef)
      ]);

      if (!profileSnapshot.exists) throw new ApiError(409, "PROFILE_REQUIRED", "La cuenta no tiene un perfil administrativo.");
      const parsedProfile = userDocumentSchema.safeParse(profileSnapshot.data());
      if (!parsedProfile.success) throw new ApiError(409, "PROFILE_INCONSISTENT", "El perfil administrativo no es válido.");
      const profile = parsedProfile.data;

      if (operationSnapshot.exists) {
        const parsedOperation = adminOperationDocumentSchema.safeParse(operationSnapshot.data());
        if (!parsedOperation.success) throw new ApiError(409, "IDEMPOTENCY_CONFLICT", "La operación idempotente existente no es válida.");
        const operation = parsedOperation.data;
        if (operation.inputHash !== hash || operation.actorUid !== input.principal.uid || operation.targetUid !== uid.data) {
          throw new ApiError(409, "IDEMPOTENCY_CONFLICT", "La clave idempotente ya fue usada con otra solicitud.");
        }
        if (operation.status === "completed") return { completed: operation.result as UserOperationResult, skipAuth: true };
        if (profile.pendingOperationId !== key.data) {
          throw new ApiError(409, "PROFILE_INCONSISTENT", "La reserva de la operación no coincide con el perfil.");
        }
        if (operation.status === "pending" && operation.leaseExpiresAt.toMillis() > now.toMillis() && operation.leaseOwner !== input.requestId) {
          throw new ApiError(409, "OPERATION_IN_PROGRESS", "La operación ya está en curso.");
        }
        transaction.update(operationRef, {
          leaseOwner: input.requestId,
          leaseExpiresAt,
          requestId: input.requestId,
          attempts: operation.attempts + 1,
          updatedAt: now,
          failureCode: null
        });
        return { completed: null, skipAuth: operation.status === "auth_applied" };
      }

      if (profile.pendingOperationId) throw new ApiError(409, "OPERATION_IN_PROGRESS", "Otra operación sobre la cuenta está en curso.");
      if (profile.revision !== body.expectedRevision) throw new ApiError(409, "REVISION_CONFLICT", "El perfil cambió desde la última consulta.");
      this.assertConsistent(profile, target);
      this.assertTransition(input.action, profile);

      transaction.create(operationRef, {
        operationId: key.data,
        type: operationType(input.action),
        targetUid: uid.data,
        actorUid: input.principal.uid,
        inputHash: hash,
        expectedRevision: body.expectedRevision,
        status: "pending",
        requestId: input.requestId,
        leaseOwner: input.requestId,
        leaseExpiresAt,
        attempts: 1,
        result: null,
        failureCode: null,
        createdAt: now,
        updatedAt: now,
        completedAt: null,
        version: 1
      });
      transaction.update(profileRef, { pendingOperationId: key.data });
      return { completed: null, skipAuth: false };
    });

    if (reservation.completed) return reservation.completed;

    try {
      if (!reservation.skipAuth) await this.applyAuth(input.action, uid.data);
      await this.db.runTransaction(async (transaction) => {
        const snapshot = await transaction.get(operationRef);
        const operation = adminOperationDocumentSchema.parse(snapshot.data());
        if (operation.leaseOwner !== input.requestId) throw new ApiError(409, "OPERATION_IN_PROGRESS", "La operación fue reclamada por otra solicitud.");
        transaction.update(operationRef, { status: "auth_applied", updatedAt: this.now() });
      });
      return await this.finalize({
        operationRef,
        profileRef,
        operationId: key.data,
        action: input.action,
        uid: uid.data,
        expectedRevision: body.expectedRevision,
        reason: body.reason,
        principal: input.principal as AdminPrincipal & { email: string },
        requestId: input.requestId
      });
    } catch (error) {
      if (error instanceof ApiError && error.code === "OPERATION_IN_PROGRESS") throw error;
      await this.markForRecovery(
        operationRef,
        input.action,
        uid.data,
        body.reason,
        input.principal as AdminPrincipal & { email: string },
        input.requestId,
        authCode(error)
      );
      throw new ApiError(500, "INTERNAL_ERROR", "La operación quedó pendiente de recuperación segura.");
    }
  }

  private assertMutableTarget(target: DirectoryUser, actorUid: string) {
    if (target.uid === actorUid || target.uid === this.protectedUid || target.customClaims?.super_admin === true) {
      throw new ApiError(409, "PROTECTED_ACCOUNT", "La cuenta está protegida y no puede modificarse.");
    }
  }

  private assertConsistent(profile: UserDocument, target: DirectoryUser) {
    if (!target.email || profile.normalizedEmail !== target.email.toLowerCase() || profile.authDisabled !== target.disabled) {
      throw new ApiError(409, "PROFILE_INCONSISTENT", "Authentication y el perfil no son consistentes.");
    }
  }

  private assertTransition(action: UserControlAction, profile: UserDocument) {
    if (action === "suspend" && profile.authDisabled) {
      throw new ApiError(409, "INVALID_STATE_TRANSITION", "La cuenta ya está suspendida.");
    }
    if (action === "reactivate" && (!profile.authDisabled || profile.status !== "disabled")) {
      throw new ApiError(409, "INVALID_STATE_TRANSITION", "Sólo una cuenta suspendida puede reactivarse.");
    }
  }

  private async applyAuth(action: UserControlAction, uid: string) {
    if (action === "suspend") {
      await this.directory.updateUser(uid, { disabled: true });
      await this.directory.revokeRefreshTokens(uid);
    } else if (action === "reactivate") {
      await this.directory.updateUser(uid, { disabled: false });
    } else {
      await this.directory.revokeRefreshTokens(uid);
    }
  }

  private async finalize(input: {
    operationRef: FirebaseFirestore.DocumentReference;
    profileRef: FirebaseFirestore.DocumentReference;
    operationId: string;
    action: UserControlAction;
    uid: string;
    expectedRevision: number;
    reason: string | undefined;
    principal: AdminPrincipal & { email: string };
    requestId: string;
  }) {
    return this.db.runTransaction(async (transaction) => {
      const [operationSnapshot, profileSnapshot] = await Promise.all([
        transaction.get(input.operationRef),
        transaction.get(input.profileRef)
      ]);
      const operation = adminOperationDocumentSchema.parse(operationSnapshot.data());
      const profile = userDocumentSchema.parse(profileSnapshot.data());
      if (operation.status === "completed") return operation.result as UserOperationResult;
      if (operation.status !== "auth_applied" || operation.leaseOwner !== input.requestId || profile.pendingOperationId !== input.operationId) {
        throw new ApiError(409, "OPERATION_IN_PROGRESS", "La operación no puede finalizarse desde esta solicitud.");
      }
      if (profile.revision !== input.expectedRevision) throw new ApiError(409, "REVISION_CONFLICT", "El perfil cambió durante la operación.");

      const timestamp = this.now();
      const authDisabled = input.action === "suspend" ? true : input.action === "reactivate" ? false : profile.authDisabled;
      const status = input.action === "suspend" ? "disabled" as const : input.action === "reactivate" ? "active" as const : profile.status;
      const updated = userDocumentSchema.parse({
        ...profile,
        authDisabled,
        status,
        updatedAt: timestamp,
        updatedBy: input.principal.uid,
        revision: profile.revision + 1,
        pendingOperationId: null
      });
      const result: UserOperationResult = {
        operationId: input.operationId,
        uid: input.uid,
        action: input.action,
        status: updated.status,
        authDisabled: updated.authDisabled,
        sessionsRevoked: input.action !== "reactivate",
        revision: updated.revision
      };
      const auditRef = this.db.collection("auditEvents").doc(randomUUID());
      const audit = auditEventDocumentSchema.parse({
        occurredAt: timestamp,
        actorUid: input.principal.uid,
        actorEmail: input.principal.email,
        action: auditAction(input.action),
        resourceType: "user",
        resourceId: input.uid,
        targetUid: input.uid,
        appId: null,
        before: profileProjection(profile),
        after: profileProjection(updated),
        reason: input.reason ?? null,
        requestId: input.requestId,
        source: "admin-api",
        result: "success",
        version: 1
      });
      transaction.set(input.profileRef, updated);
      transaction.create(auditRef, audit);
      transaction.update(input.operationRef, {
        status: "completed",
        result,
        failureCode: null,
        updatedAt: timestamp,
        completedAt: timestamp
      });
      return result;
    });
  }

  private async markForRecovery(
    operationRef: FirebaseFirestore.DocumentReference,
    action: UserControlAction,
    uid: string,
    reason: string | undefined,
    principal: AdminPrincipal & { email: string },
    requestId: string,
    failureCode: string
  ) {
    const timestamp = this.now();
    await this.db.runTransaction(async (transaction) => {
      const snapshot = await transaction.get(operationRef);
      if (!snapshot.exists) return;
      const operation = adminOperationDocumentSchema.parse(snapshot.data());
      if (operation.status === "completed") return;
      const auditRef = this.db.collection("auditEvents").doc(randomUUID());
      transaction.update(operationRef, {
        status: "reconciliation_required",
        failureCode: failureCode.replace(/[^A-Za-z0-9_]/g, "_").toUpperCase().slice(0, 80) || "AUTH_OPERATION_FAILED",
        updatedAt: timestamp,
        leaseExpiresAt: timestamp
      });
      transaction.create(auditRef, auditEventDocumentSchema.parse({
        occurredAt: timestamp,
        actorUid: principal.uid,
        actorEmail: principal.email,
        action: auditAction(action),
        resourceType: "user",
        resourceId: uid,
        targetUid: uid,
        appId: null,
        before: null,
        after: null,
        reason: reason ?? null,
        requestId,
        source: "admin-api",
        result: "failure",
        version: 1
      }));
    });
  }
}
