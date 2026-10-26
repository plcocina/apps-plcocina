import { createHash, randomUUID } from "node:crypto";
import { Timestamp, type Firestore } from "firebase-admin/firestore";
import { z } from "zod";
import type { AdminPrincipal } from "../auth/require-super-admin.js";
import { ApiError } from "../http/errors.js";
import {
  adminOperationDocumentSchema,
  invitationDocumentSchema,
  userDocumentSchema,
  type InvitationDocument
} from "../models/admin-collections.js";
import type { DirectoryUser, UserDirectory } from "../users/user-query-service.js";
import { InvitationEmailProviderError, type InvitationEmailProvider } from "./invitation-email-provider.js";
import { effectiveInvitationStatus } from "./invitation-transitions.js";
import {
  INVITATION_DEFAULT_HOURS,
  INVITATION_MAX_HOURS,
  InvitationTokenKeyring
} from "./invitation-token.js";

const createInvitationSchema = z.object({
  displayName: z.string().trim().min(1).max(160),
  email: z.string().trim().email().max(254).transform((value) => value.toLowerCase()),
  expiresInHours: z.number().int().min(1).max(INVITATION_MAX_HOURS).default(INVITATION_DEFAULT_HOURS)
}).strict();
const keySchema = z.string().uuid();
const invitationIdSchema = z.string().uuid();
const resendInvitationSchema = z.object({
  expectedRevision: z.number().int().positive(),
  expiresInHours: z.number().int().min(1).max(INVITATION_MAX_HOURS).default(INVITATION_DEFAULT_HOURS)
}).strict();
const revokeInvitationSchema = z.object({
  expectedRevision: z.number().int().positive(),
  reason: z.string().trim().min(3).max(500)
}).strict();

export type InvitationResult = {
  invitationId: string;
  uid: string;
  email: string;
  displayName: string;
  status: "active" | "expired" | "revoked" | "reconciliation_required";
  deliveryStatus: InvitationDocument["delivery"]["status"];
  expiresAt: string;
  revision: number;
};

function authCode(error: unknown) {
  return typeof error === "object" && error !== null && "code" in error ? String(error.code) : undefined;
}

function canonicalHash(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function deterministicUid(invitationId: string) {
  return `inv_${createHash("sha256").update(`plcocina:${invitationId}`).digest("hex").slice(0, 40)}`;
}

function uniqueEmailId(normalizedEmail: string) {
  return createHash("sha256").update(normalizedEmail).digest("hex");
}

function deterministicOperationId(namespace: string, value: string) {
  const hex = createHash("sha256").update(`${namespace}:${value}`).digest("hex").slice(0, 32).split("");
  hex[12] = "5";
  hex[16] = ((Number.parseInt(hex[16]!, 16) & 3) | 8).toString(16);
  return `${hex.slice(0, 8).join("")}-${hex.slice(8, 12).join("")}-${hex.slice(12, 16).join("")}-${hex.slice(16, 20).join("")}-${hex.slice(20).join("")}`;
}

function publicResult(invitation: InvitationDocument, now?: Timestamp): InvitationResult {
  const status = now ? effectiveInvitationStatus(invitation, now.toMillis()) : invitation.status;
  if (!["active", "expired", "revoked", "reconciliation_required"].includes(status)) {
    throw new ApiError(409, "INVALID_STATE_TRANSITION", "La invitación todavía no tiene un estado publicable.");
  }
  return {
    invitationId: invitation.invitationId,
    uid: invitation.uid,
    email: invitation.email,
    displayName: invitation.displayName,
    status: status as InvitationResult["status"],
    deliveryStatus: invitation.delivery.status,
    expiresAt: invitation.expiresAt.toDate().toISOString(),
    revision: invitation.revision
  };
}

export class InvitationService {
  constructor(
    private readonly directory: UserDirectory,
    private readonly db: Firestore,
    private readonly tokens: InvitationTokenKeyring | null,
    private readonly emailProvider: InvitationEmailProvider,
    private readonly protectedUid: string | null,
    private readonly now: () => Timestamp = () => Timestamp.now()
  ) {}

  async create(input: {
    body: unknown;
    idempotencyKey: string | undefined;
    principal: AdminPrincipal;
    requestId: string;
  }): Promise<InvitationResult> {
    if (!this.tokens || !this.emailProvider.configured || !this.protectedUid) {
      throw new ApiError(503, "INTERNAL_ERROR", "El servicio de invitaciones no está configurado de forma segura.");
    }
    if (!input.principal.email) throw new ApiError(403, "ADMIN_REQUIRED", "La cuenta administrativa requiere un correo válido.");
    const key = keySchema.safeParse(input.idempotencyKey);
    if (!key.success) throw new ApiError(400, "IDEMPOTENCY_REQUIRED", "Se requiere un encabezado Idempotency-Key UUID válido.");
    const parsed = createInvitationSchema.safeParse(input.body);
    if (!parsed.success) throw new ApiError(400, "VALIDATION_ERROR", parsed.error.issues[0]?.message ?? "Datos no válidos.");

    const request = parsed.data;
    const invitationId = key.data;
    const uid = deterministicUid(invitationId);
    if (uid === this.protectedUid || uid === input.principal.uid) throw new ApiError(409, "PROTECTED_ACCOUNT", "La cuenta está protegida.");
    const existingEmail = await this.directory.getUserByEmail(request.email).catch((error) => {
      if (authCode(error) === "auth/user-not-found") return null;
      throw error;
    });
    if (existingEmail && existingEmail.uid !== uid) {
      throw new ApiError(409, "DUPLICATE_INVITATION", "Ya existe una cuenta para ese correo.");
    }
    const operationRef = this.db.collection("adminOperations").doc(key.data);
    const invitationRef = this.db.collection("invitations").doc(invitationId);
    const profileRef = this.db.collection("users").doc(uid);
    const uniqueRef = this.db.collection("invitationUniqueKeys").doc(uniqueEmailId(request.email));
    const requestHash = canonicalHash({ type: "invitation.create", ...request });
    const timestamp = this.now();
    const leaseExpiresAt = Timestamp.fromMillis(timestamp.toMillis() + 60_000);

    const reservation = await this.db.runTransaction(async (transaction) => {
      const [operationSnapshot, uniqueSnapshot] = await Promise.all([
        transaction.get(operationRef),
        transaction.get(uniqueRef)
      ]);
      if (operationSnapshot.exists) {
        const operation = adminOperationDocumentSchema.safeParse(operationSnapshot.data());
        if (!operation.success) throw new ApiError(409, "IDEMPOTENCY_CONFLICT", "La operación existente no es válida.");
        if (operation.data.type !== "invitation.create" || operation.data.inputHash !== requestHash || operation.data.actorUid !== input.principal.uid) {
          throw new ApiError(409, "IDEMPOTENCY_CONFLICT", "La clave idempotente ya fue usada con otra solicitud.");
        }
        if (operation.data.status === "completed") return { completed: operation.data.result as InvitationResult };
        if (operation.data.status === "pending" && operation.data.leaseExpiresAt.toMillis() > timestamp.toMillis() && operation.data.leaseOwner !== input.requestId) {
          throw new ApiError(409, "OPERATION_IN_PROGRESS", "La invitación ya está en proceso.");
        }
        transaction.update(operationRef, {
          requestId: input.requestId,
          leaseOwner: input.requestId,
          leaseExpiresAt,
          attempts: operation.data.attempts + 1,
          updatedAt: timestamp,
          status: "pending",
          failureCode: null
        });
        return { completed: null };
      }
      if (uniqueSnapshot.exists) throw new ApiError(409, "DUPLICATE_INVITATION", "Ya existe una invitación o cuenta para ese correo.");

      const material = this.tokens!.issue(invitationId);
      const expiresAt = Timestamp.fromMillis(timestamp.toMillis() + request.expiresInHours * 3_600_000);
      const idempotencyKey = `invitation/${invitationId}/generation/1`;
      const invitation = invitationDocumentSchema.parse({
        invitationId,
        email: request.email,
        normalizedEmail: request.email,
        displayName: request.displayName,
        uid,
        status: "provisioning",
        token: { hash: material.hash, generation: 1, salt: material.salt, keyVersion: material.keyVersion, issuedAt: timestamp, expiresAt },
        delivery: {
          provider: this.emailProvider.name,
          status: "pending",
          idempotencyKey,
          providerMessageId: null,
          templateVersion: 1,
          firstAttemptAt: null,
          retryUntil: null,
          sentAt: null,
          deliveredAt: null,
          failureCode: null
        },
        expiresAt,
        createdAt: timestamp,
        createdBy: input.principal.uid,
        updatedAt: timestamp,
        updatedBy: input.principal.uid,
        pendingOperationId: key.data,
        consumeOperationId: null,
        consumeLeaseExpiresAt: null,
        passwordSetAt: null,
        confirmationExpiresAt: null,
        deliveredAt: null,
        acceptedAt: null,
        revokedAt: null,
        revokedBy: null,
        revokeReason: null,
        expiredAt: null,
        resendCount: 0,
        lastSentAt: null,
        revision: 1,
        version: 2
      });
      transaction.create(invitationRef, invitation);
      transaction.create(uniqueRef, {
        normalizedEmailHash: uniqueEmailId(request.email), invitationId, uid, state: "reserved", createdAt: timestamp, updatedAt: timestamp, version: 1
      });
      transaction.create(operationRef, {
        operationId: key.data,
        type: "invitation.create",
        targetUid: uid,
        invitationId,
        actorUid: input.principal.uid,
        inputHash: requestHash,
        expectedRevision: null,
        status: "pending",
        checkpoint: "reserved",
        requestId: input.requestId,
        leaseOwner: input.requestId,
        leaseExpiresAt,
        attempts: 1,
        result: null,
        failureCode: null,
        createdAt: timestamp,
        updatedAt: timestamp,
        completedAt: null,
        version: 1
      });
      return { completed: null };
    });
    if (reservation.completed) return reservation.completed;

    try {
      await this.ensureAuthUser(uid, request.email, request.displayName);
      await this.updateCheckpoint(operationRef, input.requestId, "auth_created");
      await this.persistProfileCheckpoint({ invitationRef, profileRef, operationRef, uniqueRef, uid, request, principal: input.principal });
      const invitationSnapshot = await invitationRef.get();
      const invitation = invitationDocumentSchema.parse(invitationSnapshot.data());
      if (!invitation.token) throw new ApiError(409, "PROFILE_INCONSISTENT", "La invitación no tiene token activo.");
      const token = this.tokens.reconstruct(invitationId, invitation.token.generation, invitation.token.salt, invitation.token.keyVersion);
      const firstAttemptAt = await this.prepareEmailCheckpoint(invitationRef, operationRef, input.requestId);
      const delivery = await this.emailProvider.send({
        to: invitation.email,
        displayName: invitation.displayName,
        invitationId,
        token,
        expiresAt: invitation.expiresAt.toDate().toISOString(),
        from: "invitaciones@plcocina.com",
        templateVersion: 1,
        tracking: { opens: false, clicks: false }
      }, invitation.delivery.idempotencyKey);
      return await this.finalize({ invitationRef, operationRef, uniqueRef, principal: input.principal as AdminPrincipal & { email: string }, requestId: input.requestId, delivery, firstAttemptAt });
    } catch (error) {
      await this.markRecovery(operationRef, invitationRef, input.requestId, error).catch(() => undefined);
      if (error instanceof ApiError) throw error;
      if (authCode(error) === "auth/email-already-exists") {
        throw new ApiError(409, "DUPLICATE_INVITATION", "Ya existe una cuenta para ese correo.");
      }
      throw new ApiError(500, "INTERNAL_ERROR", "La invitación quedó pendiente de recuperación segura.");
    }
  }

  async resend(input: {
    invitationId: string;
    body: unknown;
    idempotencyKey: string | undefined;
    principal: AdminPrincipal;
    requestId: string;
  }): Promise<InvitationResult> {
    this.assertConfigured(input.principal);
    const invitationId = this.parseInvitationId(input.invitationId);
    const key = this.parseIdempotencyKey(input.idempotencyKey);
    const parsed = resendInvitationSchema.safeParse(input.body);
    if (!parsed.success) throw new ApiError(400, "VALIDATION_ERROR", parsed.error.issues[0]?.message ?? "Datos no válidos.");
    const requestHash = canonicalHash({ type: "invitation.resend", invitationId, ...parsed.data });
    const operationRef = this.db.collection("adminOperations").doc(key);
    const invitationRef = this.db.collection("invitations").doc(invitationId);
    const timestamp = this.now();
    const leaseExpiresAt = Timestamp.fromMillis(timestamp.toMillis() + 60_000);

    const reservation = await this.db.runTransaction(async (transaction) => {
      const [operationSnapshot, invitationSnapshot] = await Promise.all([
        transaction.get(operationRef), transaction.get(invitationRef)
      ]);
      if (!invitationSnapshot.exists) throw new ApiError(404, "NOT_FOUND", "La invitación no existe.");
      const invitation = invitationDocumentSchema.parse(invitationSnapshot.data());
      if (operationSnapshot.exists) {
        const operation = adminOperationDocumentSchema.parse(operationSnapshot.data());
        this.assertSameOperation(operation, "invitation.resend", requestHash, input.principal.uid, invitationId);
        if (operation.status === "completed") return { completed: operation.result as InvitationResult, invitation };
        if (operation.failureCode === "DELIVERY_RETRY_WINDOW_EXPIRED") {
          throw new ApiError(409, "DELIVERY_RETRY_WINDOW_EXPIRED", "La ventana automática de reintento terminó; realice un nuevo reenvío explícito.");
        }
        if (operation.status === "pending" && operation.leaseExpiresAt.toMillis() > timestamp.toMillis() && operation.leaseOwner !== input.requestId) {
          throw new ApiError(409, "OPERATION_IN_PROGRESS", "El reenvío ya está en proceso.");
        }
        if (invitation.delivery.retryUntil && invitation.delivery.retryUntil.toMillis() < timestamp.toMillis()) {
          transaction.update(operationRef, { status: "reconciliation_required", failureCode: "DELIVERY_RETRY_WINDOW_EXPIRED", updatedAt: timestamp, leaseExpiresAt: timestamp });
          if (invitation.pendingOperationId === key) transaction.update(invitationRef, { pendingOperationId: null, updatedAt: timestamp });
          return { retryExpired: true, invitation };
        }
        transaction.update(operationRef, {
          status: "pending", requestId: input.requestId, leaseOwner: input.requestId, leaseExpiresAt,
          attempts: operation.attempts + 1, updatedAt: timestamp, failureCode: null
        });
        return { completed: null, invitation };
      }

      const effectiveStatus = effectiveInvitationStatus(invitation, timestamp.toMillis());
      if (!["active", "pending_delivery", "expired", "reconciliation_required"].includes(effectiveStatus)) {
        throw new ApiError(409, "INVALID_STATE_TRANSITION", "La invitación no admite reenvío en su estado actual.");
      }
      if (invitation.revision !== parsed.data.expectedRevision) throw new ApiError(409, "REVISION_CONFLICT", "La invitación fue modificada por otra operación.");
      if (invitation.pendingOperationId) throw new ApiError(409, "OPERATION_IN_PROGRESS", "La invitación tiene una operación pendiente.");
      const generation = (invitation.token?.generation ?? invitation.resendCount + 1) + 1;
      const material = this.tokens!.issue(invitationId, generation);
      const expiresAt = Timestamp.fromMillis(timestamp.toMillis() + parsed.data.expiresInHours * 3_600_000);
      const updated = invitationDocumentSchema.parse({
        ...invitation, status: "pending_delivery",
        token: { hash: material.hash, generation, salt: material.salt, keyVersion: material.keyVersion, issuedAt: timestamp, expiresAt },
        delivery: {
          provider: this.emailProvider.name, status: "pending", idempotencyKey: `invitation/${invitationId}/generation/${generation}`,
          providerMessageId: null, templateVersion: 1, firstAttemptAt: null, retryUntil: null,
          sentAt: null, deliveredAt: null, failureCode: null
        },
        expiresAt, expiredAt: null, pendingOperationId: key, resendCount: invitation.resendCount + 1,
        updatedAt: timestamp, updatedBy: input.principal.uid, revision: invitation.revision + 1
      });
      transaction.set(invitationRef, updated);
      transaction.create(operationRef, {
        operationId: key, type: "invitation.resend", targetUid: invitation.uid, invitationId,
        actorUid: input.principal.uid, inputHash: requestHash, expectedRevision: parsed.data.expectedRevision,
        status: "pending", checkpoint: "reserved", requestId: input.requestId, leaseOwner: input.requestId,
        leaseExpiresAt, attempts: 1, result: null, failureCode: null,
        createdAt: timestamp, updatedAt: timestamp, completedAt: null, version: 1
      });
      return { completed: null, invitation: updated };
    });
    if ("retryExpired" in reservation && reservation.retryExpired) {
      throw new ApiError(409, "DELIVERY_RETRY_WINDOW_EXPIRED", "La ventana automática de reintento terminó; realice un nuevo reenvío explícito.");
    }
    if (reservation.completed) return reservation.completed;

    const invitationSnapshot = await invitationRef.get();
    const invitation = invitationDocumentSchema.parse(invitationSnapshot.data());
    try {
      if (!invitation.token) throw new ApiError(409, "INVALID_STATE_TRANSITION", "La invitación no tiene un token activo.");
      const token = this.tokens!.reconstruct(invitationId, invitation.token.generation, invitation.token.salt, invitation.token.keyVersion);
      const firstAttemptAt = await this.prepareEmailCheckpoint(invitationRef, operationRef, input.requestId);
      const delivery = await this.emailProvider.send({
        to: invitation.email, displayName: invitation.displayName, invitationId, token,
        expiresAt: invitation.expiresAt.toDate().toISOString(), from: "invitaciones@plcocina.com",
        templateVersion: 1, tracking: { opens: false, clicks: false }
      }, invitation.delivery.idempotencyKey);
      return await this.finalize({
        invitationRef, operationRef, uniqueRef: this.db.collection("invitationUniqueKeys").doc(uniqueEmailId(invitation.normalizedEmail)),
        principal: input.principal as AdminPrincipal & { email: string }, requestId: input.requestId,
        delivery, firstAttemptAt, auditAction: "invitation.resent"
      });
    } catch (error) {
      await this.markDeliveryRecovery(operationRef, invitationRef, input.requestId, input.principal, error).catch(() => undefined);
      if (error instanceof ApiError) throw error;
      throw new ApiError(500, "INTERNAL_ERROR", "El reenvío quedó pendiente de recuperación segura.");
    }
  }

  async revoke(input: {
    invitationId: string;
    body: unknown;
    idempotencyKey: string | undefined;
    principal: AdminPrincipal;
    requestId: string;
  }): Promise<InvitationResult> {
    this.assertConfigured(input.principal);
    const invitationId = this.parseInvitationId(input.invitationId);
    const key = this.parseIdempotencyKey(input.idempotencyKey);
    const parsed = revokeInvitationSchema.safeParse(input.body);
    if (!parsed.success) throw new ApiError(400, "VALIDATION_ERROR", parsed.error.issues[0]?.message ?? "Datos no válidos.");
    const invitationRef = this.db.collection("invitations").doc(invitationId);
    const initialSnapshot = await invitationRef.get();
    if (!initialSnapshot.exists) throw new ApiError(404, "NOT_FOUND", "La invitación no existe.");
    const initial = invitationDocumentSchema.parse(initialSnapshot.data());
    const authUser = await this.directory.getUser(initial.uid).catch((error) => authCode(error) === "auth/user-not-found" ? null : Promise.reject(error));
    if (initial.uid === input.principal.uid || initial.uid === this.protectedUid || authUser?.customClaims?.super_admin === true) {
      throw new ApiError(409, "PROTECTED_ACCOUNT", "La cuenta está protegida.");
    }
    const requestHash = canonicalHash({ type: "invitation.revoke", invitationId, ...parsed.data });
    const operationRef = this.db.collection("adminOperations").doc(key);
    const profileRef = this.db.collection("users").doc(initial.uid);
    const uniqueRef = this.db.collection("invitationUniqueKeys").doc(uniqueEmailId(initial.normalizedEmail));
    const timestamp = this.now();
    const leaseExpiresAt = Timestamp.fromMillis(timestamp.toMillis() + 60_000);

    const reservation = await this.db.runTransaction(async (transaction) => {
      const [operationSnapshot, invitationSnapshot, profileSnapshot] = await Promise.all([
        transaction.get(operationRef), transaction.get(invitationRef), transaction.get(profileRef)
      ]);
      if (!invitationSnapshot.exists) throw new ApiError(404, "NOT_FOUND", "La invitación no existe.");
      const invitation = invitationDocumentSchema.parse(invitationSnapshot.data());
      if (operationSnapshot.exists) {
        const operation = adminOperationDocumentSchema.parse(operationSnapshot.data());
        this.assertSameOperation(operation, "invitation.revoke", requestHash, input.principal.uid, invitationId);
        if (operation.status === "completed") return operation.result as InvitationResult;
        if (operation.status === "pending" && operation.leaseExpiresAt.toMillis() > timestamp.toMillis() && operation.leaseOwner !== input.requestId) {
          throw new ApiError(409, "OPERATION_IN_PROGRESS", "La revocación ya está en proceso.");
        }
        transaction.update(operationRef, { status: "pending", requestId: input.requestId, leaseOwner: input.requestId, leaseExpiresAt, attempts: operation.attempts + 1, updatedAt: timestamp, failureCode: null });
        return null;
      }
      if (!profileSnapshot.exists || !userDocumentSchema.safeParse(profileSnapshot.data()).success) {
        throw new ApiError(409, "PROFILE_REQUIRED", "La cuenta invitada requiere un perfil válido.");
      }
      if (["accepted", "revoked"].includes(invitation.status)) throw new ApiError(409, "INVALID_STATE_TRANSITION", "La invitación no admite revocación en su estado actual.");
      if (invitation.revision !== parsed.data.expectedRevision) throw new ApiError(409, "REVISION_CONFLICT", "La invitación fue modificada por otra operación.");
      if (invitation.pendingOperationId) throw new ApiError(409, "OPERATION_IN_PROGRESS", "La invitación tiene una operación pendiente.");
      const updated = invitationDocumentSchema.parse({
        ...invitation, status: "revoked", token: null, revokedAt: timestamp, revokedBy: input.principal.uid,
        revokeReason: parsed.data.reason, pendingOperationId: key, updatedAt: timestamp,
        updatedBy: input.principal.uid, revision: invitation.revision + 1
      });
      transaction.set(invitationRef, updated);
      transaction.create(operationRef, {
        operationId: key, type: "invitation.revoke", targetUid: invitation.uid, invitationId,
        actorUid: input.principal.uid, inputHash: requestHash, expectedRevision: parsed.data.expectedRevision,
        status: "pending", checkpoint: "reserved", requestId: input.requestId, leaseOwner: input.requestId,
        leaseExpiresAt, attempts: 1, result: null, failureCode: null,
        createdAt: timestamp, updatedAt: timestamp, completedAt: null, version: 1
      });
      return null;
    });
    if (reservation) return reservation;

    try {
      if (authUser) {
        await this.directory.updateUser(initial.uid, { disabled: true });
        await this.directory.revokeRefreshTokens(initial.uid);
      }
      await this.markAuthApplied(operationRef, input.requestId);
      return await this.finalizeRevocation({ invitationRef, operationRef, profileRef, uniqueRef, principal: input.principal as AdminPrincipal & { email: string }, requestId: input.requestId });
    } catch (error) {
      await this.markRevocationRecovery(operationRef, invitationRef, input.requestId, error).catch(() => undefined);
      if (error instanceof ApiError) throw error;
      throw new ApiError(500, "INTERNAL_ERROR", "La invitación quedó revocada y sus efectos requieren conciliación.");
    }
  }

  async reconcileExpired(limit = 100): Promise<{ inspected: number; expired: number; reconciliationRequired: number }> {
    if (!this.tokens || !this.protectedUid) throw new ApiError(503, "INTERNAL_ERROR", "El servicio de invitaciones no está configurado de forma segura.");
    if (!Number.isInteger(limit) || limit < 1 || limit > 500) throw new ApiError(400, "VALIDATION_ERROR", "El límite de conciliación no es válido.");
    const timestamp = this.now();
    const [expirySnapshots, confirmationSnapshots] = await Promise.all([
      this.db.collection("invitations").where("expiresAt", "<=", timestamp).limit(limit).get(),
      this.db.collection("invitations").where("confirmationExpiresAt", "<=", timestamp).limit(limit).get()
    ]);
    const documents = new Map([...expirySnapshots.docs, ...confirmationSnapshots.docs].map((document) => [document.id, document]));
    let expired = 0;
    let reconciliationRequired = 0;
    for (const snapshot of [...documents.values()].slice(0, limit)) {
      const invitation = invitationDocumentSchema.safeParse(snapshot.data());
      if (!invitation.success || effectiveInvitationStatus(invitation.data, timestamp.toMillis()) !== "expired") continue;
      if (invitation.data.status === "expired" && invitation.data.pendingOperationId === null) continue;
      const outcome = await this.expireOne(invitation.data, timestamp).catch(() => "reconciliation_required" as const);
      if (outcome === "expired") expired += 1;
      else reconciliationRequired += 1;
    }
    return { inspected: Math.min(documents.size, limit), expired, reconciliationRequired };
  }

  private async expireOne(initial: InvitationDocument, timestamp: Timestamp): Promise<"expired" | "reconciliation_required"> {
    const invitationRef = this.db.collection("invitations").doc(initial.invitationId);
    const profileRef = this.db.collection("users").doc(initial.uid);
    const operationId = initial.status === "expired" && initial.pendingOperationId
      ? initial.pendingOperationId
      : deterministicOperationId("invitation.expire", `${initial.invitationId}:${initial.token?.generation ?? 0}`);
    const operationRef = this.db.collection("adminOperations").doc(operationId);
    const requestId = randomUUID();
    const authUser = await this.directory.getUser(initial.uid).catch((error) => authCode(error) === "auth/user-not-found" ? null : Promise.reject(error));
    const protectedAccount = initial.uid === this.protectedUid || authUser?.customClaims?.super_admin === true;
    await this.db.runTransaction(async (transaction) => {
      const [invitationSnapshot, operationSnapshot] = await Promise.all([transaction.get(invitationRef), transaction.get(operationRef)]);
      const invitation = invitationDocumentSchema.parse(invitationSnapshot.data());
      if (invitation.status === "expired" && invitation.pendingOperationId === operationId && operationSnapshot.exists) {
        const operation = adminOperationDocumentSchema.parse(operationSnapshot.data());
        transaction.update(operationRef, {
          status: "pending", requestId, leaseOwner: requestId, leaseExpiresAt: Timestamp.fromMillis(timestamp.toMillis() + 60_000),
          attempts: operation.attempts + 1, updatedAt: timestamp, failureCode: null
        });
        return;
      }
      if (invitation.status === "expired" || invitation.status === "revoked" || invitation.status === "accepted") return;
      if (effectiveInvitationStatus(invitation, timestamp.toMillis()) !== "expired") return;
      transaction.update(invitationRef, {
        status: "expired", token: null, expiredAt: timestamp, pendingOperationId: operationId,
        updatedAt: timestamp, updatedBy: "system", revision: invitation.revision + 1
      });
      if (!operationSnapshot.exists) transaction.create(operationRef, {
        operationId, type: "invitation.expire", targetUid: invitation.uid, invitationId: invitation.invitationId,
        actorUid: "system", inputHash: canonicalHash({ type: "invitation.expire", invitationId: invitation.invitationId, generation: invitation.token?.generation ?? 0 }),
        expectedRevision: invitation.revision, status: "pending", checkpoint: "reserved", requestId,
        leaseOwner: requestId, leaseExpiresAt: Timestamp.fromMillis(timestamp.toMillis() + 60_000), attempts: 1,
        result: null, failureCode: null, createdAt: timestamp, updatedAt: timestamp, completedAt: null, version: 1
      });
    });
    if (protectedAccount) {
      await this.markRevocationRecovery(operationRef, invitationRef, requestId, new Error("PROTECTED_ACCOUNT"));
      return "reconciliation_required";
    }
    try {
      if (authUser) {
        await this.directory.updateUser(initial.uid, { disabled: true });
        await this.directory.revokeRefreshTokens(initial.uid);
      }
      await this.markAuthApplied(operationRef, requestId);
      await this.db.runTransaction(async (transaction) => {
        const [invitationSnapshot, profileSnapshot, operationSnapshot] = await Promise.all([
          transaction.get(invitationRef), transaction.get(profileRef), transaction.get(operationRef)
        ]);
        const invitation = invitationDocumentSchema.parse(invitationSnapshot.data());
        const operation = adminOperationDocumentSchema.parse(operationSnapshot.data());
        const result = publicResult(invitation, timestamp);
        if (profileSnapshot.exists) {
          const profile = userDocumentSchema.safeParse(profileSnapshot.data());
          if (profile.success) transaction.update(profileRef, {
            status: "disabled", authDisabled: true, invitationStatus: "expired", updatedAt: timestamp,
            updatedBy: "system", revision: profile.data.revision + 1, pendingOperationId: null
          });
        }
        transaction.update(invitationRef, { pendingOperationId: null, updatedAt: timestamp });
        transaction.update(operationRef, { status: "completed", checkpoint: "completed", result, updatedAt: timestamp, completedAt: timestamp, failureCode: null });
        if (operation.status !== "completed") transaction.create(this.db.collection("auditEvents").doc(randomUUID()), {
          occurredAt: timestamp, actorType: "system", actorUid: null, actorEmail: null, providerEventId: null,
          action: "invitation.expired", resourceType: "invitation", resourceId: invitation.invitationId,
          targetUid: invitation.uid, appId: null, before: { status: initial.status }, after: { status: "expired", revision: invitation.revision },
          reason: "La vigencia de la invitación terminó según el reloj del servidor.", requestId, source: "admin-api", result: "success", version: 1
        });
      });
      return "expired";
    } catch (error) {
      await this.markRevocationRecovery(operationRef, invitationRef, requestId, error).catch(() => undefined);
      return "reconciliation_required";
    }
  }

  private assertConfigured(principal: AdminPrincipal) {
    if (!this.tokens || !this.emailProvider.configured || !this.protectedUid) throw new ApiError(503, "INTERNAL_ERROR", "El servicio de invitaciones no está configurado de forma segura.");
    if (!principal.email) throw new ApiError(403, "ADMIN_REQUIRED", "La cuenta administrativa requiere un correo válido.");
  }

  private parseInvitationId(value: string) {
    const parsed = invitationIdSchema.safeParse(value);
    if (!parsed.success) throw new ApiError(400, "VALIDATION_ERROR", "El identificador de invitación no es válido.");
    return parsed.data;
  }

  private parseIdempotencyKey(value: string | undefined) {
    const parsed = keySchema.safeParse(value);
    if (!parsed.success) throw new ApiError(400, "IDEMPOTENCY_REQUIRED", "Se requiere un encabezado Idempotency-Key UUID válido.");
    return parsed.data;
  }

  private assertSameOperation(operation: z.infer<typeof adminOperationDocumentSchema>, type: "invitation.resend" | "invitation.revoke", inputHash: string, actorUid: string, invitationId: string) {
    if (operation.type !== type || operation.inputHash !== inputHash || operation.actorUid !== actorUid || operation.invitationId !== invitationId) {
      throw new ApiError(409, "IDEMPOTENCY_CONFLICT", "La clave idempotente ya fue usada con otra solicitud.");
    }
  }

  private async ensureAuthUser(uid: string, email: string, displayName: string) {
    const existingByUid = await this.directory.getUser(uid).catch((error) => {
      if (authCode(error) === "auth/user-not-found") return null;
      throw error;
    });
    const user = existingByUid ?? await this.directory.createUser({ uid, email, displayName, emailVerified: false, disabled: true });
    this.assertProvisionalUser(user, uid, email);
  }

  private async updateCheckpoint(
    operationRef: FirebaseFirestore.DocumentReference,
    requestId: string,
    checkpoint: "auth_created" | "profile_created" | "email_requested"
  ) {
    const timestamp = this.now();
    await this.db.runTransaction(async (transaction) => {
      const snapshot = await transaction.get(operationRef);
      const operation = adminOperationDocumentSchema.parse(snapshot.data());
      if (operation.status === "completed") return;
      if (operation.leaseOwner !== requestId) throw new ApiError(409, "OPERATION_IN_PROGRESS", "La operación fue reclamada por otra solicitud.");
      transaction.update(operationRef, { checkpoint, updatedAt: timestamp });
    });
  }

  private async markAuthApplied(operationRef: FirebaseFirestore.DocumentReference, requestId: string) {
    const timestamp = this.now();
    await this.db.runTransaction(async (transaction) => {
      const snapshot = await transaction.get(operationRef);
      const operation = adminOperationDocumentSchema.parse(snapshot.data());
      if (operation.status === "completed" || operation.status === "auth_applied") return;
      if (operation.leaseOwner !== requestId) throw new ApiError(409, "OPERATION_IN_PROGRESS", "La operación fue reclamada por otra solicitud.");
      transaction.update(operationRef, { status: "auth_applied", updatedAt: timestamp });
    });
  }

  private async prepareEmailCheckpoint(
    invitationRef: FirebaseFirestore.DocumentReference,
    operationRef: FirebaseFirestore.DocumentReference,
    requestId: string
  ) {
    return this.db.runTransaction(async (transaction) => {
      const [invitationSnapshot, operationSnapshot] = await Promise.all([
        transaction.get(invitationRef), transaction.get(operationRef)
      ]);
      const invitation = invitationDocumentSchema.parse(invitationSnapshot.data());
      const operation = adminOperationDocumentSchema.parse(operationSnapshot.data());
      if (operation.leaseOwner !== requestId) throw new ApiError(409, "OPERATION_IN_PROGRESS", "La operación fue reclamada por otra solicitud.");
      const firstAttemptAt = invitation.delivery.firstAttemptAt ?? this.now();
      const retryUntil = invitation.delivery.retryUntil ?? Timestamp.fromMillis(firstAttemptAt.toMillis() + 23 * 3_600_000);
      transaction.update(invitationRef, {
        delivery: { ...invitation.delivery, firstAttemptAt, retryUntil },
        updatedAt: firstAttemptAt
      });
      transaction.update(operationRef, { checkpoint: "email_requested", updatedAt: firstAttemptAt });
      return firstAttemptAt;
    });
  }

  private assertProvisionalUser(user: DirectoryUser, uid: string, email: string) {
    if (user.uid !== uid || user.email?.toLowerCase() !== email || user.disabled !== true || user.emailVerified !== false || user.customClaims?.super_admin === true) {
      throw new ApiError(409, "PROFILE_INCONSISTENT", "La cuenta provisional no coincide con la invitación.");
    }
  }

  private async persistProfileCheckpoint(input: {
    invitationRef: FirebaseFirestore.DocumentReference;
    profileRef: FirebaseFirestore.DocumentReference;
    operationRef: FirebaseFirestore.DocumentReference;
    uniqueRef: FirebaseFirestore.DocumentReference;
    uid: string;
    request: z.infer<typeof createInvitationSchema>;
    principal: AdminPrincipal;
  }) {
    const timestamp = this.now();
    await this.db.runTransaction(async (transaction) => {
      const [profileSnapshot, invitationSnapshot] = await Promise.all([
        transaction.get(input.profileRef), transaction.get(input.invitationRef)
      ]);
      const invitation = invitationDocumentSchema.parse(invitationSnapshot.data());
      if (profileSnapshot.exists) {
        const profile = userDocumentSchema.safeParse(profileSnapshot.data());
        if (!profile.success || profile.data.normalizedEmail !== input.request.email || profile.data.status !== "invited") {
          throw new ApiError(409, "PROFILE_INCONSISTENT", "El perfil existente no pertenece a esta invitación.");
        }
      } else {
        transaction.create(input.profileRef, userDocumentSchema.parse({
          email: input.request.email,
          normalizedEmail: input.request.email,
          displayName: input.request.displayName,
          status: "invited",
          authDisabled: true,
          invitationStatus: "pending",
          createdAt: timestamp,
          createdBy: input.principal.uid,
          updatedAt: timestamp,
          updatedBy: input.principal.uid,
          revision: 1,
          pendingOperationId: null,
          version: 1
        }));
      }
      transaction.update(input.invitationRef, { status: "pending_delivery", updatedAt: timestamp, revision: invitation.revision + 1 });
      transaction.update(input.uniqueRef, { state: "active", updatedAt: timestamp });
      transaction.update(input.operationRef, { checkpoint: "profile_created", updatedAt: timestamp });
    });
  }

  private async finalize(input: {
    invitationRef: FirebaseFirestore.DocumentReference;
    operationRef: FirebaseFirestore.DocumentReference;
    uniqueRef: FirebaseFirestore.DocumentReference;
    principal: AdminPrincipal & { email: string };
    requestId: string;
    delivery: { messageId: string; acceptedAt: Date };
    firstAttemptAt: Timestamp;
    auditAction?: "invitation.created" | "invitation.resent";
  }) {
    return this.db.runTransaction(async (transaction) => {
      const [invitationSnapshot, operationSnapshot] = await Promise.all([
        transaction.get(input.invitationRef),
        transaction.get(input.operationRef)
      ]);
      const invitation = invitationDocumentSchema.parse(invitationSnapshot.data());
      const operation = adminOperationDocumentSchema.parse(operationSnapshot.data());
      if (operation.status === "completed") return operation.result as InvitationResult;
      if (operation.leaseOwner !== input.requestId) {
        throw new ApiError(409, "OPERATION_IN_PROGRESS", "La operación fue reclamada por otra solicitud.");
      }
      const sentAt = Timestamp.fromDate(input.delivery.acceptedAt);
      const retryUntil = invitation.delivery.retryUntil ?? Timestamp.fromMillis(input.firstAttemptAt.toMillis() + 23 * 3_600_000);
      const updated = invitationDocumentSchema.parse({
        ...invitation,
        status: "active",
        delivery: {
          ...invitation.delivery,
          status: "accepted",
          providerMessageId: input.delivery.messageId,
          firstAttemptAt: input.firstAttemptAt,
          retryUntil,
          sentAt
        },
        lastSentAt: sentAt,
        pendingOperationId: null,
        updatedAt: sentAt,
        updatedBy: input.principal.uid,
        revision: invitation.revision + 1
      });
      const result = publicResult(updated);
      transaction.set(input.invitationRef, updated);
      transaction.update(input.uniqueRef, { state: "active", updatedAt: sentAt });
      transaction.update(input.operationRef, { status: "completed", checkpoint: "completed", result, updatedAt: sentAt, completedAt: sentAt, failureCode: null });
      transaction.create(this.db.collection("auditEvents").doc(randomUUID()), {
        occurredAt: sentAt,
        actorType: "admin",
        actorUid: input.principal.uid,
        actorEmail: input.principal.email,
        providerEventId: null,
        action: input.auditAction ?? "invitation.created",
        resourceType: "invitation",
        resourceId: updated.invitationId,
        targetUid: updated.uid,
        appId: null,
        before: null,
        after: { status: updated.status, deliveryStatus: updated.delivery.status, revision: updated.revision },
        reason: null,
        requestId: input.requestId,
        source: "admin-api",
        result: "success",
        version: 1
      });
      return result;
    });
  }

  private async finalizeRevocation(input: {
    invitationRef: FirebaseFirestore.DocumentReference;
    operationRef: FirebaseFirestore.DocumentReference;
    profileRef: FirebaseFirestore.DocumentReference;
    uniqueRef: FirebaseFirestore.DocumentReference;
    principal: AdminPrincipal & { email: string };
    requestId: string;
  }) {
    const timestamp = this.now();
    return this.db.runTransaction(async (transaction) => {
      const [invitationSnapshot, operationSnapshot, profileSnapshot] = await Promise.all([
        transaction.get(input.invitationRef), transaction.get(input.operationRef), transaction.get(input.profileRef)
      ]);
      const invitation = invitationDocumentSchema.parse(invitationSnapshot.data());
      const operation = adminOperationDocumentSchema.parse(operationSnapshot.data());
      if (operation.status === "completed") return operation.result as InvitationResult;
      if (operation.leaseOwner !== input.requestId) throw new ApiError(409, "OPERATION_IN_PROGRESS", "La operación fue reclamada por otra solicitud.");
      const profile = userDocumentSchema.safeParse(profileSnapshot.data());
      if (!profile.success) throw new ApiError(409, "PROFILE_REQUIRED", "La cuenta invitada requiere un perfil válido.");
      const updated = invitationDocumentSchema.parse({ ...invitation, pendingOperationId: null, updatedAt: timestamp });
      const result = publicResult(updated, timestamp);
      transaction.set(input.invitationRef, updated);
      transaction.update(input.profileRef, {
        status: "disabled", authDisabled: true, invitationStatus: "revoked", updatedAt: timestamp,
        updatedBy: input.principal.uid, revision: profile.data.revision + 1, pendingOperationId: null
      });
      transaction.update(input.uniqueRef, { state: "released", updatedAt: timestamp });
      transaction.update(input.operationRef, { status: "completed", checkpoint: "completed", result, updatedAt: timestamp, completedAt: timestamp, failureCode: null });
      transaction.create(this.db.collection("auditEvents").doc(randomUUID()), {
        occurredAt: timestamp, actorType: "admin", actorUid: input.principal.uid, actorEmail: input.principal.email,
        providerEventId: null, action: "invitation.revoked", resourceType: "invitation", resourceId: invitation.invitationId,
        targetUid: invitation.uid, appId: null, before: null,
        after: { status: "revoked", revision: invitation.revision }, reason: invitation.revokeReason,
        requestId: input.requestId, source: "admin-api", result: "success", version: 1
      });
      return result;
    });
  }

  private async markDeliveryRecovery(
    operationRef: FirebaseFirestore.DocumentReference,
    invitationRef: FirebaseFirestore.DocumentReference,
    requestId: string,
    principal: AdminPrincipal,
    error: unknown
  ) {
    const timestamp = this.now();
    const providerError = error instanceof InvitationEmailProviderError ? error : null;
    const failureCode = (providerError?.code ?? authCode(error) ?? "INVITATION_DELIVERY_FAILED").replace(/[^A-Za-z0-9_]/g, "_").toUpperCase().slice(0, 80);
    await this.db.runTransaction(async (transaction) => {
      const [operationSnapshot, invitationSnapshot] = await Promise.all([transaction.get(operationRef), transaction.get(invitationRef)]);
      if (!operationSnapshot.exists || !invitationSnapshot.exists) return;
      const operation = adminOperationDocumentSchema.parse(operationSnapshot.data());
      const invitation = invitationDocumentSchema.parse(invitationSnapshot.data());
      if (operation.status === "completed") return;
      transaction.update(operationRef, { status: "reconciliation_required", failureCode, updatedAt: timestamp, leaseExpiresAt: timestamp, requestId });
      transaction.update(invitationRef, {
        status: "reconciliation_required",
        delivery: { ...invitation.delivery, status: providerError?.ambiguous ? "unknown" : "failed", failureCode },
        updatedAt: timestamp
      });
      if (principal.email) transaction.create(this.db.collection("auditEvents").doc(randomUUID()), {
        occurredAt: timestamp, actorType: "admin", actorUid: principal.uid, actorEmail: principal.email,
        providerEventId: null, action: "invitation.delivery_failed", resourceType: "invitation",
        resourceId: invitation.invitationId, targetUid: invitation.uid, appId: null,
        before: null, after: { status: "reconciliation_required", deliveryStatus: providerError?.ambiguous ? "unknown" : "failed" },
        reason: failureCode, requestId, source: "admin-api", result: "failure", version: 1
      });
    });
  }

  private async markRevocationRecovery(
    operationRef: FirebaseFirestore.DocumentReference,
    invitationRef: FirebaseFirestore.DocumentReference,
    requestId: string,
    error: unknown
  ) {
    const timestamp = this.now();
    const failureCode = (authCode(error) ?? (error instanceof Error ? error.message : "INVITATION_REVOKE_FAILED"))
      .replace(/[^A-Za-z0-9_]/g, "_").toUpperCase().slice(0, 80);
    await this.db.runTransaction(async (transaction) => {
      const [operationSnapshot, invitationSnapshot] = await Promise.all([transaction.get(operationRef), transaction.get(invitationRef)]);
      if (operationSnapshot.exists) transaction.update(operationRef, { status: "reconciliation_required", failureCode, updatedAt: timestamp, leaseExpiresAt: timestamp, requestId });
      if (invitationSnapshot.exists) {
        const invitation = invitationDocumentSchema.safeParse(invitationSnapshot.data());
        if (invitation.success && (invitation.data.status === "revoked" || invitation.data.status === "expired")) {
          transaction.update(invitationRef, { token: null, updatedAt: timestamp });
        }
      }
    });
  }

  private async markRecovery(operationRef: FirebaseFirestore.DocumentReference, invitationRef: FirebaseFirestore.DocumentReference, requestId: string, error: unknown) {
    const timestamp = this.now();
    const failureCode = (authCode(error) ?? "INVITATION_OPERATION_FAILED").replace(/[^A-Za-z0-9_]/g, "_").toUpperCase().slice(0, 80);
    await this.db.runTransaction(async (transaction) => {
      const [operationSnapshot, invitationSnapshot] = await Promise.all([transaction.get(operationRef), transaction.get(invitationRef)]);
      if (operationSnapshot.exists) transaction.update(operationRef, { status: "reconciliation_required", failureCode, updatedAt: timestamp, leaseExpiresAt: timestamp, requestId });
      if (invitationSnapshot.exists) transaction.update(invitationRef, { status: "reconciliation_required", updatedAt: timestamp });
    });
  }
}
