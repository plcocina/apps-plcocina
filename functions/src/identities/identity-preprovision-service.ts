import { createHash, randomUUID } from "node:crypto";
import type { Auth, CreateRequest, UserRecord } from "firebase-admin/auth";
import { Timestamp, type Firestore } from "firebase-admin/firestore";
import { z } from "zod";
import type { AdminPrincipal } from "../auth/require-super-admin.js";
import {
  adminOperationDocumentSchema,
  auditEventDocumentSchema,
  userDocumentSchema,
  userProfileDocumentSchema
} from "../models/admin-collections.js";
import {
  identityPreprovisionRequestSchema,
  identityPreprovisionResponseSchema,
  identityStatusResponseSchema,
  type IdentityPreprovisionRequest,
  type IdentityPreprovisionResponse,
  type IdentityStatusResponse
} from "./identity-admin-http-contracts.js";
import {
  identityIdentifierKeyDocumentSchema,
  normalizeIdentityEmail,
  normalizePhoneE164,
  userV2DocumentSchema,
  type UserV2Document
} from "./identity-models.js";
import { IdentityReservationError, IdentityReservationService } from "./identity-reservation-service.js";

export type IdentityDirectoryUser = {
  uid: string;
  email: string | null;
  phoneNumber: string | null;
  displayName: string | null;
  emailVerified: boolean;
  disabled: boolean;
  customClaims?: Record<string, unknown>;
};

export interface IdentityDirectory {
  getUser(uid: string): Promise<IdentityDirectoryUser>;
  getUserByEmail(email: string): Promise<IdentityDirectoryUser>;
  getUserByPhoneNumber(phoneNumber: string): Promise<IdentityDirectoryUser>;
  createUser(properties: {
    uid: string;
    displayName: string;
    disabled: true;
    email?: string;
    emailVerified?: false;
    phoneNumber?: string;
  }): Promise<IdentityDirectoryUser>;
}

function directoryUser(user: UserRecord): IdentityDirectoryUser {
  const result: IdentityDirectoryUser = {
    uid: user.uid,
    email: user.email ?? null,
    phoneNumber: user.phoneNumber ?? null,
    displayName: user.displayName ?? null,
    emailVerified: user.emailVerified,
    disabled: user.disabled
  };
  if (user.customClaims) result.customClaims = user.customClaims;
  return result;
}

export class FirebaseIdentityDirectory implements IdentityDirectory {
  constructor(private readonly auth: Auth) {}

  async getUser(uid: string) { return directoryUser(await this.auth.getUser(uid)); }
  async getUserByEmail(email: string) { return directoryUser(await this.auth.getUserByEmail(email)); }
  async getUserByPhoneNumber(phoneNumber: string) { return directoryUser(await this.auth.getUserByPhoneNumber(phoneNumber)); }
  async createUser(properties: Parameters<IdentityDirectory["createUser"]>[0]) {
    const request: CreateRequest = {
      uid: properties.uid,
      displayName: properties.displayName,
      disabled: true
    };
    if (properties.email) {
      request.email = properties.email;
      request.emailVerified = false;
    }
    if (properties.phoneNumber) request.phoneNumber = properties.phoneNumber;
    return directoryUser(await this.auth.createUser(request));
  }
}

type ErrorCode =
  | "ADMIN_REQUIRED"
  | "ADMIN_EMAIL_REQUIRED"
  | "PROTECTED_ACCOUNT"
  | "IDENTIFIER_COLLISION"
  | "IDEMPOTENCY_CONFLICT"
  | "AUTH_IDENTITY_MISMATCH"
  | "RECONCILIATION_REQUIRED"
  | "IDENTITY_NOT_FOUND";

export class IdentityPreprovisionError extends Error {
  constructor(readonly code: ErrorCode, message: string) {
    super(message);
    this.name = "IdentityPreprovisionError";
  }
}

const uuidSchema = z.string().uuid();
const uidSchema = z.string().min(1).max(128).refine((value) => !value.includes("/"));

function authCode(error: unknown): string | undefined {
  return typeof error === "object" && error !== null && "code" in error ? String(error.code) : undefined;
}

function isNotFound(error: unknown): boolean {
  return authCode(error) === "auth/user-not-found";
}

function derivedUuid(namespace: string, operationId: string): string {
  const hex = createHash("sha256").update(`${namespace}\0${operationId}`).digest("hex").slice(0, 32).split("");
  hex[12] = "4";
  hex[16] = ((Number.parseInt(hex[16] ?? "0", 16) & 3) | 8).toString(16);
  return `${hex.slice(0, 8).join("")}-${hex.slice(8, 12).join("")}-${hex.slice(12, 16).join("")}-${hex.slice(16, 20).join("")}-${hex.slice(20).join("")}`;
}

export function preprovisionedUid(operationId: string): string {
  const validated = uuidSchema.parse(operationId);
  return `employee_${createHash("sha256").update(`plcocina-preprovision\0${validated}`).digest("hex").slice(0, 40)}`;
}

function canonicalInput(input: IdentityPreprovisionRequest, identifierHash: string, actorUid: string): string {
  return createHash("sha256").update(JSON.stringify({
    displayName: input.displayName,
    authMethod: input.authMethod,
    identifierHash,
    actorUid
  })).digest("hex");
}

function matches(user: IdentityDirectoryUser, uid: string, request: IdentityPreprovisionRequest): boolean {
  if (user.uid !== uid || user.disabled !== true || user.customClaims?.super_admin === true) return false;
  if (request.authMethod === "sms") return user.phoneNumber === normalizePhoneE164(request.phoneE164) && user.email === null;
  return user.email?.toLowerCase() === normalizeIdentityEmail(request.email) && user.phoneNumber === null && !user.emailVerified;
}

export class IdentityPreprovisionService {
  constructor(
    private readonly db: Firestore,
    private readonly directory: IdentityDirectory,
    private readonly reservations: IdentityReservationService,
    private readonly protectedSuperAdminUid: string,
    private readonly now: () => Timestamp = () => Timestamp.now()
  ) {
    uidSchema.parse(protectedSuperAdminUid);
  }

  async preprovision(input: {
    operationId: string;
    requestId: string;
    principal: AdminPrincipal;
    body: unknown;
  }): Promise<IdentityPreprovisionResponse> {
    const operationId = uuidSchema.parse(input.operationId);
    const requestId = uuidSchema.parse(input.requestId);
    if (input.principal.superAdmin !== true) throw new IdentityPreprovisionError("ADMIN_REQUIRED", "Se requiere autorización de Super Admin.");
    if (!input.principal.email) throw new IdentityPreprovisionError("ADMIN_EMAIL_REQUIRED", "La cuenta administrativa requiere correo verificable para auditoría.");
    const principal: AdminPrincipal & { email: string } = { ...input.principal, email: input.principal.email };
    const request = identityPreprovisionRequestSchema.parse(input.body);
    const uid = preprovisionedUid(operationId);
    if (uid === this.protectedSuperAdminUid || uid === input.principal.uid) {
      throw new IdentityPreprovisionError("PROTECTED_ACCOUNT", "La identidad administrativa protegida no puede modificarse.");
    }

    const kind = request.authMethod === "sms" ? "phone" as const : "email" as const;
    const value = request.authMethod === "sms" ? request.phoneE164 : request.email;
    let reservation;
    try {
      reservation = await this.reservations.reserve({
        operationId: derivedUuid("reservation", operationId), uid, kind, value
      });
    } catch (error) {
      if (error instanceof IdentityReservationError) throw new IdentityPreprovisionError(error.code, error.message);
      throw error;
    }
    const inputHash = canonicalInput(request, reservation.identifierHash, principal.uid);
    const operationRef = this.db.collection("adminOperations").doc(operationId);
    const replay = await this.reserveOperation({ operationId, requestId, uid, inputHash, principal });
    if (replay) return replay;

    try {
      const authUser = await this.ensureAuthUser(uid, request);
      if (!matches(authUser, uid, request)) {
        throw new IdentityPreprovisionError("AUTH_IDENTITY_MISMATCH", "El UID determinista existe con otra identidad o privilegios.");
      }
      await operationRef.update({ status: "auth_applied", checkpoint: "auth_created", updatedAt: this.now() });
      return await this.finalize({
        operationId, requestId, uid, inputHash, request, identifierHash: reservation.identifierHash,
        reservationOperationId: reservation.operationId, principal
      });
    } catch (error) {
      await this.markReconciliation(operationRef, requestId, principal, uid, error);
      if (error instanceof IdentityPreprovisionError || error instanceof IdentityReservationError) throw error;
      throw new IdentityPreprovisionError("RECONCILIATION_REQUIRED", "La preprovisión requiere conciliación y debe reintentarse con la misma clave.");
    }
  }

  async getStatus(uidInput: string): Promise<IdentityStatusResponse> {
    const uid = uidSchema.parse(uidInput);
    const profileSnapshot = await this.db.collection("users").doc(uid).get();
    let auth: IdentityDirectoryUser | null = null;
    try { auth = await this.directory.getUser(uid); } catch (error) { if (!isNotFound(error)) throw error; }
    if (!profileSnapshot.exists && !auth) throw new IdentityPreprovisionError("IDENTITY_NOT_FOUND", "No existe la identidad.");
    if (!profileSnapshot.exists) return identityStatusResponseSchema.parse({
      uid, profileVersion: 2, authMethod: null, activationStatus: null, authDisabled: auth!.disabled,
      authRecordPresent: true, integrity: "missing_profile", revision: null
    });
    const parsed = userProfileDocumentSchema.safeParse(profileSnapshot.data());
    if (!parsed.success) return identityStatusResponseSchema.parse({
      uid, profileVersion: 2, authMethod: null, activationStatus: null, authDisabled: auth?.disabled ?? true,
      authRecordPresent: auth !== null, integrity: "invalid_profile", revision: null
    });
    if (parsed.data.version === 1) {
      return identityStatusResponseSchema.parse({
        uid, profileVersion: 1, authMethod: null, activationStatus: null, authDisabled: parsed.data.authDisabled,
        authRecordPresent: auth !== null,
        integrity: !auth ? "missing_auth" : auth.email?.toLowerCase() === parsed.data.normalizedEmail && auth.disabled === parsed.data.authDisabled ? "linked" : "mismatch",
        revision: parsed.data.revision
      });
    }
    const profile = parsed.data;
    return identityStatusResponseSchema.parse({
      uid, profileVersion: 2, authMethod: profile.authMethod, activationStatus: profile.activationStatus,
      authDisabled: profile.authDisabled, authRecordPresent: auth !== null,
      integrity: !auth ? "missing_auth" : matches(auth, uid, profile.authMethod === "sms"
        ? { displayName: profile.displayName, authMethod: "sms", phoneE164: profile.phoneE164! }
        : { displayName: profile.displayName, authMethod: "email", email: profile.email! }) ? "linked" : "mismatch",
      revision: profile.revision
    });
  }

  private async reserveOperation(input: {
    operationId: string; requestId: string; uid: string; inputHash: string; principal: AdminPrincipal;
  }): Promise<IdentityPreprovisionResponse | null> {
    return this.db.runTransaction(async (transaction) => {
      const reference = this.db.collection("adminOperations").doc(input.operationId);
      const snapshot = await transaction.get(reference);
      if (snapshot.exists) {
        const operation = adminOperationDocumentSchema.parse(snapshot.data());
        if (operation.type !== "identity.preprovision" || operation.targetUid !== input.uid || operation.inputHash !== input.inputHash || operation.actorUid !== input.principal.uid) {
          throw new IdentityPreprovisionError("IDEMPOTENCY_CONFLICT", "La clave de idempotencia ya fue usada con otros datos.");
        }
        if (operation.status === "completed") return identityPreprovisionResponseSchema.parse({ ...operation.result, replayed: true });
        transaction.update(reference, { requestId: input.requestId, leaseOwner: input.requestId, attempts: operation.attempts + 1, updatedAt: this.now() });
        return null;
      }
      const timestamp = this.now();
      transaction.create(reference, adminOperationDocumentSchema.parse({
        operationId: input.operationId, type: "identity.preprovision", targetUid: input.uid,
        appId: null, invitationId: null, actorUid: input.principal.uid, inputHash: input.inputHash,
        expectedRevision: null, status: "pending", checkpoint: "identifier_reserved", requestId: input.requestId,
        leaseOwner: input.requestId, leaseExpiresAt: Timestamp.fromMillis(timestamp.toMillis() + 60_000), attempts: 1,
        result: null, failureCode: null, createdAt: timestamp, updatedAt: timestamp, completedAt: null, version: 1
      }));
      return null;
    });
  }

  private async ensureAuthUser(uid: string, request: IdentityPreprovisionRequest): Promise<IdentityDirectoryUser> {
    try { return await this.directory.getUser(uid); } catch (error) { if (!isNotFound(error)) throw error; }
    const normalized = request.authMethod === "sms" ? normalizePhoneE164(request.phoneE164) : normalizeIdentityEmail(request.email);
    try {
      const duplicate = request.authMethod === "sms"
        ? await this.directory.getUserByPhoneNumber(normalized)
        : await this.directory.getUserByEmail(normalized);
      if (duplicate.uid !== uid) throw new IdentityPreprovisionError("IDENTIFIER_COLLISION", "El identificador pertenece a otro UID de Authentication.");
      return duplicate;
    } catch (error) {
      if (error instanceof IdentityPreprovisionError) throw error;
      if (!isNotFound(error)) throw error;
    }
    const properties = request.authMethod === "sms"
      ? { uid, displayName: request.displayName, disabled: true as const, phoneNumber: normalized }
      : { uid, displayName: request.displayName, disabled: true as const, email: normalized, emailVerified: false as const };
    try { return await this.directory.createUser(properties); } catch (error) {
      // Una respuesta ambigua nunca genera otro UID: sólo se recupera el UID determinista.
      try { return await this.directory.getUser(uid); } catch { throw error; }
    }
  }

  private async finalize(input: {
    operationId: string; requestId: string; uid: string; inputHash: string; request: IdentityPreprovisionRequest;
    identifierHash: string; reservationOperationId: string; principal: AdminPrincipal & { email: string };
  }): Promise<IdentityPreprovisionResponse> {
    return this.db.runTransaction(async (transaction) => {
      const operationRef = this.db.collection("adminOperations").doc(input.operationId);
      const profileRef = this.db.collection("users").doc(input.uid);
      const keyRef = this.db.collection("authIdentifierKeys").doc(input.identifierHash);
      const [operationSnapshot, profileSnapshot, keySnapshot] = await Promise.all([
        transaction.get(operationRef), transaction.get(profileRef), transaction.get(keyRef)
      ]);
      const operation = adminOperationDocumentSchema.parse(operationSnapshot.data());
      if (operation.inputHash !== input.inputHash || operation.targetUid !== input.uid) throw new IdentityPreprovisionError("IDEMPOTENCY_CONFLICT", "La operación cambió durante la preprovisión.");
      if (operation.status === "completed") return identityPreprovisionResponseSchema.parse({ ...operation.result, replayed: true });
      const key = identityIdentifierKeyDocumentSchema.parse(keySnapshot.data());
      if (key.uid !== input.uid || key.operationId !== input.reservationOperationId || key.state === "released") {
        throw new IdentityPreprovisionError("IDENTIFIER_COLLISION", "La reserva no pertenece a esta identidad.");
      }
      const timestamp = this.now();
      let profile: UserV2Document;
      if (profileSnapshot.exists) {
        const existing = userV2DocumentSchema.safeParse(profileSnapshot.data());
        if (!existing.success || existing.data.createdBy !== input.principal.uid || existing.data.authMethod !== input.request.authMethod) {
          throw new IdentityPreprovisionError("AUTH_IDENTITY_MISMATCH", "El perfil existente no corresponde a esta operación.");
        }
        profile = existing.data;
      } else {
        profile = userV2DocumentSchema.parse({
          displayName: input.request.displayName, status: "invited", authDisabled: true, invitationStatus: "pending",
          authMethod: input.request.authMethod,
          phoneE164: input.request.authMethod === "sms" ? normalizePhoneE164(input.request.phoneE164) : null,
          normalizedPhone: input.request.authMethod === "sms" ? normalizePhoneE164(input.request.phoneE164) : null,
          email: input.request.authMethod === "email" ? normalizeIdentityEmail(input.request.email) : null,
          normalizedEmail: input.request.authMethod === "email" ? normalizeIdentityEmail(input.request.email) : null,
          phoneVerifiedAt: null, emailVerifiedAt: null, activationStatus: "pending",
          credentialRevision: 1, authorizationRevision: 1, sessionValidAfter: timestamp,
          createdAt: timestamp, createdBy: input.principal.uid, updatedAt: timestamp, updatedBy: input.principal.uid,
          revision: 1, pendingOperationId: null, version: 2
        });
        transaction.create(profileRef, profile);
      }
      const result = identityPreprovisionResponseSchema.parse({
        operationId: input.operationId, uid: input.uid, authMethod: profile.authMethod,
        activationStatus: "pending", authDisabled: true, revision: 1, replayed: false
      });
      transaction.update(keyRef, { state: "active", updatedAt: timestamp, releasedAt: null });
      transaction.create(this.db.collection("auditEvents").doc(randomUUID()), auditEventDocumentSchema.parse({
        occurredAt: timestamp, actorType: "admin", actorUid: input.principal.uid, actorEmail: input.principal.email,
        providerEventId: null, action: "identity.preprovisioned", resourceType: "user", resourceId: input.uid,
        targetUid: input.uid, appId: null, before: null,
        after: { version: 2, authMethod: profile.authMethod, activationStatus: profile.activationStatus, authDisabled: true, identifierHash: input.identifierHash },
        reason: null, requestId: input.requestId, source: "admin-api", result: "success", version: 1
      }));
      transaction.update(operationRef, {
        status: "completed", checkpoint: "completed", result: { ...result, replayed: false }, failureCode: null,
        updatedAt: timestamp, completedAt: timestamp
      });
      return result;
    });
  }

  private async markReconciliation(
    operationRef: FirebaseFirestore.DocumentReference,
    requestId: string,
    principal: AdminPrincipal & { email: string },
    uid: string,
    error: unknown
  ): Promise<void> {
    const failureCode = (error instanceof IdentityPreprovisionError ? error.code : authCode(error) ?? "PREPROVISION_FAILED")
      .replace(/[^A-Za-z0-9_]/g, "_").toUpperCase().slice(0, 80);
    try {
      const timestamp = this.now();
      await this.db.runTransaction(async (transaction) => {
        const snapshot = await transaction.get(operationRef);
        if (!snapshot.exists) return;
        const operation = adminOperationDocumentSchema.parse(snapshot.data());
        if (operation.status === "completed") return;
        transaction.update(operationRef, { status: "reconciliation_required", failureCode, updatedAt: timestamp, leaseExpiresAt: timestamp });
        transaction.create(this.db.collection("auditEvents").doc(randomUUID()), auditEventDocumentSchema.parse({
          occurredAt: timestamp, actorType: "admin", actorUid: principal.uid, actorEmail: principal.email,
          providerEventId: null, action: "identity.preprovisioned", resourceType: "user", resourceId: uid,
          targetUid: uid, appId: null, before: null, after: null, reason: null,
          requestId, source: "admin-api", result: "failure", version: 1
        }));
      });
    } catch {
      // El error original se conserva; un fallo de persistencia se concilia con la misma operación determinista.
    }
  }
}
