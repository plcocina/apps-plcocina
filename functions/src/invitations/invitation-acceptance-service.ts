import { createHash, randomUUID } from "node:crypto";
import { Timestamp, type Firestore } from "firebase-admin/firestore";
import { z } from "zod";
import type { AuthenticatedPrincipal } from "../auth/require-authenticated-user.js";
import { ApiError } from "../http/errors.js";
import { adminOperationDocumentSchema, invitationDocumentSchema, userDocumentSchema } from "../models/admin-collections.js";
import type { UserDirectory } from "../users/user-query-service.js";
import { effectiveInvitationStatus } from "./invitation-transitions.js";
import { INVITATION_CONFIRMATION_MINUTES, INVITATION_PASSWORD_POLICY, InvitationTokenKeyring } from "./invitation-token.js";

const invitationIdSchema = z.string().uuid();
const tokenSchema = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
const validateSchema = z.object({ invitationId: invitationIdSchema, token: tokenSchema }).strict();
const establishSchema = z.object({
  invitationId: invitationIdSchema,
  token: tokenSchema,
  password: z.string().min(INVITATION_PASSWORD_POLICY.minLength).max(INVITATION_PASSWORD_POLICY.maxLength)
}).strict();

type RateKind = "validate" | "establish";
type PublicInvitation = z.infer<typeof invitationDocumentSchema>;

function hash(value: string) {
  return createHash("sha256").update(value).digest("hex");
}

function authCode(error: unknown) {
  return typeof error === "object" && error !== null && "code" in error ? String(error.code) : undefined;
}

export class InvitationAcceptanceService {
  constructor(
    private readonly directory: UserDirectory,
    private readonly db: Firestore,
    private readonly tokens: InvitationTokenKeyring | null,
    private readonly protectedUid: string | null,
    private readonly now: () => Timestamp = () => Timestamp.now()
  ) {}

  async validate(body: unknown, sourceIdentifier: string) {
    this.assertConfigured();
    const parsed = validateSchema.safeParse(body);
    if (!parsed.success) throw this.invalidInvitation();
    await this.consumeRateLimit("validate", parsed.data.invitationId, sourceIdentifier);
    const invitation = await this.loadValidInvitation(parsed.data.invitationId, parsed.data.token);
    return { valid: true as const, expiresAt: invitation.expiresAt.toDate().toISOString() };
  }

  async establishPassword(body: unknown, sourceIdentifier: string, requestId: string) {
    this.assertConfigured();
    const parsed = establishSchema.safeParse(body);
    if (!parsed.success) {
      const passwordIssue = parsed.error.issues.some((issue) => issue.path[0] === "password");
      throw new ApiError(400, "VALIDATION_ERROR", passwordIssue ? "La contraseña debe tener entre 12 y 128 caracteres." : "La invitación no es válida.");
    }
    await this.consumeRateLimit("establish", parsed.data.invitationId, sourceIdentifier);
    const invitation = await this.loadValidInvitation(parsed.data.invitationId, parsed.data.token);
    const authUser = await this.directory.getUser(invitation.uid).catch((error) => {
      if (authCode(error) === "auth/user-not-found") throw this.invalidInvitation();
      throw error;
    });
    if (invitation.uid === this.protectedUid || authUser.customClaims?.super_admin === true) throw this.invalidInvitation();
    if (authUser.email?.toLowerCase() !== invitation.normalizedEmail) throw this.invalidInvitation();

    const operationId = randomUUID();
    const operationRef = this.db.collection("adminOperations").doc(operationId);
    const invitationRef = this.db.collection("invitations").doc(invitation.invitationId);
    const profileRef = this.db.collection("users").doc(invitation.uid);
    const timestamp = this.now();
    const inputHash = hash(JSON.stringify({ type: "invitation.accept", invitationId: invitation.invitationId, generation: invitation.token!.generation }));

    await this.db.runTransaction(async (transaction) => {
      const [invitationSnapshot, profileSnapshot] = await Promise.all([transaction.get(invitationRef), transaction.get(profileRef)]);
      if (!invitationSnapshot.exists) throw this.invalidInvitation();
      const current = invitationDocumentSchema.parse(invitationSnapshot.data());
      this.assertToken(current, parsed.data.token, timestamp);
      if (current.pendingOperationId || current.consumeOperationId) throw this.invalidInvitation();
      const profile = userDocumentSchema.safeParse(profileSnapshot.data());
      if (!profile.success || profile.data.status !== "invited" || profile.data.normalizedEmail !== current.normalizedEmail) throw this.invalidInvitation();
      transaction.update(invitationRef, {
        status: "accepting", token: null, consumeOperationId: operationId,
        consumeLeaseExpiresAt: Timestamp.fromMillis(timestamp.toMillis() + 60_000), pendingOperationId: operationId,
        updatedAt: timestamp, updatedBy: current.uid, revision: current.revision + 1
      });
      transaction.create(operationRef, {
        operationId, type: "invitation.accept", targetUid: current.uid, invitationId: current.invitationId,
        actorUid: current.uid, inputHash, expectedRevision: current.revision, status: "pending", checkpoint: "reserved",
        requestId, leaseOwner: requestId, leaseExpiresAt: Timestamp.fromMillis(timestamp.toMillis() + 60_000), attempts: 1,
        result: null, failureCode: null, createdAt: timestamp, updatedAt: timestamp, completedAt: null, version: 1
      });
    });

    try {
      await this.directory.updateUser(invitation.uid, { password: parsed.data.password, disabled: false });
      await this.markPasswordApplied(operationRef, requestId);
      return await this.finalizePasswordSet(invitationRef, operationRef, requestId);
    } catch (error) {
      await this.compensateAndMarkReconciliation(invitationRef, operationRef, invitation.uid, requestId, error).catch(() => undefined);
      throw new ApiError(503, "RECONCILIATION_REQUIRED", "No fue posible completar la invitación. Solicite un nuevo enlace al administrador.");
    }
  }

  async confirm(invitationIdInput: string, principal: AuthenticatedPrincipal, requestId: string) {
    this.assertConfigured();
    const parsedId = invitationIdSchema.safeParse(invitationIdInput);
    if (!parsedId.success) throw this.invalidInvitation();
    if (principal.superAdmin || principal.uid === this.protectedUid) throw this.invalidInvitation();
    const authUser = await this.directory.getUser(principal.uid).catch(() => { throw this.invalidInvitation(); });
    if (authUser.customClaims?.super_admin === true || authUser.uid === this.protectedUid) throw this.invalidInvitation();
    const invitationRef = this.db.collection("invitations").doc(parsedId.data);
    const profileRef = this.db.collection("users").doc(principal.uid);
    const timestamp = this.now();

    return this.db.runTransaction(async (transaction) => {
      const [invitationSnapshot, profileSnapshot] = await Promise.all([transaction.get(invitationRef), transaction.get(profileRef)]);
      if (!invitationSnapshot.exists) throw this.invalidInvitation();
      const invitation = invitationDocumentSchema.parse(invitationSnapshot.data());
      if (invitation.uid !== principal.uid || invitation.normalizedEmail !== principal.email || authUser.email?.toLowerCase() !== invitation.normalizedEmail) throw this.invalidInvitation();
      if (invitation.status === "accepted") return { status: "accepted" as const, acceptedAt: invitation.acceptedAt!.toDate().toISOString() };
      if (invitation.pendingOperationId) throw this.invalidInvitation();
      if (effectiveInvitationStatus(invitation, timestamp.toMillis()) !== "password_set" || !invitation.confirmationExpiresAt || invitation.confirmationExpiresAt.toMillis() <= timestamp.toMillis()) throw this.invalidInvitation();
      const profile = userDocumentSchema.safeParse(profileSnapshot.data());
      if (!profile.success || profile.data.status !== "invited" || profile.data.invitationStatus !== "pending") throw this.invalidInvitation();
      const updatedRevision = invitation.revision + 1;
      transaction.update(invitationRef, {
        status: "accepted", acceptedAt: timestamp, confirmationExpiresAt: null, pendingOperationId: null,
        consumeLeaseExpiresAt: null, updatedAt: timestamp, updatedBy: principal.uid, revision: updatedRevision
      });
      transaction.update(profileRef, {
        status: "active", authDisabled: false, invitationStatus: "accepted", updatedAt: timestamp,
        updatedBy: principal.uid, revision: profile.data.revision + 1, pendingOperationId: null
      });
      transaction.update(this.db.collection("invitationUniqueKeys").doc(hash(invitation.normalizedEmail)), { state: "accepted", updatedAt: timestamp });
      transaction.create(this.db.collection("auditEvents").doc(randomUUID()), {
        occurredAt: timestamp, actorType: "user", actorUid: principal.uid, actorEmail: principal.email,
        providerEventId: null, action: "invitation.accepted", resourceType: "invitation", resourceId: invitation.invitationId,
        targetUid: invitation.uid, appId: null, before: { status: "password_set" }, after: { status: "accepted", revision: updatedRevision },
        reason: null, requestId, source: "admin-api", result: "success", version: 1
      });
      return { status: "accepted" as const, acceptedAt: timestamp.toDate().toISOString() };
    });
  }

  private assertConfigured() {
    if (!this.tokens || !this.protectedUid) throw new ApiError(503, "INTERNAL_ERROR", "El servicio de invitaciones no está configurado de forma segura.");
  }

  private invalidInvitation() {
    return new ApiError(400, "INVITATION_INVALID", "La invitación no es válida o ya no está disponible.");
  }

  private async loadValidInvitation(invitationId: string, token: string) {
    const snapshot = await this.db.collection("invitations").doc(invitationId).get();
    if (!snapshot.exists) throw this.invalidInvitation();
    const parsed = invitationDocumentSchema.safeParse(snapshot.data());
    if (!parsed.success) throw this.invalidInvitation();
    this.assertToken(parsed.data, token, this.now());
    return parsed.data;
  }

  private assertToken(invitation: PublicInvitation, token: string, timestamp: Timestamp) {
    if (effectiveInvitationStatus(invitation, timestamp.toMillis()) !== "active" || !invitation.token) throw this.invalidInvitation();
    if (invitation.token.expiresAt.toMillis() <= timestamp.toMillis() || invitation.expiresAt.toMillis() <= timestamp.toMillis()) throw this.invalidInvitation();
    if (!this.tokens!.verify(token, invitation.token.hash)) throw this.invalidInvitation();
  }

  private async consumeRateLimit(kind: RateKind, invitationId: string, sourceIdentifier: string) {
    const timestamp = this.now();
    const config = kind === "validate" ? { limit: 12, windowMs: 5 * 60_000 } : { limit: 5, windowMs: 15 * 60_000 };
    const window = Math.floor(timestamp.toMillis() / config.windowMs);
    const keys = [
      `${kind}_inv_${hash(invitationId).slice(0, 40)}_${window}`,
      `${kind}_src_${hash(sourceIdentifier).slice(0, 40)}_${window}`
    ];
    const refs = keys.map((key) => this.db.collection("invitationRateLimits").doc(key));
    await this.db.runTransaction(async (transaction) => {
      const snapshots = await Promise.all(refs.map((reference) => transaction.get(reference)));
      if (snapshots.some((snapshot) => snapshot.exists && Number(snapshot.data()?.count) >= config.limit)) {
        throw new ApiError(429, "RATE_LIMITED", "Demasiados intentos. Espere antes de intentarlo nuevamente.");
      }
      const expiresAt = Timestamp.fromMillis((window + 2) * config.windowMs);
      snapshots.forEach((snapshot, index) => transaction.set(refs[index]!, {
        kind, subjectHash: keys[index]!.split("_")[2], window, count: snapshot.exists ? Number(snapshot.data()?.count) + 1 : 1,
        updatedAt: timestamp, expiresAt, version: 1
      }));
    });
  }

  private async markPasswordApplied(operationRef: FirebaseFirestore.DocumentReference, requestId: string) {
    const timestamp = this.now();
    await this.db.runTransaction(async (transaction) => {
      const operation = adminOperationDocumentSchema.parse((await transaction.get(operationRef)).data());
      if (operation.leaseOwner !== requestId) throw new ApiError(409, "OPERATION_IN_PROGRESS", "La operación fue reclamada por otra solicitud.");
      transaction.update(operationRef, { status: "auth_applied", checkpoint: "password_applied", updatedAt: timestamp });
    });
  }

  private async finalizePasswordSet(invitationRef: FirebaseFirestore.DocumentReference, operationRef: FirebaseFirestore.DocumentReference, requestId: string) {
    const timestamp = this.now();
    return this.db.runTransaction(async (transaction) => {
      const [invitationSnapshot, operationSnapshot] = await Promise.all([transaction.get(invitationRef), transaction.get(operationRef)]);
      const invitation = invitationDocumentSchema.parse(invitationSnapshot.data());
      const operation = adminOperationDocumentSchema.parse(operationSnapshot.data());
      if (operation.leaseOwner !== requestId || invitation.status !== "accepting" || invitation.consumeOperationId !== operation.operationId) throw this.invalidInvitation();
      const confirmationExpiresAt = Timestamp.fromMillis(timestamp.toMillis() + INVITATION_CONFIRMATION_MINUTES * 60_000);
      const revision = invitation.revision + 1;
      const result = { status: "password_set" as const, confirmationExpiresAt: confirmationExpiresAt.toDate().toISOString() };
      transaction.update(invitationRef, {
        status: "password_set", passwordSetAt: timestamp, confirmationExpiresAt, pendingOperationId: null,
        consumeLeaseExpiresAt: null, updatedAt: timestamp, updatedBy: invitation.uid, revision
      });
      transaction.update(operationRef, { status: "completed", checkpoint: "completed", result, updatedAt: timestamp, completedAt: timestamp, failureCode: null });
      transaction.create(this.db.collection("auditEvents").doc(randomUUID()), {
        occurredAt: timestamp, actorType: "system", actorUid: null, actorEmail: null, providerEventId: null,
        action: "invitation.password_set", resourceType: "invitation", resourceId: invitation.invitationId,
        targetUid: invitation.uid, appId: null, before: { status: "accepting" }, after: { status: "password_set", revision },
        reason: null, requestId, source: "admin-api", result: "success", version: 1
      });
      return result;
    });
  }

  private async compensateAndMarkReconciliation(
    invitationRef: FirebaseFirestore.DocumentReference,
    operationRef: FirebaseFirestore.DocumentReference,
    uid: string,
    requestId: string,
    error: unknown
  ) {
    let compensationFailed = false;
    try {
      await this.directory.updateUser(uid, { disabled: true });
      await this.directory.revokeRefreshTokens(uid);
    } catch {
      compensationFailed = true;
    }
    const timestamp = this.now();
    const code = compensationFailed ? "AUTH_STATE_AMBIGUOUS" : (authCode(error) ?? "PASSWORD_OPERATION_INCOMPLETE").replace(/[^A-Za-z0-9_]/g, "_").toUpperCase().slice(0, 80);
    await this.db.runTransaction(async (transaction) => {
      const [invitationSnapshot, operationSnapshot] = await Promise.all([transaction.get(invitationRef), transaction.get(operationRef)]);
      if (invitationSnapshot.exists) transaction.update(invitationRef, {
        status: "reconciliation_required", token: null, pendingOperationId: null, consumeLeaseExpiresAt: null,
        updatedAt: timestamp, updatedBy: uid
      });
      if (operationSnapshot.exists) transaction.update(operationRef, {
        status: "reconciliation_required", failureCode: code, leaseExpiresAt: timestamp, updatedAt: timestamp, requestId
      });
    });
  }
}
