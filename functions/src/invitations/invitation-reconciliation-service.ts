import { createHash, randomUUID } from "node:crypto";
import { Timestamp, type DocumentReference, type Firestore, type QueryDocumentSnapshot } from "firebase-admin/firestore";
import { adminOperationDocumentSchema, invitationDocumentSchema, userDocumentSchema } from "../models/admin-collections.js";
import type { UserDirectory } from "../users/user-query-service.js";

function hash(value: string) {
  return createHash("sha256").update(value).digest("hex");
}

type Candidate = QueryDocumentSnapshot;

export class InvitationReconciliationService {
  constructor(
    private readonly directory: UserDirectory,
    private readonly db: Firestore,
    private readonly protectedUid: string | null,
    private readonly now: () => Timestamp = () => Timestamp.now()
  ) {}

  async reconcileOnce(limit = 100) {
    if (!Number.isInteger(limit) || limit < 1 || limit > 500) throw new Error("INVALID_RECONCILIATION_LIMIT");
    const timestamp = this.now();
    const [expired, confirmationExpired, stalled] = await Promise.all([
      this.db.collection("invitations").where("expiresAt", "<=", timestamp).limit(limit).get(),
      this.db.collection("invitations").where("confirmationExpiresAt", "<=", timestamp).limit(limit).get(),
      this.db.collection("invitations").where("consumeLeaseExpiresAt", "<=", timestamp).limit(limit).get()
    ]);
    const candidates = new Map<string, Candidate>();
    for (const snapshot of [...expired.docs, ...confirmationExpired.docs, ...stalled.docs]) candidates.set(snapshot.id, snapshot);
    const result = { inspected: candidates.size, expired: 0, secured: 0, reconciliationRequired: 0, protected: 0, skipped: 0 };
    for (const candidate of candidates.values()) {
      const reservation = await this.reserve(candidate.ref, timestamp);
      if (reservation.kind === "skip") { result.skipped += 1; continue; }
      if (reservation.kind === "expired") { result.expired += 1; continue; }
      const authUser = await this.directory.getUser(reservation.uid).catch(() => null);
      if (!authUser || authUser.uid === this.protectedUid || authUser.customClaims?.super_admin === true) {
        result.protected += 1;
        await this.markProtected(candidate.ref, reservation.operationRef, timestamp);
        continue;
      }
      try {
        await this.directory.updateUser(reservation.uid, { disabled: true });
        await this.directory.revokeRefreshTokens(reservation.uid);
        await this.finalizeSecured(candidate.ref, reservation.operationRef, timestamp);
        result.secured += 1;
      } catch {
        result.reconciliationRequired += 1;
        await this.markAuthAmbiguous(reservation.operationRef, timestamp);
      }
    }
    return result;
  }

  private async reserve(reference: DocumentReference, timestamp: Timestamp) {
    return this.db.runTransaction(async (transaction) => {
      const snapshot = await transaction.get(reference);
      if (!snapshot.exists) return { kind: "skip" as const };
      const invitation = invitationDocumentSchema.parse(snapshot.data());
      if (["accepted", "expired", "revoked"].includes(invitation.status)) return { kind: "skip" as const };
      const ordinaryExpiry = invitation.expiresAt.toMillis() <= timestamp.toMillis()
        && ["provisioning", "pending_delivery", "active"].includes(invitation.status);
      if (ordinaryExpiry) {
        await this.expireWithoutAuth(transaction, reference, invitation, timestamp);
        return { kind: "expired" as const };
      }
      const confirmationExpired = invitation.status === "password_set"
        && invitation.confirmationExpiresAt !== null
        && invitation.confirmationExpiresAt.toMillis() <= timestamp.toMillis();
      const acceptanceStalled = invitation.status === "accepting"
        && invitation.consumeLeaseExpiresAt !== null
        && invitation.consumeLeaseExpiresAt.toMillis() <= timestamp.toMillis();
      if (!confirmationExpired && !acceptanceStalled) return { kind: "skip" as const };
      const operationId = randomUUID();
      const operationRef = this.db.collection("adminOperations").doc(operationId);
      transaction.update(reference, {
        status: "reconciliation_required", token: null, pendingOperationId: operationId,
        consumeLeaseExpiresAt: null, updatedAt: timestamp, updatedBy: invitation.uid,
        revision: invitation.revision + 1
      });
      transaction.create(operationRef, adminOperationDocumentSchema.parse({
        operationId, type: "invitation.expire", targetUid: invitation.uid, invitationId: invitation.invitationId,
        actorUid: "system-reconciliation", inputHash: hash(`invitation.expire:${invitation.invitationId}:${invitation.revision}`),
        expectedRevision: invitation.revision, status: "pending", checkpoint: "reserved", requestId: randomUUID(),
        leaseOwner: operationId, leaseExpiresAt: Timestamp.fromMillis(timestamp.toMillis() + 60_000),
        attempts: 1, result: null, failureCode: null, createdAt: timestamp, updatedAt: timestamp,
        completedAt: null, version: 1
      }));
      return { kind: "secure" as const, uid: invitation.uid, operationRef };
    });
  }

  private async expireWithoutAuth(transaction: FirebaseFirestore.Transaction, reference: DocumentReference, invitation: ReturnType<typeof invitationDocumentSchema.parse>, timestamp: Timestamp) {
    const profileRef = this.db.collection("users").doc(invitation.uid);
    const profileSnapshot = await transaction.get(profileRef);
    const profile = userDocumentSchema.safeParse(profileSnapshot.data());
    transaction.update(reference, {
      status: "expired", token: null, expiredAt: timestamp, pendingOperationId: null,
      consumeLeaseExpiresAt: null, updatedAt: timestamp, updatedBy: "system-reconciliation",
      revision: invitation.revision + 1
    });
    if (profile.success && profile.data.status === "invited") transaction.update(profileRef, {
      status: "disabled", authDisabled: true, invitationStatus: "expired", updatedAt: timestamp,
      updatedBy: "system-reconciliation", revision: profile.data.revision + 1, pendingOperationId: null
    });
    transaction.update(this.db.collection("invitationUniqueKeys").doc(hash(invitation.normalizedEmail)), { state: "released", updatedAt: timestamp });
    transaction.create(this.db.collection("auditEvents").doc(randomUUID()), {
      occurredAt: timestamp, actorType: "system", actorUid: null, actorEmail: null, providerEventId: null,
      action: "invitation.expired", resourceType: "invitation", resourceId: invitation.invitationId,
      targetUid: invitation.uid, appId: null, before: { status: invitation.status }, after: { status: "expired" },
      reason: "SERVER_CLOCK_EXPIRATION", requestId: randomUUID(), source: "admin-api", result: "success", version: 1
    });
  }

  private async finalizeSecured(invitationRef: DocumentReference, operationRef: DocumentReference, timestamp: Timestamp) {
    await this.db.runTransaction(async (transaction) => {
      const [invitationSnapshot, operationSnapshot] = await Promise.all([transaction.get(invitationRef), transaction.get(operationRef)]);
      const invitation = invitationDocumentSchema.parse(invitationSnapshot.data());
      const operation = adminOperationDocumentSchema.parse(operationSnapshot.data());
      if (invitation.status !== "reconciliation_required" || invitation.pendingOperationId !== operation.operationId) return;
      const profileRef = this.db.collection("users").doc(invitation.uid);
      const profile = userDocumentSchema.safeParse((await transaction.get(profileRef)).data());
      transaction.update(invitationRef, {
        status: "expired", expiredAt: timestamp, pendingOperationId: null, updatedAt: timestamp,
        updatedBy: "system-reconciliation", revision: invitation.revision + 1
      });
      if (profile.success && profile.data.status === "invited") transaction.update(profileRef, {
        status: "disabled", authDisabled: true, invitationStatus: "expired", pendingOperationId: null,
        updatedAt: timestamp, updatedBy: "system-reconciliation", revision: profile.data.revision + 1
      });
      transaction.update(this.db.collection("invitationUniqueKeys").doc(hash(invitation.normalizedEmail)), { state: "released", updatedAt: timestamp });
      transaction.update(operationRef, {
        status: "completed", checkpoint: "completed", result: { status: "expired", secured: true },
        updatedAt: timestamp, completedAt: timestamp, failureCode: null
      });
      transaction.create(this.db.collection("auditEvents").doc(randomUUID()), {
        occurredAt: timestamp, actorType: "system", actorUid: null, actorEmail: null, providerEventId: null,
        action: "invitation.expired", resourceType: "invitation", resourceId: invitation.invitationId,
        targetUid: invitation.uid, appId: null, before: { status: "reconciliation_required" },
        after: { status: "expired", authDisabled: true }, reason: "ACCEPTANCE_WINDOW_EXPIRED",
        requestId: randomUUID(), source: "admin-api", result: "success", version: 1
      });
    });
  }

  private async markProtected(invitationRef: DocumentReference, operationRef: DocumentReference, timestamp: Timestamp) {
    await this.db.runTransaction(async (transaction) => {
      transaction.update(invitationRef, { pendingOperationId: null, updatedAt: timestamp });
      transaction.update(operationRef, {
        status: "reconciliation_required", failureCode: "PROTECTED_OR_MISSING_ACCOUNT",
        leaseExpiresAt: timestamp, updatedAt: timestamp
      });
    });
  }

  private async markAuthAmbiguous(operationRef: DocumentReference, timestamp: Timestamp) {
    await operationRef.update({
      status: "reconciliation_required", failureCode: "AUTH_STATE_AMBIGUOUS",
      leaseExpiresAt: timestamp, updatedAt: timestamp
    });
  }
}
