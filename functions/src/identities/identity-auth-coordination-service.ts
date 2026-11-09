import { createHash } from "node:crypto";
import { Timestamp, type Firestore, type Transaction } from "firebase-admin/firestore";
import { z } from "zod";
import { auditEventDocumentSchema } from "../models/admin-collections.js";
import { authCoordinationDocumentSchema, type AuthCoordinationDocument, type TrustedAuthCoordinationEvent } from "./identity-auth-coordination-contracts.js";
import { evaluateAuthCoordinationTransition } from "./identity-auth-coordination-transitions.js";

const uidSchema = z.string().min(1).max(128).refine((value) => !value.includes("/"));
const hashSchema = z.string().regex(/^[a-f0-9]{64}$/);
const uuidSchema = z.string().uuid();

const lockSchema = z.object({
  kind: z.enum(["uid", "googleSubject"]), keyHash: hashSchema, operationId: uuidSchema,
  expectedFirebaseUid: uidSchema, googleSubjectHash: hashSchema, state: z.string().min(1).max(80),
  revision: z.number().int().positive(), createdAt: z.instanceof(Timestamp), updatedAt: z.instanceof(Timestamp), version: z.literal(1)
}).strict();

const idempotencySchema = z.object({
  idempotencyKey: uuidSchema, operationId: uuidSchema, kind: z.enum(["create", "transition"]),
  inputHash: hashSchema, resultingRevision: z.number().int().positive(), createdAt: z.instanceof(Timestamp), version: z.literal(1)
}).strict();

export type AuthCoordinationPersistenceResult = { document: AuthCoordinationDocument; replayed: boolean };
export type AuthCoordinationPersistenceErrorCode = "TRUSTED_CONTEXT_MISMATCH" | "SUPER_ADMIN_FORBIDDEN"
  | "INITIAL_STATE_INVALID" | "OPERATION_NOT_FOUND" | "OPERATION_CONFLICT" | "UID_LOCK_CONFLICT"
  | "SUBJECT_LOCK_CONFLICT" | "LOCK_INCONSISTENT" | "IDEMPOTENCY_CONFLICT" | "REVISION_CONFLICT";

export class AuthCoordinationPersistenceError extends Error {
  constructor(readonly code: AuthCoordinationPersistenceErrorCode) {
    super("Auth coordination persistence rejected");
    this.name = "AuthCoordinationPersistenceError";
  }
}

function canonical(value: unknown): unknown {
  if (value instanceof Timestamp) return { seconds: value.seconds, nanoseconds: value.nanoseconds };
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => [key, canonical(item)]));
  }
  return value;
}

function canonicalHash(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(canonical(value))).digest("hex");
}

function lockId(kind: "uid" | "googleSubject", value: string): string {
  return `${kind}-${createHash("sha256").update(value).digest("hex")}`;
}

function assertInitial(document: AuthCoordinationDocument): void {
  if (document.state !== "not_started" || document.revision !== 1 || document.lastEvent !== null
    || document.conflictReason !== null || document.challengeId !== null || document.evidence.challenge !== null
    || document.evidence.googleVerification !== null || document.evidence.firebaseSession !== null
    || document.evidence.firebaseProvider !== null || document.evidence.postflight !== null) {
    throw new AuthCoordinationPersistenceError("INITIAL_STATE_INVALID");
  }
}

export type PreparedAuthCoordinationTransition = Readonly<{
  previousDocument: AuthCoordinationDocument;
  result: AuthCoordinationPersistenceResult;
  apply: () => void;
}>;

export async function prepareAuthCoordinationTransition(input: {
  db: Firestore;
  transaction: Transaction;
  trustedAdministratorUid: string;
  protectedSuperAdminUid: string;
  operationId: string;
  expectedRevision: number;
  event: TrustedAuthCoordinationEvent;
  now: Timestamp;
}): Promise<PreparedAuthCoordinationTransition> {
  const actorUid = uidSchema.parse(input.trustedAdministratorUid);
  const protectedUid = uidSchema.parse(input.protectedSuperAdminUid);
  if (actorUid !== protectedUid) throw new AuthCoordinationPersistenceError("TRUSTED_CONTEXT_MISMATCH");
  const operationId = uuidSchema.parse(input.operationId);
  const expectedRevision = z.number().int().positive().parse(input.expectedRevision);
  if (input.event.operationId !== operationId || input.event.expectedCoordinationRevision !== expectedRevision) {
    throw new AuthCoordinationPersistenceError("REVISION_CONFLICT");
  }
  const inputHash = canonicalHash(input.event);
  const operationRef = input.db.collection("identityAuthCoordinations").doc(operationId);
  const idempotencyRef = input.db.collection("identityAuthCoordinationIdempotency").doc(input.event.idempotencyKey);
  const operationSnapshot = await input.transaction.get(operationRef);
  if (!operationSnapshot.exists) throw new AuthCoordinationPersistenceError("OPERATION_NOT_FOUND");
  const document = authCoordinationDocumentSchema.parse(operationSnapshot.data());
  const uidLockRef = input.db.collection("identityAuthCoordinationLocks").doc(lockId("uid", document.expectedFirebaseUid));
  const subjectLockRef = input.db.collection("identityAuthCoordinationLocks").doc(lockId("googleSubject", document.googleSubjectHash));
  const [idempotencySnapshot, uidLockSnapshot, subjectLockSnapshot] = await Promise.all([
    input.transaction.get(idempotencyRef), input.transaction.get(uidLockRef), input.transaction.get(subjectLockRef)
  ]);
  if (idempotencySnapshot.exists) {
    const stored = idempotencySchema.safeParse(idempotencySnapshot.data());
    if (!stored.success || stored.data.kind !== "transition" || stored.data.operationId !== operationId
      || stored.data.inputHash !== inputHash) throw new AuthCoordinationPersistenceError("IDEMPOTENCY_CONFLICT");
    return Object.freeze({ previousDocument: document, result: { document, replayed: true }, apply: () => undefined });
  }
  for (const snapshot of [uidLockSnapshot, subjectLockSnapshot]) {
    const lock = lockSchema.safeParse(snapshot.data());
    if (!snapshot.exists || !lock.success || lock.data.operationId !== operationId
      || lock.data.expectedFirebaseUid !== document.expectedFirebaseUid
      || lock.data.googleSubjectHash !== document.googleSubjectHash) {
      throw new AuthCoordinationPersistenceError("LOCK_INCONSISTENT");
    }
  }
  if (document.revision !== expectedRevision) throw new AuthCoordinationPersistenceError("REVISION_CONFLICT");
  const evaluated = evaluateAuthCoordinationTransition({ document, event: input.event, now: input.now,
    protectedSuperAdminUid: protectedUid });
  if (evaluated.replayed) {
    return Object.freeze({ previousDocument: document, result: { document: evaluated.document, replayed: true },
      apply: () => undefined });
  }
  const next = evaluated.document;
  const auditRef = input.db.collection("auditEvents").doc(`auth-coordination-${operationId}-${next.revision}`);
  const idempotency = idempotencySchema.parse({ idempotencyKey: input.event.idempotencyKey, operationId,
    kind: "transition", inputHash, resultingRevision: next.revision, createdAt: input.now, version: 1 });
  const audit = auditEventDocumentSchema.parse({ occurredAt: input.now, actorType: "admin", actorUid,
    actorEmail: null, providerEventId: null, action: "identity.coordination_transitioned", resourceType: "user",
    resourceId: next.expectedFirebaseUid, targetUid: next.expectedFirebaseUid, appId: null,
    before: { operationId, state: document.state, revision: document.revision },
    after: { operationId, state: next.state, revision: next.revision, authDisabled: next.localAuthDisabled },
    reason: input.event.type, requestId: input.event.idempotencyKey, source: "admin-api", result: "success", version: 1 });
  return Object.freeze({ previousDocument: document, result: { document: next, replayed: false }, apply: () => {
    input.transaction.set(operationRef, next);
    input.transaction.create(idempotencyRef, idempotency);
    input.transaction.update(uidLockRef, { state: next.state, revision: next.revision, updatedAt: input.now });
    input.transaction.update(subjectLockRef, { state: next.state, revision: next.revision, updatedAt: input.now });
    input.transaction.create(auditRef, audit);
  } });
}

export class AuthCoordinationPersistenceService {
  constructor(private readonly db: Firestore, private readonly protectedSuperAdminUid: string,
    private readonly now: () => Timestamp = () => Timestamp.now()) {
    uidSchema.parse(protectedSuperAdminUid);
  }

  async create(input: { trustedAdministratorUid: string; document: unknown }): Promise<AuthCoordinationPersistenceResult> {
    const actorUid = uidSchema.parse(input.trustedAdministratorUid);
    if (actorUid !== this.protectedSuperAdminUid) throw new AuthCoordinationPersistenceError("TRUSTED_CONTEXT_MISMATCH");
    const document = authCoordinationDocumentSchema.parse(input.document);
    assertInitial(document);
    if (document.expectedFirebaseUid === this.protectedSuperAdminUid) throw new AuthCoordinationPersistenceError("SUPER_ADMIN_FORBIDDEN");
    const inputHash = canonicalHash(document);
    const operationRef = this.db.collection("identityAuthCoordinations").doc(document.operationId);
    const idempotencyRef = this.db.collection("identityAuthCoordinationIdempotency").doc(document.idempotencyKey);
    const uidLockRef = this.db.collection("identityAuthCoordinationLocks").doc(lockId("uid", document.expectedFirebaseUid));
    const subjectLockRef = this.db.collection("identityAuthCoordinationLocks").doc(lockId("googleSubject", document.googleSubjectHash));
    const auditRef = this.db.collection("auditEvents").doc(`auth-coordination-${document.operationId}-1`);

    return this.db.runTransaction(async (transaction) => {
      const [operationSnapshot, idempotencySnapshot, uidLockSnapshot, subjectLockSnapshot] = await Promise.all([
        transaction.get(operationRef), transaction.get(idempotencyRef), transaction.get(uidLockRef), transaction.get(subjectLockRef)
      ]);
      if (idempotencySnapshot.exists) {
        const stored = idempotencySchema.safeParse(idempotencySnapshot.data());
        if (!stored.success || stored.data.kind !== "create" || stored.data.operationId !== document.operationId
          || stored.data.inputHash !== inputHash) throw new AuthCoordinationPersistenceError("IDEMPOTENCY_CONFLICT");
        if (!operationSnapshot.exists) throw new AuthCoordinationPersistenceError("OPERATION_CONFLICT");
        return { document: authCoordinationDocumentSchema.parse(operationSnapshot.data()), replayed: true };
      }
      if (operationSnapshot.exists) throw new AuthCoordinationPersistenceError("OPERATION_CONFLICT");
      if (uidLockSnapshot.exists) throw new AuthCoordinationPersistenceError("UID_LOCK_CONFLICT");
      if (subjectLockSnapshot.exists) throw new AuthCoordinationPersistenceError("SUBJECT_LOCK_CONFLICT");
      const timestamp = this.now();
      const baseLock = { operationId: document.operationId, expectedFirebaseUid: document.expectedFirebaseUid,
        googleSubjectHash: document.googleSubjectHash, state: document.state, revision: 1,
        createdAt: timestamp, updatedAt: timestamp, version: 1 as const };
      const idempotency = idempotencySchema.parse({ idempotencyKey: document.idempotencyKey,
        operationId: document.operationId, kind: "create", inputHash, resultingRevision: 1, createdAt: timestamp, version: 1 });
      const audit = auditEventDocumentSchema.parse({ occurredAt: timestamp, actorType: "admin", actorUid,
        actorEmail: null, providerEventId: null, action: "identity.coordination_created", resourceType: "user",
        resourceId: document.expectedFirebaseUid, targetUid: document.expectedFirebaseUid, appId: null, before: null,
        after: { operationId: document.operationId, state: document.state, revision: 1, authDisabled: true },
        reason: "Firebase Auth coordination created", requestId: document.operationId, source: "admin-api", result: "success", version: 1 });
      transaction.create(operationRef, document);
      transaction.create(idempotencyRef, idempotency);
      transaction.create(uidLockRef, lockSchema.parse({ ...baseLock, kind: "uid", keyHash: canonicalHash(document.expectedFirebaseUid) }));
      transaction.create(subjectLockRef, lockSchema.parse({ ...baseLock, kind: "googleSubject", keyHash: canonicalHash(document.googleSubjectHash) }));
      transaction.create(auditRef, audit);
      return { document, replayed: false };
    });
  }

  async get(operationId: string): Promise<AuthCoordinationDocument> {
    const snapshot = await this.db.collection("identityAuthCoordinations").doc(uuidSchema.parse(operationId)).get();
    if (!snapshot.exists) throw new AuthCoordinationPersistenceError("OPERATION_NOT_FOUND");
    return authCoordinationDocumentSchema.parse(snapshot.data());
  }

  async transition(input: { trustedAdministratorUid: string; operationId: string; expectedRevision: number;
    event: TrustedAuthCoordinationEvent }): Promise<AuthCoordinationPersistenceResult> {
    return this.db.runTransaction(async (transaction) => {
      const prepared = await prepareAuthCoordinationTransition({ db: this.db, transaction,
        trustedAdministratorUid: input.trustedAdministratorUid, protectedSuperAdminUid: this.protectedSuperAdminUid,
        operationId: input.operationId, expectedRevision: input.expectedRevision, event: input.event, now: this.now() });
      prepared.apply();
      return prepared.result;
    });
  }
}
