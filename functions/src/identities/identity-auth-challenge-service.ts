import { Timestamp, type Firestore, type Transaction } from "firebase-admin/firestore";
import { z } from "zod";
import {
  authChallengeDocumentSchema,
  evaluateAuthChallenge,
  type AuthChallengeDocument,
  type AuthChallengeTrustedContext
} from "./identity-auth-challenge-contracts.js";
import {
  generateAuthChallengeSecrets,
  hashAuthChallengeSecret,
  type AuthChallengeSecrets
} from "./identity-auth-challenge-crypto.js";

const uidSchema = z.string().min(1).max(128).refine((value) => !value.includes("/"));
const uuidSchema = z.string().uuid();
const hashSchema = z.string().regex(/^[a-f0-9]{64}$/);
const trustedSessionIdSchema = z.string().min(16).max(256).regex(/^[A-Za-z0-9._~-]+$/);
const MAX_CHALLENGE_LIFETIME_MS = 15 * 60 * 1000;

const createInputSchema = z.object({
  trustedOperatorUid: uidSchema,
  expectedInternalUid: uidSchema,
  expectedFirebaseUid: uidSchema,
  coordinationOperationId: uuidSchema,
  authorizationId: uuidSchema,
  googleSubjectHash: hashSchema.nullable(),
  trustedSessionId: trustedSessionIdSchema,
  lifetimeMs: z.number().int().positive().max(MAX_CHALLENGE_LIFETIME_MS)
}).strict();

const lookupInputSchema = z.object({
  trustedOperatorUid: uidSchema,
  challengeId: uuidSchema,
  expectedInternalUid: uidSchema,
  expectedFirebaseUid: uidSchema,
  coordinationOperationId: uuidSchema,
  authorizationId: uuidSchema,
  trustedSessionId: trustedSessionIdSchema,
  googleSubjectHash: hashSchema.nullable()
}).strict();

export type AuthChallengeCreateInput = z.input<typeof createInputSchema>;
export type AuthChallengeLookupInput = z.input<typeof lookupInputSchema>;
export type AuthChallengeCreationResult = Readonly<{
  document: AuthChallengeDocument;
  oneTimeSecrets: AuthChallengeSecrets;
}>;

export type AuthChallengePersistenceErrorCode = "TRUSTED_CONTEXT_MISMATCH" | "SUPER_ADMIN_FORBIDDEN"
  | "UID_MISMATCH" | "CHALLENGE_NOT_FOUND" | "CHALLENGE_ID_CONFLICT" | "CHALLENGE_MALFORMED"
  | "CONTEXT_MISMATCH" | "REVISION_CONFLICT" | "REPLAY_DETECTED" | "CHALLENGE_REVOKED"
  | "CHALLENGE_EXPIRED" | "CHALLENGE_NOT_EXPIRED";

export class AuthChallengePersistenceError extends Error {
  constructor(readonly code: AuthChallengePersistenceErrorCode) {
    super("Auth challenge persistence rejected");
    this.name = "AuthChallengePersistenceError";
  }
}

function parseStored(value: unknown): AuthChallengeDocument {
  const parsed = authChallengeDocumentSchema.safeParse(value);
  if (!parsed.success) throw new AuthChallengePersistenceError("CHALLENGE_MALFORMED");
  return parsed.data;
}

function assertLookupContext(document: AuthChallengeDocument, input: z.output<typeof lookupInputSchema>): void {
  if (document.expectedInternalUid !== input.expectedInternalUid
    || document.expectedFirebaseUid !== input.expectedFirebaseUid
    || document.coordinationOperationId !== input.coordinationOperationId
    || document.authorizationId !== input.authorizationId
    || document.trustedSessionId !== input.trustedSessionId
    || document.googleSubjectHash !== input.googleSubjectHash) {
    throw new AuthChallengePersistenceError("CONTEXT_MISMATCH");
  }
}

export type PreparedAuthChallengeConsumption = Readonly<{
  document: AuthChallengeDocument;
  apply: () => void;
}>;

export async function prepareAuthChallengeConsumption(input: {
  db: Firestore;
  transaction: Transaction;
  challengeId: string;
  context: AuthChallengeTrustedContext;
  now: Timestamp;
}): Promise<PreparedAuthChallengeConsumption> {
  const challengeId = uuidSchema.parse(input.challengeId);
  const reference = input.db.collection("identityAuthChallenges").doc(challengeId);
  const snapshot = await input.transaction.get(reference);
  if (!snapshot.exists) throw new AuthChallengePersistenceError("CHALLENGE_NOT_FOUND");
  const document = parseStored(snapshot.data());
  if (document.challengeId !== challengeId) throw new AuthChallengePersistenceError("CHALLENGE_MALFORMED");
  evaluateAuthChallenge({ challenge: document, context: input.context, now: input.now });
  const next = authChallengeDocumentSchema.parse({
    ...document,
    state: "consumed",
    stateChangedAt: input.now,
    revision: document.revision + 1
  });
  return Object.freeze({ document: next, apply: () => input.transaction.set(reference, next) });
}

export class AuthChallengePersistenceService {
  constructor(
    private readonly db: Firestore,
    private readonly protectedSuperAdminUid: string,
    private readonly now: () => Timestamp = () => Timestamp.now(),
    private readonly generateSecrets: () => AuthChallengeSecrets = generateAuthChallengeSecrets
  ) {
    uidSchema.parse(protectedSuperAdminUid);
  }

  private assertAuthorized(operatorUid: string): void {
    if (operatorUid !== this.protectedSuperAdminUid) {
      throw new AuthChallengePersistenceError("TRUSTED_CONTEXT_MISMATCH");
    }
  }

  async create(input: AuthChallengeCreateInput): Promise<AuthChallengeCreationResult> {
    const value = createInputSchema.parse(input);
    this.assertAuthorized(value.trustedOperatorUid);
    if (value.expectedInternalUid !== value.expectedFirebaseUid) {
      throw new AuthChallengePersistenceError("UID_MISMATCH");
    }
    if (value.expectedFirebaseUid === this.protectedSuperAdminUid) {
      throw new AuthChallengePersistenceError("SUPER_ADMIN_FORBIDDEN");
    }
    const secrets = this.generateSecrets();
    const issuedAt = this.now();
    const document = authChallengeDocumentSchema.parse({
      challengeId: secrets.challengeId,
      expectedInternalUid: value.expectedInternalUid,
      expectedFirebaseUid: value.expectedFirebaseUid,
      coordinationOperationId: value.coordinationOperationId,
      authorizationId: value.authorizationId,
      googleSubjectHash: value.googleSubjectHash,
      trustedSessionId: value.trustedSessionId,
      nonceHash: hashAuthChallengeSecret(secrets.nonce),
      stateHash: hashAuthChallengeSecret(secrets.state),
      issuedAt,
      expiresAt: Timestamp.fromMillis(issuedAt.toMillis() + value.lifetimeMs),
      state: "issued",
      stateChangedAt: null,
      revision: 1,
      version: 1
    });
    const reference = this.db.collection("identityAuthChallenges").doc(document.challengeId);
    await this.db.runTransaction(async (transaction) => {
      if ((await transaction.get(reference)).exists) {
        throw new AuthChallengePersistenceError("CHALLENGE_ID_CONFLICT");
      }
      transaction.create(reference, document);
    });
    return Object.freeze({ document, oneTimeSecrets: Object.freeze({ ...secrets }) });
  }

  async get(input: AuthChallengeLookupInput): Promise<AuthChallengeDocument> {
    const value = lookupInputSchema.parse(input);
    this.assertAuthorized(value.trustedOperatorUid);
    const snapshot = await this.db.collection("identityAuthChallenges").doc(value.challengeId).get();
    if (!snapshot.exists) throw new AuthChallengePersistenceError("CHALLENGE_NOT_FOUND");
    const document = parseStored(snapshot.data());
    assertLookupContext(document, value);
    return document;
  }

  async consume(input: {
    trustedOperatorUid: string;
    challengeId: string;
    context: AuthChallengeTrustedContext;
  }): Promise<AuthChallengeDocument> {
    this.assertAuthorized(uidSchema.parse(input.trustedOperatorUid));
    return this.db.runTransaction(async (transaction) => {
      const prepared = await prepareAuthChallengeConsumption({ db: this.db, transaction,
        challengeId: input.challengeId, context: input.context, now: this.now() });
      prepared.apply();
      return prepared.document;
    });
  }

  async revoke(input: AuthChallengeLookupInput & { expectedRevision: number }): Promise<AuthChallengeDocument> {
    const value = lookupInputSchema.extend({ expectedRevision: z.number().int().positive() }).strict().parse(input);
    this.assertAuthorized(value.trustedOperatorUid);
    const reference = this.db.collection("identityAuthChallenges").doc(value.challengeId);
    return this.db.runTransaction(async (transaction) => {
      const snapshot = await transaction.get(reference);
      if (!snapshot.exists) throw new AuthChallengePersistenceError("CHALLENGE_NOT_FOUND");
      const document = parseStored(snapshot.data());
      assertLookupContext(document, value);
      if (document.state === "consumed") throw new AuthChallengePersistenceError("REPLAY_DETECTED");
      if (document.state === "revoked") throw new AuthChallengePersistenceError("CHALLENGE_REVOKED");
      const changedAt = this.now();
      if (document.state === "expired" || changedAt.toMillis() >= document.expiresAt.toMillis()) {
        throw new AuthChallengePersistenceError("CHALLENGE_EXPIRED");
      }
      if (document.revision !== value.expectedRevision) throw new AuthChallengePersistenceError("REVISION_CONFLICT");
      const next = authChallengeDocumentSchema.parse({ ...document, state: "revoked", stateChangedAt: changedAt,
        revision: document.revision + 1 });
      transaction.set(reference, next);
      return next;
    });
  }

  async expire(input: AuthChallengeLookupInput & { expectedRevision: number }): Promise<AuthChallengeDocument> {
    const value = lookupInputSchema.extend({ expectedRevision: z.number().int().positive() }).strict().parse(input);
    this.assertAuthorized(value.trustedOperatorUid);
    const reference = this.db.collection("identityAuthChallenges").doc(value.challengeId);
    return this.db.runTransaction(async (transaction) => {
      const snapshot = await transaction.get(reference);
      if (!snapshot.exists) throw new AuthChallengePersistenceError("CHALLENGE_NOT_FOUND");
      const document = parseStored(snapshot.data());
      assertLookupContext(document, value);
      if (document.state === "consumed") throw new AuthChallengePersistenceError("REPLAY_DETECTED");
      if (document.state === "revoked") throw new AuthChallengePersistenceError("CHALLENGE_REVOKED");
      if (document.state === "expired") return document;
      if (document.revision !== value.expectedRevision) throw new AuthChallengePersistenceError("REVISION_CONFLICT");
      const changedAt = this.now();
      if (changedAt.toMillis() < document.expiresAt.toMillis()) {
        throw new AuthChallengePersistenceError("CHALLENGE_NOT_EXPIRED");
      }
      const next = authChallengeDocumentSchema.parse({ ...document, state: "expired", stateChangedAt: changedAt,
        revision: document.revision + 1 });
      transaction.set(reference, next);
      return next;
    });
  }
}
