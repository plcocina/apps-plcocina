import { hkdfSync } from "node:crypto";
import { Timestamp, type Firestore } from "firebase-admin/firestore";
import { z } from "zod";
import type { AdminPrincipal } from "../auth/require-super-admin.js";
import { authChallengeDocumentSchema } from "./identity-auth-challenge-contracts.js";
import { verifyAuthChallengeSecret } from "./identity-auth-challenge-crypto.js";
import { authCoordinationDocumentSchema } from "./identity-auth-coordination-contracts.js";
import { GoogleBootstrapChallengeCoordinator } from "./identity-google-bootstrap-challenge-coordinator.js";
import { createInternalAuthOrchestrationService, type InternalAuthOrchestrationConfiguration,
  type InternalAuthOrchestrationDependencies } from "./identity-auth-orchestration-composition.js";

const uuidSchema = z.string().uuid();
const issueInputSchema = z.object({ principal: z.custom<AdminPrincipal>(), authorizationId: uuidSchema,
  idempotencyKey: uuidSchema, lifetimeMs: z.number().int().positive().max(15 * 60 * 1000).optional() }).strict();
const consumeInputSchema = z.object({ challengeId: uuidSchema, idempotencyKey: uuidSchema,
  googleIdToken: z.string().min(1).max(20_000), nonce: z.string().min(1).max(512), state: z.string().min(1).max(512) }).strict();

export type GoogleBootstrapConsumeInput = z.input<typeof consumeInputSchema>;
export type GoogleBootstrapCompositionErrorCode = "CHALLENGE_NOT_FOUND" | "CHALLENGE_CONTEXT_INVALID"
  | "COORDINATION_NOT_FOUND" | "COORDINATION_CONTEXT_INVALID" | "IDEMPOTENCY_CONTEXT_INVALID";

export class GoogleBootstrapCompositionError extends Error {
  constructor(readonly code: GoogleBootstrapCompositionErrorCode) {
    super("Google bootstrap composition rejected");
    this.name = "GoogleBootstrapCompositionError";
  }
}

function matchesSecret(secret: string, expectedHash: string): boolean {
  try { return verifyAuthChallengeSecret(secret, expectedHash); }
  catch { return false; }
}

/** HKDF purpose-separates this stable subkey from identifier HMACs. */
export function deriveGoogleBootstrapChallengeKey(identifierPepper: Buffer): Buffer {
  if (!Buffer.isBuffer(identifierPepper) || identifierPepper.length < 32) {
    throw new Error("IDENTIFIER_PEPPER_TOO_SHORT");
  }
  return Buffer.from(hkdfSync("sha256", identifierPepper,
    Buffer.from("apps-pl-cocina/identity-pepper/v1"),
    Buffer.from("apps-pl-cocina/google-bootstrap-challenge-hmac/v1"), 32));
}

/** Internal-only facade. Caller-supplied values contain proof and references, never identity evidence. */
export class InternalGoogleBootstrapComposition {
  private readonly coordinator: GoogleBootstrapChallengeCoordinator;
  private readonly orchestration: ReturnType<typeof createInternalAuthOrchestrationService>;
  private readonly protectedSuperAdminUid: string;

  constructor(private readonly db: Firestore, configuration: InternalAuthOrchestrationConfiguration,
    dependencies: InternalAuthOrchestrationDependencies = {}) {
    const now = dependencies.now ?? (() => new Date());
    this.protectedSuperAdminUid = configuration.protectedSuperAdminUid;
    this.coordinator = new GoogleBootstrapChallengeCoordinator(db, configuration.protectedSuperAdminUid,
      deriveGoogleBootstrapChallengeKey(configuration.identifierPepper), () => Timestamp.fromDate(now()));
    this.orchestration = createInternalAuthOrchestrationService(db, configuration, dependencies);
  }

  async issue(input: unknown) {
    const value = issueInputSchema.parse(input);
    return this.coordinator.issue(value);
  }

  async verifyAndConsume(input: GoogleBootstrapConsumeInput) {
    const value = consumeInputSchema.parse(input);
    const challengeSnapshot = await this.db.collection("identityAuthChallenges").doc(value.challengeId).get();
    const challenge = authChallengeDocumentSchema.safeParse(challengeSnapshot.data());
    if (!challengeSnapshot.exists) throw new GoogleBootstrapCompositionError("CHALLENGE_NOT_FOUND");
    if (!challenge.success || challenge.data.challengeId !== value.challengeId
      || challenge.data.contextType !== "google_bootstrap" || challenge.data.trustedSessionId !== undefined
      || challenge.data.issuanceIdempotencyKey === undefined
      || !matchesSecret(value.nonce, challenge.data.nonceHash)
      || !matchesSecret(value.state, challenge.data.stateHash)) {
      throw new GoogleBootstrapCompositionError("CHALLENGE_CONTEXT_INVALID");
    }
    const coordinationSnapshot = await this.db.collection("identityAuthCoordinations")
      .doc(challenge.data.coordinationOperationId).get();
    const coordination = authCoordinationDocumentSchema.safeParse(coordinationSnapshot.data());
    if (!coordinationSnapshot.exists) throw new GoogleBootstrapCompositionError("COORDINATION_NOT_FOUND");
    if (!coordination.success || coordination.data.operationId !== challenge.data.coordinationOperationId
      || coordination.data.challengeId !== value.challengeId
      || coordination.data.authorizationId !== challenge.data.authorizationId
      || coordination.data.expectedFirebaseUid !== challenge.data.expectedFirebaseUid
      || coordination.data.expectedInternalUid !== challenge.data.expectedInternalUid
      || coordination.data.googleSubjectHash !== challenge.data.googleSubjectHash
      || !["challenge_issued", "google_proof_verified"].includes(coordination.data.state)) {
      throw new GoogleBootstrapCompositionError("COORDINATION_CONTEXT_INVALID");
    }

    // On retry, reuse the original expected revision from E5D2's persisted idempotency record.
    let expectedCoordinationRevision = coordination.data.revision;
    if (coordination.data.state === "google_proof_verified") {
      const idempotencySnapshot = await this.db.collection("identityAuthCoordinationIdempotency")
        .doc(value.idempotencyKey).get();
      const stored = idempotencySnapshot.data();
      if (!idempotencySnapshot.exists || stored?.operationId !== coordination.data.operationId
        || stored?.kind !== "transition" || typeof stored?.resultingRevision !== "number") {
        throw new GoogleBootstrapCompositionError("IDEMPOTENCY_CONTEXT_INVALID");
      }
      expectedCoordinationRevision = stored.resultingRevision - 1;
    }
    return this.orchestration.verifyConsumeAndRecord({
      trustedAdministratorUid: this.protectedSuperAdminUid,
      contextType: "google_bootstrap",
      operationId: challenge.data.coordinationOperationId,
      challengeId: value.challengeId,
      authorizationId: challenge.data.authorizationId,
      idempotencyKey: value.idempotencyKey,
      verificationId: value.idempotencyKey,
      expectedCoordinationRevision,
      expectedChallengeRevision: challenge.data.state === "issued" ? challenge.data.revision : 1,
      googleIdToken: value.googleIdToken,
      nonce: value.nonce,
      state: value.state
    });
  }
}

export function createInternalGoogleBootstrapComposition(db: Firestore,
  configuration: InternalAuthOrchestrationConfiguration,
  dependencies: InternalAuthOrchestrationDependencies = {}): InternalGoogleBootstrapComposition {
  return new InternalGoogleBootstrapComposition(db, configuration, dependencies);
}
