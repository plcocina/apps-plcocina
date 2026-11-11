import { createHmac } from "node:crypto";
import { Timestamp, type Firestore } from "firebase-admin/firestore";
import { z } from "zod";
import type { AdminPrincipal } from "../auth/require-super-admin.js";
import { createTrustedAuthCoordinationEvent, authCoordinationDocumentSchema } from "./identity-auth-coordination-contracts.js";
import { AuthCoordinationPersistenceService } from "./identity-auth-coordination-service.js";
import { AuthChallengePersistenceService } from "./identity-auth-challenge-service.js";
import { identityLinkAuthorizationSchema } from "./identity-linking-contracts.js";

const uidSchema = z.string().min(1).max(128).refine((value) => !value.includes("/"));
const uuidSchema = z.string().uuid();
const adminPrincipalSchema = z.object({
  uid: uidSchema,
  email: z.string().nullable(),
  authTime: z.number().int().nonnegative(),
  issuedAt: z.number().int().nonnegative(),
  superAdmin: z.literal(true)
}).strict();
const inputSchema = z.object({
  principal: adminPrincipalSchema,
  authorizationId: uuidSchema,
  idempotencyKey: uuidSchema,
  lifetimeMs: z.number().int().positive().max(15 * 60 * 1000).default(5 * 60 * 1000)
}).strict();

export type GoogleBootstrapChallengeCoordinatorInput = z.input<typeof inputSchema>;
export type GoogleBootstrapChallengeBootstrap = Readonly<{
  challengeId: string;
  nonce: string;
  state: string;
  expiresAt: Timestamp;
}>;

export type GoogleBootstrapChallengeCoordinatorErrorCode = "ADMIN_REQUIRED" | "AUTHORIZATION_NOT_FOUND"
  | "AUTHORIZATION_INVALID" | "COORDINATION_NOT_FOUND" | "COORDINATION_AMBIGUOUS"
  | "COORDINATION_CONTEXT_INVALID";

export class GoogleBootstrapChallengeCoordinatorError extends Error {
  constructor(readonly code: GoogleBootstrapChallengeCoordinatorErrorCode) {
    super("Google bootstrap challenge issuance rejected");
    this.name = "GoogleBootstrapChallengeCoordinatorError";
  }
}

function digest(key: Buffer, purpose: string, authorizationId: string, idempotencyKey: string): Buffer {
  return createHmac("sha256", key).update(`apps-pl-cocina/b4a/${purpose}/v1\0${authorizationId}\0${idempotencyKey}`)
    .digest();
}

function uuidFromDigest(value: Buffer): string {
  const bytes = Buffer.from(value.subarray(0, 16));
  bytes[6] = (bytes[6]! & 0x0f) | 0x40;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export class GoogleBootstrapChallengeCoordinator {
  constructor(
    private readonly db: Firestore,
    private readonly protectedSuperAdminUid: string,
    private readonly bootstrapChallengeSecretKey: Buffer,
    private readonly now: () => Timestamp = () => Timestamp.now()
  ) {
    uidSchema.parse(protectedSuperAdminUid);
    if (!Buffer.isBuffer(bootstrapChallengeSecretKey) || bootstrapChallengeSecretKey.length < 32) {
      throw new Error("BOOTSTRAP_CHALLENGE_SECRET_KEY_TOO_SHORT");
    }
  }

  async issue(input: GoogleBootstrapChallengeCoordinatorInput): Promise<GoogleBootstrapChallengeBootstrap> {
    const value = inputSchema.parse(input);
    if (value.principal.superAdmin !== true || value.principal.uid !== this.protectedSuperAdminUid) {
      throw new GoogleBootstrapChallengeCoordinatorError("ADMIN_REQUIRED");
    }

    const authorizationSnapshot = await this.db.collection("identityLinkAuthorizations").doc(value.authorizationId).get();
    if (!authorizationSnapshot.exists) throw new GoogleBootstrapChallengeCoordinatorError("AUTHORIZATION_NOT_FOUND");
    const authorization = identityLinkAuthorizationSchema.safeParse(authorizationSnapshot.data());
    if (!authorization.success || authorization.data.authorizationId !== value.authorizationId
      || authorization.data.authorizedByUid !== value.principal.uid) {
      throw new GoogleBootstrapChallengeCoordinatorError("AUTHORIZATION_INVALID");
    }

    const coordinationSnapshots = await this.db.collection("identityAuthCoordinations")
      .where("authorizationId", "==", value.authorizationId).limit(2).get();
    if (coordinationSnapshots.empty) throw new GoogleBootstrapChallengeCoordinatorError("COORDINATION_NOT_FOUND");
    if (coordinationSnapshots.size !== 1) throw new GoogleBootstrapChallengeCoordinatorError("COORDINATION_AMBIGUOUS");
    const coordinationParsed = authCoordinationDocumentSchema.safeParse(coordinationSnapshots.docs[0]!.data());
    if (!coordinationParsed.success) throw new GoogleBootstrapChallengeCoordinatorError("COORDINATION_CONTEXT_INVALID");
    const coordination = coordinationParsed.data;
    if (coordination.authorizationId !== authorization.data.authorizationId
      || coordination.expectedFirebaseUid !== authorization.data.targetUid
      || coordination.expectedInternalUid !== authorization.data.targetUid
      || coordination.googleSubjectHash !== authorization.data.googleSubjectHash
      || coordination.evidence.firestoreLink.linkOperationId !== authorization.data.operationId
      || coordination.expectedFirebaseUid === this.protectedSuperAdminUid
      || !["not_started", "challenge_issued"].includes(coordination.state)) {
      throw new GoogleBootstrapChallengeCoordinatorError("COORDINATION_CONTEXT_INVALID");
    }

    const secretKey = createHmac("sha256", this.bootstrapChallengeSecretKey)
      .update("apps-pl-cocina/b4a/google-bootstrap-secret-derivation/v1").digest();
    const challengeService = new AuthChallengePersistenceService(this.db, this.protectedSuperAdminUid, this.now, () => ({
      challengeId: authorization.data.authorizationId,
      nonce: digest(secretKey, "nonce", value.authorizationId, value.idempotencyKey).toString("base64url"),
      state: digest(secretKey, "state", value.authorizationId, value.idempotencyKey).toString("base64url")
    }));
    const challenge = await challengeService.create({
      trustedOperatorUid: value.principal.uid,
      expectedInternalUid: coordination.expectedInternalUid,
      expectedFirebaseUid: coordination.expectedFirebaseUid,
      coordinationOperationId: coordination.operationId,
      authorizationId: authorization.data.authorizationId,
      googleSubjectHash: authorization.data.googleSubjectHash,
      contextType: "google_bootstrap",
      issuanceIdempotencyKey: value.idempotencyKey,
      expectedProfileRevision: coordination.currentProfileRevision,
      authorizationBinding: { operationId: authorization.data.operationId,
        expectedRevision: authorization.data.expectedRevision },
      lifetimeMs: value.lifetimeMs
    });

    const coordinationService = new AuthCoordinationPersistenceService(this.db, this.protectedSuperAdminUid, this.now);
    const current = await coordinationService.get(coordination.operationId);
    const transitionIdempotencyKey = uuidFromDigest(digest(secretKey, "coordination-transition",
      value.authorizationId, value.idempotencyKey));
    if (current.state === "not_started") {
      if (current.challengeId !== null || current.evidence.challenge !== null) {
        throw new GoogleBootstrapChallengeCoordinatorError("COORDINATION_CONTEXT_INVALID");
      }
      await coordinationService.transition({ trustedAdministratorUid: value.principal.uid,
        operationId: coordination.operationId, expectedRevision: current.revision,
        event: createTrustedAuthCoordinationEvent({ type: "challenge_issued", operationId: coordination.operationId,
          idempotencyKey: transitionIdempotencyKey, expectedFirebaseUid: coordination.expectedFirebaseUid,
          expectedInternalUid: coordination.expectedInternalUid, googleSubjectHash: authorization.data.googleSubjectHash,
          expectedCoordinationRevision: current.revision, expectedProfileRevision: current.currentProfileRevision,
          challenge: { challengeId: challenge.document.challengeId, issuedBy: "identity-challenge-service",
            issuedAt: challenge.document.issuedAt, expiresAt: challenge.document.expiresAt } })
      });
    } else if (current.state !== "challenge_issued" || current.challengeId !== challenge.document.challengeId
      || current.evidence.challenge?.challengeId !== challenge.document.challengeId
      || current.lastEvent?.idempotencyKey !== transitionIdempotencyKey) {
      throw new GoogleBootstrapChallengeCoordinatorError("COORDINATION_CONTEXT_INVALID");
    }

    return Object.freeze({ challengeId: challenge.document.challengeId, nonce: challenge.oneTimeSecrets.nonce,
      state: challenge.oneTimeSecrets.state, expiresAt: challenge.document.expiresAt });
  }
}
