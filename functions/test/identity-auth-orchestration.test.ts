import { createHash, randomUUID } from "node:crypto";
import { Timestamp } from "firebase-admin/firestore";
import { describe, expect, it } from "vitest";
import {
  createTrustedAdministrativeOrchestrationEvidence,
  createTrustedChallengeOrchestrationEvidence,
  createTrustedCoordinationOrchestrationEvidence,
  createTrustedGoogleOrchestrationEvidence,
  authOrchestrationInputSchema,
  type AuthOrchestrationInput
} from "../src/identities/identity-auth-orchestration-contracts.js";
import { evaluateAuthOrchestration } from "../src/identities/identity-auth-orchestration-policy.js";

const now = Timestamp.fromDate(new Date("2026-11-07T18:00:00.000Z"));
const later = Timestamp.fromMillis(now.toMillis() + 300_000);
const adminUid = "protected-admin";
const hash = (value: string) => createHash("sha256").update(value).digest("hex");

function fixture(options: {
  google?: Record<string, unknown> | null;
  challenge?: Record<string, unknown> | null;
  administrative?: Record<string, unknown> | null;
  coordination?: Record<string, unknown> | null;
  input?: Record<string, unknown>;
  partialState?: AuthOrchestrationInput["evidence"]["partialState"];
} = {}): AuthOrchestrationInput {
  const uid = `user-${randomUUID()}`;
  const operationId = randomUUID();
  const challengeId = randomUUID();
  const authorizationId = randomUUID();
  const idempotencyKey = randomUUID();
  const subject = `subject-${randomUUID()}`;
  const googleSubjectHash = hash(subject);
  const trustedSessionId = `session-${randomUUID()}`;
  const requestHash = hash(`request-${randomUUID()}`);
  const google = options.google === null ? null : createTrustedGoogleOrchestrationEvidence({
    verificationId: randomUUID(),
    identity: {
      issuer: "https://accounts.google.com", audience: "approved-client", authorizedParty: "approved-client",
      subject, email: "user@plcocina.test", emailVerified: true, hostedDomain: "plcocina.test",
      issuedAt: new Date(now.toMillis() - 1_000),
      expiresAt: (options.google?.expiresAt as Date | undefined) ?? later.toDate(), nonceVerified: true
    },
    googleSubjectHash: String(options.google?.googleSubjectHash ?? googleSubjectHash), verifiedAt: now
  });
  const challenge = options.challenge === null ? null : createTrustedChallengeOrchestrationEvidence({
    challengeId, verifiedBy: "identity-auth-challenge-service", operationId,
    expectedFirebaseUid: uid, expectedInternalUid: uid, authorizationId, trustedSessionId, googleSubjectHash,
    status: "validated", revision: 1, validatedAt: now, consumedAt: null, validUntil: later,
    ...options.challenge
  });
  const administrative = options.administrative === null ? null : createTrustedAdministrativeOrchestrationEvidence({
    authorizationId, verifiedBy: "identity-link-authorization", operationId, targetUid: uid, googleSubjectHash,
    profileRevision: 3, state: "authorized", profileStatus: "linked_pending_activation", authDisabled: true,
    verifiedAt: now, validUntil: later, ...options.administrative
  });
  const coordination = options.coordination === null ? null : createTrustedCoordinationOrchestrationEvidence({
    operationId, verifiedBy: "identity-auth-coordination-service", expectedFirebaseUid: uid,
    expectedInternalUid: uid, googleSubjectHash, authorizationId, challengeId, state: "challenge_issued",
    revision: 2, conflictReason: null, lastIdempotencyKey: null, lastRequestHash: null, lastOutcome: null,
    observedAt: now, ...options.coordination
  });
  return {
    operationId, expectedFirebaseUid: uid, expectedInternalUid: uid, googleSubjectHash, challengeId,
    authorizationId, trustedSessionId, idempotencyKey, requestHash, expectedCoordinationState: "challenge_issued",
    expectedCoordinationRevision: 2, requestedAction: "consume_challenge_and_record_google_proof",
    contextTime: now, evidence: { google, challenge, administrative, coordination,
      partialState: options.partialState ?? null }, activationRequested: false, version: 1, ...options.input
  } as AuthOrchestrationInput;
}

function expectReject(input: AuthOrchestrationInput, code: string) {
  expect(evaluateAuthOrchestration(input, adminUid)).toEqual({ decision: "reject", code });
}

describe("pure identity auth orchestration policy", () => {
  it("accepts a strict valid orchestration contract", () => {
    expect(evaluateAuthOrchestration(fixture(), adminUid)).toMatchObject({
      decision: "proceed", nextStep: "atomic_consume_and_record", requiresAtomicPersistence: true,
      automaticActivation: false
    });
  });

  it("rejects unknown contract fields", () => expectReject(fixture({ input: { clientPermission: "admin" } }), "CONTRACT_INVALID"));

  it("requires identical Firebase and internal UIDs", () => {
    const input = fixture();
    expectReject({ ...input, expectedInternalUid: "different-user" }, "UID_MISMATCH");
  });

  it("rejects contradictory UIDs in trusted evidence", () => {
    const input = fixture();
    const challenge = createTrustedChallengeOrchestrationEvidence({ ...input.evidence.challenge,
      expectedFirebaseUid: "different-user" });
    expectReject({ ...input, evidence: { ...input.evidence, challenge } }, "UID_MISMATCH");
  });

  it("rejects a different Google subject", () => {
    const input = fixture({ google: { googleSubjectHash: hash("other-subject") } });
    expectReject(input, "SUBJECT_MISMATCH");
  });

  it("rejects an unrelated challenge", () => {
    const input = fixture();
    expectReject({ ...input, challengeId: randomUUID() }, "CHALLENGE_MISMATCH");
  });

  it("rejects another trusted session", () => {
    const input = fixture();
    expectReject({ ...input, trustedSessionId: `other-${randomUUID()}` }, "SESSION_MISMATCH");
  });

  it("rejects missing administrative evidence", () => expectReject(fixture({ administrative: null }), "EVIDENCE_MISSING"));

  it("rejects expired administrative evidence", () => {
    const input = fixture({ input: { contextTime: later } });
    expectReject(input, "AUTHORIZATION_EXPIRED");
  });

  it("rejects revoked administrative evidence", () => expectReject(fixture({ administrative: { state: "revoked" } }),
    "AUTHORIZATION_REVOKED"));

  it("rejects expired Google evidence", () => {
    const contextTime = Timestamp.fromMillis(later.toMillis());
    const input = fixture({ input: { contextTime }, administrative: { validUntil: Timestamp.fromMillis(later.toMillis() + 1_000) },
      challenge: { validUntil: Timestamp.fromMillis(later.toMillis() + 1_000) } });
    expectReject(input, "GOOGLE_EVIDENCE_EXPIRED");
  });

  it("rejects expired challenge evidence", () => {
    const contextTime = Timestamp.fromMillis(later.toMillis());
    const input = fixture({ google: { expiresAt: new Date(later.toMillis() + 1_000) }, input: { contextTime },
      administrative: { validUntil: Timestamp.fromMillis(later.toMillis() + 1_000) } });
    expectReject(input, "CHALLENGE_EXPIRED");
  });

  it("rejects missing Google evidence", () => expectReject(fixture({ google: null }), "EVIDENCE_MISSING"));

  it("rejects Google evidence not created by its trusted adapter", () => {
    const input = fixture();
    const untrusted: AuthOrchestrationInput["evidence"]["google"] = Object.fromEntries(
      Object.entries(input.evidence.google ?? {})
    ) as never;
    expectReject({ ...input, evidence: { ...input.evidence, google: untrusted } }, "UNTRUSTED_EVIDENCE");
  });

  it("rejects incomplete challenge evidence", () => {
    const input = fixture();
    const incomplete: AuthOrchestrationInput["evidence"]["challenge"] = {
      ...input.evidence.challenge, trustedSessionId: undefined
    } as never;
    expectReject({ ...input, evidence: { ...input.evidence, challenge: incomplete } }, "CONTRACT_INVALID");
  });

  it("does not consume an already consumed challenge again during recovery", () => {
    const consumedAt = Timestamp.fromMillis(now.toMillis() + 1_000);
    const input = fixture({ challenge: { status: "consumed", consumedAt, revision: 2 },
      partialState: "challenge_consumed_coordination_pending" });
    expect(evaluateAuthOrchestration(input, adminUid)).toEqual({ decision: "proceed",
      nextStep: "record_consumed_challenge_result", requiresAtomicPersistence: false,
      consumeChallengeAgain: false, automaticActivation: false });
  });

  it("rejects a consumed challenge outside a proven recovery path", () => {
    const input = fixture({ challenge: { status: "consumed", consumedAt: now, revision: 2 } });
    expectReject(input, "CHALLENGE_ALREADY_CONSUMED");
  });

  it("rejects a stale coordination revision", () => {
    const input = fixture();
    expectReject({ ...input, expectedCoordinationRevision: 1 }, "REVISION_CONFLICT");
  });

  it("rejects an incompatible coordination state", () => {
    const input = fixture({ coordination: { state: "google_proof_verified" } });
    expectReject(input, "COORDINATION_STATE_INVALID");
  });

  it("blocks suspended and reconciliation profiles", () => {
    const input = fixture({ administrative: { profileStatus: "suspended" } });
    expect(evaluateAuthOrchestration(input, adminUid)).toMatchObject({ decision: "blocked", reason: "OPERATION_BLOCKED" });
  });

  it("blocks a coordination operation with a conflict", () => {
    const input = fixture({ coordination: { state: "reconciliation_required", conflictReason: "FIRESTORE_INCONSISTENT" },
      input: { expectedCoordinationState: "reconciliation_required" } });
    expect(evaluateAuthOrchestration(input, adminUid)).toMatchObject({ decision: "blocked", reason: "OPERATION_BLOCKED" });
  });

  it("returns the recorded result for an equivalent retry", () => {
    const base = fixture();
    const coordination = createTrustedCoordinationOrchestrationEvidence({ ...base.evidence.coordination,
      lastIdempotencyKey: base.idempotencyKey, lastRequestHash: base.requestHash, lastOutcome: "confirmed" });
    expect(evaluateAuthOrchestration({ ...base, evidence: { ...base.evidence, coordination } }, adminUid)).toEqual({
      decision: "replay", outcome: "confirmed", consumeChallengeAgain: false
    });
  });

  it("rejects conflicting reuse of an idempotency key", () => {
    const base = fixture();
    const coordination = createTrustedCoordinationOrchestrationEvidence({ ...base.evidence.coordination,
      lastIdempotencyKey: base.idempotencyKey, lastRequestHash: hash("different-request"), lastOutcome: "confirmed" });
    expectReject({ ...base, evidence: { ...base.evidence, coordination } }, "IDEMPOTENCY_CONFLICT");
  });

  it("represents unsafe partial effects as reconciliation", () => {
    const input = fixture({ partialState: "coordination_updated_challenge_pending" });
    expect(evaluateAuthOrchestration(input, adminUid)).toMatchObject({ decision: "reconciliation_required",
      reason: "COORDINATION_WITHOUT_CHALLENGE_CONSUMPTION", retry: "forbidden_until_observed" });
  });

  it("requires reconciliation when a Google reservation belongs to another UID", () => {
    expect(evaluateAuthOrchestration(fixture({ partialState: "reservation_owned_by_other_uid" }), adminUid)).toMatchObject({
      decision: "reconciliation_required", reason: "RESERVATION_UID_CONFLICT"
    });
  });

  it("classifies pending Firestore, Firebase Auth, and postflight work without reconsuming", () => {
    for (const [partialState, reason] of [["firestore_link_pending", "FIRESTORE_LINK_PENDING"],
      ["firestore_linked_firebase_auth_pending", "FIREBASE_AUTH_PENDING"], ["postflight_pending", "POSTFLIGHT_PENDING"]] as const) {
      expect(evaluateAuthOrchestration(fixture({ partialState }), adminUid)).toMatchObject({
        decision: "pending", reason, consumeChallengeAgain: false
      });
    }
  });

  it("permits only state-compatible Firebase provider preparation and confirmation", () => {
    for (const [requestedAction, state, nextStep] of [
      ["prepare_firebase_provider_link", "google_proof_verified", "prepare_firebase_provider_link"],
      ["confirm_firebase_provider_link", "provider_link_pending", "confirm_firebase_provider_link"]
    ] as const) {
      const input = fixture({ challenge: { status: "consumed", consumedAt: now, revision: 2 },
        coordination: { state }, input: { requestedAction, expectedCoordinationState: state } });
      expect(evaluateAuthOrchestration(input, adminUid)).toMatchObject({ decision: "proceed", nextStep,
        automaticActivation: false });
    }
  });

  it("prohibits automatic activation", () => {
    const input = { ...fixture(), activationRequested: true } as unknown as AuthOrchestrationInput;
    expectReject(input, "AUTOMATIC_ACTIVATION_FORBIDDEN");
  });

  it("protects the Super Admin", () => {
    const input = fixture();
    expectReject({ ...input, expectedFirebaseUid: adminUid, expectedInternalUid: adminUid }, "SUPER_ADMIN_FORBIDDEN");
  });

  it("has no side effects", () => {
    const input = fixture();
    const before = JSON.stringify(input);
    evaluateAuthOrchestration(input, adminUid);
    expect(JSON.stringify(input)).toBe(before);
  });
});

describe("E5D2 context contract", () => {
  function bootstrapInput() {
    const base = fixture();
    const { trustedSessionId: _trustedSessionId, ...baseInput } = base;
    const { trustedSessionId: _challengeSessionId, ...challenge } = base.evidence.challenge!;
    const bootstrapChallenge = createTrustedChallengeOrchestrationEvidence({ ...challenge,
      contextType: "google_bootstrap" });
    return { ...baseInput, contextType: "google_bootstrap" as const,
      evidence: { ...base.evidence, challenge: bootstrapChallenge } };
  }

  it("preserves trusted_session and requires trustedSessionId", () => {
    const valid = fixture();
    expect(authOrchestrationInputSchema.parse(valid).contextType).toBe("trusted_session");
    const { trustedSessionId: _session, ...missingSession } = valid;
    expect(authOrchestrationInputSchema.safeParse(missingSession).success).toBe(false);
  });

  it("accepts a structurally valid google_bootstrap contract without trustedSessionId", () => {
    const value = bootstrapInput();
    expect(value).not.toHaveProperty("trustedSessionId");
    expect(authOrchestrationInputSchema.safeParse(value).success).toBe(true);
  });

  it("rejects incompatible context and Challenge combinations", () => {
    const valid = fixture();
    expect(authOrchestrationInputSchema.safeParse({ ...valid, contextType: "google_bootstrap" }).success).toBe(false);
    const bootstrap = bootstrapInput();
    expect(authOrchestrationInputSchema.safeParse({ ...bootstrap, trustedSessionId: valid.trustedSessionId }).success)
      .toBe(false);
  });

  it("rejects bootstrap contracts missing Challenge, authorization, or revision evidence", () => {
    const valid = bootstrapInput();
    expect(authOrchestrationInputSchema.safeParse({ ...valid, challengeId: undefined }).success).toBe(false);
    expect(authOrchestrationInputSchema.safeParse({ ...valid, authorizationId: undefined }).success).toBe(false);
    expect(authOrchestrationInputSchema.safeParse({ ...valid, expectedCoordinationRevision: undefined }).success)
      .toBe(false);
    expectReject({ ...valid, evidence: { ...valid.evidence, challenge: null } } as AuthOrchestrationInput,
      "EVIDENCE_MISSING");
    expectReject({ ...valid, expectedCoordinationRevision: 1 } as AuthOrchestrationInput, "REVISION_CONFLICT");
  });

  it("requires backend evidence markers instead of client supplied evidence data", () => {
    const valid = fixture();
    const clientEvidence = (value: object | null) => value === null ? null : Object.fromEntries(Object.entries(value));
    const clientData = { ...valid, evidence: {
      ...valid.evidence,
      google: clientEvidence(valid.evidence.google),
      challenge: clientEvidence(valid.evidence.challenge),
      administrative: clientEvidence(valid.evidence.administrative),
      coordination: clientEvidence(valid.evidence.coordination)
    } } as AuthOrchestrationInput;
    expect(authOrchestrationInputSchema.safeParse(clientData).success).toBe(true);
    expect(evaluateAuthOrchestration(clientData, adminUid)).toEqual({ decision: "reject", code: "UNTRUSTED_EVIDENCE" });
  });
});
