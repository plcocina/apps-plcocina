import { randomUUID } from "node:crypto";
import { Timestamp } from "firebase-admin/firestore";
import { describe, expect, it } from "vitest";
import {
  authCoordinationDocumentSchema,
  authCoordinationEventSchema,
  authCoordinationStateSchema,
  createTrustedAuthCoordinationEvent,
  type AuthCoordinationDocument,
  type AuthCoordinationEvent
} from "../src/identities/identity-auth-coordination-contracts.js";
import {
  AuthCoordinationTransitionError,
  evaluateAuthCoordinationTransition
} from "../src/identities/identity-auth-coordination-transitions.js";
import { linkGoogleIdentityRequestSchema } from "../src/identities/identity-linking-contracts.js";

const now = Timestamp.fromDate(new Date("2026-11-05T18:00:00.000Z"));
const later = (milliseconds: number) => Timestamp.fromMillis(now.toMillis() + milliseconds);
const before = (milliseconds: number) => Timestamp.fromMillis(now.toMillis() - milliseconds);
const uid = "employee-google-e5b1";
const adminUid = "protected-admin";
const subjectHash = "a".repeat(64);

function document(overrides: Record<string, unknown> = {}): AuthCoordinationDocument {
  const authorizationId = randomUUID();
  return authCoordinationDocumentSchema.parse({
    operationId: randomUUID(),
    operation: "google.firebase_provider_link",
    expectedFirebaseUid: uid,
    expectedInternalUid: uid,
    googleSubjectHash: subjectHash,
    state: "not_started",
    expectedProfileRevision: 3,
    currentProfileRevision: 3,
    idempotencyKey: randomUUID(),
    authorizationId,
    challengeId: null,
    evidence: {
      authorization: {
        authorizationId,
        operation: "google.identity_link",
        validatedBy: "identity-link-authorization",
        validatedAt: before(60_000),
        validUntil: later(600_000)
      },
      firestoreLink: {
        linkOperationId: randomUUID(),
        observedBy: "identity-linking-service",
        linkedAt: before(30_000),
        profileRevision: 3,
        activationStatus: "linked_pending_activation",
        authDisabled: true
      },
      challenge: null,
      googleVerification: null,
      firebaseSession: null,
      firebaseProvider: null,
      postflight: null
    },
    conflictReason: null,
    revision: 1,
    lastEvent: null,
    createdAt: before(120_000),
    updatedAt: before(120_000),
    expiresAt: later(900_000),
    localActivationStatus: "linked_pending_activation",
    localAuthDisabled: true,
    version: 1,
    ...overrides
  });
}

function binding(current: AuthCoordinationDocument) {
  return {
    operationId: current.operationId,
    idempotencyKey: randomUUID(),
    expectedFirebaseUid: current.expectedFirebaseUid,
    expectedInternalUid: current.expectedInternalUid,
    googleSubjectHash: current.googleSubjectHash,
    expectedCoordinationRevision: current.revision,
    expectedProfileRevision: current.currentProfileRevision
  };
}

function challengeEvent(current: AuthCoordinationDocument, overrides: Record<string, unknown> = {}) {
  return createTrustedAuthCoordinationEvent({
    ...binding(current),
    type: "challenge_issued",
    challenge: {
      challengeId: randomUUID(),
      issuedBy: "identity-challenge-service",
      issuedAt: now,
      expiresAt: later(300_000)
    },
    ...overrides
  });
}

function googleEvent(current: AuthCoordinationDocument, overrides: Record<string, unknown> = {}) {
  return createTrustedAuthCoordinationEvent({
    ...binding(current),
    type: "google_proof_verified",
    verification: {
      verificationId: randomUUID(),
      verifiedBy: "google-token-verifier",
      googleSubjectHash: subjectHash,
      verifiedAt: now,
      validUntil: later(300_000),
      nonceVerified: true
    },
    ...overrides
  });
}

function providerRequestEvent(current: AuthCoordinationDocument, overrides: Record<string, unknown> = {}) {
  return createTrustedAuthCoordinationEvent({
    ...binding(current),
    type: "provider_link_requested",
    session: {
      sessionVerificationId: randomUUID(),
      verifiedBy: "firebase-session-verifier",
      firebaseUid: uid,
      verifiedAt: now,
      authTime: before(60_000),
      revoked: false,
      disabled: false
    },
    ...overrides
  });
}

function postflightEvent(current: AuthCoordinationDocument, overrides: Record<string, unknown> = {}) {
  return createTrustedAuthCoordinationEvent({
    ...binding(current),
    type: "postflight_verified",
    provider: {
      observationId: randomUUID(),
      observedBy: "firebase-admin-postflight",
      firebaseUid: uid,
      providerId: "google.com",
      providerUidHash: subjectHash,
      observedAt: now
    },
    postflight: {
      postflightId: randomUUID(),
      verifiedBy: "firebase-admin-postflight",
      firebaseUid: uid,
      providerUidHash: subjectHash,
      authRecordDisabled: true,
      verifiedAt: now
    },
    ...overrides
  });
}

function apply(current: AuthCoordinationDocument, event: ReturnType<typeof createTrustedAuthCoordinationEvent>) {
  return evaluateAuthCoordinationTransition({ document: current, event, now, protectedSuperAdminUid: adminUid });
}

function issued(current = document()) { return apply(current, challengeEvent(current)).document; }
function verified(current = issued()) { return apply(current, googleEvent(current)).document; }
function pending(current = verified()) { return apply(current, providerRequestEvent(current)).document; }
function confirmed(current = pending()) { return apply(current, postflightEvent(current)).document; }

async function expectCode(work: () => unknown, code: string) {
  expect(work).toThrowError(AuthCoordinationTransitionError);
  try { work(); } catch (error) { expect(error).toMatchObject({ code }); }
}

describe("E5B1 authentication coordination contracts", () => {
  it("accepts an initial strict contract with trusted authorization and E4B2 evidence", () => {
    expect(document()).toMatchObject({ state: "not_started", localActivationStatus: "linked_pending_activation", localAuthDisabled: true });
  });

  it("requires Firebase and internal UID to be identical", () => {
    expect(authCoordinationDocumentSchema.safeParse({ ...document(), expectedInternalUid: "different" }).success).toBe(false);
  });

  it("rejects a transition bound to another UID", async () => {
    const current = document();
    const event = challengeEvent(current, { expectedFirebaseUid: "other-uid" });
    await expectCode(() => apply(current, event), "UID_MISMATCH");
  });

  it("rejects malformed subject hashes", () => {
    expect(authCoordinationDocumentSchema.safeParse({ ...document(), googleSubjectHash: "invalid" }).success).toBe(false);
  });

  it("rejects unknown states and fields", () => {
    expect(authCoordinationStateSchema.safeParse("firebase_magic").success).toBe(false);
    expect(authCoordinationDocumentSchema.safeParse({ ...document(), rawGoogleToken: "forbidden" }).success).toBe(false);
  });

  it("applies the documented happy-path transitions without activation", () => {
    const challenge = issued();
    const google = verified(challenge);
    const linkPending = pending(google);
    const providerConfirmed = confirmed(linkPending);
    const activation = apply(providerConfirmed, createTrustedAuthCoordinationEvent({
      ...binding(providerConfirmed), type: "activation_prepared"
    })).document;
    expect([challenge.state, google.state, linkPending.state, providerConfirmed.state, activation.state]).toEqual([
      "challenge_issued", "google_proof_verified", "provider_link_pending", "provider_link_confirmed", "activation_pending"
    ]);
    expect(activation.localAuthDisabled).toBe(true);
  });

  it("rejects an event outside its documented order", async () => {
    const current = document();
    await expectCode(() => apply(current, googleEvent(current)), "EVENT_OUT_OF_ORDER");
  });

  it("rejects skipping critical stages directly to postflight", async () => {
    const current = issued();
    await expectCode(() => apply(current, postflightEvent(current)), "EVENT_OUT_OF_ORDER");
  });

  it("returns an exact duplicate event as a no-op replay", () => {
    const current = document();
    const event = challengeEvent(current);
    const first = apply(current, event).document;
    const replay = apply(first, event);
    expect(replay).toMatchObject({ decision: "replay", replayed: true });
    expect(replay.document).toEqual(first);
  });

  it("rejects reuse of an idempotency key with different parameters", async () => {
    const current = document();
    const event = challengeEvent(current);
    const first = apply(current, event).document;
    const conflicting = createTrustedAuthCoordinationEvent({
      ...event,
      expectedCoordinationRevision: first.revision,
      challenge: { ...event.challenge, expiresAt: later(400_000) }
    });
    await expectCode(() => apply(first, conflicting), "IDEMPOTENCY_CONFLICT");
  });

  it("rejects a stale coordination revision", async () => {
    const current = document();
    await expectCode(() => apply(current, challengeEvent(current, { expectedCoordinationRevision: 99 })), "REVISION_CONFLICT");
  });

  it("fails closed when administrative authorization is revoked", () => {
    const current = issued();
    const result = apply(current, createTrustedAuthCoordinationEvent({ ...binding(current), type: "authorization_revoked" }));
    expect(result.document).toMatchObject({ state: "cancelled", conflictReason: "AUTHORIZATION_REVOKED", localAuthDisabled: true });
  });

  it("rejects verification after the challenge has expired", async () => {
    const base = document();
    const expired = apply(base, challengeEvent(base)).document;
    const event = googleEvent(expired);
    await expectCode(() => evaluateAuthCoordinationTransition({
      document: expired,
      event,
      now: later(400_000),
      protectedSuperAdminUid: adminUid
    }), "CHALLENGE_EXPIRED");
  });

  it("represents Firebase provider linking as pending without claiming completion", () => {
    const current = verified();
    const result = apply(current, providerRequestEvent(current)).document;
    expect(result).toMatchObject({ state: "provider_link_pending", localAuthDisabled: true });
    expect(result.evidence.firebaseProvider).toBeNull();
  });

  it("moves an observed provider plus inconsistent Firestore state to reconciliation", () => {
    const current = pending();
    const result = apply(current, createTrustedAuthCoordinationEvent({ ...binding(current), type: "firestore_inconsistent" })).document;
    expect(result).toMatchObject({ state: "reconciliation_required", conflictReason: "FIRESTORE_INCONSISTENT" });
  });

  it("represents a provider credential already owned elsewhere as conflict", () => {
    const current = pending();
    const result = apply(current, createTrustedAuthCoordinationEvent({ ...binding(current), type: "provider_credential_conflict" })).document;
    expect(result).toMatchObject({ state: "provider_conflict", conflictReason: "PROVIDER_CREDENTIAL_IN_USE" });
  });

  it("moves a failed postflight to reconciliation", () => {
    const current = pending();
    const result = apply(current, createTrustedAuthCoordinationEvent({ ...binding(current), type: "postflight_failed" })).document;
    expect(result).toMatchObject({ state: "reconciliation_required", conflictReason: "POSTFLIGHT_FAILED" });
  });

  it("blocks all normal progress after reconciliation", async () => {
    const current = pending();
    const reconciled = apply(current, createTrustedAuthCoordinationEvent({ ...binding(current), type: "postflight_failed" })).document;
    await expectCode(() => apply(reconciled, postflightEvent(reconciled)), "OPERATION_BLOCKED");
  });

  it("prohibits automatic activation", async () => {
    const current = confirmed();
    const prepared = apply(current, createTrustedAuthCoordinationEvent({ ...binding(current), type: "activation_prepared" })).document;
    await expectCode(() => apply(prepared, createTrustedAuthCoordinationEvent({ ...binding(prepared), type: "activation_completed" })), "ACTIVATION_OUT_OF_SCOPE");
  });

  it("protects the password-only Super Admin UID", async () => {
    const current = document({ expectedFirebaseUid: adminUid, expectedInternalUid: adminUid });
    await expectCode(() => apply(current, challengeEvent(current)), "SUPER_ADMIN_FORBIDDEN");
  });

  it("remains compatible with the E4B1 request and E4B2 final profile invariants", () => {
    const current = document();
    expect(linkGoogleIdentityRequestSchema.safeParse({
      authorizationId: current.authorizationId,
      operation: "google.identity_link",
      operationId: current.evidence.firestoreLink.linkOperationId,
      idempotencyKey: randomUUID(),
      targetUid: current.expectedInternalUid,
      googleSubjectHash: current.googleSubjectHash,
      expectedRevision: 2,
      requestedActivationStatus: "linked_pending_activation"
    }).success).toBe(true);
    expect(current.evidence.firestoreLink).toMatchObject({ activationStatus: "linked_pending_activation", authDisabled: true });
  });

  it("is deterministic and leaves its inputs without side effects", () => {
    const current = document();
    const event = challengeEvent(current);
    const documentBefore = structuredClone(current);
    const first = apply(current, event);
    const second = apply(current, event);
    expect(first).toEqual(second);
    expect(current).toEqual(documentBefore);
    expect(first.document).not.toBe(current);
  });
});

describe("trusted event boundary", () => {
  it("rejects raw client-declared verification evidence", async () => {
    const current = issued();
    const raw = authCoordinationEventSchema.parse({
      ...binding(current),
      type: "google_proof_verified",
      verification: {
        verificationId: randomUUID(), verifiedBy: "google-token-verifier", googleSubjectHash: subjectHash,
        verifiedAt: now, validUntil: later(300_000), nonceVerified: true
      }
    }) as AuthCoordinationEvent;
    await expectCode(() => evaluateAuthCoordinationTransition({
      document: current,
      event: raw as never,
      now,
      protectedSuperAdminUid: adminUid
    }), "UNTRUSTED_EVIDENCE");
  });
});
