import { randomUUID } from "node:crypto";
import { Timestamp } from "firebase-admin/firestore";
import { describe, expect, it } from "vitest";
import {
  evaluateGoogleIdentityLink,
  evaluateIdentityLinkAuthorization,
  IdentityLinkingContractError,
  identityLinkAuthorizationSchema,
  linkGoogleIdentityRequestSchema
} from "../src/identities/identity-linking-contracts.js";
import {
  googleWorkspaceUserV21DocumentSchema,
  userV2DocumentSchema
} from "../src/identities/identity-models.js";

const now = Timestamp.fromDate(new Date("2026-11-04T18:00:00.000Z"));
const issuedAt = Timestamp.fromMillis(now.toMillis() - 60_000);
const expiresAt = Timestamp.fromMillis(now.toMillis() + 5 * 60_000);
const subjectHash = "a".repeat(64);
const targetUid = "employee-google-1";
const adminUid = "protected-admin";
const authorizationId = randomUUID();
const operationId = randomUUID();
const idempotencyKey = randomUUID();

function authorization(overrides: Record<string, unknown> = {}) {
  return {
    authorizationId,
    operation: "google.identity_link",
    operationId,
    idempotencyKey,
    targetUid,
    googleSubjectHash: subjectHash,
    authorizedByUid: adminUid,
    expectedRevision: 2,
    reason: "Vinculación aprobada por administración",
    issuedAt,
    expiresAt,
    state: "pending",
    stateChangedAt: null,
    version: 1,
    ...overrides
  };
}

function request(overrides: Record<string, unknown> = {}) {
  return {
    authorizationId,
    operation: "google.identity_link",
    operationId,
    idempotencyKey,
    targetUid,
    googleSubjectHash: subjectHash,
    expectedRevision: 2,
    requestedActivationStatus: "linked_pending_activation",
    ...overrides
  };
}

function evaluation(overrides: Record<string, unknown> = {}) {
  return {
    request: request(),
    authorization: authorization(),
    now,
    protectedSuperAdminUid: adminUid,
    currentProfile: {
      uid: targetUid,
      revision: 2,
      linkingStatus: "verified" as const,
      activationStatus: "auth_enabled_pending_proof",
      authDisabled: true
    },
    verifiedGoogleSubjectHash: subjectHash,
    reservationOwnerUid: targetUid,
    ...overrides
  };
}

function linkedPendingGoogle(overrides: Record<string, unknown> = {}) {
  return {
    uid: targetUid,
    displayName: "Empleado Workspace",
    status: "invited",
    authDisabled: true,
    invitationStatus: "accepted",
    authMethod: "googleWorkspace",
    phoneE164: null,
    normalizedPhone: null,
    email: "employee@plcocina.com",
    normalizedEmail: "employee@plcocina.com",
    phoneVerifiedAt: null,
    emailVerifiedAt: now,
    googleWorkspace: {
      authorizedDomain: "plcocina.com",
      subject: "google-subject-123",
      linkingStatus: "linked",
      verificationStatus: "verified",
      verifiedAt: now,
      linkedAt: now,
      verificationRevision: 2,
      operationId: null
    },
    activationStatus: "linked_pending_activation",
    credentialRevision: 2,
    authorizationRevision: 1,
    sessionValidAfter: now,
    createdAt: now,
    createdBy: adminUid,
    updatedAt: now,
    updatedBy: adminUid,
    revision: 3,
    pendingOperationId: null,
    identityContractVersion: "2.1",
    version: 2,
    ...overrides
  };
}

async function expectCode(work: () => unknown, code: string): Promise<void> {
  expect(work).toThrowError(IdentityLinkingContractError);
  try {
    work();
  } catch (error) {
    expect(error).toMatchObject({ code });
  }
}

describe("Google-only linked pending activation contract", () => {
  it("accepts a linked and verified identity while keeping Authentication disabled", () => {
    const parsed = googleWorkspaceUserV21DocumentSchema.parse(linkedPendingGoogle());
    expect(parsed.activationStatus).toBe("linked_pending_activation");
    expect(parsed.authDisabled).toBe(true);
    expect(parsed.uid).toBe(targetUid);
  });

  it("rejects linked state without subject or verification evidence", () => {
    expect(googleWorkspaceUserV21DocumentSchema.safeParse(linkedPendingGoogle({
      googleWorkspace: { ...linkedPendingGoogle().googleWorkspace as object, subject: null }
    })).success).toBe(false);
    expect(googleWorkspaceUserV21DocumentSchema.safeParse(linkedPendingGoogle({
      googleWorkspace: { ...linkedPendingGoogle().googleWorkspace as object, verifiedAt: null }
    })).success).toBe(false);
  });

  it("requires authDisabled true and rejects automatic active profile state", () => {
    expect(googleWorkspaceUserV21DocumentSchema.safeParse(linkedPendingGoogle({ authDisabled: false })).success).toBe(false);
    expect(googleWorkspaceUserV21DocumentSchema.safeParse(linkedPendingGoogle({ status: "active" })).success).toBe(false);
  });

  it("keeps linked_pending_activation outside operational SMS and Email Link profiles", () => {
    const sms = {
      displayName: "SMS", status: "invited", authDisabled: true, invitationStatus: "pending",
      authMethod: "sms", phoneE164: "+528112345678", normalizedPhone: "+528112345678",
      email: null, normalizedEmail: null, phoneVerifiedAt: null, emailVerifiedAt: null,
      activationStatus: "linked_pending_activation", credentialRevision: 1, authorizationRevision: 1,
      sessionValidAfter: now, createdAt: now, createdBy: adminUid, updatedAt: now, updatedBy: adminUid,
      revision: 1, pendingOperationId: null, version: 2
    };
    expect(userV2DocumentSchema.safeParse(sms).success).toBe(false);
    expect(userV2DocumentSchema.safeParse({ ...sms, authMethod: "email", phoneE164: null, normalizedPhone: null,
      email: "user@example.test", normalizedEmail: "user@example.test" }).success).toBe(false);
  });
});

describe("identity linking authorization contracts and pure evaluation", () => {
  it("accepts a bounded, explicit administrative authorization", () => {
    expect(identityLinkAuthorizationSchema.parse(authorization())).toMatchObject({
      targetUid, googleSubjectHash: subjectHash, state: "pending", expectedRevision: 2
    });
    expect(evaluateIdentityLinkAuthorization(authorization(), now)).toBe("valid");
  });

  it("rejects expired, revoked and consumed authorizations", async () => {
    await expectCode(() => evaluateIdentityLinkAuthorization(authorization({ expiresAt: now }), now), "AUTHORIZATION_EXPIRED");
    await expectCode(() => evaluateIdentityLinkAuthorization(authorization({ state: "revoked", stateChangedAt: now }), now), "AUTHORIZATION_REVOKED");
    await expectCode(() => evaluateIdentityLinkAuthorization(authorization({ state: "consumed", stateChangedAt: now }), now), "AUTHORIZATION_CONSUMED");
  });

  it("rejects stale revision and incorrect profile UID", async () => {
    await expectCode(() => evaluateGoogleIdentityLink(evaluation({
      currentProfile: { ...evaluation().currentProfile, revision: 1 }
    }) as never), "REVISION_CONFLICT");
    await expectCode(() => evaluateGoogleIdentityLink(evaluation({
      currentProfile: { ...evaluation().currentProfile, uid: "other-uid" }
    }) as never), "UID_CONFLICT");
  });

  it("rejects a different verified subject hash and mismatched idempotency binding", async () => {
    await expectCode(() => evaluateGoogleIdentityLink(evaluation({ verifiedGoogleSubjectHash: "b".repeat(64) }) as never), "SUBJECT_CONFLICT");
    await expectCode(() => evaluateGoogleIdentityLink(evaluation({
      authorization: authorization({ idempotencyKey: randomUUID() })
    }) as never), "AUTHORIZATION_MISMATCH");
  });

  it("returns a pure linked_pending_activation transition without activation", () => {
    expect(evaluateGoogleIdentityLink(evaluation() as never)).toEqual({
      decision: "link",
      uid: targetUid,
      googleSubjectHash: subjectHash,
      nextLinkingStatus: "linked",
      nextActivationStatus: "linked_pending_activation",
      nextAuthDisabled: true,
      nextRevision: 3,
      replayed: false
    });
  });

  it("rejects automatic activation and protected Super Admin destination", async () => {
    expect(linkGoogleIdentityRequestSchema.safeParse(request({ requestedActivationStatus: "active" })).success).toBe(false);
    await expectCode(() => evaluateGoogleIdentityLink(evaluation({ request: request({ targetUid: adminUid }) }) as never), "SUPER_ADMIN_LINK_FORBIDDEN");
  });

  it("replays an equivalent completed operation and rejects different reuse", async () => {
    const completed = { ...request(), status: "completed", resultingRevision: 3 };
    expect(evaluateGoogleIdentityLink(evaluation({ completedOperation: completed }) as never)).toMatchObject({ decision: "replay", replayed: true });
    await expectCode(() => evaluateGoogleIdentityLink(evaluation({
      completedOperation: { ...completed, idempotencyKey: randomUUID() }
    }) as never), "IDEMPOTENCY_CONFLICT");
  });

  it("enters reconciliation for missing or conflicting reservations", () => {
    expect(evaluateGoogleIdentityLink(evaluation({ reservationOwnerUid: null }) as never)).toMatchObject({
      decision: "reconciliation_required", reason: "RESERVATION_MISSING"
    });
    expect(evaluateGoogleIdentityLink(evaluation({ reservationOwnerUid: "other-uid" }) as never)).toMatchObject({
      decision: "reconciliation_required", reason: "RESERVATION_UID_CONFLICT"
    });
  });

  it("rejects unknown fields and malformed subject hashes", () => {
    expect(identityLinkAuthorizationSchema.safeParse({ ...authorization(), super_admin: true }).success).toBe(false);
    expect(linkGoogleIdentityRequestSchema.safeParse({ ...request(), uid: "injected", googleSubjectHash: "not-a-hash" }).success).toBe(false);
  });
});
