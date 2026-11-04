import { randomUUID } from "node:crypto";
import { deleteApp, initializeApp } from "firebase-admin/app";
import { Timestamp, getFirestore, type Firestore } from "firebase-admin/firestore";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { GoogleIdentityLinkingService } from "../src/identities/identity-linking-service.js";
import { IdentityReservationService } from "../src/identities/identity-reservation-service.js";

let app: ReturnType<typeof initializeApp>;
let db: Firestore;
const pepper = Buffer.alloc(32, 0x4c);
const adminUid = "protected-admin";
const clock = Timestamp.fromDate(new Date("2026-11-04T20:00:00.000Z"));

beforeAll(() => {
  if (!process.env.FIRESTORE_EMULATOR_HOST) throw new Error("Esta prueba requiere Firestore Emulator.");
  app = initializeApp({ projectId: "demo-plcocina-apps" }, `identity-linking-${randomUUID()}`);
  db = getFirestore(app);
});

afterAll(async () => { await deleteApp(app); });

type Fixture = Awaited<ReturnType<typeof fixture>>;

async function fixture(overrides: { uid?: string; subject?: string; profile?: Record<string, unknown>; authorization?: Record<string, unknown> } = {}) {
  const uid = overrides.uid ?? `google-user-${randomUUID()}`;
  const subject = overrides.subject ?? `google-subject-${randomUUID()}`;
  const operationId = randomUUID();
  const idempotencyKey = randomUUID();
  const authorizationId = randomUUID();
  const reservation = await new IdentityReservationService(db, pepper, () => clock).reserve({
    operationId: randomUUID(), uid, kind: "googleSubject", value: subject
  });
  const profile = {
    uid,
    displayName: "Empleado Workspace",
    status: "invited",
    authDisabled: true,
    invitationStatus: "accepted",
    authMethod: "googleWorkspace",
    phoneE164: null,
    normalizedPhone: null,
    email: `employee-${randomUUID()}@plcocina.com`,
    normalizedEmail: "",
    phoneVerifiedAt: null,
    emailVerifiedAt: clock,
    googleWorkspace: {
      authorizedDomain: "plcocina.com",
      subject,
      linkingStatus: "verified",
      verificationStatus: "verified",
      verifiedAt: clock,
      linkedAt: null,
      verificationRevision: 1,
      operationId: null
    },
    activationStatus: "recovery_required",
    credentialRevision: 1,
    authorizationRevision: 1,
    sessionValidAfter: clock,
    createdAt: clock,
    createdBy: adminUid,
    updatedAt: clock,
    updatedBy: adminUid,
    revision: 2,
    pendingOperationId: null,
    identityContractVersion: "2.1",
    version: 2,
    ...overrides.profile
  };
  profile.normalizedEmail = profile.email as string;
  await db.collection("users").doc(uid).set(profile);
  const authorization = {
    authorizationId,
    operation: "google.identity_link",
    operationId,
    idempotencyKey,
    targetUid: uid,
    googleSubjectHash: reservation.identifierHash,
    authorizedByUid: adminUid,
    expectedRevision: 2,
    reason: "Vinculación aprobada para prueba aislada",
    issuedAt: Timestamp.fromMillis(clock.toMillis() - 60_000),
    expiresAt: Timestamp.fromMillis(clock.toMillis() + 5 * 60_000),
    state: "pending",
    stateChangedAt: null,
    version: 1,
    ...overrides.authorization
  };
  const service = new GoogleIdentityLinkingService(db, pepper, adminUid, () => clock);
  await service.persistAuthorization(authorization);
  const request = {
    authorizationId,
    operation: "google.identity_link",
    operationId,
    idempotencyKey,
    targetUid: uid,
    googleSubjectHash: reservation.identifierHash,
    expectedRevision: 2,
    requestedActivationStatus: "linked_pending_activation"
  };
  const verifiedIdentity = {
    subject,
    verifiedAt: clock,
    validUntil: Timestamp.fromMillis(clock.toMillis() + 5 * 60_000),
    verificationId: randomUUID()
  };
  return { uid, subject, reservation, authorization, request, verifiedIdentity, service };
}

async function link(value: Fixture) {
  return value.service.linkVerifiedIdentity({
    trustedTargetUid: value.uid,
    trustedAdministratorUid: adminUid,
    request: value.request,
    verifiedIdentity: value.verifiedIdentity
  });
}

async function expectRejected(work: Promise<unknown>, code: string) {
  await expect(work).rejects.toMatchObject({ code });
}

describe("transactional Google Workspace identity linking", () => {
  it("links a verified identity to the existing UID", async () => {
    const value = await fixture();
    const result = await link(value);
    expect(result).toMatchObject({ uid: value.uid, revision: 3, replayed: false });
    expect((await db.collection("users").doc(value.uid).get()).id).toBe(value.uid);
  });

  it("persists only linked_pending_activation with Authentication disabled", async () => {
    const value = await fixture();
    await link(value);
    expect((await db.collection("users").doc(value.uid).get()).data()).toMatchObject({
      status: "invited", authDisabled: true, activationStatus: "linked_pending_activation",
      googleWorkspace: { linkingStatus: "linked", verificationStatus: "verified", subject: value.subject }
    });
  });

  it("consumes the authorization exactly once and writes one audit", async () => {
    const value = await fixture();
    await link(value);
    expect((await db.collection("identityLinkAuthorizations").doc(value.authorization.authorizationId).get()).data()).toMatchObject({ state: "consumed" });
    expect((await db.collection("auditEvents").where("targetUid", "==", value.uid).get()).size).toBe(1);
  });

  it("replays exactly without revision or audit changes", async () => {
    const value = await fixture();
    const first = await link(value);
    const second = await link(value);
    expect(second).toEqual({ ...first, replayed: true });
    expect((await db.collection("users").doc(value.uid).get()).data()?.revision).toBe(3);
    expect((await db.collection("auditEvents").where("targetUid", "==", value.uid).get()).size).toBe(1);
  });

  it("coalesces two equivalent concurrent requests", async () => {
    const value = await fixture();
    const results = await Promise.all([link(value), link(value)]);
    expect(results.map((result) => result.replayed).sort()).toEqual([false, true]);
    expect((await db.collection("auditEvents").where("targetUid", "==", value.uid).get()).size).toBe(1);
  });

  it("rejects a second UID for the reserved subject", async () => {
    const owner = await fixture();
    const contender = await fixture();
    contender.subject = owner.subject;
    contender.verifiedIdentity.subject = owner.subject;
    contender.request.googleSubjectHash = owner.reservation.identifierHash;
    await db.collection("users").doc(contender.uid).update({ "googleWorkspace.subject": owner.subject });
    await db.collection("identityLinkAuthorizations").doc(contender.authorization.authorizationId).update({
      googleSubjectHash: owner.reservation.identifierHash
    });
    await expectRejected(link(contender), "RESERVATION_CONFLICT");
    expect((await db.collection("users").doc(contender.uid).get()).data()?.revision).toBe(2);
  });

  it("allows at most one incompatible subject for one UID", async () => {
    const first = await fixture();
    const second = await fixture({ uid: first.uid });
    const results = await Promise.allSettled([link(first), link(second)]);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect((await db.collection("users").doc(first.uid).get()).data()?.revision).toBe(3);
  });

  it("rejects an expired authorization without consuming it", async () => {
    const value = await fixture({ authorization: { expiresAt: clock } });
    await expectRejected(link(value), "AUTHORIZATION_EXPIRED");
    expect((await db.collection("identityLinkAuthorizations").doc(value.authorization.authorizationId).get()).data()?.state).toBe("pending");
  });

  it("rejects a revoked authorization", async () => {
    const value = await fixture({ authorization: { state: "revoked", stateChangedAt: clock } });
    await expectRejected(link(value), "AUTHORIZATION_REVOKED");
  });

  it("rejects an obsolete revision", async () => {
    const value = await fixture();
    await db.collection("users").doc(value.uid).update({ revision: 3 });
    await expectRejected(link(value), "REVISION_CONFLICT");
  });

  it("rejects a verified subject different from the authorization", async () => {
    const value = await fixture();
    value.verifiedIdentity.subject = `different-${randomUUID()}`;
    await expectRejected(link(value), "SUBJECT_CONFLICT");
  });

  it("rejects an absent reservation", async () => {
    const value = await fixture();
    await db.collection("authIdentifierKeys").doc(value.reservation.identifierHash).delete();
    await expectRejected(link(value), "RESERVATION_REQUIRED");
  });

  it("rejects a reservation owned by another UID", async () => {
    const value = await fixture();
    await db.collection("authIdentifierKeys").doc(value.reservation.identifierHash).update({ uid: `other-${randomUUID()}` });
    await expectRejected(link(value), "RESERVATION_CONFLICT");
  });

  it("rejects a suspended user", async () => {
    const value = await fixture({ profile: { status: "disabled" } });
    await expectRejected(link(value), "IDENTITY_STATE_INVALID");
  });

  it("protects the Super Admin destination", async () => {
    const value = await fixture({ uid: adminUid });
    await expectRejected(link(value), "SUPER_ADMIN_LINK_FORBIDDEN");
  });

  it("rejects an invalid transition from declared", async () => {
    const value = await fixture();
    await db.collection("users").doc(value.uid).update({
      "googleWorkspace.linkingStatus": "declared", "googleWorkspace.verificationStatus": "unverified",
      "googleWorkspace.subject": null, "googleWorkspace.verifiedAt": null, emailVerifiedAt: null, activationStatus: "pending"
    });
    await expectRejected(link(value), "IDENTITY_STATE_INVALID");
  });

  it("rejects expired verified evidence", async () => {
    const value = await fixture();
    value.verifiedIdentity.verifiedAt = Timestamp.fromMillis(clock.toMillis() - 120_000);
    value.verifiedIdentity.validUntil = Timestamp.fromMillis(clock.toMillis() - 60_000);
    await expectRejected(link(value), "VERIFICATION_EXPIRED");
  });

  it("rejects reuse of an idempotency key with different parameters", async () => {
    const value = await fixture();
    await link(value);
    value.request.operationId = randomUUID();
    await expectRejected(link(value), "IDEMPOTENCY_CONFLICT");
  });

  it("rejects reuse of a consumed authorization outside its exact replay", async () => {
    const value = await fixture();
    await link(value);
    await db.collection("identityLinkOperations").doc(value.request.idempotencyKey).delete();
    await expectRejected(link(value), "AUTHORIZATION_CONSUMED");
  });

  it("aborts every write when the final deterministic audit conflicts", async () => {
    const value = await fixture();
    await db.collection("auditEvents").doc(`google-link-${value.request.operationId}`).set({ occupied: true });
    await expect(link(value)).rejects.toBeTruthy();
    expect((await db.collection("users").doc(value.uid).get()).data()?.revision).toBe(2);
    expect((await db.collection("identityLinkAuthorizations").doc(value.authorization.authorizationId).get()).data()?.state).toBe("pending");
    expect((await db.collection("identityLinkOperations").doc(value.request.idempotencyKey).get()).exists).toBe(false);
  });

  it("does not create Access Grants, custom claims or active profiles", async () => {
    const value = await fixture();
    await link(value);
    expect((await db.collection("accessGrants").where("userId", "==", value.uid).get()).empty).toBe(true);
    expect((await db.collection("customClaims").doc(value.uid).get()).exists).toBe(false);
    expect((await db.collection("users").doc(value.uid).get()).data()?.status).not.toBe("active");
  });

  it("leaves SMS and Email Link profiles outside the Google transaction", async () => {
    const value = await fixture();
    await db.collection("users").doc(value.uid).set({
      displayName: "SMS", status: "invited", authDisabled: true, invitationStatus: "pending",
      authMethod: "sms", phoneE164: "+528112345678", normalizedPhone: "+528112345678",
      email: null, normalizedEmail: null, phoneVerifiedAt: null, emailVerifiedAt: null,
      activationStatus: "pending", credentialRevision: 1, authorizationRevision: 1,
      sessionValidAfter: clock, createdAt: clock, createdBy: adminUid, updatedAt: clock, updatedBy: adminUid,
      revision: 2, pendingOperationId: null, version: 2
    });
    await expectRejected(link(value), "IDENTITY_STATE_INVALID");
    expect((await db.collection("users").doc(value.uid).get()).data()?.authMethod).toBe("sms");
  });
});
