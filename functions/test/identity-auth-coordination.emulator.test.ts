import { createHash, randomUUID } from "node:crypto";
import { deleteApp, initializeApp } from "firebase-admin/app";
import { Timestamp, getFirestore, type Firestore } from "firebase-admin/firestore";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createTrustedAuthCoordinationEvent } from "../src/identities/identity-auth-coordination-contracts.js";
import { AuthCoordinationPersistenceService } from "../src/identities/identity-auth-coordination-service.js";

let app: ReturnType<typeof initializeApp>;
let db: Firestore;
const adminUid = "protected-admin";
const clock = Timestamp.fromDate(new Date("2026-11-05T18:00:00.000Z"));

beforeAll(() => {
  if (!process.env.FIRESTORE_EMULATOR_HOST) throw new Error("Esta prueba requiere Firestore Emulator.");
  app = initializeApp({ projectId: "demo-plcocina-apps" }, `auth-coordination-${randomUUID()}`);
  db = getFirestore(app);
});

afterAll(async () => { await deleteApp(app); });

function hash(value: string) { return createHash("sha256").update(value).digest("hex"); }

function document(overrides: Record<string, unknown> = {}) {
  const uid = `user-${randomUUID()}`;
  const operationId = randomUUID();
  const authorizationId = randomUUID();
  return {
    operationId, operation: "google.firebase_provider_link", expectedFirebaseUid: uid, expectedInternalUid: uid,
    googleSubjectHash: hash(`subject-${randomUUID()}`), state: "not_started", expectedProfileRevision: 3,
    currentProfileRevision: 3, idempotencyKey: randomUUID(), authorizationId, challengeId: null,
    evidence: {
      authorization: { authorizationId, operation: "google.identity_link", validatedBy: "identity-link-authorization",
        validatedAt: clock, validUntil: Timestamp.fromMillis(clock.toMillis() + 600_000) },
      firestoreLink: { linkOperationId: randomUUID(), observedBy: "identity-linking-service", linkedAt: clock,
        profileRevision: 3, activationStatus: "linked_pending_activation", authDisabled: true },
      challenge: null, googleVerification: null, firebaseSession: null, firebaseProvider: null, postflight: null
    },
    conflictReason: null, revision: 1, lastEvent: null, createdAt: clock, updatedAt: clock,
    expiresAt: Timestamp.fromMillis(clock.toMillis() + 900_000), localActivationStatus: "linked_pending_activation",
    localAuthDisabled: true, version: 1, ...overrides
  };
}

function service() { return new AuthCoordinationPersistenceService(db, adminUid, () => Timestamp.fromMillis(clock.toMillis() + 1_000)); }

function event(value: ReturnType<typeof document>, type: "challenge_issued" | "provider_result_unknown" = "challenge_issued",
  overrides: Record<string, unknown> = {}) {
  const base = { type, operationId: value.operationId, idempotencyKey: randomUUID(),
    expectedFirebaseUid: value.expectedFirebaseUid, expectedInternalUid: value.expectedInternalUid,
    googleSubjectHash: value.googleSubjectHash, expectedCoordinationRevision: value.revision,
    expectedProfileRevision: value.currentProfileRevision };
  return createTrustedAuthCoordinationEvent(type === "challenge_issued" ? {
    ...base, challenge: { challengeId: randomUUID(), issuedBy: "identity-challenge-service", issuedAt: clock,
      expiresAt: Timestamp.fromMillis(clock.toMillis() + 300_000) }, ...overrides
  } : { ...base, ...overrides });
}

async function create(value: ReturnType<typeof document>) {
  return service().create({ trustedAdministratorUid: adminUid, document: value });
}

async function rejected(work: Promise<unknown>, code: string) {
  await expect(work).rejects.toMatchObject({ code });
}

describe("persistent transactional auth coordination", () => {
  it("creates and retrieves a strict isolated operation", async () => {
    const value = document();
    const result = await create(value);
    expect(result.replayed).toBe(false);
    expect(await service().get(value.operationId)).toMatchObject({ state: "not_started", revision: 1, localAuthDisabled: true });
  });

  it("coalesces equivalent concurrent creates", async () => {
    const value = document();
    const results = await Promise.all([create(value), create(value)]);
    expect(results.map((result) => result.replayed).sort()).toEqual([false, true]);
    expect((await db.collection("auditEvents").where("resourceId", "==", value.expectedFirebaseUid).get()).size).toBe(1);
  });

  it("allows one winner for concurrent operations on the same UID", async () => {
    const first = document();
    const second = document({ expectedFirebaseUid: first.expectedFirebaseUid, expectedInternalUid: first.expectedInternalUid });
    const results = await Promise.allSettled([create(first), create(second)]);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
  });

  it("allows one winner for concurrent operations on the same subject", async () => {
    const first = document();
    const second = document({ googleSubjectHash: first.googleSubjectHash });
    const results = await Promise.allSettled([create(first), create(second)]);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
  });

  it("rejects operation and idempotency reuse with different parameters", async () => {
    const value = document();
    await create(value);
    await rejected(create(document({ operationId: value.operationId })), "OPERATION_CONFLICT");
    await rejected(create(document({ idempotencyKey: value.idempotencyKey })), "IDEMPOTENCY_CONFLICT");
  });

  it("persists a valid E5B1 transition and one append-only audit", async () => {
    const value = document();
    await create(value);
    const result = await service().transition({ trustedAdministratorUid: adminUid, operationId: value.operationId,
      expectedRevision: 1, event: event(value) });
    expect(result).toMatchObject({ replayed: false, document: { state: "challenge_issued", revision: 2, localAuthDisabled: true } });
    expect((await db.collection("auditEvents").where("resourceId", "==", value.expectedFirebaseUid).get()).size).toBe(2);
  });

  it("coalesces concurrent equivalent transitions without extra revision or audit", async () => {
    const value = document();
    await create(value);
    const trustedEvent = event(value);
    const run = () => service().transition({ trustedAdministratorUid: adminUid, operationId: value.operationId,
      expectedRevision: 1, event: trustedEvent });
    const results = await Promise.all([run(), run()]);
    expect(results.map((result) => result.replayed).sort()).toEqual([false, true]);
    expect((await service().get(value.operationId)).revision).toBe(2);
    expect((await db.collection("auditEvents").where("resourceId", "==", value.expectedFirebaseUid).get()).size).toBe(2);
  });

  it("permits exactly one incompatible transition from the same revision", async () => {
    const value = document();
    await create(value);
    const first = event(value);
    const second = event(value, "provider_result_unknown");
    const run = (trustedEvent: ReturnType<typeof event>) => service().transition({ trustedAdministratorUid: adminUid,
      operationId: value.operationId, expectedRevision: 1, event: trustedEvent });
    const results = await Promise.allSettled([run(first), run(second)]);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect((await service().get(value.operationId)).revision).toBe(2);
  });

  it("persists unknown external results as blocked and does not release locks", async () => {
    const value = document();
    await create(value);
    await service().transition({ trustedAdministratorUid: adminUid, operationId: value.operationId,
      expectedRevision: 1, event: event(value, "provider_result_unknown") });
    expect(await service().get(value.operationId)).toMatchObject({ state: "auth_state_unknown", conflictReason: "PROVIDER_RESULT_UNKNOWN" });
    await rejected(create(document({ expectedFirebaseUid: value.expectedFirebaseUid, expectedInternalUid: value.expectedInternalUid })), "UID_LOCK_CONFLICT");
  });

  it("replays exact input but rejects a new event with stale revision", async () => {
    const value = document();
    await create(value);
    const trustedEvent = event(value);
    await service().transition({ trustedAdministratorUid: adminUid, operationId: value.operationId, expectedRevision: 1, event: trustedEvent });
    const replay = await service().transition({ trustedAdministratorUid: adminUid, operationId: value.operationId,
      expectedRevision: 1, event: trustedEvent });
    expect(replay.replayed).toBe(true);
    await rejected(service().transition({ trustedAdministratorUid: adminUid, operationId: value.operationId,
      expectedRevision: 1, event: event(value, "provider_result_unknown") }), "REVISION_CONFLICT");
    expect((await service().get(value.operationId)).revision).toBe(2);
  });

  it("rolls back all transition writes when deterministic audit creation fails", async () => {
    const value = document();
    await create(value);
    await db.collection("auditEvents").doc(`auth-coordination-${value.operationId}-2`).set({ occupied: true });
    await expect(service().transition({ trustedAdministratorUid: adminUid, operationId: value.operationId,
      expectedRevision: 1, event: event(value) })).rejects.toBeTruthy();
    expect(await service().get(value.operationId)).toMatchObject({ state: "not_started", revision: 1 });
  });

  it("does not create grants, claims, profiles, endpoints or active identities", async () => {
    const value = document();
    await create(value);
    await service().transition({ trustedAdministratorUid: adminUid, operationId: value.operationId,
      expectedRevision: 1, event: event(value) });
    expect((await db.collection("accessGrants").where("userId", "==", value.expectedFirebaseUid).get()).empty).toBe(true);
    expect((await db.collection("users").doc(value.expectedFirebaseUid).get()).exists).toBe(false);
    expect((await service().get(value.operationId)).localAuthDisabled).toBe(true);
  });

  it("protects the Super Admin and rejects untrusted callers", async () => {
    await rejected(service().create({ trustedAdministratorUid: adminUid,
      document: document({ expectedFirebaseUid: adminUid, expectedInternalUid: adminUid }) }), "SUPER_ADMIN_FORBIDDEN");
    await rejected(service().create({ trustedAdministratorUid: "other-admin", document: document() }), "TRUSTED_CONTEXT_MISMATCH");
  });
});
