import { randomUUID } from "node:crypto";
import { deleteApp, initializeApp } from "firebase-admin/app";
import { getFirestore, type DocumentData, type Firestore } from "firebase-admin/firestore";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { identifierKeyHash } from "../src/identities/identity-models.js";
import { IdentityReservationService } from "../src/identities/identity-reservation-service.js";

let db: Firestore;
let app: ReturnType<typeof initializeApp>;
const pepper = Buffer.alloc(32, 0x6b);

beforeAll(() => {
  if (!process.env.FIRESTORE_EMULATOR_HOST) throw new Error("Esta prueba requiere Firestore Emulator.");
  app = initializeApp({ projectId: "demo-plcocina-apps" }, `identity-reservation-${randomUUID()}`);
  db = getFirestore(app);
});

afterAll(async () => { await deleteApp(app); });

describe("identity reservation concurrency", () => {
  it("allows exactly one UID to reserve a normalized identifier", async () => {
    const service = new IdentityReservationService(db, pepper);
    const results = await Promise.allSettled([
      service.reserve({ operationId: randomUUID(), uid: `uid-a-${randomUUID()}`, kind: "email", value: " Concurrent@Example.test " }),
      service.reserve({ operationId: randomUUID(), uid: `uid-b-${randomUUID()}`, kind: "email", value: "concurrent@example.test" })
    ]);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((result) => result.status === "rejected").map((result) => result.reason?.code)).toEqual(["IDENTIFIER_COLLISION"]);
  });

  it("allows exactly one UID to reserve a googleSubject concurrently and preserves the winner", async () => {
    const service = new IdentityReservationService(db, pepper);
    const subject = `google-subject-${randomUUID()}`;
    const operationA = randomUUID();
    const operationB = randomUUID();
    const uidA = `google-a-${randomUUID()}`;
    const uidB = `google-b-${randomUUID()}`;
    const results = await Promise.allSettled([
      service.reserve({ operationId: operationA, uid: uidA, kind: "googleSubject", value: subject }),
      service.reserve({ operationId: operationB, uid: uidB, kind: "googleSubject", value: ` ${subject} ` })
    ]);

    const fulfilled = results.filter((result): result is PromiseFulfilledResult<Awaited<ReturnType<typeof service.reserve>>> => result.status === "fulfilled");
    const rejected = results.filter((result): result is PromiseRejectedResult => result.status === "rejected");
    expect(fulfilled).toHaveLength(1);
    expect(rejected).toHaveLength(1);
    expect(rejected[0]?.reason?.code).toBe("IDENTIFIER_COLLISION");

    const winner = fulfilled[0]!.value;
    const key = await db.collection("authIdentifierKeys").doc(winner.identifierHash).get();
    expect(key.data()).toMatchObject({ kind: "googleSubject", uid: winner.uid, state: "reserved", operationId: winner.operationId });
    const loserUid = winner.uid === uidA ? uidB : uidA;
    const loserOperation = winner.uid === uidA ? operationB : operationA;
    expect(key.data()?.uid).not.toBe(loserUid);
    expect((await db.collection("identityOperations").doc(loserOperation).get()).exists).toBe(false);
  });

  it("coalesces concurrent equivalent googleSubject reservations for the same UID", async () => {
    const service = new IdentityReservationService(db, pepper);
    const subject = `google-subject-${randomUUID()}`;
    const uid = `google-same-${randomUUID()}`;
    const operationA = randomUUID();
    const operationB = randomUUID();
    const [first, second] = await Promise.all([
      service.reserve({ operationId: operationA, uid, kind: "googleSubject", value: subject }),
      service.reserve({ operationId: operationB, uid, kind: "googleSubject", value: ` ${subject} ` })
    ]);

    expect(first.operationId).toBe(second.operationId);
    expect([first.replayed, second.replayed].sort()).toEqual([false, true]);
    const operationDocuments = await Promise.all([
      db.collection("identityOperations").doc(operationA).get(),
      db.collection("identityOperations").doc(operationB).get()
    ]);
    expect(operationDocuments.filter((snapshot) => snapshot.exists)).toHaveLength(1);
  });

  it("returns a no-op for an equivalent same-owner retry with a new operation ID", async () => {
    const service = new IdentityReservationService(db, pepper);
    const subject = `google-subject-${randomUUID()}`;
    const uid = `google-retry-${randomUUID()}`;
    const originalOperation = randomUUID();
    const retryOperation = randomUUID();
    const first = await service.reserve({ operationId: originalOperation, uid, kind: "googleSubject", value: subject });
    const keyRef = db.collection("authIdentifierKeys").doc(first.identifierHash);
    const before = (await keyRef.get()).data() as DocumentData;
    const replay = await service.reserve({ operationId: retryOperation, uid, kind: "googleSubject", value: ` ${subject} ` });
    const after = (await keyRef.get()).data() as DocumentData;

    expect(replay).toMatchObject({ operationId: originalOperation, uid, replayed: true, state: "reserved" });
    expect(after).toEqual(before);
    expect((await db.collection("identityOperations").doc(retryOperation).get()).exists).toBe(false);
    expect((await db.collection("auditEvents").where("targetUid", "==", uid).get()).empty).toBe(true);
  });

  it("replays the confirmed operation without changing its reservation", async () => {
    const service = new IdentityReservationService(db, pepper);
    const subject = `google-subject-${randomUUID()}`;
    const uid = `google-confirmed-${randomUUID()}`;
    const operationId = randomUUID();
    const first = await service.reserve({ operationId, uid, kind: "googleSubject", value: subject });
    const keyRef = db.collection("authIdentifierKeys").doc(first.identifierHash);
    const operationRef = db.collection("identityOperations").doc(operationId);
    const beforeKey = (await keyRef.get()).data();
    const beforeOperation = (await operationRef.get()).data();
    const replay = await service.reserve({ operationId, uid, kind: "googleSubject", value: subject });

    expect(replay.replayed).toBe(true);
    expect((await keyRef.get()).data()).toEqual(beforeKey);
    expect((await operationRef.get()).data()).toEqual(beforeOperation);
  });

  it("rejects sequential conflicts without overwriting the existing owner", async () => {
    const service = new IdentityReservationService(db, pepper);
    const subject = `google-subject-${randomUUID()}`;
    const first = await service.reserve({ operationId: randomUUID(), uid: `owner-${randomUUID()}`, kind: "googleSubject", value: subject });
    const before = (await db.collection("authIdentifierKeys").doc(first.identifierHash).get()).data();
    const loserOperation = randomUUID();
    await expect(service.reserve({
      operationId: loserOperation, uid: `loser-${randomUUID()}`, kind: "googleSubject", value: subject
    })).rejects.toMatchObject({ code: "IDENTIFIER_COLLISION" });
    expect((await db.collection("authIdentifierKeys").doc(first.identifierHash).get()).data()).toEqual(before);
    expect((await db.collection("identityOperations").doc(loserOperation).get()).exists).toBe(false);
  });

  it("keeps a confirmed operation atomic when its key is reused for another subject", async () => {
    const service = new IdentityReservationService(db, pepper);
    const uid = `google-atomic-${randomUUID()}`;
    const operationId = randomUUID();
    const firstSubject = `google-subject-${randomUUID()}`;
    const secondSubject = `google-subject-${randomUUID()}`;
    const first = await service.reserve({ operationId, uid, kind: "googleSubject", value: firstSubject });
    const secondHash = identifierKeyHash("googleSubject", secondSubject, pepper);
    await expect(service.reserve({ operationId, uid, kind: "googleSubject", value: secondSubject }))
      .rejects.toMatchObject({ code: "IDEMPOTENCY_CONFLICT" });
    expect((await db.collection("authIdentifierKeys").doc(first.identifierHash).get()).data()).toMatchObject({ uid, state: "reserved" });
    expect((await db.collection("authIdentifierKeys").doc(secondHash).get()).exists).toBe(false);
  });

  it("leaves no partial key when an invalid existing operation aborts the transaction", async () => {
    const service = new IdentityReservationService(db, pepper);
    const operationId = randomUUID();
    const subject = `google-subject-${randomUUID()}`;
    const identifierHash = identifierKeyHash("googleSubject", subject, pepper);
    const operationRef = db.collection("identityOperations").doc(operationId);
    const invalidOperation = { type: "invalid-test-fixture", marker: randomUUID() };
    await operationRef.set(invalidOperation);

    await expect(service.reserve({
      operationId, uid: `google-abort-${randomUUID()}`, kind: "googleSubject", value: subject
    })).rejects.toMatchObject({ code: "IDEMPOTENCY_CONFLICT" });
    expect((await db.collection("authIdentifierKeys").doc(identifierHash).get()).exists).toBe(false);
    expect((await operationRef.get()).data()).toEqual(invalidOperation);
  });

  it("rejects an invalid googleSubject before creating Firestore state", async () => {
    const service = new IdentityReservationService(db, pepper);
    const operationId = randomUUID();
    await expect(service.reserve({
      operationId, uid: `google-invalid-${randomUUID()}`, kind: "googleSubject", value: "invalid subject with spaces"
    })).rejects.toThrow("INVALID_GOOGLE_SUBJECT");
    expect((await db.collection("identityOperations").doc(operationId).get()).exists).toBe(false);
  });

  it("creates only a pending reservation and no profile, grant, claim or audit state", async () => {
    const service = new IdentityReservationService(db, pepper);
    const uid = `google-pending-${randomUUID()}`;
    const result = await service.reserve({
      operationId: randomUUID(), uid, kind: "googleSubject", value: `google-subject-${randomUUID()}`
    });
    expect((await db.collection("authIdentifierKeys").doc(result.identifierHash).get()).data()).toMatchObject({
      uid, kind: "googleSubject", state: "reserved"
    });
    expect((await db.collection("users").doc(uid).get()).exists).toBe(false);
    expect((await db.collection("accessGrants").where("userId", "==", uid).get()).empty).toBe(true);
    expect((await db.collection("auditEvents").where("targetUid", "==", uid).get()).empty).toBe(true);
  });

  it("keeps SMS and Email Link reservations isolated from googleSubject", async () => {
    const service = new IdentityReservationService(db, pepper);
    const email = await service.reserve({
      operationId: randomUUID(), uid: `email-${randomUUID()}`, kind: "email", value: `user-${randomUUID()}@example.test`
    });
    const phone = await service.reserve({
      operationId: randomUUID(), uid: `phone-${randomUUID()}`, kind: "phone", value: "+5281" + Math.floor(10_000_000 + Math.random() * 89_999_999)
    });
    const google = await service.reserve({
      operationId: randomUUID(), uid: `google-${randomUUID()}`, kind: "googleSubject", value: `google-subject-${randomUUID()}`
    });
    expect(new Set([email.identifierHash, phone.identifierHash, google.identifierHash]).size).toBe(3);
    expect((await db.collection("authIdentifierKeys").doc(email.identifierHash).get()).data()?.kind).toBe("email");
    expect((await db.collection("authIdentifierKeys").doc(phone.identifierHash).get()).data()?.kind).toBe("phone");
    expect((await db.collection("authIdentifierKeys").doc(google.identifierHash).get()).data()?.kind).toBe("googleSubject");
  });
});
