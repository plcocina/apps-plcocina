import { randomUUID } from "node:crypto";
import { deleteApp, initializeApp } from "firebase-admin/app";
import { getFirestore, Timestamp, type Firestore } from "firebase-admin/firestore";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { FirestoreIdentityBlockingStore, IdentityBlockingService } from "../src/identities/identity-blocking-service.js";

let app: ReturnType<typeof initializeApp>;
let db: Firestore;
const adminUid = "emulator-protected-admin";

function profile(authMethod: "sms" | "email", identifier: string) {
  const timestamp = Timestamp.now();
  return {
    displayName: "Empleado Emulator", status: "active", authDisabled: false, invitationStatus: "accepted",
    authMethod,
    phoneE164: authMethod === "sms" ? identifier : null,
    normalizedPhone: authMethod === "sms" ? identifier : null,
    email: authMethod === "email" ? identifier : null,
    normalizedEmail: authMethod === "email" ? identifier : null,
    phoneVerifiedAt: authMethod === "sms" ? timestamp : null,
    emailVerifiedAt: authMethod === "email" ? timestamp : null,
    activationStatus: "active", credentialRevision: 1, authorizationRevision: 1,
    sessionValidAfter: timestamp, createdAt: timestamp, createdBy: adminUid,
    updatedAt: timestamp, updatedBy: adminUid, revision: 1, pendingOperationId: null, version: 2
  };
}

beforeAll(() => {
  if (!process.env.FIRESTORE_EMULATOR_HOST) throw new Error("Esta prueba requiere Firestore Emulator.");
  app = initializeApp({ projectId: "demo-plcocina-apps" }, `identity-blocking-${randomUUID()}`);
  db = getFirestore(app);
});

afterAll(async () => { await deleteApp(app); });

describe("identity blocking policy with Firestore Emulator", () => {
  it("authorizes preprovisioned SMS and Email Link profiles", async () => {
    const smsUid = `sms-${randomUUID()}`;
    const emailUid = `email-${randomUUID()}`;
    await Promise.all([
      db.collection("users").doc(smsUid).set(profile("sms", "+5215512345678")),
      db.collection("users").doc(emailUid).set(profile("email", "employee@example.test"))
    ]);
    const service = new IdentityBlockingService(new FirestoreIdentityBlockingStore(db), adminUid);
    await expect(service.beforeSignIn({ uid: smsUid, phoneNumber: "+5215512345678", emailVerified: false, disabled: false }, { signInMethod: "phone" })).resolves.toBeUndefined();
    await expect(service.beforeSignIn({ uid: emailUid, email: "employee@example.test", emailVerified: true, disabled: false }, { signInMethod: "emailLink" })).resolves.toBeUndefined();
  });

  it("rejects orphan identities without creating profiles", async () => {
    const uid = `orphan-${randomUUID()}`;
    const service = new IdentityBlockingService(new FirestoreIdentityBlockingStore(db), adminUid);
    await expect(service.beforeSignIn({ uid, phoneNumber: "+5215512345679", emailVerified: false, disabled: false }, { signInMethod: "phone" }))
      .rejects.toMatchObject({ code: "USER_NOT_AUTHORIZED" });
    expect((await db.collection("users").doc(uid).get()).exists).toBe(false);
  });

  it("fails closed when an administrative operation requires reconciliation", async () => {
    const uid = `reconcile-${randomUUID()}`;
    const operationId = randomUUID();
    const timestamp = Timestamp.now();
    await Promise.all([
      db.collection("users").doc(uid).set(profile("sms", "+5215512345680")),
      db.collection("adminOperations").doc(operationId).set({
        operationId, type: "identity.preprovision", targetUid: uid, appId: null, invitationId: null,
        actorUid: adminUid, inputHash: "a".repeat(64), expectedRevision: null,
        status: "reconciliation_required", checkpoint: "auth_created", requestId: randomUUID(),
        leaseOwner: randomUUID(), leaseExpiresAt: timestamp, attempts: 1, result: null,
        failureCode: "AUTH_STATE_AMBIGUOUS", createdAt: timestamp, updatedAt: timestamp, completedAt: null, version: 1
      })
    ]);
    const service = new IdentityBlockingService(new FirestoreIdentityBlockingStore(db), adminUid);
    await expect(service.beforeSignIn({ uid, phoneNumber: "+5215512345680", emailVerified: false, disabled: false }, { signInMethod: "phone" }))
      .rejects.toMatchObject({ code: "RECONCILIATION_REQUIRED" });
  });
});
