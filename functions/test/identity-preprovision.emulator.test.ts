import { randomUUID } from "node:crypto";
import { deleteApp, initializeApp } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import { getFirestore, type Firestore } from "firebase-admin/firestore";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { AdminPrincipal } from "../src/auth/require-super-admin.js";
import { FirebaseIdentityDirectory, IdentityPreprovisionService } from "../src/identities/identity-preprovision-service.js";
import { IdentityReservationService } from "../src/identities/identity-reservation-service.js";

let app: ReturnType<typeof initializeApp>;
let db: Firestore;
let service: IdentityPreprovisionService;
const principal: AdminPrincipal = {
  uid: "protected-admin", email: "admin@example.test", authTime: 1, issuedAt: 1, superAdmin: true
};

beforeAll(() => {
  if (!process.env.FIRESTORE_EMULATOR_HOST || !process.env.FIREBASE_AUTH_EMULATOR_HOST) {
    throw new Error("Esta prueba requiere Auth y Firestore Emulator.");
  }
  app = initializeApp({ projectId: "demo-plcocina-apps" }, `identity-preprovision-${randomUUID()}`);
  db = getFirestore(app);
  service = new IdentityPreprovisionService(
    db,
    new FirebaseIdentityDirectory(getAuth(app)),
    new IdentityReservationService(db, Buffer.alloc(32, 0x73)),
    "protected-admin"
  );
});

afterAll(async () => { await deleteApp(app); });

describe("identity preprovisioning with Auth and Firestore emulators", () => {
  it("persists one disabled SMS identity under the same UID without grants", async () => {
    const result = await service.preprovision({
      operationId: randomUUID(), requestId: randomUUID(), principal,
      body: { displayName: "Empleado Emulator", authMethod: "sms", phoneE164: "+5215512345678" }
    });
    const [authUser, profile, grants] = await Promise.all([
      getAuth(app).getUser(result.uid),
      db.collection("users").doc(result.uid).get(),
      db.collection("accessGrants").where("userId", "==", result.uid).get()
    ]);
    expect(authUser.uid).toBe(profile.id);
    expect(authUser.disabled).toBe(true);
    expect(authUser.customClaims?.super_admin).not.toBe(true);
    expect(profile.data()).toMatchObject({ version: 2, authMethod: "sms", activationStatus: "pending" });
    expect(grants.empty).toBe(true);
  });

  it("allows exactly one concurrent operation to claim an email", async () => {
    const email = `concurrent-${randomUUID()}@example.test`;
    const results = await Promise.allSettled([
      service.preprovision({ operationId: randomUUID(), requestId: randomUUID(), principal, body: { displayName: "A", authMethod: "email", email } }),
      service.preprovision({ operationId: randomUUID(), requestId: randomUUID(), principal, body: { displayName: "B", authMethod: "email", email: email.toUpperCase() } })
    ]);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((result) => result.status === "rejected").map((result) => result.reason?.code)).toEqual(["IDENTIFIER_COLLISION"]);
  });
});
