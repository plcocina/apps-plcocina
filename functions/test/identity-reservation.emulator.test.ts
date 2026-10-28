import { randomUUID } from "node:crypto";
import { deleteApp, initializeApp } from "firebase-admin/app";
import { getFirestore, type Firestore } from "firebase-admin/firestore";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
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
});
