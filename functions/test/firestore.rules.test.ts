import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import {
  assertFails,
  initializeTestEnvironment,
  type RulesTestEnvironment
} from "@firebase/rules-unit-testing";
import { doc, getDoc, setDoc } from "firebase/firestore";
import { afterAll, beforeAll, describe, it } from "vitest";

const PROJECT_ID = "demo-plcocina-apps";
const COLLECTIONS = [
  "users",
  "applications",
  "applicationUniqueKeys",
  "accessGrants",
  "invitations",
  "invitationUniqueKeys",
  "auditEvents",
  "adminOperations",
  "invitationRateLimits",
  "webhookReplayEvents"
];

let environment: RulesTestEnvironment;

function firestoreHost(): { host: string; port: number } {
  const configured = process.env.FIRESTORE_EMULATOR_HOST;
  if (!configured) throw new Error("FIRESTORE_EMULATOR_HOST no está definido");
  const separator = configured.lastIndexOf(":");
  return {
    host: configured.slice(0, separator),
    port: Number(configured.slice(separator + 1))
  };
}

beforeAll(async () => {
  const rulesPath = fileURLToPath(new URL("../../firestore.rules", import.meta.url));
  environment = await initializeTestEnvironment({
    projectId: PROJECT_ID,
    firestore: {
      ...firestoreHost(),
      rules: await readFile(rulesPath, "utf8")
    }
  });
});

afterAll(async () => {
  await environment.cleanup();
});

describe("administrative Firestore collections", () => {
  for (const collection of COLLECTIONS) {
    it(`denies direct client reads and writes to ${collection}`, async () => {
      await environment.withSecurityRulesDisabled(async (context) => {
        await setDoc(doc(context.firestore(), collection, "record"), { seeded: true });
      });

      for (const context of [
        environment.unauthenticatedContext(),
        environment.authenticatedContext("user-uid"),
        environment.authenticatedContext("admin-uid", { super_admin: true })
      ]) {
        const reference = doc(context.firestore(), collection, "record");
        await assertFails(getDoc(reference));
        await assertFails(setDoc(reference, { changed: true }));
      }
    });
  }
});
