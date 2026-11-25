import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { firebaseConfig, firebaseConfigForLocation, isLocalPilot } from "../public/assets/firebase-client-config.js";
import { adminApiBaseForLocation } from "../public/assets/admin-api-client.js";

const local = { origin: "https://localhost:8443" };

test("local pilot selects the demo Auth project and emulator API path", () => {
  assert.equal(isLocalPilot(local), true);
  assert.equal(firebaseConfigForLocation(local).projectId, "demo-plcocina-apps");
  assert.equal(adminApiBaseForLocation(local), "");
});

test("all other origins retain production Firebase and API configuration", () => {
  for (const location of [
    { origin: "https://apps.plcocina.com" },
    { origin: "http://localhost:8443" },
    { origin: "https://localhost:5002" }
  ]) {
    assert.equal(isLocalPilot(location), false);
    assert.equal(firebaseConfigForLocation(location), firebaseConfig);
    assert.equal(adminApiBaseForLocation(location), "https://adminapi-nnra4xim6q-uc.a.run.app");
  }
});

test("the API rewrite exists only in emulator Hosting configuration", async () => {
  const [emulatorConfig, productionConfig] = await Promise.all([
    readFile(new URL("../firebase.emulators.json", import.meta.url), "utf8").then(JSON.parse),
    readFile(new URL("../firebase.json", import.meta.url), "utf8").then(JSON.parse)
  ]);
  assert.deepEqual(emulatorConfig.hosting.rewrites, [
    { source: "/api/**", function: { functionId: "adminApi", region: "us-central1" } }
  ]);
  assert.equal(productionConfig.hosting.rewrites, undefined);
});
