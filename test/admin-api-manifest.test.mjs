import assert from "node:assert/strict";
import test from "node:test";
import {
  assertAllowedRuntimeSecrets,
  assertAllowedSecretParameters,
  assertOnlyAdminApiFunction
} from "../scripts/admin-api-manifest-contract.mjs";

function deployedFunction(name) {
  const fn = () => undefined;
  fn.__endpoint = { platform: "gcfv2", entryPoint: name };
  return fn;
}

test("accepts the adminApi manifest and ignores ordinary JavaScript helpers", () => {
  const endpoint = assertOnlyAdminApiFunction({ adminApi: deployedFunction("adminApi"), helper: () => "helper" });
  assert.equal(endpoint.platform, "gcfv2");
});

test("rejects an additional Firebase Function export", () => {
  assert.throws(() => assertOnlyAdminApiFunction({
    adminApi: deployedFunction("adminApi"),
    extraApi: deployedFunction("extraApi")
  }), /únicamente la Function adminApi/);
});

test("accepts only IDENTIFIER_PEPPER_BASE64 as a runtime secret", () => {
  assert.doesNotThrow(() => assertAllowedRuntimeSecrets([{ key: "IDENTIFIER_PEPPER_BASE64" }]));
  assert.throws(() => assertAllowedRuntimeSecrets([
    { key: "IDENTIFIER_PEPPER_BASE64" }, { key: "UNEXPECTED_SECRET" }
  ]), /exclusivamente IDENTIFIER_PEPPER_BASE64/);
  assert.doesNotThrow(() => assertAllowedSecretParameters([
    { name: "IDENTIFIER_PEPPER_BASE64", type: "secret" }, { name: "GOOGLE_AUTH_AUDIENCES", type: "list" }
  ]));
  assert.throws(() => assertAllowedSecretParameters([
    { name: "IDENTIFIER_PEPPER_BASE64", type: "secret" }, { name: "UNEXPECTED_SECRET", type: "secret" }
  ]), /Sólo IDENTIFIER_PEPPER_BASE64/);
});
