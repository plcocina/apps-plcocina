import { createRequire } from "node:module";
import { dirname, join } from "node:path";

const requireFromFunctions = createRequire(new URL("../functions/package.json", import.meta.url));
const functionsEntry = requireFromFunctions.resolve("firebase-functions");
const { extractStack } = requireFromFunctions(join(dirname(functionsEntry), "../runtime/loader.js"));

export const ALLOWED_RUNTIME_SECRET = "IDENTIFIER_PEPPER_BASE64";

export function discoverFunctionEndpoints(moduleExports) {
  const endpoints = {};
  extractStack(moduleExports, endpoints, [], {});
  return endpoints;
}

export function assertOnlyAdminApiFunction(moduleExports) {
  const endpoints = discoverFunctionEndpoints(moduleExports);
  const names = Object.keys(endpoints);
  if (names.length !== 1 || names[0] !== "adminApi") {
    throw new Error("La salida compilada debe exportar únicamente la Function adminApi");
  }
  return endpoints.adminApi;
}

export function assertAllowedRuntimeSecrets(secrets) {
  const runtimeSecrets = (secrets ?? []).map((secret) => secret.key);
  if (runtimeSecrets.length !== 1 || runtimeSecrets[0] !== ALLOWED_RUNTIME_SECRET) {
    throw new Error("adminApi debe declarar exclusivamente IDENTIFIER_PEPPER_BASE64 como secreto runtime");
  }
}

export function assertAllowedSecretParameters(parameters) {
  const secretParameters = parameters
    .filter((parameter) => parameter.type === "secret")
    .map((parameter) => parameter.name);
  if (secretParameters.length !== 1 || secretParameters[0] !== ALLOWED_RUNTIME_SECRET) {
    throw new Error("Sólo IDENTIFIER_PEPPER_BASE64 puede declararse como parámetro secreto");
  }
}
