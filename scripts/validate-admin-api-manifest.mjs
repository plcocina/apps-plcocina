import { createRequire } from "node:module";

const EXPECTED_REGION = "us-central1";
const EXPECTED_RUNTIME_SERVICE_ACCOUNT =
  "portal-admin-api@plcocina-apps.iam.gserviceaccount.com";
const FORBIDDEN_PARAMETERS = new Set([
  "RESEND_INVITATIONS_ENABLED",
  "RESEND_API_KEY",
  "RESEND_WEBHOOK_SIGNING_SECRET",
  "INVITATION_TOKEN_KEY_V1"
]);

const { adminApi } = await import("../functions/lib/index.js");
const requireFromFunctions = createRequire(
  new URL("../functions/package.json", import.meta.url)
);
const { declaredParams } = requireFromFunctions("firebase-functions/params");
const endpoint = adminApi?.__endpoint;

if (!endpoint || endpoint.platform !== "gcfv2") {
  throw new Error("adminApi debe generar un manifiesto de Cloud Functions 2nd gen");
}
if (
  !Array.isArray(endpoint.region) ||
  endpoint.region.length !== 1 ||
  endpoint.region[0] !== EXPECTED_REGION
) {
  throw new Error(`adminApi debe desplegarse exclusivamente en ${EXPECTED_REGION}`);
}
if (endpoint.serviceAccountEmail !== EXPECTED_RUNTIME_SERVICE_ACCOUNT) {
  throw new Error("La identidad runtime generada para adminApi no es la aprobada");
}
if (!endpoint.httpsTrigger || Object.hasOwn(endpoint.httpsTrigger, "invoker")) {
  throw new Error("El manifiesto de adminApi no debe declarar httpsTrigger.invoker");
}
if (
  Array.isArray(endpoint.secretEnvironmentVariables)
  && endpoint.secretEnvironmentVariables.length > 0
) {
  throw new Error("El perfil productivo deshabilitado no debe declarar secretos");
}

const parameterSpecs = declaredParams.map((parameter) => parameter.toSpec());
const secretParameters = parameterSpecs.filter((parameter) => parameter.type === "secret");
if (secretParameters.length > 0) {
  throw new Error("El perfil productivo deshabilitado no debe declarar parámetros secretos");
}
const forbiddenParameter = parameterSpecs.find((parameter) =>
  FORBIDDEN_PARAMETERS.has(parameter.name)
);
if (forbiddenParameter) {
  throw new Error(`El parámetro ${forbiddenParameter.name} no puede habilitar el perfil productivo`);
}

console.log("Manifiesto generado de adminApi verificado.");
