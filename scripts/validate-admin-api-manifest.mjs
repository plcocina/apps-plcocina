const EXPECTED_REGION = "us-central1";
const EXPECTED_RUNTIME_SERVICE_ACCOUNT =
  "portal-admin-api@plcocina-apps.iam.gserviceaccount.com";

const { adminApi } = await import("../functions/lib/index.js");
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

console.log("Manifiesto generado de adminApi verificado.");
