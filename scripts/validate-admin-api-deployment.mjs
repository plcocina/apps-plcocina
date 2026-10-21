import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

export const EXPECTED = Object.freeze({
  projectId: "plcocina-apps",
  region: "us-central1",
  functionName: "adminApi",
  runService: "adminapi",
  runtimeServiceAccount:
    "portal-admin-api@plcocina-apps.iam.gserviceaccount.com",
  artifactRepository: "gcf-artifacts",
  cleanupPolicy: "firebase-functions-cleanup",
  cleanupOlderThan: "604800s"
});

function requireObject(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} no contiene un objeto JSON válido`);
  }
  return value;
}

function expectedResourceName(kind, name) {
  return `projects/${EXPECTED.projectId}/locations/${EXPECTED.region}/${kind}/${name}`;
}

export function validateFunctionState(value) {
  const fn = requireObject(value, "La descripción de Cloud Functions");
  const expectedName = expectedResourceName("functions", EXPECTED.functionName);

  if (fn.name !== expectedName) throw new Error(`No se encontró ${expectedName}`);
  if (fn.environment !== "GEN_2") throw new Error("adminApi no es una función Gen 2");
  if (fn.state !== "ACTIVE") throw new Error(`adminApi no está ACTIVE: ${fn.state ?? "sin estado"}`);
  if (fn.serviceConfig?.serviceAccountEmail !== EXPECTED.runtimeServiceAccount) {
    throw new Error("La identidad runtime efectiva de adminApi no es la aprobada");
  }

  const uri = fn.serviceConfig?.uri;
  let parsedUri;
  try {
    parsedUri = new URL(uri);
  } catch {
    throw new Error("adminApi no expone una URI HTTPS válida");
  }
  if (parsedUri.protocol !== "https:") {
    throw new Error("La URI efectiva de adminApi no usa HTTPS");
  }

  return { uri: parsedUri.origin };
}

export function validateRunServiceState(value) {
  const service = requireObject(value, "La descripción de Cloud Run");
  const expectedName = expectedResourceName("services", EXPECTED.runService);

  if (service.name !== expectedName) throw new Error(`No se encontró ${expectedName}`);
  if (service.invokerIamDisabled !== true) {
    throw new Error("Cloud Run no confirma invokerIamDisabled=true");
  }
  if (service.reconciling === true) {
    throw new Error("El servicio Cloud Run todavía se está reconciliando");
  }
  if (service.terminalCondition?.state !== "CONDITION_SUCCEEDED") {
    throw new Error("El servicio Cloud Run no está listo");
  }
}

export function validateArtifactRepository(value) {
  const repository = requireObject(value, "La descripción de Artifact Registry");
  const expectedName = expectedResourceName(
    "repositories",
    EXPECTED.artifactRepository
  );

  if (repository.name !== expectedName) throw new Error(`No se encontró ${expectedName}`);
  if (repository.cleanupPolicyDryRun === true) {
    throw new Error("La política de limpieza está configurada sólo como simulación");
  }

  const policy = repository.cleanupPolicies?.[EXPECTED.cleanupPolicy];
  if (!policy || policy.action !== "DELETE") {
    throw new Error("No existe la política DELETE firebase-functions-cleanup");
  }
  if (policy.condition?.olderThan !== EXPECTED.cleanupOlderThan) {
    throw new Error("firebase-functions-cleanup no conserva exactamente siete días");
  }
}

export async function validateAnonymousHealth(uri, fetchImpl = globalThis.fetch) {
  const base = new URL(uri);
  if (base.protocol !== "https:") throw new Error("El health check debe usar HTTPS");
  const healthUrl = new URL("/api/admin/health", base);
  const response = await fetchImpl(healthUrl, {
    method: "GET",
    headers: { Accept: "application/json" },
    redirect: "error",
    signal: AbortSignal.timeout(15_000)
  });

  if (response.status === 403) {
    throw new Error("Cloud Run bloqueó la solicitud antes de llegar a adminApi (HTTP 403)");
  }
  if (response.status !== 401) {
    throw new Error(`adminApi devolvió HTTP ${response.status}; se esperaba 401`);
  }
  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.toLowerCase().includes("application/json")) {
    throw new Error("El 401 de adminApi no contiene JSON");
  }

  let body;
  try {
    body = await response.json();
  } catch {
    throw new Error("El 401 de adminApi contiene JSON inválido");
  }
  if (body?.ok !== false || body?.error?.code !== "AUTH_REQUIRED") {
    throw new Error("El 401 no coincide con el contrato AUTH_REQUIRED de adminApi");
  }
}

async function readJson(path, label) {
  let text;
  try {
    text = await readFile(path, "utf8");
  } catch {
    throw new Error(`No se pudo leer ${label}`);
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`${label} no contiene JSON válido`);
  }
}

async function main() {
  const [mode, functionPath, runPath, artifactPath] = process.argv.slice(2);
  if (!mode || !functionPath) {
    throw new Error("Uso: cloud-state <function.json> <run.json> <artifact.json> | anonymous-health <function.json>");
  }

  const fn = await readJson(functionPath, "la descripción de Cloud Functions");
  const { uri } = validateFunctionState(fn);

  if (mode === "cloud-state") {
    if (!runPath || !artifactPath) throw new Error("Faltan archivos para validar el estado cloud");
    validateRunServiceState(await readJson(runPath, "la descripción de Cloud Run"));
    validateArtifactRepository(
      await readJson(artifactPath, "la descripción de Artifact Registry")
    );
    console.log("Estado efectivo de adminApi y sus artefactos verificado.");
    return;
  }
  if (mode === "anonymous-health") {
    await validateAnonymousHealth(uri);
    console.log("Health check anónimo rechazado correctamente por adminApi.");
    return;
  }
  throw new Error(`Modo desconocido: ${mode}`);
}

const invokedDirectly = process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedDirectly) {
  await main();
}
