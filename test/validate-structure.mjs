import { readFile, stat } from "node:fs/promises";

const requiredFiles = [
  "public/index.html",
  "public/logo_PL-Cocina-icono.png",
  "public/admin/index.html",
  "public/assets/admin.css",
  "public/assets/admin-api-client.js",
  "public/assets/admin-auth.js",
  "public/assets/firebase-client-config.js",
  "scripts/bootstrap-super-admin.mjs",
  "docs/super-admin-bootstrap.md",
  "functions/package.json",
  "functions/package-lock.json",
  "functions/src/index.ts",
  "functions/src/app.ts",
  "firestore.rules",
  "firestore.indexes.json",
  "docs/backend-iam.md",
  "docs/backend-development.md",
  ".github/workflows/firebase-functions-deploy.yml"
];

for (const path of requiredFiles) {
  const details = await stat(path);
  if (!details.isFile()) throw new Error(`${path} no es un archivo`);
}

const firebase = JSON.parse(await readFile("firebase.json", "utf8"));
if (firebase.hosting?.target !== "portal") throw new Error("Hosting debe usar target portal");
if (firebase.hosting?.public !== "public") throw new Error("Hosting sólo debe publicar public/");
if (firebase.hosting?.rewrites) throw new Error("No se deben publicar rewrites antes de desplegar el backend");
if (firebase.functions?.source !== "functions") throw new Error("Functions debe usar functions/");
if (firebase.functions?.codebase !== "admin-api") throw new Error("Functions debe usar el codebase admin-api");
if (firebase.functions?.runtime !== "nodejs22") throw new Error("Functions debe usar Node.js 22");

const workflow = await readFile(".github/workflows/firebase-deploy.yml", "utf8");
if (!workflow.includes("firebase deploy --only hosting:portal --project plcocina-apps")) {
  throw new Error("El workflow debe conservar el despliegue exclusivo hosting:portal");
}

const functionsWorkflow = await readFile(
  ".github/workflows/firebase-functions-deploy.yml",
  "utf8"
);
const functionIndex = await readFile("functions/src/index.ts", "utf8");
const functionConfig = await readFile("functions/src/config.ts", "utf8");
if (!functionsWorkflow.includes("workflow_dispatch:")) {
  throw new Error("El workflow de Functions debe ser exclusivamente manual");
}
if (/\n\s*push:/.test(functionsWorkflow)) {
  throw new Error("Un push no debe desplegar Functions automáticamente");
}
if (!functionsWorkflow.includes("inputs.confirmation == 'DEPLOY'")) {
  throw new Error("Falta la confirmación explícita del despliegue de Functions");
}
if (!functionsWorkflow.includes("firebase deploy --only functions:admin-api")) {
  throw new Error("El workflow debe desplegar exclusivamente el codebase admin-api");
}
if (!functionsWorkflow.includes("FUNCTIONS_DEPLOY_SERVICE_ACCOUNT")) {
  throw new Error("Falta una identidad dedicada para desplegar Functions");
}
if (!functionsWorkflow.includes("google-github-actions/setup-gcloud@v3")) {
  throw new Error("El workflow debe configurar gcloud después de WIF");
}
if (!functionsWorkflow.includes('test -f "$GOOGLE_APPLICATION_CREDENTIALS"')) {
  throw new Error("El workflow debe comprobar el archivo temporal de ADC");
}
if (!functionsWorkflow.includes("gcloud auth application-default print-access-token >/dev/null")) {
  throw new Error("El workflow debe validar ADC sin imprimir el access token");
}
const unitTestsPosition = functionsWorkflow.indexOf("npm run functions:test");
const emulatorTestsPosition = functionsWorkflow.indexOf("npm run functions:test:emulator");
const authPosition = functionsWorkflow.indexOf("google-github-actions/auth@v3");
const setupGcloudPosition = functionsWorkflow.indexOf("google-github-actions/setup-gcloud@v3");
const adcCheckPosition = functionsWorkflow.indexOf(
  "gcloud auth application-default print-access-token >/dev/null"
);
const deployPosition = functionsWorkflow.indexOf(
  "firebase deploy --only functions:admin-api"
);
const firebaseAdcCheckPosition = functionsWorkflow.indexOf(
  'firebase functions:list --project "$PROJECT_ID" --json >/dev/null'
);
if (
  unitTestsPosition < 0 ||
  emulatorTestsPosition < unitTestsPosition ||
  authPosition < emulatorTestsPosition ||
  setupGcloudPosition < authPosition ||
  adcCheckPosition < setupGcloudPosition ||
  firebaseAdcCheckPosition < adcCheckPosition ||
  deployPosition < firebaseAdcCheckPosition
) {
  throw new Error(
    "El orden debe ser pruebas, WIF, setup-gcloud, ADC, preflight de Firebase y despliegue"
  );
}
if (!functionsWorkflow.includes('!= "$HOSTING_DEPLOY_SERVICE_ACCOUNT"')) {
  throw new Error("El workflow debe rechazar la identidad de despliegue de Hosting");
}
if (!functionsWorkflow.includes('!= "$RUNTIME_SERVICE_ACCOUNT"')) {
  throw new Error("El workflow debe separar las identidades de despliegue y runtime");
}
if (!functionIndex.includes("serviceAccount: RUNTIME_SERVICE_ACCOUNT")) {
  throw new Error("adminApi debe declarar explícitamente su identidad de runtime");
}
if (
  !functionConfig.includes(
    '"portal-admin-api@plcocina-apps.iam.gserviceaccount.com"'
  )
) {
  throw new Error("La identidad de runtime de adminApi no es la aprobada");
}

const firestoreRules = await readFile("firestore.rules", "utf8");
for (const collection of [
  "users",
  "applications",
  "accessGrants",
  "invitations",
  "auditEvents"
]) {
  if (!firestoreRules.includes(`match /${collection}/{document=**}`)) {
    throw new Error(`Falta la regla de denegación para ${collection}`);
  }
}

const publicIndex = await readFile("public/index.html", "utf8");
if (!publicIndex.includes("family=Inter")) throw new Error("La portada debe conservar Inter");
if (!publicIndex.includes("https://calculadora-burritos.plcocina.com/")) {
  throw new Error("La portada perdió el enlace a Calculadora de Burritos");
}
if (!publicIndex.includes("https://reportes-mensuales-2026.plcocina.com/")) {
  throw new Error("La portada perdió el enlace a Reportes Mensuales 2026");
}
if (!publicIndex.includes('href="/admin"')) {
  throw new Error("La portada perdió el acceso a /admin");
}

const adminHtml = await readFile("public/admin/index.html", "utf8");
const adminJs = await readFile("public/assets/admin-auth.js", "utf8");
const adminApiClient = await readFile("public/assets/admin-api-client.js", "utf8");
const clientConfig = await readFile("public/assets/firebase-client-config.js", "utf8");
const bootstrap = await readFile("scripts/bootstrap-super-admin.mjs", "utf8");
const bootstrapDocs = await readFile("docs/super-admin-bootstrap.md", "utf8");

if (/createUserWithEmailAndPassword|signUp/i.test(adminHtml + adminJs)) {
  throw new Error("El frontend no debe incluir registro de usuarios");
}
if (!adminApiClient.includes("user.getIdToken()")) {
  throw new Error("El portal debe obtener el Firebase ID token de la sesión actual");
}
if (!adminApiClient.includes("Authorization: `Bearer ${idToken}`")) {
  throw new Error("El ID token debe enviarse exclusivamente como Bearer token");
}
if (!adminApiClient.includes("payload?.data?.superAdmin !== true")) {
  throw new Error("El backend debe confirmar el rol Super Admin");
}
if (!adminApiClient.includes('payload.data.uid !== expectedUid')) {
  throw new Error("El backend debe confirmar el UID exacto de la sesión");
}
if (!adminJs.includes("authorizationRevision")) {
  throw new Error("El portal debe invalidar respuestas de autorización anteriores");
}
if (/console\.(log|info|debug|warn|error)/.test(adminJs + adminApiClient)) {
  throw new Error("El frontend administrativo no debe registrar datos de autenticación");
}
if (!adminJs.includes("browserSessionPersistence")) {
  throw new Error("La sesión administrativa debe usar persistencia de sesión");
}
if (!clientConfig.includes('projectId: "plcocina-apps"')) {
  throw new Error("La configuración cliente debe apuntar a plcocina-apps");
}
const csp = firebase.hosting.headers
  ?.flatMap((entry) => entry.headers ?? [])
  .find((header) => header.key === "Content-Security-Policy")?.value;
if (!csp?.includes("https://adminapi-nnra4xim6q-uc.a.run.app")) {
  throw new Error("La CSP debe permitir exclusivamente el origen HTTPS de adminApi");
}
if (!bootstrap.includes("getUserByEmail(EXPECTED_EMAIL)")) {
  throw new Error("El bootstrap debe contrastar el correo fijo mediante getUserByEmail");
}
if (/providerData|passwordHash|passwordSalt/.test(bootstrap)) {
  throw new Error("El bootstrap no debe inferir el acceso por providerData ni leer hashes");
}
for (const permission of [
  "firebaseauth.users.get",
  "firebaseauth.users.list",
  "firebaseauth.users.update"
]) {
  if (!bootstrapDocs.includes(permission)) {
    throw new Error(`Falta documentar el permiso mínimo ${permission}`);
  }
}
if (!bootstrapDocs.includes("read -r -p 'UID validado: ' EXPECTED_SUPER_ADMIN_UID")) {
  throw new Error("Los ejemplos del bootstrap deben ser compatibles con Bash");
}

console.log("Estructura y controles estáticos verificados.");
