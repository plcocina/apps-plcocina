import { readFile, stat } from "node:fs/promises";

const requiredFiles = [
  "public/index.html",
  "public/logo_PL-Cocina-icono.png",
  "public/admin/index.html",
  "public/assets/admin.css",
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
const clientConfig = await readFile("public/assets/firebase-client-config.js", "utf8");
const bootstrap = await readFile("scripts/bootstrap-super-admin.mjs", "utf8");
const bootstrapDocs = await readFile("docs/super-admin-bootstrap.md", "utf8");

if (/createUserWithEmailAndPassword|signUp/i.test(adminHtml + adminJs)) {
  throw new Error("El frontend no debe incluir registro de usuarios");
}
if (!adminJs.includes("claims.super_admin === true")) {
  throw new Error("Falta la comprobación booleana estricta de super_admin");
}
if (!adminJs.includes("browserSessionPersistence")) {
  throw new Error("La sesión administrativa debe usar persistencia de sesión");
}
if (!clientConfig.includes('projectId: "plcocina-apps"')) {
  throw new Error("La configuración cliente debe apuntar a plcocina-apps");
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
