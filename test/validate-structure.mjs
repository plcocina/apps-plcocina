import { readFile, stat } from "node:fs/promises";

const requiredFiles = [
  "public/index.html",
  "public/logo_PL-Cocina-icono.png",
  "public/admin/index.html",
  "public/assets/admin.css",
  "public/assets/admin-auth.js",
  "public/assets/firebase-client-config.js",
  "scripts/bootstrap-super-admin.mjs",
  "docs/super-admin-bootstrap.md"
];

for (const path of requiredFiles) {
  const details = await stat(path);
  if (!details.isFile()) throw new Error(`${path} no es un archivo`);
}

const firebase = JSON.parse(await readFile("firebase.json", "utf8"));
if (firebase.hosting?.target !== "portal") throw new Error("Hosting debe usar target portal");
if (firebase.hosting?.public !== "public") throw new Error("Hosting sólo debe publicar public/");

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
