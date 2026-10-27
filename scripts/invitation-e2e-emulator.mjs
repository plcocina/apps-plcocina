import { createHash, createHmac, randomUUID } from "node:crypto";
import { initializeApp } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import { getFirestore } from "firebase-admin/firestore";

if (process.env.FIREBASE_AUTH_EMULATOR_HOST !== "127.0.0.1:9099" || process.env.FIRESTORE_EMULATOR_HOST !== "127.0.0.1:8080") {
  throw new Error("Este script sólo puede ejecutarse contra los emuladores locales aprobados.");
}

const projectId = "demo-plcocina-apps";
const app = initializeApp({ projectId }, `e2e-${randomUUID()}`);
const auth = getAuth(app);
const db = getFirestore(app);
const functionBase = "http://127.0.0.1:5001/demo-plcocina-apps/us-central1/adminApi";
const origin = "http://127.0.0.1:5002";
const command = process.argv[2];
const revealLinks = process.env.E2E_REVEAL_LINKS === "true";

async function authToken() {
  const uid = "e2e-super-admin";
  const email = "e2e-super-admin@plcocina.test";
  const password = "E2E-admin-password-2026!";
  await auth.getUser(uid).catch(async (error) => {
    if (error.code !== "auth/user-not-found") throw error;
    await auth.createUser({ uid, email, password, emailVerified: true });
  });
  await auth.setCustomUserClaims(uid, { super_admin: true });
  const response = await fetch(`http://127.0.0.1:9099/identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=fake`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ email, password, returnSecureToken: true })
  });
  if (!response.ok) throw new Error("No fue posible autenticar el administrador simulado.");
  return (await response.json()).idToken;
}

function reconstruct(invitation) {
  const token = createHmac("sha256", Buffer.alloc(32, 0x5a))
    .update(`invite\0${invitation.invitationId}\0${invitation.token.generation}\0${invitation.token.salt}`, "utf8")
    .digest("base64url");
  const actual = createHash("sha256").update(token).digest("hex");
  if (actual !== invitation.token.hash) throw new Error("El token simulado no coincide con el hash persistido.");
  return token;
}

async function adminRequest(idToken, path, body, idempotencyKey) {
  const response = await fetch(`${functionBase}${path}`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${idToken}`,
      "content-type": "application/json",
      "idempotency-key": idempotencyKey,
      origin
    },
    body: JSON.stringify(body)
  });
  const payload = await response.json();
  if (!response.ok || payload.ok !== true) {
    throw new Error(`Operación administrativa simulada fallida: ${payload?.error?.code ?? response.status}`);
  }
  return payload.data;
}

async function createInvitation(idToken, label) {
  const invitationId = randomUUID();
  const email = `e2e-${label}-${invitationId.slice(0, 8)}@example.test`;
  await adminRequest(idToken, "/api/admin/invitations", {
    displayName: `Usuario E2E ${label}`,
    email,
    expiresInHours: 72
  }, invitationId);
  const invitation = (await db.collection("invitations").doc(invitationId).get()).data();
  if (!invitation || invitation.delivery?.provider !== "simulated" || invitation.delivery?.status !== "accepted") {
    throw new Error("El proveedor simulado no aceptó la invitación.");
  }
  return { invitationId, invitation, token: reconstruct(invitation) };
}

function link(invitationId, token) {
  return `${origin}/accept-invitation/#invitationId=${encodeURIComponent(invitationId)}&token=${encodeURIComponent(token)}`;
}

if (command === "seed") {
  const idToken = await authToken();
  const { invitationId, invitation, token } = await createInvitation(idToken, "invited");
  process.stdout.write(JSON.stringify({
    invitationId,
    uid: invitation.uid,
    email: invitation.email,
    ...(revealLinks ? { link: link(invitationId, token) } : { linkPrepared: true })
  }));
} else if (command === "scenarios") {
  const idToken = await authToken();

  const revoked = await createInvitation(idToken, "revoked");
  await adminRequest(idToken, `/api/admin/invitations/${revoked.invitationId}/revoke`, {
    expectedRevision: revoked.invitation.revision,
    reason: "Prueba integral en emuladores"
  }, randomUUID());

  const resent = await createInvitation(idToken, "resent");
  const oldToken = resent.token;
  const resendResult = await adminRequest(idToken, `/api/admin/invitations/${resent.invitationId}/resend`, {
    expectedRevision: resent.invitation.revision,
    expiresInHours: 72
  }, randomUUID());
  const resentDocument = (await db.collection("invitations").doc(resent.invitationId).get()).data();
  const newToken = reconstruct(resentDocument);

  const expired = await createInvitation(idToken, "expired");
  const past = new Date(Date.now() - 60_000);
  await db.collection("invitations").doc(expired.invitationId).update({
    expiresAt: past,
    "token.expiresAt": past
  });

  const validate = async (invitationId, token) => {
    const response = await fetch(`${functionBase}/api/invitations/validate`, {
      method: "POST",
      headers: { "content-type": "application/json", origin },
      body: JSON.stringify({ invitationId, token })
    });
    const payload = await response.json();
    return { status: response.status, code: payload?.error?.code ?? null, ok: payload?.ok === true };
  };
  const checks = {
    revoked: await validate(revoked.invitationId, revoked.token),
    resentOld: await validate(resent.invitationId, oldToken),
    resentNew: await validate(resent.invitationId, newToken),
    expired: await validate(expired.invitationId, expired.token)
  };
  if (checks.revoked.ok || checks.resentOld.ok || checks.expired.ok || !checks.resentNew.ok || resendResult.status !== "active") {
    throw new Error(`Los escenarios de ciclo de vida no produjeron el resultado esperado: ${JSON.stringify(checks)}`);
  }
  process.stdout.write(JSON.stringify({
    checks,
    ...(revealLinks ? { links: {
      revoked: link(revoked.invitationId, revoked.token),
      resentOld: link(resent.invitationId, oldToken),
      resentNew: link(resent.invitationId, newToken),
      expired: link(expired.invitationId, expired.token)
    } } : { linksPrepared: true })
  }));
} else if (command === "inspect") {
  const invitationId = process.argv[3];
  if (!/^[0-9a-f-]{36}$/i.test(invitationId ?? "")) throw new Error("Invitation ID inválido.");
  const invitation = (await db.collection("invitations").doc(invitationId).get()).data();
  if (!invitation) throw new Error("Invitación no encontrada.");
  const profile = (await db.collection("users").doc(invitation.uid).get()).data();
  const user = await auth.getUser(invitation.uid);
  const grants = await db.collection("accessGrants").where("uid", "==", invitation.uid).get();
  const [operations, audits] = await Promise.all([
    db.collection("adminOperations").where("invitationId", "==", invitationId).get(),
    db.collection("auditEvents").where("resourceId", "==", invitationId).get()
  ]);
  const persisted = JSON.stringify([invitation, profile, ...operations.docs.map((doc) => doc.data()), ...audits.docs.map((doc) => doc.data())]);
  const forbidden = [process.env.E2E_TOKEN, process.env.E2E_PASSWORD].filter(Boolean);
  process.stdout.write(JSON.stringify({
    invitationStatus: invitation.status,
    profileStatus: profile?.status,
    tokenCleared: invitation.token === null,
    authDisabled: user.disabled,
    superAdmin: user.customClaims?.super_admin === true,
    accessGrants: grants.size,
    forbiddenPersisted: forbidden.some((value) => persisted.includes(value)),
    operations: operations.size,
    audits: audits.size
  }));
} else {
  throw new Error("Use seed, scenarios o inspect.");
}
