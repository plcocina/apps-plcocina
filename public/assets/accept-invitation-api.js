import { ADMIN_API_BASE } from "./admin-api-client.js";

export function invitationApiBase(locationRef = globalThis.location) {
  if (locationRef && (locationRef.hostname === "127.0.0.1" || locationRef.hostname === "localhost")) {
    return "http://127.0.0.1:5001/demo-plcocina-apps/us-central1/adminApi";
  }
  return ADMIN_API_BASE;
}

export class InvitationApiError extends Error {
  constructor(code, message, status = null) {
    super(message);
    this.name = "InvitationApiError";
    this.code = code;
    this.status = status;
  }
}

async function request(path, options = {}) {
  let response;
  try {
    response = await (options.fetchImpl ?? globalThis.fetch)(`${options.baseUrl ?? invitationApiBase()}${path}`, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        ...(options.idToken ? { Authorization: `Bearer ${options.idToken}` } : {})
      },
      body: JSON.stringify(options.body ?? {}),
      cache: "no-store",
      credentials: "omit",
      referrerPolicy: "no-referrer",
      signal: options.signal
    });
  } catch (error) {
    if (error?.name === "AbortError") throw error;
    throw new InvitationApiError("NETWORK_ERROR", "No fue posible contactar al servicio de invitaciones.");
  }

  let payload = null;
  try { payload = await response.json(); } catch { /* respuesta inválida */ }
  if (!response.ok || payload?.ok !== true) {
    throw new InvitationApiError(
      payload?.error?.code ?? "SERVICE_UNAVAILABLE",
      payload?.error?.message ?? "No fue posible completar la solicitud.",
      response.status
    );
  }
  return payload.data;
}

function validDate(value) {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

export async function validateInvitation(invitationId, token, options = {}) {
  const data = await request("/api/invitations/validate", {
    ...options,
    body: { invitationId, token }
  });
  if (data?.valid !== true || !validDate(data.expiresAt)) throw new InvitationApiError("INVALID_RESPONSE", "El servidor devolvió una respuesta no válida.");
  return data;
}

function validOpaqueValue(value) {
  return typeof value === "string" && /^[A-Za-z0-9_-]{43}$/.test(value);
}

function validChallengeId(value) {
  return typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

export async function startInvitationGoogleProof(invitationId, token, options = {}) {
  const data = await request("/api/invitations/google-bootstrap/proof/start", {
    ...options,
    body: { invitationId, token }
  });
  if (!validChallengeId(data?.challengeId) || !validOpaqueValue(data?.nonce) || !validDate(data?.expiresAt)) {
    throw new InvitationApiError("INVALID_RESPONSE", "El servidor devolvió una respuesta no válida.");
  }
  return data;
}

export async function verifyInvitationGoogleProof(invitationId, token, challengeId, nonce, googleIdToken, options = {}) {
  const data = await request("/api/invitations/google-bootstrap/proof/verify", {
    ...options,
    body: { invitationId, token, challengeId, nonce, googleIdToken }
  });
  if (data?.state !== "verified" || !validDate(data?.verifiedAt)) {
    throw new InvitationApiError("INVALID_RESPONSE", "El servidor devolvió una respuesta no válida.");
  }
  return data;
}

export async function recoverInvitationGoogleChallenge(invitationId, token, options = {}) {
  const data = await request("/api/invitations/google-bootstrap/challenge/recover", {
    ...options,
    body: { invitationId, token }
  });
  if (!validChallengeId(data?.challengeId) || !validOpaqueValue(data?.nonce)
    || !validOpaqueValue(data?.state) || !validDate(data?.expiresAt)) {
    throw new InvitationApiError("INVALID_RESPONSE", "El servidor devolvió una respuesta no válida.");
  }
  return data;
}

export async function verifyInvitationGoogleChallenge(invitationId, token, challengeId, state, googleIdToken, options = {}) {
  const data = await request("/api/invitations/google-bootstrap/challenge/verify", {
    ...options,
    body: { invitationId, token, challengeId, state, googleIdToken }
  });
  if (data?.state !== "google_proof_verified") {
    throw new InvitationApiError("INVALID_RESPONSE", "El servidor devolvió una respuesta no válida.");
  }
  return data;
}

export async function establishInvitationPassword(invitationId, token, password, options = {}) {
  const data = await request("/api/invitations/establish-password", {
    ...options,
    body: { invitationId, token, password }
  });
  if (data?.status !== "password_set" || !validDate(data.confirmationExpiresAt)) throw new InvitationApiError("INVALID_RESPONSE", "El servidor devolvió una respuesta no válida.");
  return data;
}

export async function confirmInvitation(invitationId, user, options = {}) {
  const idToken = await user.getIdToken();
  const data = await request(`/api/invitations/${encodeURIComponent(invitationId)}/confirm`, {
    ...options,
    idToken,
    body: {}
  });
  if (data?.status !== "accepted" || !validDate(data.acceptedAt)) throw new InvitationApiError("INVALID_RESPONSE", "El servidor devolvió una respuesta no válida.");
  return data;
}
