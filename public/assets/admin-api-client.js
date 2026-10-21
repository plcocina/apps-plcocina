export const ADMIN_ME_URL =
  "https://adminapi-nnra4xim6q-uc.a.run.app/api/admin/me";
export const ADMIN_API_BASE = "https://adminapi-nnra4xim6q-uc.a.run.app";

export class AdminApiError extends Error {
  constructor(code, message, status = null) {
    super(message);
    this.name = "AdminApiError";
    this.code = code;
    this.status = status;
  }
}

function validatedPrincipal(payload, expectedUid) {
  if (
    payload?.ok !== true ||
    payload?.data?.superAdmin !== true ||
    typeof payload.data.uid !== "string" ||
    payload.data.uid !== expectedUid
  ) {
    throw new AdminApiError(
      "INVALID_RESPONSE",
      "El servidor no confirmó la autorización administrativa."
    );
  }

  return payload.data;
}

export async function verifySuperAdminSession(user, options = {}) {
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  const idToken = await user.getIdToken();
  let response;

  try {
    response = await fetchImpl(ADMIN_ME_URL, {
      method: "GET",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${idToken}`
      },
      cache: "no-store",
      credentials: "omit",
      referrerPolicy: "no-referrer",
      signal: options.signal
    });
  } catch (error) {
    if (error?.name === "AbortError") throw error;
    throw new AdminApiError(
      "NETWORK_ERROR",
      "No fue posible contactar al servicio administrativo."
    );
  }

  if (response.status === 401) {
    throw new AdminApiError(
      "AUTH_REQUIRED",
      "La sesión expiró o fue revocada. Inicia sesión nuevamente.",
      401
    );
  }
  if (response.status === 403) {
    throw new AdminApiError(
      "ADMIN_REQUIRED",
      "La cuenta no tiene autorización de Super Admin.",
      403
    );
  }
  if (response.status !== 200) {
    throw new AdminApiError(
      "SERVICE_UNAVAILABLE",
      "El servicio administrativo no está disponible temporalmente.",
      response.status
    );
  }

  let payload;
  try {
    payload = await response.json();
  } catch {
    throw new AdminApiError(
      "INVALID_RESPONSE",
      "El servidor devolvió una respuesta no válida."
    );
  }

  return validatedPrincipal(payload, user.uid);
}

export async function adminApiRequest(user, path, options = {}) {
  const token = await user.getIdToken();
  let response;
  try {
    response = await (options.fetchImpl ?? globalThis.fetch)(`${ADMIN_API_BASE}${path}`, {
      method: options.method ?? "GET",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${token}`,
        ...(options.body === undefined ? {} : { "Content-Type": "application/json" })
      },
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      cache: "no-store",
      credentials: "omit",
      referrerPolicy: "no-referrer",
      signal: options.signal
    });
  } catch (error) {
    if (error?.name === "AbortError") throw error;
    throw new AdminApiError("NETWORK_ERROR", "No fue posible contactar al servicio administrativo.");
  }
  let payload = null;
  try { payload = await response.json(); } catch { /* contrato inválido */ }
  if (!response.ok || payload?.ok !== true) {
    throw new AdminApiError(payload?.error?.code ?? "SERVICE_UNAVAILABLE", payload?.error?.message ?? "No fue posible completar la solicitud.", response.status);
  }
  return payload.data;
}
