const GENERIC_SIGN_IN_ERROR = "No fue posible iniciar sesión. Verifica tus datos e intenta nuevamente.";
const SAFE_AUTH_CODE = /^auth\/[a-z0-9-]+$/;

export function signInFailureMessage(error, localPilot = false) {
  if (!localPilot) return GENERIC_SIGN_IN_ERROR;

  const code = typeof error?.code === "string" && SAFE_AUTH_CODE.test(error.code)
    ? error.code
    : error?.name === "TypeError" ? "network-error" : "unknown-error";
  return `${GENERIC_SIGN_IN_ERROR} Código local: ${code}.`;
}
