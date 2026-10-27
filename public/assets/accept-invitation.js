import { firebaseConfig } from "./firebase-client-config.js";
import {
  InvitationApiError,
  confirmInvitation,
  establishInvitationPassword,
  validateInvitation
} from "./accept-invitation-api.js";

const INVITATION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const TOKEN = /^[A-Za-z0-9_-]{43}$/;

export function credentialsAreWellFormed(credentials) {
  return INVITATION_ID.test(credentials?.invitationId ?? "") && TOKEN.test(credentials?.token ?? "");
}

export function passwordValidation(password, confirmation) {
  if (password.length < 12 || password.length > 128) return "La contraseña debe tener entre 12 y 128 caracteres.";
  if (password !== confirmation) return "Las contraseñas no coinciden.";
  return null;
}

function icon(documentRef, kind) {
  const svg = documentRef.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("aria-hidden", "true");
  const path = documentRef.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("d", kind === "success" ? "m5 12 4 4L19 6" : "M12 9v4m0 4h.01M10.3 3.9 2.1 18a2 2 0 0 0 1.7 3h16.4a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z");
  svg.append(path);
  return svg;
}

function errorMessage(error) {
  if (error instanceof InvitationApiError) {
    if (error.code === "RECONCILIATION_REQUIRED") return "La activación quedó pendiente de conciliación segura. Solicita un nuevo enlace al administrador.";
    if (error.code === "RATE_LIMITED") return "Se alcanzó el límite de intentos. Espera unos minutos antes de volver a intentarlo.";
    if (error.code === "INVITATION_INVALID") return "La invitación es inválida, venció o fue revocada. Solicita un nuevo enlace al administrador.";
    if (error.code === "NETWORK_ERROR" || error.status >= 500) return "El servicio no está disponible temporalmente. Intenta nuevamente.";
  }
  return "No fue posible completar la activación. Intenta nuevamente.";
}

export async function startAcceptance(initialCredentials, dependencies = {}) {
  const documentRef = dependencies.documentRef ?? document;
  const api = dependencies.api ?? { validateInvitation, establishInvitationPassword, confirmInvitation };
  let invitationId = initialCredentials?.invitationId ?? "";
  let token = initialCredentials?.token ?? "";
  let passwordEstablished = false;
  let busy = false;
  let authContext = null;

  const loadingView = documentRef.getElementById("loading-view");
  const passwordView = documentRef.getElementById("password-view");
  const resultView = documentRef.getElementById("result-view");
  const status = documentRef.getElementById("acceptance-status");
  const form = documentRef.getElementById("password-form");
  const emailInput = documentRef.getElementById("invited-email");
  const passwordInput = documentRef.getElementById("new-password");
  const confirmationInput = documentRef.getElementById("confirm-password");
  const continueButton = documentRef.getElementById("continue-button");
  const formGuidance = documentRef.getElementById("form-guidance");
  const formError = documentRef.getElementById("form-error");
  const resultMark = documentRef.getElementById("result-mark");
  const resultTitle = documentRef.getElementById("result-title");
  const resultMessage = documentRef.getElementById("result-message");
  const retryButton = documentRef.getElementById("retry-button");
  const portalLink = documentRef.getElementById("portal-link");
  const steps = ["step-verify", "step-password", "step-confirm"].map((id) => documentRef.getElementById(id));

  function showOnly(view) {
    for (const candidate of [loadingView, passwordView, resultView]) candidate.hidden = candidate !== view;
  }

  function setStep(index) {
    steps.forEach((step, position) => {
      step.classList.toggle("complete", position < index);
      step.classList.toggle("current", position === index);
      if (position === index) step.setAttribute("aria-current", "step");
      else step.removeAttribute("aria-current");
    });
  }

  function showResult(kind, title, message, retry = false) {
    resultMark.className = `status-mark ${kind}`;
    resultMark.replaceChildren(icon(documentRef, kind));
    resultTitle.textContent = title;
    resultMessage.textContent = message;
    retryButton.hidden = !retry;
    portalLink.hidden = kind !== "success";
    showOnly(resultView);
  }

  function setPending(pending) {
    busy = pending;
    for (const input of [emailInput, passwordInput, confirmationInput]) input.disabled = pending;
    continueButton.disabled = pending;
    continueButton.textContent = pending ? "Protegiendo tu cuenta…" : (passwordEstablished ? "Confirmar cuenta" : "Establecer contraseña y confirmar");
  }

  async function loadFirebaseAuth() {
    if (dependencies.authAdapter) return dependencies.authAdapter;
    if (authContext) return authContext;
    const [{ initializeApp }, authModule] = await Promise.all([
      import("https://www.gstatic.com/firebasejs/12.4.0/firebase-app.js"),
      import("https://www.gstatic.com/firebasejs/12.4.0/firebase-auth.js")
    ]);
    if (firebaseConfig.projectId !== "plcocina-apps") throw new Error("INVALID_FIREBASE_PROJECT");
    const localEmulator = globalThis.location && (globalThis.location.hostname === "127.0.0.1" || globalThis.location.hostname === "localhost");
    const runtimeConfig = localEmulator
      ? { ...firebaseConfig, projectId: "demo-plcocina-apps", authDomain: "demo-plcocina-apps.firebaseapp.com" }
      : firebaseConfig;
    const app = initializeApp(runtimeConfig, `invitation-${Date.now()}`);
    const auth = authModule.initializeAuth(app, { persistence: authModule.inMemoryPersistence });
    if (localEmulator) authModule.connectAuthEmulator(auth, "http://127.0.0.1:9099", { disableWarnings: true });
    authContext = {
      signIn: (email, password) => authModule.signInWithEmailAndPassword(auth, email, password),
      signOut: () => authModule.signOut(auth)
    };
    return authContext;
  }

  async function verify() {
    setStep(0);
    showOnly(loadingView);
    status.textContent = "Comprobando que el enlace siga vigente…";
    retryButton.hidden = true;
    if (!credentialsAreWellFormed({ invitationId, token })) {
      token = "";
      showResult("failure", "Invitación no disponible", "La invitación es inválida, venció o fue revocada. Solicita un nuevo enlace al administrador.");
      return;
    }
    try {
      await api.validateInvitation(invitationId, token);
      setStep(1);
      showOnly(passwordView);
      emailInput.focus();
    } catch (error) {
      const retry = error instanceof InvitationApiError && (error.code === "NETWORK_ERROR" || error.status >= 500);
      if (!retry) token = "";
      showResult("failure", retry ? "Servicio temporalmente no disponible" : "Invitación no disponible", errorMessage(error), retry);
    }
  }

  retryButton.addEventListener("click", () => { if (!busy && token) void verify(); });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (busy) return;
    formError.hidden = true;
    emailInput.setAttribute("aria-invalid", "false");
    passwordInput.setAttribute("aria-invalid", "false");
    confirmationInput.setAttribute("aria-invalid", "false");
    const email = emailInput.value.trim().toLowerCase();
    const password = passwordInput.value;
    const confirmation = confirmationInput.value;
    if (!emailInput.validity.valid) {
      emailInput.setAttribute("aria-invalid", "true");
      formError.textContent = "Escribe el correo que recibió la invitación.";
      formError.hidden = false;
      emailInput.focus();
      return;
    }
    const passwordError = passwordValidation(password, confirmation);
    if (passwordError) {
      passwordInput.setAttribute("aria-invalid", "true");
      confirmationInput.setAttribute("aria-invalid", "true");
      formError.textContent = passwordError;
      formError.hidden = false;
      passwordInput.focus();
      return;
    }

    setPending(true);
    let activeAuthentication = null;
    try {
      if (!passwordEstablished) {
        await api.establishInvitationPassword(invitationId, token, password);
        passwordEstablished = true;
        token = "";
        setStep(2);
      }
      const authentication = await loadFirebaseAuth();
      activeAuthentication = authentication;
      await authentication.signOut().catch(() => {});
      const credential = await authentication.signIn(email, password);
      if (credential.user.email?.toLowerCase() !== email) throw new Error("IDENTITY_MISMATCH");
      await api.confirmInvitation(invitationId, credential.user);
      await authentication.signOut().catch(() => {});
      invitationId = "";
      emailInput.value = "";
      showResult("success", "Cuenta confirmada", "Tu cuenta quedó activa. Ya puedes volver al portal de APPS PL COCINA.");
    } catch (error) {
      await activeAuthentication?.signOut().catch(() => {});
      if (!passwordEstablished) {
        const uncertain = error instanceof InvitationApiError && (error.code === "NETWORK_ERROR" || error.code === "RECONCILIATION_REQUIRED" || error.status >= 500);
        if (uncertain) {
          token = "";
          showResult("failure", "Activación pendiente", error.code === "RECONCILIATION_REQUIRED" ? errorMessage(error) : "No pudimos confirmar el resultado de forma segura. Solicita un nuevo enlace al administrador.");
          return;
        }
        if (error instanceof InvitationApiError && error.code === "INVITATION_INVALID") {
          token = "";
          showResult("failure", "Invitación no disponible", errorMessage(error));
          return;
        }
      }
      formGuidance.textContent = "La contraseña ya quedó protegida. Verifica el correo y vuelve a escribir la misma contraseña para confirmar tu identidad.";
      continueButton.textContent = "Confirmar cuenta";
      formError.textContent = errorMessage(error);
      formError.hidden = false;
      showOnly(passwordView);
    } finally {
      passwordInput.value = "";
      confirmationInput.value = "";
      setPending(false);
    }
  });

  await verify();
}
