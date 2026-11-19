import { firebaseConfig } from "./firebase-client-config.js";
import {
  InvitationApiError,
  confirmInvitation,
  establishInvitationPassword,
  recoverInvitationGoogleChallenge,
  startInvitationGoogleProof,
  validateInvitation,
  verifyInvitationGoogleChallenge,
  verifyInvitationGoogleProof
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

function loadGoogleIdentitySdk(documentRef) {
  const identity = () => globalThis.google?.accounts?.id;
  if (identity()) return Promise.resolve(identity());
  return new Promise((resolve, reject) => {
    let script = documentRef.getElementById("google-identity-services-sdk");
    if (!script) {
      script = documentRef.createElement("script");
      script.id = "google-identity-services-sdk";
      script.src = "https://accounts.google.com/gsi/client";
      script.async = true;
      script.defer = true;
      documentRef.head.append(script);
    }
    script.addEventListener("load", () => {
      if (identity()) resolve(identity());
      else { script.remove(); reject(new Error("GOOGLE_SDK_UNAVAILABLE")); }
    }, { once: true });
    script.addEventListener("error", () => { script.remove(); reject(new Error("GOOGLE_SDK_UNAVAILABLE")); }, { once: true });
  });
}

export async function startAcceptance(initialCredentials, dependencies = {}) {
  const documentRef = dependencies.documentRef ?? document;
  const api = dependencies.api ?? {
    validateInvitation,
    establishInvitationPassword,
    confirmInvitation,
    startInvitationGoogleProof,
    verifyInvitationGoogleProof,
    recoverInvitationGoogleChallenge,
    verifyInvitationGoogleChallenge
  };
  const googleClientId = dependencies.googleClientId ?? firebaseConfig.googleIdentityClientId ?? "";
  let invitationId = initialCredentials?.invitationId ?? "";
  let token = initialCredentials?.token ?? "";
  let passwordEstablished = false;
  let busy = false;
  let authContext = null;
  let googleBusy = false;
  let googleEpoch = 0;
  let googlePhase = "initial";
  let googleChallenge = null;

  const loadingView = documentRef.getElementById("loading-view");
  const passwordView = documentRef.getElementById("password-view");
  const resultView = documentRef.getElementById("result-view");
  const googleView = documentRef.getElementById("google-view");
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
  const passwordStepLabel = documentRef.getElementById("step-password-label");
  const confirmStepLabel = documentRef.getElementById("step-confirm-label");
  const googleTitle = documentRef.getElementById("google-title");
  const googleStatus = documentRef.getElementById("google-status");
  const googleButtonSlot = documentRef.getElementById("google-button-slot");
  const googleStartButton = documentRef.getElementById("google-start-button");
  const googleRecoverButton = documentRef.getElementById("google-recover-button");
  const googleRetryButton = documentRef.getElementById("google-retry-button");

  function showOnly(view) {
    for (const candidate of [loadingView, passwordView, googleView, resultView]) candidate.hidden = candidate !== view;
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

  function showGoogleView(title, message) {
    googleTitle.textContent = title;
    googleStatus.textContent = message;
    showOnly(googleView);
  }

  async function googleIdentitySdk() {
    if (dependencies.googleIdentity) return dependencies.googleIdentity.accounts?.id ?? dependencies.googleIdentity;
    return (dependencies.loadGoogleIdentitySdk ?? loadGoogleIdentitySdk)(documentRef);
  }

  function clearGoogleChallenge() {
    googleEpoch += 1;
    googleChallenge = null;
    googleButtonSlot.replaceChildren();
  }

  async function renderGoogleButton(challenge, phase) {
    const clientId = typeof googleClientId === "string" ? googleClientId.trim() : "";
    if (!clientId) throw new Error("GOOGLE_CLIENT_ID_MISSING");
    const googleIdentity = await googleIdentitySdk();
    if (!googleIdentity?.initialize || !googleIdentity?.renderButton) throw new Error("GOOGLE_SDK_UNAVAILABLE");
    const epoch = ++googleEpoch;
    googleChallenge = { ...challenge, phase, epoch };
    googlePhase = phase;
    googleButtonSlot.replaceChildren();
    googleIdentity.initialize({
      client_id: clientId,
      nonce: challenge.nonce,
      callback: (credentialResponse) => {
        const current = googleChallenge;
        if (googleBusy || !current || current.epoch !== epoch || current.phase !== phase) return;
        const credential = credentialResponse?.credential;
        if (typeof credential !== "string" || !credential) {
          googleStatus.textContent = "Google no devolvió una credencial válida. Intenta nuevamente.";
          return;
        }
        void submitGoogleCredential(epoch, phase, credential);
      }
    });
    googleIdentity.renderButton(googleButtonSlot, {
      theme: "outline", size: "large", type: "standard", text: "continue_with", shape: "rectangular", width: 280
    });
  }

  async function beginGoogleProof() {
    if (googleBusy || googlePhase !== "initial") return;
    googleBusy = true;
    googleStartButton.hidden = true;
    googleRecoverButton.hidden = true;
    googleRetryButton.hidden = true;
    googleRetryButton.disabled = true;
    showGoogleView("Verifica tu identidad con Google", "Preparando la primera verificación…");
    setStep(0);
    clearGoogleChallenge();
    try {
      const clientId = typeof googleClientId === "string" ? googleClientId.trim() : "";
      if (!clientId) throw new Error("GOOGLE_CLIENT_ID_MISSING");
      await googleIdentitySdk();
      const challenge = await api.startInvitationGoogleProof(invitationId, token);
      if (!googleBusy) return;
      await renderGoogleButton(challenge, "initial");
      googleStatus.textContent = "Usa el botón oficial de Google para verificar tu identidad.";
    } catch (error) {
      clearGoogleChallenge();
      googleStatus.textContent = error?.message === "GOOGLE_CLIENT_ID_MISSING"
        ? "La verificación de Google no está configurada en este portal. Contacta al administrador para continuar."
        : "No pudimos cargar Google o iniciar la verificación. Comprueba tu conexión e intenta nuevamente.";
      googleRetryButton.hidden = error?.message === "GOOGLE_CLIENT_ID_MISSING";
      googleRecoverButton.hidden = error?.message === "GOOGLE_CLIENT_ID_MISSING";
      googleStartButton.hidden = true;
    } finally {
      googleBusy = false;
      googleRetryButton.disabled = false;
    }
  }

  async function recoverGoogleChallenge() {
    if (googleBusy || !["initial", "review"].includes(googlePhase)) return;
    const phaseBeforeRecovery = googlePhase;
    googleBusy = true;
    googleRecoverButton.disabled = true;
    googleRetryButton.hidden = true;
    googleStatus.textContent = "Consultando la revisión del administrador…";
    try {
      const clientId = typeof googleClientId === "string" ? googleClientId.trim() : "";
      if (!clientId) throw new Error("GOOGLE_CLIENT_ID_MISSING");
      await googleIdentitySdk();
      const challenge = await api.recoverInvitationGoogleChallenge(invitationId, token);
      if (!googleBusy || phaseBeforeRecovery !== googlePhase) return;
      clearGoogleChallenge();
      await renderGoogleButton(challenge, "challenge");
      setStep(2);
      googleTitle.textContent = "Completa la verificación de Google";
      googleStatus.textContent = "La segunda verificación está lista. Usa el botón oficial de Google para continuar.";
      googleStartButton.hidden = true;
      googleRecoverButton.hidden = true;
    } catch (error) {
      googlePhase = phaseBeforeRecovery;
      if (error?.message === "GOOGLE_CLIENT_ID_MISSING") {
        googleStatus.textContent = "La verificación de Google no está configurada en este portal. Contacta al administrador para continuar.";
        googleStartButton.hidden = true;
        googleRecoverButton.hidden = true;
      } else if (error?.message === "GOOGLE_SDK_UNAVAILABLE") {
        googleStatus.textContent = "No pudimos cargar Google. Comprueba tu conexión e intenta nuevamente.";
        googleStartButton.hidden = false;
        googleRecoverButton.hidden = false;
      } else {
        googleStatus.textContent = "No pudimos consultar el estado todavía. Puedes volver a consultar en unos momentos.";
        googleStartButton.hidden = phaseBeforeRecovery !== "initial";
        googleRecoverButton.hidden = false;
      }
    } finally {
      googleBusy = false;
      googleRecoverButton.disabled = false;
    }
  }

  async function submitGoogleCredential(epoch, phase, googleIdToken) {
    const challenge = googleChallenge;
    if (googleBusy || !challenge || challenge.epoch !== epoch || challenge.phase !== phase) return;
    googleBusy = true;
    googleStatus.textContent = "Verificando tu identidad de forma segura…";
    googleRecoverButton.disabled = true;
    try {
      if (phase === "initial") {
        await api.verifyInvitationGoogleProof(invitationId, token, challenge.challengeId, challenge.nonce, googleIdToken);
        if (googleChallenge?.epoch !== epoch) return;
        clearGoogleChallenge();
        googlePhase = "review";
        setStep(1);
        googleTitle.textContent = "Verificación inicial completada";
        googleStatus.textContent = "Verificación inicial completada. Falta la revisión del administrador.";
        googleStartButton.hidden = true;
        googleRecoverButton.textContent = "Volver a consultar";
        googleRecoverButton.hidden = false;
      } else {
        const result = await api.verifyInvitationGoogleChallenge(invitationId, token, challenge.challengeId, challenge.state, googleIdToken);
        if (googleChallenge?.epoch !== epoch || result?.state !== "google_proof_verified") return;
        clearGoogleChallenge();
        googlePhase = "complete";
        googleBusy = false;
        token = "";
        invitationId = "";
        setStep(3);
        googleTitle.textContent = "Identidad verificada";
        googleStatus.textContent = "Identidad verificada. Tu cuenta está pendiente de activación.";
        googleRecoverButton.hidden = true;
      }
    } catch {
      if (googleChallenge?.epoch !== epoch) return;
      if (phase === "initial") {
        clearGoogleChallenge();
        googlePhase = "initial";
        googleStatus.textContent = "No pudimos completar la primera verificación. Puedes intentarlo nuevamente.";
        googleRetryButton.hidden = false;
        googleRecoverButton.hidden = false;
        googleStartButton.hidden = true;
      } else {
        clearGoogleChallenge();
        googlePhase = "review";
        googleStatus.textContent = "No pudimos completar la segunda verificación. Vuelve a consultar para continuar.";
        googleRecoverButton.hidden = false;
      }
    } finally {
      googleBusy = false;
      googleRecoverButton.disabled = false;
    }
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
      const invitation = await api.validateInvitation(invitationId, token);
      if (invitation.verificationMethod === "googleWorkspace") {
        passwordStepLabel.textContent = "Revisión";
        confirmStepLabel.textContent = "Google";
        googlePhase = "initial";
        showGoogleView("Verifica tu identidad con Google", "Inicia la primera verificación o vuelve a consultar si ya completaste ese paso.");
        setStep(0);
        const clientId = typeof googleClientId === "string" ? googleClientId.trim() : "";
        if (!clientId) {
          googleStatus.textContent = "La verificación de Google no está configurada en este portal. Contacta al administrador para continuar.";
          googleStartButton.hidden = true;
          googleRecoverButton.hidden = true;
        } else {
          googleStartButton.hidden = false;
          googleRecoverButton.hidden = false;
        }
        return;
      }
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
  googleStartButton.addEventListener("click", () => { void beginGoogleProof(); });
  googleRecoverButton.addEventListener("click", () => { void recoverGoogleChallenge(); });
  googleRetryButton.addEventListener("click", () => {
    if (!googleBusy && googlePhase === "initial") void beginGoogleProof();
  });

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
