import { initializeApp } from "https://www.gstatic.com/firebasejs/12.4.0/firebase-app.js";
import {
  browserSessionPersistence,
  getAuth,
  onAuthStateChanged,
  setPersistence,
  signInWithEmailAndPassword,
  signOut
} from "https://www.gstatic.com/firebasejs/12.4.0/firebase-auth.js";
import {
  AdminApiError,
  verifySuperAdminSession
} from "/assets/admin-api-client.js";
import { firebaseConfig } from "/assets/firebase-client-config.js";
import { initializeApplications } from "/assets/admin-applications.js";
import { initializeUsers } from "/assets/admin-users.js";
import { initializeInvitations } from "/assets/admin-invitations.js";

const EXPECTED_PROJECT_ID = "plcocina-apps";

if (firebaseConfig.projectId !== EXPECTED_PROJECT_ID) {
  throw new Error("Configuración de Firebase no válida para este portal.");
}

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);

const loadingView = document.querySelector("#loading-view");
const loginView = document.querySelector("#login-view");
const authorizedView = document.querySelector("#authorized-view");
const loginForm = document.querySelector("#login-form");
const emailInput = document.querySelector("#email");
const passwordInput = document.querySelector("#password");
const submitButton = document.querySelector("#submit-button");
const errorMessage = document.querySelector("#auth-error");
const loginPage = document.querySelector(".page");
const dashboard = document.querySelector("#admin-dashboard");
const dashboardEmail = document.querySelector("#dashboard-email");
const dashboardSignOut = document.querySelector("#dashboard-sign-out");
const loadingContent = loadingView.firstElementChild;

let authorizationRevision = 0;
let activeVerification = null;
let signOutMessage = null;

function showOnly(view) {
  for (const element of [loadingView, loginView, authorizedView]) {
    element.hidden = element !== view;
  }
}

function setFormPending(isPending) {
  emailInput.disabled = isPending;
  passwordInput.disabled = isPending;
  submitButton.disabled = isPending;
  submitButton.textContent = isPending ? "Verificando…" : "Iniciar sesión";
}

function showError(message) {
  errorMessage.textContent = message;
  errorMessage.hidden = false;
}

function resetLoadingView() {
  loadingContent.replaceChildren();
  const spinner = document.createElement("div");
  spinner.className = "spinner";
  spinner.setAttribute("aria-hidden", "true");
  loadingContent.append(spinner, "Verificando sesión segura…");
}

function showRetry(message) {
  loadingContent.replaceChildren();
  const error = document.createElement("p");
  error.className = "error";
  error.setAttribute("role", "alert");
  error.textContent = message;
  const retryButton = document.createElement("button");
  retryButton.className = "secondary-button";
  retryButton.type = "button";
  retryButton.textContent = "Reintentar verificación";
  retryButton.addEventListener("click", () => {
    const user = auth.currentUser;
    if (user) void authorizeUser(user);
  }, { once: true });
  loadingContent.append(error, retryButton);
  showOnly(loadingView);
}

function invalidateVerification() {
  authorizationRevision += 1;
  activeVerification?.abort();
  activeVerification = null;
}

async function authorizeUser(user) {
  invalidateVerification();
  const revision = authorizationRevision;
  const controller = new AbortController();
  activeVerification = controller;
  resetLoadingView();
  showOnly(loadingView);

  try {
    const principal = await verifySuperAdminSession(user, {
      signal: controller.signal
    });
    if (
      revision !== authorizationRevision ||
      auth.currentUser?.uid !== user.uid
    ) {
      return;
    }

    dashboardEmail.textContent = principal.email ?? user.email ?? "Cuenta autorizada";
    loginPage.hidden = true;
    dashboard.hidden = false;
    initializeApplications(user);
    initializeUsers(user, {
      onSessionExpired: async (message) => {
        signOutMessage = message;
        invalidateVerification();
        await signOut(auth).catch(() => {});
      }
    });
    initializeInvitations(user, {
      onSessionExpired: async (message) => {
        signOutMessage = message;
        invalidateVerification();
        await signOut(auth).catch(() => {});
      }
    });
  } catch (error) {
    if (
      revision !== authorizationRevision ||
      auth.currentUser?.uid !== user.uid ||
      error?.name === "AbortError"
    ) {
      return;
    }

    if (error instanceof AdminApiError && (error.status === 401 || error.status === 403)) {
      signOutMessage = error.message;
      invalidateVerification();
      await signOut(auth).catch(() => {});
      return;
    }

    const message = error instanceof AdminApiError
      ? error.message
      : "No fue posible verificar el acceso. Intenta nuevamente.";
    showRetry(message);
  } finally {
    if (revision === authorizationRevision) activeVerification = null;
  }
}

function authorizeOrSignOut(user) {
  if (!user) {
    invalidateVerification();
    dashboard.hidden = true;
    loginPage.hidden = false;
    errorMessage.hidden = true;
    showOnly(loginView);
    if (signOutMessage) {
      showError(signOutMessage);
      signOutMessage = null;
    }
    return;
  }

  void authorizeUser(user);
}

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  errorMessage.hidden = true;
  setFormPending(true);

  try {
    await setPersistence(auth, browserSessionPersistence);
    await signInWithEmailAndPassword(
      auth,
      emailInput.value.trim(),
      passwordInput.value
    );
  } catch {
    await signOut(auth).catch(() => {});
    showError("No fue posible iniciar sesión. Verifica tus datos e intenta nuevamente.");
  } finally {
    passwordInput.value = "";
    setFormPending(false);
  }
});

dashboardSignOut.addEventListener("click", async () => {
  dashboardSignOut.disabled = true;
  invalidateVerification();
  try { await signOut(auth); } finally { dashboardSignOut.disabled = false; }
});

onAuthStateChanged(auth, authorizeOrSignOut);
