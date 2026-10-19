import { initializeApp } from "https://www.gstatic.com/firebasejs/12.4.0/firebase-app.js";
import {
  browserSessionPersistence,
  getAuth,
  onAuthStateChanged,
  setPersistence,
  signInWithEmailAndPassword,
  signOut
} from "https://www.gstatic.com/firebasejs/12.4.0/firebase-auth.js";
import { firebaseConfig } from "/assets/firebase-client-config.js";

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
const authorizedEmail = document.querySelector("#authorized-email");
const signOutButton = document.querySelector("#sign-out-button");

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

function showGenericError() {
  errorMessage.textContent = "No fue posible autorizar el acceso. Verifica tus datos o contacta al administrador del sistema.";
  errorMessage.hidden = false;
}

async function hasSuperAdminClaim(user) {
  const tokenResult = await user.getIdTokenResult(true);
  return tokenResult.claims.super_admin === true;
}

async function authorizeOrSignOut(user) {
  if (!user) {
    authorizedEmail.textContent = "";
    showOnly(loginView);
    return;
  }

  try {
    if (!(await hasSuperAdminClaim(user))) {
      await signOut(auth);
      showOnly(loginView);
      showGenericError();
      return;
    }

    authorizedEmail.textContent = user.email ?? "Cuenta autorizada";
    showOnly(authorizedView);
  } catch {
    await signOut(auth).catch(() => {});
    showOnly(loginView);
    showGenericError();
  }
}

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  errorMessage.hidden = true;
  setFormPending(true);

  try {
    await setPersistence(auth, browserSessionPersistence);
    const credential = await signInWithEmailAndPassword(
      auth,
      emailInput.value.trim(),
      passwordInput.value
    );

    if (!(await hasSuperAdminClaim(credential.user))) {
      await signOut(auth);
      showGenericError();
    }
  } catch {
    await signOut(auth).catch(() => {});
    showGenericError();
  } finally {
    passwordInput.value = "";
    setFormPending(false);
  }
});

signOutButton.addEventListener("click", async () => {
  signOutButton.disabled = true;
  try {
    await signOut(auth);
  } finally {
    signOutButton.disabled = false;
  }
});

onAuthStateChanged(auth, authorizeOrSignOut);
