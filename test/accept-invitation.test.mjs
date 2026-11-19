import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import vm from "node:vm";
import test from "node:test";
import {
  InvitationApiError,
  confirmInvitation,
  establishInvitationPassword,
  invitationApiBase,
  validateInvitation
} from "../public/assets/accept-invitation-api.js";
import { credentialsAreWellFormed, passwordValidation, startAcceptance } from "../public/assets/accept-invitation.js";
import {
  recoverInvitationGoogleChallenge,
  startInvitationGoogleProof,
  verifyInvitationGoogleChallenge,
  verifyInvitationGoogleProof
} from "../public/assets/accept-invitation-api.js";

const ID = "11111111-1111-4111-8111-111111111111";
const TOKEN = "A".repeat(43);

test("routes invitation requests only to local emulators while hosted locally", () => {
  assert.equal(invitationApiBase({ hostname: "127.0.0.1" }), "http://127.0.0.1:5001/demo-plcocina-apps/us-central1/adminApi");
  assert.equal(invitationApiBase({ hostname: "localhost" }), "http://127.0.0.1:5001/demo-plcocina-apps/us-central1/adminApi");
  assert.match(invitationApiBase({ hostname: "apps.plcocina.com" }), /^https:\/\//);
});

function response(status, body) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

const NONCE_1 = "A".repeat(43);
const NONCE_2 = "B".repeat(43);
const STATE_2 = "C".repeat(43);
const GOOGLE_TOKEN_1 = "google-id-token-first";
const GOOGLE_TOKEN_2 = "google-id-token-second";

class FakeElement {
  constructor(id = "") {
    this.id = id;
    this.hidden = false;
    this.disabled = false;
    this.value = "";
    this.textContent = "";
    this.listeners = new Map();
    this.attributes = new Map();
    this.classList = { toggle: () => {} };
    this.validity = { valid: true };
    this.children = [];
  }
  addEventListener(name, listener) { this.listeners.set(name, listener); }
  setAttribute(name, value) { this.attributes.set(name, value); }
  removeAttribute(name) { this.attributes.delete(name); }
  replaceChildren(...children) { this.children = children; }
  append(...children) { this.children.push(...children); }
  focus() {}
  click() { return this.listeners.get("click")?.({ preventDefault() {} }); }
}

function fakeDocument() {
  const ids = ["loading-view", "password-view", "result-view", "google-view", "acceptance-status", "password-form",
    "invited-email", "new-password", "confirm-password", "continue-button", "form-guidance", "form-error", "result-mark",
    "result-title", "result-message", "retry-button", "portal-link", "step-verify", "step-password", "step-confirm",
    "google-title", "google-status", "google-button-slot", "google-start-button", "google-recover-button", "google-retry-button",
    "step-password-label", "step-confirm-label"];
  const elements = new Map(ids.map((id) => [id, new FakeElement(id)]));
  for (const id of ["password-view", "result-view", "google-view", "retry-button", "portal-link", "google-retry-button"]) {
    elements.get(id).hidden = true;
  }
  return {
    getElementById: (id) => elements.get(id) ?? null,
    createElement: () => new FakeElement(),
    head: new FakeElement("head"),
    elements
  };
}

async function flushAsync() {
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
}

function googleIdentityDouble() {
  const initializations = [];
  const identity = {
    accounts: { id: {
      initialize: (options) => initializations.push(options),
      renderButton: (container, options) => { container.renderOptions = options; }
    } }
  };
  return { identity, initializations };
}

test("cleans the fragment synchronously before loading the application module", async () => {
  const source = await readFile(new URL("../public/assets/accept-bootstrap.js", import.meta.url), "utf8");
  let replaced = null;
  let readyHandler = null;
  const context = {
    URLSearchParams,
    document: {
      createElement: () => ({}),
      head: { append: () => {} }
    },
    window: {
      location: { hash: `#invitationId=${ID}&token=${TOKEN}`, pathname: "/accept-invitation", search: "" },
      history: { replaceState: (_state, _title, value) => { replaced = value; } },
      addEventListener: (_name, handler) => { readyHandler = handler; }
    }
  };
  vm.runInNewContext(source, context);
  assert.equal(replaced, "/accept-invitation");
  assert.equal(typeof readyHandler, "function");
  assert.ok(source.indexOf("replaceState") < source.indexOf("import("));
});

test("loads the blocking fragment scrubber before every stylesheet or remote resource", async () => {
  const [html, bootstrapSource] = await Promise.all([
    readFile(new URL("../public/accept-invitation/index.html", import.meta.url), "utf8"),
    readFile(new URL("../public/assets/accept-bootstrap.js", import.meta.url), "utf8")
  ]);
  const bootstrap = html.indexOf("/assets/accept-bootstrap.js");
  assert.ok(bootstrap > 0);
  assert.equal(html.includes("fonts.googleapis.com"), false);
  assert.equal(html.includes("accept-invitation.css"), false);
  assert.ok(bootstrapSource.indexOf("replaceState") < bootstrapSource.indexOf("fonts.googleapis.com"));
  assert.ok(bootstrapSource.indexOf("replaceState") < bootstrapSource.indexOf("accept-invitation.css"));
  assert.match(html, /name="referrer" content="no-referrer"/);
});

test("validates invitations without credentials or browser persistence", async () => {
  let captured;
  const result = await validateInvitation(ID, TOKEN, {
    fetchImpl: async (url, options) => {
      captured = { url, options };
      return response(200, { ok: true, data: { valid: true, expiresAt: "2026-12-01T00:00:00.000Z" } });
    }
  });
  assert.equal(result.valid, true);
  assert.match(captured.url, /\/api\/invitations\/validate$/);
  assert.equal(captured.options.credentials, "omit");
  assert.equal(captured.options.referrerPolicy, "no-referrer");
  assert.equal(captured.options.headers.Authorization, undefined);
});

test("sends the first Google proof to the invitation-scoped start and verify routes", async () => {
  const calls = [];
  const fetchImpl = async (url, options) => {
    calls.push({ url, body: JSON.parse(options.body), options });
    return response(200, { ok: true, data: calls.length === 1
      ? { challengeId: ID, nonce: NONCE_1, expiresAt: "2026-12-01T00:00:00.000Z" }
      : { state: "verified", verifiedAt: "2026-12-01T00:00:00.000Z" } });
  };
  await startInvitationGoogleProof(ID, TOKEN, { fetchImpl, baseUrl: "https://api.example" });
  await verifyInvitationGoogleProof(ID, TOKEN, ID, NONCE_1, GOOGLE_TOKEN_1, { fetchImpl, baseUrl: "https://api.example" });
  assert.match(calls[0].url, /\/api\/invitations\/google-bootstrap\/proof\/start$/);
  assert.deepEqual(calls[0].body, { invitationId: ID, token: TOKEN });
  assert.match(calls[1].url, /\/api\/invitations\/google-bootstrap\/proof\/verify$/);
  assert.deepEqual(calls[1].body, { invitationId: ID, token: TOKEN, challengeId: ID, nonce: NONCE_1, googleIdToken: GOOGLE_TOKEN_1 });
  assert.equal(calls[1].url.includes(TOKEN), false);
});

test("recovers a second Google Challenge and sends its challenge ID, state and new ID token", async () => {
  const calls = [];
  const fetchImpl = async (url, options) => {
    calls.push({ url, body: JSON.parse(options.body) });
    return response(200, { ok: true, data: calls.length === 1
      ? { challengeId: ID, nonce: NONCE_2, state: STATE_2, expiresAt: "2026-12-01T00:00:00.000Z" }
      : { state: "google_proof_verified" } });
  };
  await recoverInvitationGoogleChallenge(ID, TOKEN, { fetchImpl, baseUrl: "https://api.example" });
  await verifyInvitationGoogleChallenge(ID, TOKEN, ID, STATE_2, GOOGLE_TOKEN_2, { fetchImpl, baseUrl: "https://api.example" });
  assert.match(calls[0].url, /\/api\/invitations\/google-bootstrap\/challenge\/recover$/);
  assert.deepEqual(calls[0].body, { invitationId: ID, token: TOKEN });
  assert.match(calls[1].url, /\/api\/invitations\/google-bootstrap\/challenge\/verify$/);
  assert.deepEqual(calls[1].body, { invitationId: ID, token: TOKEN, challengeId: ID, state: STATE_2, googleIdToken: GOOGLE_TOKEN_2 });
});

test("sends the password once and never adds secrets to the URL", async () => {
  const password = "Contraseña-segura-2026!";
  let captured;
  await establishInvitationPassword(ID, TOKEN, password, {
    fetchImpl: async (url, options) => {
      captured = { url, options };
      return response(200, { ok: true, data: { status: "password_set", confirmationExpiresAt: "2026-12-01T00:10:00.000Z" } });
    }
  });
  assert.match(captured.url, /\/api\/invitations\/establish-password$/);
  assert.equal(captured.url.includes(TOKEN), false);
  assert.equal(captured.url.includes(password), false);
  assert.deepEqual(JSON.parse(captured.options.body), { invitationId: ID, token: TOKEN, password });
});

test("confirms with the Firebase ID token and a body without invitation secrets", async () => {
  let captured;
  const user = { getIdToken: async () => "firebase-id-token" };
  await confirmInvitation(ID, user, {
    fetchImpl: async (url, options) => {
      captured = { url, options };
      return response(200, { ok: true, data: { status: "accepted", acceptedAt: "2026-12-01T00:05:00.000Z" } });
    }
  });
  assert.match(captured.url, new RegExp(`/api/invitations/${ID}/confirm$`));
  assert.equal(captured.options.headers.Authorization, "Bearer firebase-id-token");
  assert.deepEqual(JSON.parse(captured.options.body), {});
});

test("runs both Google proofs with their own nonce and waits for administrator review", async () => {
  const documentRef = fakeDocument();
  const { identity, initializations } = googleIdentityDouble();
  const calls = [];
  const api = {
    validateInvitation: async () => ({ valid: true, expiresAt: "2026-12-01T00:00:00.000Z", verificationMethod: "googleWorkspace" }),
    startInvitationGoogleProof: async (...args) => { calls.push(["start", ...args]); return { challengeId: ID, nonce: NONCE_1 }; },
    verifyInvitationGoogleProof: async (...args) => { calls.push(["verify-first", ...args]); return { state: "verified" }; },
    recoverInvitationGoogleChallenge: async (...args) => { calls.push(["recover", ...args]); return { challengeId: "22222222-2222-4222-8222-222222222222", nonce: NONCE_2, state: STATE_2 }; },
    verifyInvitationGoogleChallenge: async (...args) => { calls.push(["verify-second", ...args]); return { state: "google_proof_verified" }; }
  };
  await startAcceptance({ invitationId: ID, token: TOKEN }, { documentRef, api, googleIdentity: identity, googleClientId: "portal.apps.googleusercontent.com" });
  assert.equal(documentRef.getElementById("google-view").hidden, false);
  assert.equal(documentRef.getElementById("password-view").hidden, true);
  await documentRef.getElementById("google-start-button").click();
  await flushAsync();
  assert.equal(initializations[0].nonce, NONCE_1);
  assert.deepEqual(calls[0], ["start", ID, TOKEN]);
  const firstCallback = initializations[0].callback;
  firstCallback({ credential: GOOGLE_TOKEN_1 });
  firstCallback({ credential: "duplicate-first-token" });
  await flushAsync();
  assert.equal(calls.filter(([name]) => name === "verify-first").length, 1);
  assert.deepEqual(calls.find(([name]) => name === "verify-first"), ["verify-first", ID, TOKEN, ID, NONCE_1, GOOGLE_TOKEN_1]);
  assert.equal(documentRef.getElementById("google-status").textContent,
    "Verificación inicial completada. Falta la revisión del administrador.");
  assert.equal(documentRef.getElementById("google-recover-button").hidden, false);
  assert.equal(calls.some(([name]) => name === "recover"), false);

  await documentRef.getElementById("google-recover-button").click();
  await flushAsync();
  assert.equal(initializations[1].nonce, NONCE_2);
  assert.deepEqual(calls.find(([name]) => name === "recover"), ["recover", ID, TOKEN]);
  firstCallback({ credential: "late-first-token" });
  await flushAsync();
  assert.equal(calls.filter(([name]) => name === "verify-first").length, 1);

  initializations[1].callback({ credential: GOOGLE_TOKEN_2 });
  await flushAsync();
  assert.deepEqual(calls.find(([name]) => name === "verify-second"), ["verify-second", ID, TOKEN,
    "22222222-2222-4222-8222-222222222222", STATE_2, GOOGLE_TOKEN_2]);
  assert.equal(documentRef.getElementById("google-status").textContent,
    "Identidad verificada. Tu cuenta está pendiente de activación.");
  assert.deepEqual(calls.map(([name]) => name), ["start", "verify-first", "recover", "verify-second"]);
});

test("keeps the administrator retry available after a generic recovery failure", async () => {
  const documentRef = fakeDocument();
  const { identity, initializations } = googleIdentityDouble();
  let recoveries = 0;
  const api = {
    validateInvitation: async () => ({ valid: true, expiresAt: "2026-12-01T00:00:00.000Z", verificationMethod: "googleWorkspace" }),
    startInvitationGoogleProof: async () => ({ challengeId: ID, nonce: NONCE_1 }),
    verifyInvitationGoogleProof: async () => ({ state: "verified" }),
    recoverInvitationGoogleChallenge: async () => {
      recoveries += 1;
      if (recoveries === 1) throw new InvitationApiError("SERVICE_UNAVAILABLE", "generic", 503);
      return { challengeId: "22222222-2222-4222-8222-222222222222", nonce: NONCE_2, state: STATE_2 };
    },
    verifyInvitationGoogleChallenge: async () => ({ state: "google_proof_verified" })
  };
  await startAcceptance({ invitationId: ID, token: TOKEN }, { documentRef, api, googleIdentity: identity, googleClientId: "client-id" });
  await documentRef.getElementById("google-start-button").click();
  await flushAsync();
  initializations[0].callback({ credential: GOOGLE_TOKEN_1 });
  await flushAsync();
  await documentRef.getElementById("google-recover-button").click();
  await flushAsync();
  assert.match(documentRef.getElementById("google-status").textContent, /No pudimos consultar el estado.*volver a consultar/i);
  assert.equal(documentRef.getElementById("google-recover-button").hidden, false);
  await documentRef.getElementById("google-recover-button").click();
  await flushAsync();
  assert.equal(recoveries, 2);
  assert.equal(initializations[1].nonce, NONCE_2);
});

test("shows clear configuration and SDK loading errors without starting a Google proof", async () => {
  for (const scenario of ["client-id", "sdk"]) {
    const documentRef = fakeDocument();
    let starts = 0;
    const api = {
      validateInvitation: async () => ({ valid: true, expiresAt: "2026-12-01T00:00:00.000Z", verificationMethod: "googleWorkspace" }),
      startInvitationGoogleProof: async () => { starts += 1; return { challengeId: ID, nonce: NONCE_1 }; }
    };
    await startAcceptance({ invitationId: ID, token: TOKEN }, {
      documentRef,
      api,
      googleClientId: scenario === "client-id" ? "" : "client-id",
      loadGoogleIdentitySdk: async () => { throw new Error("blocked"); }
    });
    if (scenario === "sdk") {
      await documentRef.getElementById("google-start-button").click();
      await flushAsync();
    }
    assert.equal(starts, 0);
    assert.match(documentRef.getElementById("google-status").textContent,
      scenario === "client-id" ? /no está configurada/ : /cargar Google/);
    if (scenario === "sdk") assert.equal(documentRef.getElementById("google-retry-button").hidden, false);
  }
});

test("preserves the password route for SMS, Email Link and legacy invitations", async () => {
  for (const method of ["sms", "email", undefined]) {
    const documentRef = fakeDocument();
    const { identity, initializations } = googleIdentityDouble();
    await startAcceptance({ invitationId: ID, token: TOKEN }, {
      documentRef,
      googleIdentity: identity,
      googleClientId: "client-id",
      api: { validateInvitation: async () => ({ valid: true, expiresAt: "2026-12-01T00:00:00.000Z", ...(method ? { verificationMethod: method } : {}) }) }
    });
    assert.equal(documentRef.getElementById("password-view").hidden, false);
    assert.equal(documentRef.getElementById("google-view").hidden, true);
    assert.equal(initializations.length, 0);
  }
});

test("reopens the same Google invitation and resumes an administrator-issued Challenge without repeating proof one", async () => {
  const firstDocument = fakeDocument();
  const firstIdentity = googleIdentityDouble();
  let firstStarts = 0;
  let firstVerifications = 0;
  const sharedApi = {
    validateInvitation: async () => ({ valid: true, expiresAt: "2026-12-01T00:00:00.000Z", verificationMethod: "googleWorkspace" }),
    startInvitationGoogleProof: async () => { firstStarts += 1; return { challengeId: ID, nonce: NONCE_1 }; },
    verifyInvitationGoogleProof: async () => { firstVerifications += 1; return { state: "verified" }; },
    recoverInvitationGoogleChallenge: async () => { throw new InvitationApiError("CHALLENGE_NOT_FOUND", "No disponible", 404); },
    verifyInvitationGoogleChallenge: async () => ({ state: "google_proof_verified" })
  };
  await startAcceptance({ invitationId: ID, token: TOKEN }, {
    documentRef: firstDocument, api: sharedApi, googleIdentity: firstIdentity.identity, googleClientId: "client-id"
  });
  await firstDocument.getElementById("google-start-button").click();
  await flushAsync();
  firstIdentity.initializations[0].callback({ credential: GOOGLE_TOKEN_1 });
  await flushAsync();
  assert.equal(firstVerifications, 1);
  assert.equal(firstDocument.getElementById("google-status").textContent,
    "Verificación inicial completada. Falta la revisión del administrador.");

  const secondDocument = fakeDocument();
  const secondIdentity = googleIdentityDouble();
  const challengeId = "22222222-2222-4222-8222-222222222222";
  let recoveryCalls = 0;
  const reopenedApi = {
    ...sharedApi,
    startInvitationGoogleProof: async () => { throw new Error("No se debe repetir la primera prueba al reabrir el enlace"); },
    recoverInvitationGoogleChallenge: async (invitationId, token) => {
      recoveryCalls += 1;
      assert.equal(invitationId, ID);
      assert.equal(token, TOKEN);
      return { challengeId, nonce: NONCE_2, state: STATE_2, expiresAt: "2026-12-01T00:00:00.000Z" };
    }
  };
  await startAcceptance({ invitationId: ID, token: TOKEN }, {
    documentRef: secondDocument, api: reopenedApi, googleIdentity: secondIdentity.identity, googleClientId: "client-id"
  });
  assert.equal(secondDocument.getElementById("google-start-button").hidden, false);
  assert.equal(secondDocument.getElementById("google-recover-button").hidden, false);
  await secondDocument.getElementById("google-recover-button").click();
  await flushAsync();
  assert.equal(recoveryCalls, 1);
  assert.equal(secondIdentity.initializations[0].nonce, NONCE_2);
  secondIdentity.initializations[0].callback({ credential: GOOGLE_TOKEN_2 });
  await flushAsync();
  assert.equal(firstStarts, 1);
  assert.equal(firstVerifications, 1);
  assert.equal(secondDocument.getElementById("google-status").textContent,
    "Identidad verificada. Tu cuenta está pendiente de activación.");
});

test("keeps invalid and temporary backend outcomes distinguishable without account data", async () => {
  await assert.rejects(validateInvitation(ID, TOKEN, {
    fetchImpl: async () => response(400, { ok: false, error: { code: "INVITATION_INVALID", message: "La invitación no es válida o ya no está disponible." } })
  }), (error) => error instanceof InvitationApiError && error.code === "INVITATION_INVALID");
  await assert.rejects(validateInvitation(ID, TOKEN, {
    fetchImpl: async () => { throw new Error("offline"); }
  }), (error) => error instanceof InvitationApiError && error.code === "NETWORK_ERROR" && !String(error).includes(TOKEN));
});

test("validates credentials and password confirmation locally", () => {
  assert.equal(credentialsAreWellFormed({ invitationId: ID, token: TOKEN }), true);
  assert.equal(credentialsAreWellFormed({ invitationId: ID, token: "short" }), false);
  assert.match(passwordValidation("short", "short"), /12 y 128/);
  assert.match(passwordValidation("A".repeat(12), "B".repeat(12)), /no coinciden/);
  assert.equal(passwordValidation(" A secure password ", " A secure password "), null);
});

test("contains accessible form semantics, responsive rules and no persistent secret APIs", async () => {
  const [html, css, main, bootstrap] = await Promise.all([
    readFile(new URL("../public/accept-invitation/index.html", import.meta.url), "utf8"),
    readFile(new URL("../public/assets/accept-invitation.css", import.meta.url), "utf8"),
    readFile(new URL("../public/assets/accept-invitation.js", import.meta.url), "utf8"),
    readFile(new URL("../public/assets/accept-bootstrap.js", import.meta.url), "utf8")
  ]);
  assert.match(html, /<ol class="steps"[^>]*aria-label=/);
  assert.match(html, /for="new-password"/);
  assert.match(html, /for="confirm-password"/);
  assert.match(html, /role="alert"/);
  assert.match(html, /aria-live="polite"/);
  assert.match(css, /font-family:\s*Inter/);
  assert.match(css, /@media \(max-width: 520px\)/);
  assert.match(css, /:focus-visible/);
  assert.match(css, /prefers-reduced-motion/);
  for (const source of [main, bootstrap]) {
    assert.doesNotMatch(source, /localStorage|sessionStorage|indexedDB|document\.cookie|innerHTML/);
  }
  assert.match(main, /inMemoryPersistence/);
  assert.match(main, /if \(busy\) return/);
});

test("configures no-store, no-referrer and compatible CSP for the acceptance route", async () => {
  const firebase = JSON.parse(await readFile(new URL("../firebase.json", import.meta.url), "utf8"));
  const headers = firebase.hosting.headers;
  const route = headers.find((entry) => entry.source === "/accept-invitation{,/**}");
  assert.ok(route);
  assert.equal(route.headers.find((header) => header.key === "Cache-Control")?.value, "no-store, max-age=0");
  assert.equal(route.headers.find((header) => header.key === "Referrer-Policy")?.value, "no-referrer");
  const acceptanceCsp = route.headers.find((header) => header.key === "Content-Security-Policy")?.value;
  assert.match(acceptanceCsp, /script-src[^;]*https:\/\/accounts\.google\.com\/gsi\/client/);
  assert.match(acceptanceCsp, /frame-src[^;]*https:\/\/accounts\.google\.com\/gsi\//);
  const globalCsp = headers.find((entry) => entry.source === "**").headers.find((header) => header.key === "Content-Security-Policy").value;
  assert.match(globalCsp, /script-src 'self' https:\/\/www\.gstatic\.com/);
  assert.match(globalCsp, /connect-src[^;]*adminapi-nnra4xim6q-uc\.a\.run\.app/);
  assert.match(globalCsp, /connect-src[^;]*identitytoolkit\.googleapis\.com/);
});
