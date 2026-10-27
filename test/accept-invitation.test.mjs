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
import { credentialsAreWellFormed, passwordValidation } from "../public/assets/accept-invitation.js";

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
  const globalCsp = headers.find((entry) => entry.source === "**").headers.find((header) => header.key === "Content-Security-Policy").value;
  assert.match(globalCsp, /script-src 'self' https:\/\/www\.gstatic\.com/);
  assert.match(globalCsp, /connect-src[^;]*adminapi-nnra4xim6q-uc\.a\.run\.app/);
  assert.match(globalCsp, /connect-src[^;]*identitytoolkit\.googleapis\.com/);
});
