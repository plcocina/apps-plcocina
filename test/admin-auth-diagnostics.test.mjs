import test from "node:test";
import assert from "node:assert/strict";
import { signInFailureMessage } from "../public/assets/admin-auth-diagnostics.js";

test("shows a sanitized Firebase code only on the local pilot origin", () => {
  const error = Object.assign(new Error("sensitive provider detail"), { code: "auth/invalid-credential" });
  assert.match(signInFailureMessage(error, true), /Código local: auth\/invalid-credential/);
  assert.equal(signInFailureMessage(error, false), "No fue posible iniciar sesión. Verifica tus datos e intenta nuevamente.");
});

test("reports network failures without exposing raw error messages", () => {
  const error = Object.assign(new TypeError("request failed with secret detail"), { code: "auth/network-request-failed" });
  const message = signInFailureMessage(error, true);
  assert.match(message, /Código local: auth\/network-request-failed/);
  assert.doesNotMatch(message, /secret detail|request failed/);
});

test("does not expose malformed error codes or messages", () => {
  const error = Object.assign(new Error("token must never appear"), { code: "auth/invalid credential token" });
  const message = signInFailureMessage(error, true);
  assert.match(message, /Código local: unknown-error/);
  assert.doesNotMatch(message, /token must never appear|invalid credential token/);
});
