import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { AdminApiError } from "../public/assets/admin-api-client.js";
import {
  availableUserActions,
  createLogicalUserOperation,
  createUserOperationExecutor,
  createUsersDataSource,
  isAmbiguousOperationError,
  sanitizeUser,
  usersPath
} from "../public/assets/admin-users.js";

const principal = { uid: "super-admin" };
const rawUser = {
  uid: "user-1",
  email: "User@plcocina.com",
  displayName: "Usuario Uno",
  disabled: false,
  lastSignInAt: "2026-10-20T12:00:00.000Z",
  isProtected: false,
  integrity: "linked",
  profile: { status: "active", authDisabled: false, revision: 3 },
  customClaims: { super_admin: true },
  secretInternalField: "never expose"
};

test("builds paginated paths and an exact normalized email lookup", () => {
  assert.equal(usersPath(), "/api/admin/users?pageSize=25");
  assert.equal(usersPath({ pageToken: "next/token" }), "/api/admin/users?pageSize=25&pageToken=next%2Ftoken");
  assert.equal(usersPath({ email: " User@PLCOCINA.com " }), "/api/admin/users?email=user%40plcocina.com");
});

test("uses opaque cursors for next and previous pages", async () => {
  const paths = [];
  const request = async (_user, path) => {
    paths.push(path);
    if (path.includes("cursor-2")) return { users: [{ ...rawUser, uid: "user-2" }], nextPageToken: null };
    return { users: [rawUser], nextPageToken: "cursor-2" };
  };
  const source = createUsersDataSource(principal, request);
  assert.equal((await source.first()).page, 1);
  assert.equal((await source.next()).page, 2);
  assert.equal((await source.previous()).page, 1);
  assert.deepEqual(paths, [
    "/api/admin/users?pageSize=25",
    "/api/admin/users?pageSize=25&pageToken=cursor-2",
    "/api/admin/users?pageSize=25"
  ]);
});

test("searches by exact email without listing or adding pagination", async () => {
  let captured;
  const source = createUsersDataSource(principal, async (_user, path) => { captured = path; return { users: [rawUser], nextPageToken: null }; });
  const result = await source.search("USER@plcocina.com");
  assert.equal(captured, "/api/admin/users?email=user%40plcocina.com");
  assert.equal(result.search, true);
  assert.equal(result.users.length, 1);
});

test("propagates authorization errors without exposing or transforming them", async () => {
  const expected = new AdminApiError("AUTH_REQUIRED", "Sesión vencida", 401);
  const source = createUsersDataSource(principal, async () => { throw expected; });
  await assert.rejects(source.first(), (error) => error === expected && error.status === 401);
});

test("sanitizes incomplete and inconsistent records", () => {
  const safe = sanitizeUser(rawUser);
  assert.deepEqual(Object.keys(safe).sort(), ["authDisabled", "disabled", "displayName", "email", "integrity", "isProtected", "lastSignInAt", "profileRevision", "profileStatus", "uid"].sort());
  assert.equal("customClaims" in safe, false);
  assert.equal("secretInternalField" in safe, false);
  assert.equal(safe.isProtected, false);
  assert.equal(sanitizeUser({ ...rawUser, integrity: "unexpected", profile: null }).integrity, "invalid_profile");
  assert.equal(sanitizeUser({ email: "missing-uid@example.com" }), null);
});

test("allows only state-compatible actions and blocks protected, own or inconsistent accounts", () => {
  const active = sanitizeUser(rawUser);
  assert.deepEqual(availableUserActions(active, "admin-uid"), ["suspend", "revoke-sessions"]);
  assert.deepEqual(availableUserActions({ ...active, disabled: true, authDisabled: true, profileStatus: "disabled" }, "admin-uid"), ["reactivate"]);
  assert.deepEqual(availableUserActions({ ...active, uid: "admin-uid" }, "admin-uid"), []);
  assert.deepEqual(availableUserActions({ ...active, isProtected: true }, "admin-uid"), []);
  assert.deepEqual(availableUserActions({ ...active, integrity: "profile_mismatch" }, "admin-uid"), []);
  assert.deepEqual(availableUserActions({ ...active, profileRevision: null }, "admin-uid"), []);
});

test("builds suspension and revocation requests with revision, reason and one UUID", () => {
  const active = sanitizeUser(rawUser);
  let calls = 0;
  const operation = createLogicalUserOperation(active, "suspend", " Incidente confirmado ", () => { calls += 1; return "11111111-1111-4111-8111-111111111111"; });
  assert.deepEqual(operation, {
    uid: "user-1",
    action: "suspend",
    idempotencyKey: "11111111-1111-4111-8111-111111111111",
    body: { expectedRevision: 3, reason: "Incidente confirmado" }
  });
  assert.equal(calls, 1);
  assert.throws(() => createLogicalUserOperation(active, "revoke-sessions", "x"), /motivo/);
});

test("executes suspension, reactivation and session revocation with the expected contract", async () => {
  const calls = [];
  const executor = createUserOperationExecutor(principal, async (_user, path, options) => {
    calls.push({ path, options });
    return { revision: options.body.expectedRevision + 1 };
  });
  const active = sanitizeUser(rawUser);
  const disabled = { ...active, disabled: true, authDisabled: true, profileStatus: "disabled" };
  const uuid = () => "22222222-2222-4222-8222-222222222222";
  await executor.execute(createLogicalUserOperation(active, "suspend", "Incidente", uuid));
  await executor.execute(createLogicalUserOperation(disabled, "reactivate", "", uuid));
  await executor.execute(createLogicalUserOperation(active, "revoke-sessions", "Cierre preventivo", uuid));
  assert.deepEqual(calls.map((call) => call.path), [
    "/api/admin/users/user-1/suspend",
    "/api/admin/users/user-1/reactivate",
    "/api/admin/users/user-1/revoke-sessions"
  ]);
  assert.equal(calls[0].options.idempotencyKey, "22222222-2222-4222-8222-222222222222");
  assert.deepEqual(calls[1].options.body, { expectedRevision: 3 });
});

test("preserves the logical operation key across an ambiguous retry", async () => {
  const seen = [];
  let attempt = 0;
  const executor = createUserOperationExecutor(principal, async (_user, _path, options) => {
    seen.push(options.idempotencyKey);
    attempt += 1;
    if (attempt === 1) throw new AdminApiError("NETWORK_ERROR", "Sin confirmación");
    return { revision: 4 };
  });
  const operation = createLogicalUserOperation(sanitizeUser(rawUser), "suspend", "Incidente", () => "33333333-3333-4333-8333-333333333333");
  await assert.rejects(executor.execute(operation), (error) => isAmbiguousOperationError(error));
  await executor.execute(operation);
  assert.deepEqual(seen, ["33333333-3333-4333-8333-333333333333", "33333333-3333-4333-8333-333333333333"]);
});

test("blocks simultaneous operations for the same user", async () => {
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const executor = createUserOperationExecutor(principal, async () => { await gate; return { revision: 4 }; });
  const operation = createLogicalUserOperation(sanitizeUser(rawUser), "suspend", "Incidente", () => "44444444-4444-4444-8444-444444444444");
  const first = executor.execute(operation);
  await assert.rejects(executor.execute(operation), (error) => error.code === "OPERATION_IN_PROGRESS");
  release();
  await first;
});

test("classifies conflicts separately from ambiguous recovery errors", () => {
  assert.equal(isAmbiguousOperationError(new AdminApiError("INTERNAL_ERROR", "Conciliación", 500)), true);
  assert.equal(isAmbiguousOperationError(new AdminApiError("OPERATION_IN_PROGRESS", "En curso", 409)), true);
  assert.equal(isAmbiguousOperationError(new AdminApiError("REVISION_CONFLICT", "Obsoleta", 409)), false);
});

test("provides accessible confirmation and loading, success and error announcements", async () => {
  const [html, source] = await Promise.all([
    readFile(new URL("../public/admin/index.html", import.meta.url), "utf8"),
    readFile(new URL("../public/assets/admin-users.js", import.meta.url), "utf8")
  ]);
  assert.match(html, /id="user-operation-dialog"/);
  assert.match(html, /id="users-feedback"[^>]+role="status"[^>]+aria-live="polite"/);
  assert.match(html, /id="user-operation-error"[^>]+role="alert"/);
  assert.match(source, /Cargando usuarios…/);
  assert.match(source, /Cuenta suspendida correctamente\./);
  assert.match(source, /No se pudo confirmar el resultado\./);
});
