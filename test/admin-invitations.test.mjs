import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { AdminApiError } from "../public/assets/admin-api-client.js";
import {
  availableInvitationActions,
  createInvitationActionOperation,
  createInvitationLogicalOperation,
  createInvitationOperationExecutor,
  createInvitationsDataSource,
  invitationOperationErrorKind,
  invitationsPath,
  sanitizeInvitation
} from "../public/assets/admin-invitations.js";

const principal = { uid: "admin-uid" };
const invitation = {
  invitationId: "11111111-1111-4111-8111-111111111111",
  email: "persona@plcocina.com",
  displayName: "Persona invitada",
  status: "active",
  deliveryStatus: "delivered",
  createdAt: "2026-10-20T12:00:00.000Z",
  expiresAt: "2026-10-27T12:00:00.000Z",
  acceptedAt: null,
  revision: 2,
  token: { hash: "sensitive" },
  providerMessageId: "internal-message"
};

test("builds paginated and exact-email invitation paths", () => {
  assert.equal(invitationsPath(), "/api/admin/invitations?pageSize=25");
  assert.equal(invitationsPath({ pageToken: "opaque/token" }), "/api/admin/invitations?pageSize=25&pageToken=opaque%2Ftoken");
  assert.equal(invitationsPath({ email: " PERSONA@PLCOCINA.COM " }), "/api/admin/invitations?email=persona%40plcocina.com");
});

test("paginates with opaque cursors and returns to the previous page", async () => {
  const paths = [];
  const source = createInvitationsDataSource(principal, async (_user, path) => {
    paths.push(path);
    return path.includes("page-2")
      ? { invitations: [{ ...invitation, invitationId: "22222222-2222-4222-8222-222222222222" }], nextPageToken: null }
      : { invitations: [invitation], nextPageToken: "page-2" };
  });
  assert.equal((await source.first()).page, 1);
  assert.equal((await source.next()).page, 2);
  assert.equal((await source.previous()).page, 1);
  assert.deepEqual(paths, [
    "/api/admin/invitations?pageSize=25",
    "/api/admin/invitations?pageSize=25&pageToken=page-2",
    "/api/admin/invitations?pageSize=25"
  ]);
});

test("performs an exact search without paginated listing", async () => {
  let path;
  const source = createInvitationsDataSource(principal, async (_user, value) => { path = value; return { invitations: [invitation], nextPageToken: null }; });
  const result = await source.search("PERSONA@plcocina.com");
  assert.equal(path, "/api/admin/invitations?email=persona%40plcocina.com");
  assert.equal(result.search, true);
});

test("sanitizes responses and keeps invitation and delivery statuses separate", () => {
  const safe = sanitizeInvitation(invitation);
  assert.deepEqual(Object.keys(safe).sort(), ["acceptedAt", "createdAt", "deliveryStatus", "displayName", "email", "expiresAt", "invitationId", "revision", "status"].sort());
  assert.equal(safe.status, "active");
  assert.equal(safe.deliveryStatus, "delivered");
  assert.equal("token" in safe, false);
  assert.equal("providerMessageId" in safe, false);
  assert.equal(sanitizeInvitation({ ...invitation, status: "revoked", deliveryStatus: "bounced" }).status, "revoked");
  assert.equal(sanitizeInvitation({ ...invitation, status: "expired" }).status, "expired");
});

test("propagates authorization failures for session handling", async () => {
  const expected = new AdminApiError("AUTH_REQUIRED", "Sesión vencida", 401);
  const source = createInvitationsDataSource(principal, async () => { throw expected; });
  await assert.rejects(source.first(), (error) => error === expected);
});

test("exposes accessible query and operation states", async () => {
  const [html, source] = await Promise.all([
    readFile(new URL("../public/admin/index.html", import.meta.url), "utf8"),
    readFile(new URL("../public/assets/admin-invitations.js", import.meta.url), "utf8")
  ]);
  assert.match(html, /id="invitations-message"[^>]+aria-live="polite"/);
  assert.match(html, /id="invitations-feedback"[^>]+role="status"[^>]+aria-live="polite"/);
  assert.match(html, /id="create-invitation-error"[^>]+role="alert"/);
  assert.match(html, /id="invitation-operation-error"[^>]+role="alert"/);
  assert.match(source, /Cargando invitaciones…/);
  assert.match(html, /id="new-invitation"/);
});

test("creates a normalized invitation operation with a 72-hour default", () => {
  const operation = createInvitationLogicalOperation({ displayName: " Persona invitada ", email: " PERSONA@PLCOCINA.COM " }, () => "11111111-1111-4111-8111-111111111111");
  assert.deepEqual(operation, {
    scope: "create",
    action: "create",
    idempotencyKey: "11111111-1111-4111-8111-111111111111",
    body: { displayName: "Persona invitada", email: "persona@plcocina.com", expiresInHours: 72 }
  });
  assert.throws(() => createInvitationLogicalOperation({ displayName: "", email: "invalid" }), /nombre/);
  assert.throws(() => createInvitationLogicalOperation({ displayName: "Persona", email: "invalid" }), /correo/);
  assert.throws(() => createInvitationLogicalOperation({ displayName: "Persona", email: "persona@plcocina.com", expiresInHours: 0 }), /vigencia/);
});

test("builds resend and revoke payloads with the current revision", () => {
  const record = sanitizeInvitation(invitation);
  const uuid = () => "22222222-2222-4222-8222-222222222222";
  assert.deepEqual(createInvitationActionOperation(record, "resend", "", uuid).body, { expectedRevision: 2, expiresInHours: 72 });
  assert.deepEqual(createInvitationActionOperation(record, "revoke", " Solicitud cancelada ", uuid).body, { expectedRevision: 2, reason: "Solicitud cancelada" });
  assert.throws(() => createInvitationActionOperation(record, "revoke", "x", uuid), /motivo/);
});

test("blocks invitation actions that conflict with their state", () => {
  const record = sanitizeInvitation(invitation);
  assert.deepEqual(availableInvitationActions(record), ["resend", "revoke"]);
  assert.deepEqual(availableInvitationActions({ ...record, status: "accepted" }), []);
  assert.deepEqual(availableInvitationActions({ ...record, status: "revoked" }), []);
  assert.deepEqual(availableInvitationActions({ ...record, status: "expired" }), ["resend", "revoke"]);
  assert.deepEqual(availableInvitationActions({ ...record, revision: null }), []);
});

test("sends create, resend and revoke to their exact endpoints with idempotency", async () => {
  const calls = [];
  const executor = createInvitationOperationExecutor(principal, async (_user, path, options) => { calls.push({ path, options }); return { deliveryStatus: "pending" }; });
  const uuid = () => "33333333-3333-4333-8333-333333333333";
  const record = sanitizeInvitation(invitation);
  await executor.execute(createInvitationLogicalOperation({ displayName: "Persona", email: "persona@plcocina.com" }, uuid));
  await executor.execute(createInvitationActionOperation(record, "resend", "", uuid));
  await executor.execute(createInvitationActionOperation(record, "revoke", "Solicitud cancelada", uuid));
  assert.deepEqual(calls.map((item) => item.path), [
    "/api/admin/invitations",
    "/api/admin/invitations/11111111-1111-4111-8111-111111111111/resend",
    "/api/admin/invitations/11111111-1111-4111-8111-111111111111/revoke"
  ]);
  assert.equal(calls.every((item) => item.options.idempotencyKey === "33333333-3333-4333-8333-333333333333"), true);
});

test("reuses the same key and payload after an ambiguous result", async () => {
  const seen = [];
  let attempt = 0;
  const executor = createInvitationOperationExecutor(principal, async (_user, _path, options) => {
    seen.push(structuredClone(options));
    attempt += 1;
    if (attempt === 1) throw new AdminApiError("NETWORK_ERROR", "Sin confirmación");
    return { deliveryStatus: "pending" };
  });
  const operation = createInvitationLogicalOperation({ displayName: "Persona", email: "persona@plcocina.com" }, () => "44444444-4444-4444-8444-444444444444");
  await assert.rejects(executor.execute(operation), (error) => invitationOperationErrorKind(error) === "ambiguous");
  await executor.execute(operation);
  assert.deepEqual(seen[0], seen[1]);
});

test("distinguishes a disabled provider, conflicts and ambiguous recovery", () => {
  assert.equal(invitationOperationErrorKind(new AdminApiError("INTERNAL_ERROR", "No configurado", 503)), "provider-disabled");
  assert.equal(invitationOperationErrorKind(new AdminApiError("REVISION_CONFLICT", "Obsoleta", 409)), "stale");
  assert.equal(invitationOperationErrorKind(new AdminApiError("OPERATION_IN_PROGRESS", "En curso", 409)), "ambiguous");
  assert.equal(invitationOperationErrorKind(new AdminApiError("AUTH_REQUIRED", "Sesión", 401)), "session");
});

test("blocks concurrent submissions for the same invitation", async () => {
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const executor = createInvitationOperationExecutor(principal, async () => { await gate; return { deliveryStatus: "pending" }; });
  const operation = createInvitationActionOperation(sanitizeInvitation(invitation), "resend", "", () => "55555555-5555-4555-8555-555555555555");
  const first = executor.execute(operation);
  await assert.rejects(executor.execute(operation), (error) => error.code === "OPERATION_IN_PROGRESS");
  release();
  await first;
});
