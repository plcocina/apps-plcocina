import type { DecodedIdToken } from "firebase-admin/auth";
import type { Firestore } from "firebase-admin/firestore";
import { Timestamp } from "firebase-admin/firestore";
import { createHmac } from "node:crypto";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createAdminApp } from "../src/app.js";
import { GoogleBootstrapChallengeCoordinatorError } from "../src/identities/identity-google-bootstrap-challenge-coordinator.js";
import { GoogleBootstrapPreparationError } from "../src/identities/identity-google-bootstrap-preparation-service.js";
import { GoogleBootstrapChallengeDeliveryError } from "../src/identities/identity-google-bootstrap-challenge-delivery-service.js";
import { GoogleIdentityLinkError } from "../src/identities/identity-linking-service.js";

const ORIGIN = "https://apps.plcocina.com";
const NOW = new Date("2026-10-19T18:00:00.000Z");

function token(overrides: Partial<DecodedIdToken> = {}): DecodedIdToken {
  return {
    aud: "plcocina-apps",
    auth_time: 1_792_430_000,
    exp: 1_792_433_600,
    firebase: { identities: {}, sign_in_provider: "password" },
    iat: 1_792_430_000,
    iss: "https://securetoken.google.com/plcocina-apps",
    sub: "admin-uid",
    uid: "admin-uid",
    email: "admin@plcocina.com",
    super_admin: true,
    ...overrides
  } as DecodedIdToken;
}

function authError(code: string): Error & { code: string } {
  return Object.assign(new Error("Firebase Auth rejected token"), { code });
}

function testApp(verifier = vi.fn().mockResolvedValue(token())) {
  return {
    app: createAdminApp({
      verifyIdToken: verifier,
      origins: new Set([ORIGIN]),
      now: () => NOW
    }),
    verifier
  };
}

describe("admin API authentication", () => {
  it("requires an ID token for health", async () => {
    const { app, verifier } = testApp();
    const response = await request(app).get("/api/admin/health").set("Origin", ORIGIN);

    expect(response.status).toBe(401);
    expect(response.body.error.code).toBe("AUTH_REQUIRED");
    expect(response.headers["cache-control"]).toBe("no-store, max-age=0");
    expect(verifier).not.toHaveBeenCalled();
  });

  it("checks revocation and returns the authenticated Super Admin", async () => {
    const { app, verifier } = testApp();
    const response = await request(app)
      .get("/api/admin/me")
      .set("Origin", ORIGIN)
      .set("Authorization", "Bearer valid-token");

    expect(response.status).toBe(200);
    expect(response.body).toMatchObject({
      ok: true,
      data: {
        uid: "admin-uid",
        email: "admin@plcocina.com",
        superAdmin: true
      }
    });
    expect(verifier).toHaveBeenCalledWith("valid-token", true);
  });

  it("requires the boolean super_admin claim", async () => {
    const verifier = vi.fn().mockResolvedValue(token({ super_admin: "true" }));
    const { app } = testApp(verifier);
    const response = await request(app)
      .get("/api/admin/health")
      .set("Authorization", "Bearer valid-non-admin-token");

    expect(response.status).toBe(403);
    expect(response.body.error.code).toBe("ADMIN_REQUIRED");
  });

  it("does not allow a common user to list applications", async () => {
    const verifier = vi.fn().mockResolvedValue(token({ super_admin: false }));
    const { app } = testApp(verifier);
    const response = await request(app)
      .get("/api/admin/applications")
      .set("Origin", ORIGIN)
      .set("Authorization", "Bearer common-user-token");

    expect(response.status).toBe(403);
    expect(response.body.error.code).toBe("ADMIN_REQUIRED");
  });

  it("requires authentication and Super Admin authorization for user queries", async () => {
    const unauthenticated = testApp();
    const missing = await request(unauthenticated.app).get("/api/admin/users").set("Origin", ORIGIN);
    expect(missing.status).toBe(401);
    expect(unauthenticated.verifier).not.toHaveBeenCalled();

    const verifier = vi.fn().mockResolvedValue(token({ super_admin: false }));
    const unauthorized = testApp(verifier);
    const forbidden = await request(unauthorized.app)
      .get("/api/admin/users")
      .set("Origin", ORIGIN)
      .set("Authorization", "Bearer common-user-token");
    expect(forbidden.status).toBe(403);
    expect(verifier).toHaveBeenCalledWith("common-user-token", true);
  });

  it("requires authentication and Super Admin authorization for invitation queries", async () => {
    const unauthenticated = testApp();
    const missing = await request(unauthenticated.app).get("/api/admin/invitations").set("Origin", ORIGIN);
    expect(missing.status).toBe(401);
    expect(unauthenticated.verifier).not.toHaveBeenCalled();

    const verifier = vi.fn().mockResolvedValue(token({ super_admin: false }));
    const unauthorized = testApp(verifier);
    const forbidden = await request(unauthorized.app)
      .get("/api/admin/invitations")
      .set("Origin", ORIGIN)
      .set("Authorization", "Bearer common-user-token");
    expect(forbidden.status).toBe(403);
    expect(verifier).toHaveBeenCalledWith("common-user-token", true);
  });

  it("rejects a revoked token before consulting the user directory", async () => {
    const verifier = vi.fn().mockRejectedValue(authError("auth/id-token-revoked"));
    const { app } = testApp(verifier);
    const response = await request(app)
      .get("/api/admin/users")
      .set("Origin", ORIGIN)
      .set("Authorization", "Bearer revoked-token");
    expect(response.status).toBe(401);
    expect(response.body.error.code).toBe("TOKEN_REVOKED");
    expect(verifier).toHaveBeenCalledWith("revoked-token", true);
  });

  it.each([
    ["auth/argument-error", "TOKEN_INVALID"],
    ["auth/id-token-expired", "TOKEN_EXPIRED"],
    ["auth/id-token-revoked", "TOKEN_REVOKED"],
    ["auth/user-disabled", "TOKEN_REVOKED"]
  ])("rejects %s", async (firebaseCode, apiCode) => {
    const verifier = vi.fn().mockRejectedValue(authError(firebaseCode));
    const { app } = testApp(verifier);
    const response = await request(app)
      .get("/api/admin/me")
      .set("Authorization", "Bearer rejected-token");

    expect(response.status).toBe(401);
    expect(response.body.error.code).toBe(apiCode);
    expect(verifier).toHaveBeenCalledWith("rejected-token", true);
  });
});

describe("Google bootstrap challenge HTTP endpoint", () => {
  const authorizationId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const idempotencyKey = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
  const challenge = { challengeId: authorizationId, nonce: "safe-nonce", state: "safe-state", expiresAt: "2026-10-19T18:05:00.000Z" };
  const issue = vi.fn().mockResolvedValue(challenge);
  const appWithIssue = (verifier = vi.fn().mockResolvedValue(token()), issuer = issue) => createAdminApp({
    verifyIdToken: verifier,
    origins: new Set([ORIGIN]),
    now: () => NOW,
    googleBootstrapComposition: () => ({ issue: issuer } as never)
  });
  const sendIssue = (app: ReturnType<typeof createAdminApp>, body: Record<string, unknown> = { authorizationId, idempotencyKey }) => request(app)
    .post("/api/admin/identities/google-bootstrap/challenges")
    .set("Origin", ORIGIN)
    .set("Authorization", "Bearer valid-token")
    .send(body);

  it("issues a challenge for an authenticated Super Admin", async () => {
    const verifier = vi.fn().mockResolvedValue(token());
    const issuer = vi.fn().mockResolvedValue(challenge);
    const app = createAdminApp({ verifyIdToken: verifier, origins: new Set([ORIGIN]), now: () => NOW,
      googleBootstrapComposition: () => ({ issue: issuer } as never) });
    const response = await sendIssue(app);
    expect(response.status).toBe(200);
    expect(response.body).toMatchObject({ ok: true, data: challenge });
    expect(issuer).toHaveBeenCalledWith(expect.objectContaining({ authorizationId, idempotencyKey,
      principal: expect.objectContaining({ uid: "admin-uid", superAdmin: true }) }));
    expect(verifier).toHaveBeenCalledWith("valid-token", true);
  });

  it("rejects missing authentication and non-admin callers", async () => {
    const noAuth = await request(appWithIssue()).post("/api/admin/identities/google-bootstrap/challenges")
      .set("Origin", ORIGIN).send({ authorizationId, idempotencyKey });
    expect(noAuth.status).toBe(401);
    const commonUser = appWithIssue(vi.fn().mockResolvedValue(token({ super_admin: false })));
    expect((await sendIssue(commonUser)).status).toBe(403);
  });

  it("rejects caller supplied identity fields", async () => {
    const issuer = vi.fn();
    const app = createAdminApp({ verifyIdToken: vi.fn().mockResolvedValue(token()), origins: new Set([ORIGIN]),
      googleBootstrapComposition: () => ({ issue: issuer } as never) });
    const response = await sendIssue(app, { authorizationId, idempotencyKey, uid: "forged", superAdmin: true });
    expect(response.status).toBe(400);
    expect(issuer).not.toHaveBeenCalled();
  });

  it("returns a generic error when E4B2 authorization is invalid", async () => {
    const failure = vi.fn().mockRejectedValue(new GoogleBootstrapChallengeCoordinatorError("AUTHORIZATION_INVALID"));
    const app = createAdminApp({ verifyIdToken: vi.fn().mockResolvedValue(token()), origins: new Set([ORIGIN]),
      googleBootstrapComposition: () => ({ issue: failure } as never) });
    const response = await sendIssue(app);
    expect(response.status).toBe(500);
    expect(JSON.stringify(response.body)).not.toContain("AUTHORIZATION_INVALID");
    expect(JSON.stringify(response.body)).not.toContain("safe-state");
  });

  it("returns the same challenge for repeated idempotent issuance", async () => {
    const issuer = vi.fn().mockResolvedValue(challenge);
    const app = createAdminApp({ verifyIdToken: vi.fn().mockResolvedValue(token()), origins: new Set([ORIGIN]),
      googleBootstrapComposition: () => ({ issue: issuer } as never) });
    const first = await sendIssue(app);
    const second = await sendIssue(app);
    expect(first.body.data).toEqual(second.body.data);
    expect(issuer).toHaveBeenCalledTimes(2);
    expect(issuer.mock.calls[0]?.[0]).toEqual(issuer.mock.calls[1]?.[0]);
  });

  it("sets no-store and does not expose details in service errors", async () => {
    const app = createAdminApp({ verifyIdToken: vi.fn().mockResolvedValue(token()), origins: new Set([ORIGIN]),
      googleBootstrapComposition: () => ({ issue: vi.fn().mockRejectedValue(new Error("secret-key-material")) } as never) });
    const response = await sendIssue(app);
    expect(response.headers["cache-control"]).toContain("no-store");
    expect(JSON.stringify(response.body)).not.toContain("secret-key-material");
  });

  it("fails closed for missing or invalid bootstrap configuration", async () => {
    const missing = createAdminApp({ verifyIdToken: vi.fn().mockResolvedValue(token()), origins: new Set([ORIGIN]) });
    expect((await sendIssue(missing)).status).toBe(503);
    const invalid = createAdminApp({ verifyIdToken: vi.fn().mockResolvedValue(token()), origins: new Set([ORIGIN]),
      googleBootstrapComposition: () => ({ issue: vi.fn().mockRejectedValue(new Error("AUTH_CONFIGURATION_INVALID: secret")) } as never) });
    const response = await sendIssue(invalid);
    expect(response.status).toBe(400);
    expect(JSON.stringify(response.body)).not.toContain("secret");
  });

  it("keeps existing administrative routes available", async () => {
    const app = appWithIssue();
    const me = await request(app).get("/api/admin/me").set("Authorization", "Bearer valid-token");
    expect(me.status).toBe(200);
    expect(me.body.data).toMatchObject({ uid: "admin-uid", superAdmin: true });
    const applications = await request(app).get("/api/admin/applications")
      .set("Origin", ORIGIN).set("Authorization", "Bearer valid-token");
    expect(applications.status).toBe(503);
    expect(applications.body.error.code).toBe("INTERNAL_ERROR");
  });
});

describe("Google bootstrap preparation HTTP endpoint", () => {
  const proofId = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
  const authorizationId = "ffffffff-ffff-4fff-8fff-ffffffffffff";
  const result = { proofId, uid: "private-uid", authorizationId, operationId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    coordinationOperationId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", state: "not_started", replayed: false };
  const preparation = vi.fn().mockResolvedValue(result);
  const appWithPreparation = (verifier = vi.fn().mockResolvedValue(token()), prepare = preparation) => createAdminApp({
    verifyIdToken: verifier, origins: new Set([ORIGIN]), now: () => NOW,
    googleBootstrapPreparationService: () => ({ prepare } as never)
  });
  const send = (app: ReturnType<typeof createAdminApp>, body: Record<string, unknown> = { proofId }) => request(app)
    .post("/api/admin/identities/google-bootstrap/preparations").set("Origin", ORIGIN)
    .set("Authorization", "Bearer valid-token").send(body);

  it("prepares a verified proof for an authenticated Super Admin", async () => {
    const verifier = vi.fn().mockResolvedValue(token()); const prepare = vi.fn().mockResolvedValue(result);
    const response = await send(appWithPreparation(verifier, prepare));
    expect(response.status).toBe(200);
    expect(response.headers["cache-control"]).toContain("no-store");
    expect(response.body.data).toEqual({ authorizationId, state: "not_started" });
    expect(JSON.stringify(response.body)).not.toContain("private-uid");
    expect(prepare).toHaveBeenCalledWith({ proofId }, expect.objectContaining({ uid: "admin-uid", superAdmin: true }));
    expect(verifier).toHaveBeenCalledWith("valid-token", true);
  });

  it("rejects anonymous and non-Super-Admin callers before preparation", async () => {
    const prepare = vi.fn(); const app = appWithPreparation(vi.fn().mockResolvedValue(token({ super_admin: false })), prepare);
    const anonymous = await request(app).post("/api/admin/identities/google-bootstrap/preparations")
      .set("Origin", ORIGIN).send({ proofId });
    const ordinaryUser = await send(app);
    expect(anonymous.status).toBe(401);
    expect(ordinaryUser.status).toBe(403);
    expect(prepare).not.toHaveBeenCalled();
  });

  it.each([
    ["missing", "PROOF_NOT_FOUND", 404],
    ["invalidated by invitation change", "INVITATION_INVALID", 400]
  ] as const)("returns a generic error for proof %s", async (_description, code, status) => {
    const prepare = vi.fn().mockRejectedValue(new GoogleBootstrapPreparationError(code));
    const response = await send(appWithPreparation(vi.fn().mockResolvedValue(token()), prepare));
    expect(response.status).toBe(status);
    expect(JSON.stringify(response.body)).not.toMatch(/private-uid|proofId|PROOF_NOT_FOUND/);
  });

  it("rejects identity fields in the request body", async () => {
    const prepare = vi.fn();
    const response = await send(appWithPreparation(vi.fn().mockResolvedValue(token()), prepare),
      { proofId, uid: "forged", subject: "forged", email: "forged@plcocina.com" });
    expect(response.status).toBe(400);
    expect(prepare).not.toHaveBeenCalled();
  });

  it("returns the same authorization reference for idempotent retries", async () => {
    const prepare = vi.fn().mockResolvedValueOnce(result).mockResolvedValueOnce({ ...result, replayed: true });
    const app = appWithPreparation(vi.fn().mockResolvedValue(token()), prepare);
    const first = await send(app); const second = await send(app);
    expect(first.body.data).toEqual({ authorizationId, state: "not_started" });
    expect(second.body.data).toEqual(first.body.data);
    expect(prepare).toHaveBeenCalledTimes(2);
    expect(prepare.mock.calls[0]).toEqual(prepare.mock.calls[1]);
  });
});

describe("invitation Google bootstrap challenge recovery HTTP endpoint", () => {
  const invitationId = "99999999-9999-4999-8999-999999999999";
  const tokenValue = "t".repeat(43);
  const challenge = { challengeId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", nonce: "n".repeat(43), state: "s".repeat(43),
    expiresAt: Timestamp.fromDate(new Date(NOW.getTime() + 300_000)) };
  const recover = vi.fn().mockResolvedValue(challenge);
  const appWithRecovery = (delivery = recover) => createAdminApp({ verifyIdToken: vi.fn(), origins: new Set([ORIGIN]), now: () => NOW,
    googleBootstrapChallengeDeliveryService: () => ({ recover: delivery } as never) });
  const send = (app: ReturnType<typeof createAdminApp>, body: Record<string, unknown> = { invitationId, token: tokenValue }) => request(app)
    .post("/api/invitations/google-bootstrap/challenge/recover").set("Origin", ORIGIN).send(body);

  it("returns only an existing invitation-bound challenge and is safe to retry", async () => {
    const delivery = vi.fn().mockResolvedValue(challenge);
    const app = appWithRecovery(delivery);
    const first = await send(app); const second = await send(app);
    expect(first.status).toBe(200);
    expect(first.headers["cache-control"]).toContain("no-store");
    expect(first.body.data).toEqual({ ...challenge, expiresAt: new Date(NOW.getTime() + 300_000).toISOString() });
    expect(second.body.data).toEqual(first.body.data);
    expect(delivery).toHaveBeenCalledTimes(2);
    expect(delivery.mock.calls[0]).toEqual(delivery.mock.calls[1]);
  });

  it("rejects extra identity or issuance fields and returns generic errors", async () => {
    const delivery = vi.fn().mockRejectedValue(new GoogleBootstrapChallengeDeliveryError("INVITATION_INVALID"));
    const app = appWithRecovery(delivery);
    const forged = await send(app, { invitationId, token: tokenValue, uid: "forged", subject: "forged",
      authorizationId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", challengeId: challenge.challengeId });
    const invalid = await send(app);
    expect(forged.status).toBe(400);
    expect(invalid.status).toBe(400);
    expect(invalid.headers["cache-control"]).toContain("no-store");
    expect(JSON.stringify(invalid.body)).not.toContain("forged");
    expect(delivery).toHaveBeenCalledTimes(1);
  });

  it("does not issue when no previously emitted challenge can be recovered", async () => {
    const delivery = vi.fn().mockRejectedValue(new GoogleBootstrapChallengeDeliveryError("CHALLENGE_NOT_FOUND"));
    const response = await send(appWithRecovery(delivery));
    expect(response.status).toBe(404);
    expect(JSON.stringify(response.body)).not.toContain("nonce");
    expect(delivery).toHaveBeenCalledWith({ invitationId, token: tokenValue });
  });
});

describe("invitation Google bootstrap challenge finalization HTTP endpoint", () => {
  const body = { invitationId: "99999999-9999-4999-8999-999999999999", token: "t".repeat(43),
    challengeId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", state: "s".repeat(43), googleIdToken: "signed-google-id-token" };
  const finalize = vi.fn().mockResolvedValue({ state: "google_proof_verified", replayed: false });
  const appWithFinalization = (operation = finalize) => createAdminApp({
    verifyIdToken: vi.fn(), origins: new Set([ORIGIN]), now: () => NOW,
    googleBootstrapChallengeDeliveryService: () => ({ verifyAndConsume: operation } as never),
    googleBootstrapComposition: () => ({} as never)
  });
  const send = (app: ReturnType<typeof createAdminApp>, input: Record<string, unknown> = body) => request(app)
    .post("/api/invitations/google-bootstrap/challenge/verify").set("Origin", ORIGIN).send(input);

  it("finalizes and returns only the verification state", async () => {
    const operation = vi.fn().mockResolvedValue({ state: "google_proof_verified", replayed: true, uid: "private-uid" });
    const response = await send(appWithFinalization(operation));
    expect(response.status).toBe(200);
    expect(response.headers["cache-control"]).toContain("no-store");
    expect(response.body.data).toEqual({ state: "google_proof_verified" });
    expect(JSON.stringify(response.body)).not.toContain("private-uid");
    expect(operation).toHaveBeenCalledWith(body, expect.anything());
  });

  it("rejects client supplied nonce or identity fields before finalization", async () => {
    const operation = vi.fn();
    const response = await send(appWithFinalization(operation), { ...body, nonce: "forged", uid: "forged",
      subject: "forged", email: "forged@plcocina.com" });
    expect(response.status).toBe(400);
    expect(operation).not.toHaveBeenCalled();
  });

  it("maps state and verification failures to generic no-store errors", async () => {
    const failure = vi.fn().mockRejectedValue(new GoogleBootstrapChallengeDeliveryError("CHALLENGE_STATE_INVALID"));
    const response = await send(appWithFinalization(failure));
    expect(response.status).toBe(409);
    expect(response.headers["cache-control"]).toContain("no-store");
    expect(JSON.stringify(response.body)).not.toMatch(/signed-google|nonce|state|CHALLENGE_STATE_INVALID/);
  });
});

describe("employee initial Google proof HTTP endpoints", () => {
  const invitationId = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
  const challengeId = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
  const inviteToken = "i".repeat(43);
  const nonce = "safe-initial-google-nonce-value";
  const idToken = "local-google-id-token-value";
  const start = vi.fn().mockResolvedValue({ challengeId, nonce, expiresAt: Timestamp.fromDate(new Date(NOW.getTime() + 300_000)) });
  const verify = vi.fn().mockResolvedValue({ proofId: challengeId, uid: "private-uid", state: "verified", verifiedAt: Timestamp.fromDate(NOW) });
  const appWithProof = (service: { start: typeof start; verify: typeof verify } = { start, verify }) => createAdminApp({
    verifyIdToken: vi.fn(), origins: new Set([ORIGIN]), now: () => NOW,
    invitationGoogleProofService: () => service as never
  });
  const postStart = (app: ReturnType<typeof createAdminApp>, body: Record<string, unknown> = { invitationId, token: inviteToken }) => request(app)
    .post("/api/invitations/google-bootstrap/proof/start").set("Origin", ORIGIN).send(body);
  const verifyBody = { invitationId, token: inviteToken, challengeId, nonce, googleIdToken: idToken };
  const postVerify = (app: ReturnType<typeof createAdminApp>, body: Record<string, unknown> = verifyBody) => request(app)
    .post("/api/invitations/google-bootstrap/proof/verify").set("Origin", ORIGIN).send(body);

  it("starts a proof using only the invitation capability and returns a no-store nonce", async () => {
    const starter = vi.fn().mockResolvedValue({ challengeId, nonce, expiresAt: Timestamp.fromDate(new Date(NOW.getTime() + 300_000)) });
    const response = await postStart(appWithProof({ start: starter, verify }));
    expect(response.status).toBe(200);
    expect(response.headers["cache-control"]).toContain("no-store");
    expect(response.body.data).toMatchObject({ challengeId, nonce });
    expect(starter).toHaveBeenCalledWith({ invitationId, token: inviteToken });
  });

  it("verifies and returns no identity fields", async () => {
    const verifier = vi.fn().mockResolvedValue({ proofId: challengeId, uid: "private-uid", state: "verified", verifiedAt: Timestamp.fromDate(NOW) });
    const response = await postVerify(appWithProof({ start, verify: verifier }));
    expect(response.status).toBe(200);
    expect(response.headers["cache-control"]).toContain("no-store");
    expect(response.body.data).toEqual({ state: "verified", verifiedAt: NOW.toISOString() });
    expect(JSON.stringify(response.body)).not.toContain("private-uid");
    expect(verifier).toHaveBeenCalledWith(verifyBody);
  });

  it("rejects client supplied identity claims without invoking either service method", async () => {
    const starter = vi.fn(); const verifier = vi.fn(); const app = appWithProof({ start: starter, verify: verifier });
    const forgedStart = await postStart(app, { invitationId, token: inviteToken, uid: "forged", subject: "forged-sub" });
    const forgedVerify = await postVerify(app, { ...verifyBody, uid: "forged", email: "forged@plcocina.com", subject: "forged-sub" });
    expect(forgedStart.status).toBe(400);
    expect(forgedVerify.status).toBe(400);
    expect(starter).not.toHaveBeenCalled();
    expect(verifier).not.toHaveBeenCalled();
  });

  it("maps invalid, consumed, and unavailable proof operations to generic no-store errors", async () => {
    const invalid = vi.fn().mockRejectedValue(Object.assign(new Error("secret-bearing detail"), { code: "INVITATION_INVALID" }));
    const consumed = vi.fn().mockRejectedValue(Object.assign(new Error("nonce/private identity"), { code: "CHALLENGE_CONSUMED" }));
    const invalidResponse = await postStart(appWithProof({ start: invalid, verify }));
    const consumedResponse = await postVerify(appWithProof({ start, verify: consumed }));
    const unavailable = await postStart(createAdminApp({ verifyIdToken: vi.fn(), origins: new Set([ORIGIN]) }));
    for (const response of [invalidResponse, consumedResponse, unavailable]) {
      expect(response.headers["cache-control"]).toContain("no-store");
      expect(JSON.stringify(response.body)).not.toMatch(/secret-bearing|nonce\/private identity|private-uid/);
    }
    expect(invalidResponse.status).toBe(400);
    expect(consumedResponse.status).toBe(409);
    expect(unavailable.status).toBe(503);
  });
});

describe("E4B2 invitation binding HTTP endpoint", () => {
  const authorizationId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const invitationId = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
  const operationId = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
  const authorization = { authorizationId, operationId, invitationId, state: "pending" };
  const appWithBinding = (verifier = vi.fn().mockResolvedValue(token()), binder = vi.fn().mockResolvedValue(authorization)) => createAdminApp({
    verifyIdToken: verifier,
    origins: new Set([ORIGIN]),
    bindEmployeeInvitationAuthorization: binder as never
  });
  const sendBinding = (app: ReturnType<typeof createAdminApp>, body: Record<string, unknown> = { authorizationId, invitationId }) => request(app)
    .post("/api/admin/identities/google-bootstrap/authorizations")
    .set("Origin", ORIGIN)
    .set("Authorization", "Bearer valid-token")
    .send(body);

  it("binds a valid invitation using the authenticated Super Admin principal", async () => {
    const binder = vi.fn().mockResolvedValue(authorization);
    const app = appWithBinding(vi.fn().mockResolvedValue(token()), binder);
    const response = await sendBinding(app);
    expect(response.status).toBe(200);
    expect(response.body.data).toEqual({ authorizationId, operationId, invitationId, state: "pending" });
    expect(response.body.data).not.toHaveProperty("targetUid");
    expect(response.body.data).not.toHaveProperty("googleSubjectHash");
    expect(binder).toHaveBeenCalledWith(expect.objectContaining({ authorizationId, invitationId,
      principal: expect.objectContaining({ uid: "admin-uid", superAdmin: true }) }));
  });

  it("rejects missing authentication and callers without Super Admin privileges", async () => {
    const binder = vi.fn();
    const app = appWithBinding(vi.fn().mockResolvedValue(token()), binder);
    const anonymous = await request(app).post("/api/admin/identities/google-bootstrap/authorizations")
      .set("Origin", ORIGIN).send({ authorizationId, invitationId });
    expect(anonymous.status).toBe(401);
    const commonUser = appWithBinding(vi.fn().mockResolvedValue(token({ super_admin: false })), binder);
    expect((await sendBinding(commonUser)).status).toBe(403);
    expect(binder).not.toHaveBeenCalled();
  });

  it("rejects identity evidence supplied in the request body", async () => {
    const binder = vi.fn();
    const response = await sendBinding(appWithBinding(vi.fn().mockResolvedValue(token()), binder), {
      authorizationId, invitationId, targetUid: "forged-uid", googleSubjectHash: "f".repeat(64),
      operationId, authorizedByUid: "admin-uid"
    });
    expect(response.status).toBe(400);
    expect(binder).not.toHaveBeenCalled();
  });

  it("returns a controlled invalid-invitation error", async () => {
    const binder = vi.fn().mockRejectedValue(new GoogleIdentityLinkError("INVITATION_NOT_ACTIVE", "private invite detail"));
    const response = await sendBinding(appWithBinding(vi.fn().mockResolvedValue(token()), binder));
    expect(response.status).toBe(400);
    expect(response.body.error.code).toBe("INVITATION_INVALID");
    expect(JSON.stringify(response.body)).not.toContain("private invite detail");
  });

  it("recovers equivalent retries and rejects another invitation without changing the binding", async () => {
    let storedInvitationId: string | null = null;
    const binder = vi.fn(async (input: { authorizationId: string; invitationId: string }) => {
      if (storedInvitationId && storedInvitationId !== input.invitationId) {
        throw new GoogleIdentityLinkError("AUTHORIZATION_INVITATION_CONFLICT", "conflicting invitation");
      }
      storedInvitationId = input.invitationId;
      return { ...authorization, invitationId: input.invitationId };
    });
    const app = appWithBinding(vi.fn().mockResolvedValue(token()), binder as never);
    const first = await sendBinding(app);
    const replay = await sendBinding(app);
    const conflict = await sendBinding(app, { authorizationId, invitationId: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee" });
    expect(first.status).toBe(200);
    expect(replay.body.data).toEqual(first.body.data);
    expect(conflict.status).toBe(409);
    expect(conflict.body.error.code).toBe("IDEMPOTENCY_CONFLICT");
    expect(storedInvitationId).toBe(invitationId);
  });
});

describe("Resend webhook ingress", () => {
  it("fails closed while the provider is disabled", async () => {
    const { app } = testApp();
    const response = await request(app)
      .post("/api/webhooks/resend")
      .set("Content-Type", "application/json")
      .send('{"type":"email.delivered"}');
    expect(response.status).toBe(503);
    expect(response.body.error.code).toBe("INTERNAL_ERROR");
    expect(JSON.stringify(response.body)).not.toContain("email.delivered");
  });

  it("verifies the exact raw body before accepting and deduplicates retries", async () => {
    const rawBody = '{"type":"email.delivered","data":{"email_id":"email_contract"}}';
    const now = new Date("2026-10-19T18:00:00.000Z");
    const timestamp = String(Math.floor(now.getTime() / 1000));
    const id = "msg_contractevent";
    const secretBytes = Buffer.alloc(32, 8);
    const secret = `whsec_${secretBytes.toString("base64")}`;
    const signature = createHmac("sha256", secretBytes).update(`${id}.${timestamp}.${rawBody}`).digest("base64");
    let claimed = false;
    const firestore = {
      collection: (name: string) => {
        if (name !== "invitations") throw new Error("unexpected collection");
        return { where: () => ({ limit: () => ({ get: async () => ({ empty: true, size: 0, docs: [] }) }) }) };
      }
    } as unknown as Firestore;
    const app = createAdminApp({
      verifyIdToken: vi.fn(), origins: new Set([ORIGIN]), firestore, now: () => now,
      resendWebhook: {
        enabled: true, secret,
        replayStore: { claim: vi.fn(async () => claimed ? false : (claimed = true)) }
      }
    });
    const send = () => request(app).post("/api/webhooks/resend")
      .set("Content-Type", "application/json")
      .set("svix-id", id)
      .set("svix-timestamp", timestamp)
      .set("svix-signature", `v1,${signature}`)
      .send(rawBody);
    const first = await send();
    const duplicate = await send();
    expect(first.status).toBe(200);
    expect(first.body.data).toEqual({ accepted: true, matched: false });
    expect(duplicate.status).toBe(200);
    expect(duplicate.body.data).toEqual({ accepted: true, duplicate: true });
  });

  it("rejects a signature created over a different body", async () => {
    const secretBytes = Buffer.alloc(32, 9);
    const secret = `whsec_${secretBytes.toString("base64")}`;
    const timestamp = String(Math.floor(NOW.getTime() / 1000));
    const id = "msg_modifiedbody";
    const signature = createHmac("sha256", secretBytes).update(`${id}.${timestamp}.different`).digest("base64");
    const app = createAdminApp({
      verifyIdToken: vi.fn(), origins: new Set([ORIGIN]), firestore: {} as Firestore, now: () => NOW,
      resendWebhook: { enabled: true, secret, replayStore: { claim: vi.fn(async () => true) } }
    });
    const response = await request(app).post("/api/webhooks/resend")
      .set("Content-Type", "application/json")
      .set("svix-id", id).set("svix-timestamp", timestamp).set("svix-signature", `v1,${signature}`)
      .send('{"type":"email.failed","data":{"email_id":"email_1"}}');
    expect(response.status).toBe(400);
    expect(response.body.error.code).toBe("VALIDATION_ERROR");
  });

  it("returns a retryable server error and releases the claim after a processing failure", async () => {
    const rawBody = '{"type":"email.failed","data":{"email_id":"email_retry"}}';
    const timestamp = String(Math.floor(NOW.getTime() / 1000));
    const id = "msg_retryableevent";
    const secretBytes = Buffer.alloc(32, 10);
    const secret = `whsec_${secretBytes.toString("base64")}`;
    const signature = createHmac("sha256", secretBytes).update(`${id}.${timestamp}.${rawBody}`).digest("base64");
    let available = true;
    let failOnce = true;
    const replayStore = {
      claim: vi.fn(async () => available ? (available = false, true) : false),
      complete: vi.fn(async () => undefined),
      release: vi.fn(async () => { available = true; })
    };
    const firestore = {
      collection: () => ({ where: () => ({ limit: () => ({ get: async () => {
        if (failOnce) { failOnce = false; throw new Error("temporary firestore failure"); }
        return { empty: true, size: 0, docs: [] };
      } }) }) })
    } as unknown as Firestore;
    const app = createAdminApp({
      verifyIdToken: vi.fn(), origins: new Set([ORIGIN]), firestore, now: () => NOW,
      resendWebhook: { enabled: true, secret, replayStore }
    });
    const send = () => request(app).post("/api/webhooks/resend").set("Content-Type", "application/json")
      .set("svix-id", id).set("svix-timestamp", timestamp).set("svix-signature", `v1,${signature}`).send(rawBody);
    expect((await send()).status).toBe(503);
    expect(replayStore.release).toHaveBeenCalledWith(id);
    expect((await send()).status).toBe(200);
    expect(replayStore.complete).toHaveBeenCalledWith(id);
  });
});

describe("public registration surface", () => {
  it("does not expose account creation or administrative-claim endpoints", async () => {
    const { app, verifier } = testApp();
    for (const path of ["/api/invitations", "/api/register", "/api/signup", "/api/users", "/api/claims"]) {
      const response = await request(app).post(path).send({ email: "attacker@example.test", super_admin: true });
      expect(response.status).toBe(404);
    }
    const protectedInvitation = await request(app).post("/api/admin/invitations").send({ email: "attacker@example.test" });
    expect(protectedInvitation.status).toBe(401);
    expect(verifier).not.toHaveBeenCalled();
  });
});

describe("admin user API", () => {
  it("returns a sanitized protected account by uid", async () => {
    const firestore = {
      collection: () => ({
        doc: (uid: string) => ({ id: uid, get: async () => ({ id: uid, exists: false, data: () => undefined }) })
      })
    } as unknown as Firestore;
    const userDirectory = {
      listUsers: vi.fn(),
      getUser: vi.fn().mockResolvedValue({
        uid: "protected-admin",
        email: "admin@plcocina.com",
        displayName: "Admin",
        emailVerified: true,
        disabled: false,
        customClaims: { super_admin: true, privateFlag: "not-public" },
        metadata: { creationTime: "2026-10-01T00:00:00.000Z" },
        passwordHash: "must-not-leak"
      }),
      getUserByEmail: vi.fn(),
      getUsers: vi.fn(),
      updateUser: vi.fn(),
      revokeRefreshTokens: vi.fn(),
      createUser: vi.fn()
    };
    const app = createAdminApp({ verifyIdToken: vi.fn().mockResolvedValue(token()), origins: new Set([ORIGIN]), firestore, userDirectory });
    const response = await request(app)
      .get("/api/admin/users/protected-admin")
      .set("Origin", ORIGIN)
      .set("Authorization", "Bearer valid-token");

    expect(response.status).toBe(200);
    expect(response.body.data).toMatchObject({ uid: "protected-admin", isProtected: true, integrity: "missing_profile" });
    expect(response.body.data).not.toHaveProperty("customClaims");
    expect(response.body.data).not.toHaveProperty("passwordHash");
  });

  it("requires an idempotency key before a user mutation can reach Firestore", async () => {
    const target = {
      uid: "common-user",
      email: "user@plcocina.com",
      displayName: "Usuario",
      emailVerified: true,
      disabled: false,
      metadata: { creationTime: "2026-10-01T00:00:00.000Z" }
    };
    const userDirectory = {
      listUsers: vi.fn(),
      getUser: vi.fn().mockResolvedValue(target),
      getUserByEmail: vi.fn(),
      getUsers: vi.fn(),
      updateUser: vi.fn(),
      revokeRefreshTokens: vi.fn(),
      createUser: vi.fn()
    };
    const app = createAdminApp({
      verifyIdToken: vi.fn().mockResolvedValue(token()),
      origins: new Set([ORIGIN]),
      firestore: {} as Firestore,
      userDirectory,
      protectedSuperAdminUid: "protected-admin"
    });
    const response = await request(app)
      .post("/api/admin/users/common-user/suspend")
      .set("Origin", ORIGIN)
      .set("Authorization", "Bearer valid-token")
      .send({ expectedRevision: 1, reason: "Incidente de seguridad" });

    expect(response.status).toBe(400);
    expect(response.body.error.code).toBe("IDEMPOTENCY_REQUIRED");
    expect(userDirectory.updateUser).not.toHaveBeenCalled();
    expect(response.body).not.toHaveProperty("customClaims");
  });

  it("rejects a revoked token before a session revocation operation", async () => {
    const verifier = vi.fn().mockRejectedValue(authError("auth/id-token-revoked"));
    const { app } = testApp(verifier);
    const response = await request(app)
      .post("/api/admin/users/common-user/revoke-sessions")
      .set("Authorization", "Bearer revoked-token")
      .set("Idempotency-Key", "11111111-1111-4111-8111-111111111111")
      .send({ expectedRevision: 1, reason: "Cierre preventivo" });
    expect(response.status).toBe(401);
    expect(response.body.error.code).toBe("TOKEN_REVOKED");
    expect(verifier).toHaveBeenCalledWith("revoked-token", true);
  });
});

describe("admin invitation API", () => {
  it("fails closed while protected keys and the approved provider are unavailable", async () => {
    const { app, verifier } = testApp();
    const response = await request(app)
      .post("/api/admin/invitations")
      .set("Authorization", "Bearer valid-token")
      .set("Idempotency-Key", "11111111-1111-4111-8111-111111111111")
      .send({ displayName: "Invitado", email: "outside@example.net" });
    expect(response.status).toBe(503);
    expect(response.body.error.code).toBe("INTERNAL_ERROR");
    expect(JSON.stringify(response.body)).not.toContain("outside@example.net");
    expect(verifier).toHaveBeenCalledWith("valid-token", true);
  });

  it.each(["resend", "revoke"])("authenticates %s before invitation lifecycle work", async (action) => {
    const verifier = vi.fn().mockRejectedValue(authError("auth/id-token-revoked"));
    const { app } = testApp(verifier);
    const response = await request(app)
      .post(`/api/admin/invitations/11111111-1111-4111-8111-111111111111/${action}`)
      .set("Authorization", "Bearer revoked-token")
      .set("Idempotency-Key", "22222222-2222-4222-8222-222222222222")
      .send(action === "revoke" ? { expectedRevision: 1, reason: "Retiro autorizado" } : { expectedRevision: 1 });
    expect(response.status).toBe(401);
    expect(response.body.error.code).toBe("TOKEN_REVOKED");
    expect(verifier).toHaveBeenCalledWith("revoked-token", true);
  });
});

describe("public invitation acceptance API", () => {
  it("does not require authentication for validation and fails closed without protected keys", async () => {
    const { app, verifier } = testApp();
    const response = await request(app)
      .post("/api/invitations/validate")
      .send({ invitationId: "11111111-1111-4111-8111-111111111111", token: "A".repeat(43) });
    expect(response.status).toBe(503);
    expect(response.body.error.code).toBe("INTERNAL_ERROR");
    expect(verifier).not.toHaveBeenCalled();
  });

  it("verifies a non-revoked Firebase token for confirmation without requiring Super Admin", async () => {
    const verifier = vi.fn().mockResolvedValue(token({ uid: "invited-user", sub: "invited-user", email: "invited@example.net", super_admin: false }));
    const { app } = testApp(verifier);
    const response = await request(app)
      .post("/api/invitations/11111111-1111-4111-8111-111111111111/confirm")
      .set("Authorization", "Bearer invited-token");
    expect(response.status).toBe(503);
    expect(response.body.error.code).toBe("INTERNAL_ERROR");
    expect(verifier).toHaveBeenCalledWith("invited-token", true);
  });

  it("rejects a revoked session before confirmation", async () => {
    const verifier = vi.fn().mockRejectedValue(authError("auth/id-token-revoked"));
    const { app } = testApp(verifier);
    const response = await request(app)
      .post("/api/invitations/11111111-1111-4111-8111-111111111111/confirm")
      .set("Authorization", "Bearer revoked-token");
    expect(response.status).toBe(401);
    expect(response.body.error.code).toBe("TOKEN_REVOKED");
  });
});

describe("admin API transport controls", () => {
  it("returns an authenticated health response", async () => {
    const { app } = testApp();
    const response = await request(app)
      .get("/api/admin/health")
      .set("Origin", ORIGIN)
      .set("Authorization", "Bearer valid-token");

    expect(response.status).toBe(200);
    expect(response.body.data).toEqual({
      status: "ok",
      service: "admin-api",
      version: "2C-C7",
      region: "us-central1",
      checkedAt: NOW.toISOString()
    });
    expect(response.headers["access-control-allow-origin"]).toBe(ORIGIN);
    expect(response.headers["x-content-type-options"]).toBe("nosniff");
    expect(response.body.requestId).toMatch(/^[0-9a-f-]{36}$/);
  });

  it("rejects unapproved browser origins before authentication", async () => {
    const { app, verifier } = testApp();
    const response = await request(app)
      .get("/api/admin/health")
      .set("Origin", "https://attacker.example")
      .set("Authorization", "Bearer valid-token");

    expect(response.status).toBe(403);
    expect(response.body.error.code).toBe("ORIGIN_FORBIDDEN");
    expect(verifier).not.toHaveBeenCalled();
  });

  it("answers allowed CORS preflight without exposing data", async () => {
    const { app, verifier } = testApp();
    const response = await request(app)
      .options("/api/admin/me")
      .set("Origin", ORIGIN)
      .set("Access-Control-Request-Method", "GET");

    expect(response.status).toBe(204);
    expect(response.headers["access-control-allow-origin"]).toBe(ORIGIN);
    expect(verifier).not.toHaveBeenCalled();
  });

  it("returns a consistent error for unsupported methods", async () => {
    const { app, verifier } = testApp();
    const response = await request(app)
      .post("/api/admin/me")
      .set("Origin", ORIGIN)
      .set("Authorization", "Bearer valid-token");

    expect(response.status).toBe(405);
    expect(response.body).toMatchObject({
      ok: false,
      error: { code: "METHOD_NOT_ALLOWED" }
    });
    expect(verifier).not.toHaveBeenCalled();
  });
});

describe("public application catalog", () => {
  it("returns only active public applications, sorted and without administrative fields", async () => {
    const records = [
      { appId: "private", slug: "private", name: "Privada", normalizedName: "privada", description: "", category: "Admin", normalizedCategory: "admin", launchUrl: "https://private.example.com/", normalizedLaunchUrl: "https://private.example.com/", status: "active", accessLevel: "private", iconKey: null, displayOrder: 0, revision: 1 },
      { appId: "draft", slug: "draft", name: "Borrador", normalizedName: "borrador", description: "", category: "Admin", normalizedCategory: "admin", launchUrl: "https://draft.example.com/", normalizedLaunchUrl: "https://draft.example.com/", status: "draft", accessLevel: "public", iconKey: null, displayOrder: 1, revision: 1 },
      { appId: "burritos", slug: "calculadora-burritos", name: "Calculadora de Burritos", normalizedName: "calculadora de burritos", description: "Calcula ingredientes.", category: "Producción", normalizedCategory: "produccion", launchUrl: "https://calculadora-burritos.plcocina.com/", normalizedLaunchUrl: "https://calculadora-burritos.plcocina.com/", status: "active", accessLevel: "public", iconKey: "burrito", displayOrder: 20, revision: 4 },
      { appId: "reports", slug: "reportes-mensuales-2026", name: "Reportes Mensuales 2026", normalizedName: "reportes mensuales 2026", description: "Consulta indicadores.", category: "Reportes", normalizedCategory: "reportes", launchUrl: "https://reportes-mensuales-2026.plcocina.com/", normalizedLaunchUrl: "https://reportes-mensuales-2026.plcocina.com/", status: "active", accessLevel: "public", iconKey: "reports", displayOrder: 10, revision: 3 },
      { appId: "inactive", slug: "inactive", name: "Inactiva", normalizedName: "inactiva", description: "", category: "Admin", normalizedCategory: "admin", launchUrl: "https://inactive.example.com/", normalizedLaunchUrl: "https://inactive.example.com/", status: "inactive", accessLevel: "public", iconKey: null, displayOrder: 2, revision: 1 },
      { appId: "archived", slug: "archived", name: "Archivada", normalizedName: "archivada", description: "", category: "Admin", normalizedCategory: "admin", launchUrl: "https://archived.example.com/", normalizedLaunchUrl: "https://archived.example.com/", status: "archived", accessLevel: "public", iconKey: null, displayOrder: 3, revision: 1 }
    ];
    const firestore = {
      collection: () => ({
        orderBy: () => ({
          limit: () => ({
            get: async () => ({ docs: records.map((record) => ({ data: () => record })) })
          })
        })
      })
    } as unknown as Firestore;
    const app = createAdminApp({ verifyIdToken: vi.fn(), origins: new Set([ORIGIN]), firestore });
    const response = await request(app).get("/api/catalog/applications").set("Origin", ORIGIN);

    expect(response.status).toBe(200);
    expect(response.body.data.map((application: { name: string }) => application.name)).toEqual([
      "Reportes Mensuales 2026",
      "Calculadora de Burritos"
    ]);
    expect(response.body.data[0]).toEqual({
      appId: "reports",
      slug: "reportes-mensuales-2026",
      name: "Reportes Mensuales 2026",
      description: "Consulta indicadores.",
      category: "Reportes",
      launchUrl: "https://reportes-mensuales-2026.plcocina.com/",
      iconKey: "reports",
      displayOrder: 10
    });
    expect(response.body.data[0]).not.toHaveProperty("revision");
    expect(response.body.data[0]).not.toHaveProperty("accessLevel");
    expect(response.body.data[0]).not.toHaveProperty("status");
  });
});
