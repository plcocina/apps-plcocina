import type { DecodedIdToken } from "firebase-admin/auth";
import type { Firestore } from "firebase-admin/firestore";
import { createHmac } from "node:crypto";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createAdminApp } from "../src/app.js";

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
