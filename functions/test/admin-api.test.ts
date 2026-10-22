import type { DecodedIdToken } from "firebase-admin/auth";
import type { Firestore } from "firebase-admin/firestore";
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
      version: "2A",
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
