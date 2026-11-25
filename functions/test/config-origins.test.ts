import { describe, expect, it, vi } from "vitest";
import request from "supertest";
import { createAdminApp } from "../src/app.js";
import { allowedOrigins } from "../src/config.js";

const PILOT_ORIGIN = "https://localhost:8443";
const PRODUCTION_ORIGIN = "https://apps.plcocina.com";

function postValidation() {
  const app = createAdminApp({
    verifyIdToken: vi.fn(),
    origins: allowedOrigins()
  });
  return request(app)
    .post("/api/invitations/validate")
    .set("Origin", PILOT_ORIGIN)
    .send({});
}

describe("allowedOrigins for the local pilot", () => {
  it("allows the portal POST only while Functions Emulator is enabled", async () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("FUNCTIONS_EMULATOR", "true");

    const emulatorResponse = await postValidation();
    expect(emulatorResponse.status).toBe(503);
    expect(emulatorResponse.body.error.code).toBe("INTERNAL_ERROR");
    expect(emulatorResponse.headers["access-control-allow-origin"]).toBe(PILOT_ORIGIN);
    expect(allowedOrigins().has(PRODUCTION_ORIGIN)).toBe(true);

    vi.stubEnv("FUNCTIONS_EMULATOR", "false");
    const nonEmulatorResponse = await postValidation();
    expect(nonEmulatorResponse.status).toBe(403);
    expect(nonEmulatorResponse.body.error.code).toBe("ORIGIN_FORBIDDEN");
    expect(allowedOrigins().has(PRODUCTION_ORIGIN)).toBe(true);
    expect(allowedOrigins().has(PILOT_ORIGIN)).toBe(false);
  });
});
