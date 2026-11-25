import type { DecodedIdToken } from "firebase-admin/auth";
import { Timestamp } from "firebase-admin/firestore";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createAdminApp } from "../src/app.js";
import { GoogleBootstrapPreparationError } from "../src/identities/identity-google-bootstrap-preparation-service.js";

const invitationId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const idempotencyKey = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
function app(preparation = vi.fn().mockResolvedValue({ authorizationId: invitationId }), issue = vi.fn().mockResolvedValue({
  expiresAt: Timestamp.fromDate(new Date("2026-11-24T17:30:00.000Z")), nonce: "never-returned", state: "never-returned"
}), verifyIdToken = vi.fn().mockResolvedValue({ uid: "protected-admin", sub: "protected-admin", super_admin: true } as DecodedIdToken)) {
  const value = createAdminApp({ verifyIdToken, origins: new Set(["https://localhost:8443"]),
    localInvitationAccessEnabled: true, protectedSuperAdminUid: "protected-admin",
    googleBootstrapPreparationService: () => ({ prepareLatestForInvitation: preparation } as never),
    googleBootstrapComposition: () => ({ issue } as never) });
  return { value, preparation, issue, verifyIdToken };
}
const post = (value: ReturnType<typeof app>["value"], token = "admin") => request(value)
  .post("/api/admin/identities/google-bootstrap/continue").set("Origin", "https://localhost:8443")
  .set("Authorization", `Bearer ${token}`).send({ invitationId, idempotencyKey });

describe("local Google Workspace continuation", () => {
  it("prepares and issues via existing services, returning status and expiry only", async () => {
    const f = app(); const response = await post(f.value);
    expect(response.status).toBe(200);
    expect(response.body.data).toEqual({ state: "challenge_issued", expiresAt: "2026-11-24T17:30:00.000Z" });
    expect(JSON.stringify(response.body)).not.toMatch(/nonce|never-returned|state.*never-returned/i);
    expect(f.preparation).toHaveBeenCalledWith(invitationId, expect.objectContaining({ superAdmin: true }));
    expect(f.issue).toHaveBeenCalledWith(expect.objectContaining({ authorizationId: invitationId, idempotencyKey }));
  });
  it("reports expired proof without issuing a Challenge", async () => {
    const prepare = vi.fn().mockRejectedValue(new GoogleBootstrapPreparationError("PROOF_EXPIRED"));
    const f = app(prepare); const response = await post(f.value);
    expect(response.status).toBe(409);
    expect(response.body.error.message).toBe("Es necesario repetir la verificación inicial con Google.");
    expect(f.issue).not.toHaveBeenCalled();
  });
  it("requires an authenticated Super Admin", async () => {
    const verify = vi.fn().mockRejectedValue(Object.assign(new Error("invalid"), { code: "auth/invalid-id-token" }));
    const f = app(undefined, undefined, verify); const response = await post(f.value);
    expect(response.status).toBe(401);
    expect(f.preparation).not.toHaveBeenCalled();
    expect(f.issue).not.toHaveBeenCalled();
  });
});
