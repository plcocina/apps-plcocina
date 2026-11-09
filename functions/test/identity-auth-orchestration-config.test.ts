import { describe, expect, it, vi } from "vitest";
import { resolveInternalAuthOrchestrationConfiguration } from
  "../src/identities/identity-auth-orchestration-config.js";
import { createInternalAuthOrchestrationService } from
  "../src/identities/identity-auth-orchestration-composition.js";
import type { Firestore } from "firebase-admin/firestore";

const pepper = Buffer.alloc(32, 0x73);
const complete = {
  googleAudiences: ["portal.apps.googleusercontent.com"],
  googleAuthorizedParties: ["portal.apps.googleusercontent.com"],
  googleWorkspaceDomain: "plcocina.com",
  identifierPepperBase64: pepper.toString("base64"),
  protectedSuperAdminUid: "protected-super-admin"
} as const;

describe("internal auth orchestration configuration", () => {
  it("resolves complete trusted server configuration for the E3B-E5D2 composition", () => {
    const configuration = resolveInternalAuthOrchestrationConfiguration(complete);
    expect(configuration).toMatchObject({
      googleTokenVerifier: {
        allowedAudiences: complete.googleAudiences,
        allowedAuthorizedParties: complete.googleAuthorizedParties,
        allowedWorkspaceDomains: [complete.googleWorkspaceDomain],
        requireAuthorizedParty: true
      },
      protectedSuperAdminUid: complete.protectedSuperAdminUid
    });
    expect(configuration.identifierPepper.equals(pepper)).toBe(true);
    expect(() => createInternalAuthOrchestrationService({} as Firestore, configuration)).not.toThrow();
  });

  it.each([
    { ...complete, googleAudiences: [] },
    { ...complete, googleAuthorizedParties: [" duplicated "] },
    { ...complete, googleWorkspaceDomain: "PLCOCINA.COM" },
    { ...complete, identifierPepperBase64: Buffer.alloc(8).toString("base64") },
    { ...complete, protectedSuperAdminUid: null },
    { ...complete, protectedSuperAdminUid: "invalid/uid" }
  ])("rejects incomplete or invalid configuration", (configuration) => {
    expect(() => resolveInternalAuthOrchestrationConfiguration(configuration)).toThrow(
      "AUTH_CONFIGURATION_INVALID"
    );
  });

  it("does not log or include the pepper in a rejected result", () => {
    const secret = "production-secret-that-must-never-be-exposed";
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
    const error = (() => {
      try {
        resolveInternalAuthOrchestrationConfiguration({ ...complete, identifierPepperBase64: secret });
      } catch (caught) {
        return caught;
      }
      throw new Error("expected rejection");
    })();
    expect(log).not.toHaveBeenCalled();
    expect(String(error)).not.toContain(secret);
    log.mockRestore();
  });

  it("only constructs dependencies and performs no authentication or permission operation", () => {
    const configuration = resolveInternalAuthOrchestrationConfiguration(complete);
    const firestore = new Proxy({}, {
      get: () => { throw new Error("unexpected operational access"); }
    }) as Firestore;
    expect(() => createInternalAuthOrchestrationService(firestore, configuration)).not.toThrow();
  });
});
