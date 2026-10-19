import { Timestamp } from "firebase-admin/firestore";
import { describe, expect, it } from "vitest";
import {
  accessGrantDocumentSchema,
  applicationDocumentSchema,
  invitationDocumentSchema,
  userDocumentSchema
} from "../src/models/admin-collections.js";

const now = Timestamp.fromDate(new Date("2026-10-19T18:00:00.000Z"));

describe("administrative collection models", () => {
  it("validates a user and normalizes email", () => {
    const parsed = userDocumentSchema.parse({
      email: "User@Example.com",
      normalizedEmail: "User@Example.com",
      displayName: "Usuario",
      status: "invited",
      authDisabled: false,
      invitationStatus: "pending",
      createdAt: now,
      createdBy: "admin-uid",
      updatedAt: now,
      updatedBy: "admin-uid",
      version: 1
    });
    expect(parsed.normalizedEmail).toBe("user@example.com");
  });

  it("requires HTTPS application URLs", () => {
    const result = applicationDocumentSchema.safeParse({
      slug: "reportes",
      name: "Reportes",
      description: "Reportes privados",
      launchUrl: "http://example.com",
      status: "active",
      accessMode: "restricted",
      iconKey: "chart",
      displayOrder: 10,
      createdAt: now,
      createdBy: "admin-uid",
      updatedAt: now,
      updatedBy: "admin-uid",
      version: 1
    });
    expect(result.success).toBe(false);
  });

  it("rejects an inconsistent normalized email", () => {
    const result = userDocumentSchema.safeParse({
      email: "first@example.com",
      normalizedEmail: "second@example.com",
      displayName: "Usuario",
      status: "active",
      authDisabled: false,
      invitationStatus: "accepted",
      createdAt: now,
      createdBy: "admin-uid",
      updatedAt: now,
      updatedBy: "admin-uid",
      version: 1
    });
    expect(result.success).toBe(false);
  });

  it("requires complete revocation metadata", () => {
    const result = accessGrantDocumentSchema.safeParse({
      uid: "user-uid",
      appId: "reports",
      status: "revoked",
      grantedAt: now,
      grantedBy: "admin-uid",
      validFrom: now,
      validUntil: null,
      revokedAt: null,
      revokedBy: null,
      revokeReason: null,
      updatedAt: now,
      version: 1
    });
    expect(result.success).toBe(false);
  });

  it("rejects unknown invitation fields", () => {
    const result = invitationDocumentSchema.safeParse({
      normalizedEmail: "user@example.com",
      uid: "user-uid",
      status: "pending",
      expiresAt: now,
      createdAt: now,
      createdBy: "admin-uid",
      deliveredAt: null,
      acceptedAt: null,
      revokedAt: null,
      invitationLink: "sensitive",
      version: 1
    });
    expect(result.success).toBe(false);
  });
});
