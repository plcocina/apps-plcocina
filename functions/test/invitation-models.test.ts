import { Timestamp } from "firebase-admin/firestore";
import { describe, expect, it } from "vitest";
import { adminOperationDocumentSchema, auditEventDocumentSchema, invitationDocumentSchema, invitationUniqueKeyDocumentSchema } from "../src/models/admin-collections.js";
import { InvitationEmailProviderError, SimulatedInvitationEmailProvider } from "../src/invitations/invitation-email-provider.js";
import { canTransitionInvitation, effectiveInvitationStatus } from "../src/invitations/invitation-transitions.js";
import { InvitationTokenKeyring } from "../src/invitations/invitation-token.js";

const now = Timestamp.fromDate(new Date("2026-10-22T18:00:00.000Z"));
const later = Timestamp.fromMillis(now.toMillis() + 72 * 3_600_000);

describe("C1 invitation primitives", () => {
  it("derives a reconstructable token while storing only its hash", () => {
    const keys = new Map([[1, Buffer.alloc(32, 1)], [2, Buffer.alloc(32, 2)]]);
    const keyring = new InvitationTokenKeyring(keys, 2);
    const material = keyring.issue("11111111-1111-4111-8111-111111111111", 3, "AAAAAAAAAAAAAAAAAAAAAA");
    const reconstructed = keyring.reconstruct("11111111-1111-4111-8111-111111111111", 3, material.salt, material.keyVersion);
    expect(reconstructed).toBe(material.token);
    expect(material.hash).toMatch(/^[a-f0-9]{64}$/);
    expect(material.hash).not.toContain(material.token);
    expect(keyring.verify(material.token, material.hash)).toBe(true);
    expect(keyring.verify(`${material.token}x`, material.hash)).toBe(false);
  });

  it("supports rotation while an old key version remains available", () => {
    const old = new InvitationTokenKeyring(new Map([[1, Buffer.alloc(32, 1)]]), 1);
    const issued = old.issue("11111111-1111-4111-8111-111111111111", 1, "BBBBBBBBBBBBBBBBBBBBBB");
    const rotated = new InvitationTokenKeyring(new Map([[1, Buffer.alloc(32, 1)], [2, Buffer.alloc(32, 2)]]), 2);
    expect(rotated.reconstruct("11111111-1111-4111-8111-111111111111", 1, issued.salt, 1)).toBe(issued.token);
    expect(rotated.issue("11111111-1111-4111-8111-111111111111").keyVersion).toBe(2);
  });

  it("enforces invitation lifecycle transitions", () => {
    expect(canTransitionInvitation("provisioning", "pending_delivery")).toBe(true);
    expect(canTransitionInvitation("active", "accepting")).toBe(true);
    expect(canTransitionInvitation("accepted", "active")).toBe(false);
    expect(canTransitionInvitation("revoked", "accepted")).toBe(false);
  });

  it("validates invitation, unique reservation, generalized operation and actor types", () => {
    const invitation = invitationDocumentSchema.parse({
      invitationId: "11111111-1111-4111-8111-111111111111",
      email: "outside@example.net",
      normalizedEmail: "outside@example.net",
      displayName: "Invitado",
      uid: "inv_uid",
      status: "provisioning",
      token: { hash: "a".repeat(64), generation: 1, salt: "AAAAAAAAAAAAAAAAAAAAAA", keyVersion: 1, issuedAt: now, expiresAt: later },
      delivery: { provider: "simulated", status: "pending", idempotencyKey: "invite/1", providerMessageId: null, templateVersion: 1, firstAttemptAt: null, retryUntil: null, sentAt: null, deliveredAt: null, failureCode: null },
      expiresAt: later,
      createdAt: now,
      createdBy: "admin",
      updatedAt: now,
      updatedBy: "admin",
      pendingOperationId: null,
      consumeOperationId: null,
      consumeLeaseExpiresAt: null,
      passwordSetAt: null,
      confirmationExpiresAt: null,
      deliveredAt: null,
      acceptedAt: null,
      revokedAt: null,
      revokedBy: null,
      revokeReason: null,
      expiredAt: null,
      resendCount: 0,
      lastSentAt: null,
      revision: 1,
      version: 2
    });
    expect(invitation.token?.hash).toBe("a".repeat(64));
    expect(invitation).not.toHaveProperty("token.value");
    expect(invitationUniqueKeyDocumentSchema.safeParse({ normalizedEmailHash: "b".repeat(64), invitationId: invitation.invitationId, uid: invitation.uid, state: "reserved", createdAt: now, updatedAt: now, version: 1 }).success).toBe(true);
    expect(adminOperationDocumentSchema.safeParse({ operationId: invitation.invitationId, type: "invitation.create", targetUid: invitation.uid, invitationId: invitation.invitationId, actorUid: "admin", inputHash: "c".repeat(64), expectedRevision: null, status: "pending", checkpoint: "reserved", requestId: "22222222-2222-4222-8222-222222222222", leaseOwner: "22222222-2222-4222-8222-222222222222", leaseExpiresAt: later, attempts: 1, result: null, failureCode: null, createdAt: now, updatedAt: now, completedAt: null, version: 1 }).success).toBe(true);
    expect(auditEventDocumentSchema.safeParse({ occurredAt: now, actorType: "provider", actorUid: null, actorEmail: null, providerEventId: "evt_1", action: "invitation.delivered", resourceType: "invitation", resourceId: invitation.invitationId, targetUid: invitation.uid, appId: null, before: null, after: { status: "delivered" }, reason: null, requestId: "22222222-2222-4222-8222-222222222222", source: "admin-api", result: "success", version: 1 }).success).toBe(true);
  });

  it("simulates provider idempotency without external I/O", async () => {
    const provider = new SimulatedInvitationEmailProvider(() => new Date("2026-10-22T18:00:00Z"));
    const message = { to: "outside@example.net", displayName: "Invitado", invitationId: "id", token: "secret", expiresAt: later.toDate().toISOString(), from: "invitaciones@plcocina.com" as const, templateVersion: 1 as const, tracking: { opens: false as const, clicks: false as const } };
    const first = await provider.send(message, "invite/id/1");
    const second = await provider.send(message, "invite/id/1");
    expect(second).toEqual(first);
    expect(provider.deliveries).toHaveLength(1);
    await expect(provider.send({ ...message, displayName: "Distinto" }, "invite/id/1")).rejects.toThrow("SIMULATED_IDEMPOTENCY_CONFLICT");
  });

  it.each([
    ["rejected", "PROVIDER_REJECTED", false],
    ["timeout", "PROVIDER_TIMEOUT", true],
    ["network_error", "PROVIDER_NETWORK_ERROR", false]
  ] as const)("simulates %s without exposing the message", async (outcome, code, ambiguous) => {
    const provider = new SimulatedInvitationEmailProvider();
    provider.queueOutcome(outcome);
    const message = { to: "outside@example.net", displayName: "Invitado", invitationId: "id", token: "top-secret", expiresAt: later.toDate().toISOString(), from: "invitaciones@plcocina.com" as const, templateVersion: 1 as const, tracking: { opens: false as const, clicks: false as const } };
    const error = await provider.send(message, "invite/id/failure").catch((value) => value);
    expect(error).toBeInstanceOf(InvitationEmailProviderError);
    expect(error).toMatchObject({ code, ambiguous });
    expect(String(error)).not.toContain(message.token);
  });

  it("recovers a lost provider response with the same idempotency key", async () => {
    const provider = new SimulatedInvitationEmailProvider();
    provider.queueOutcome("response_lost");
    const message = { to: "outside@example.net", displayName: "Invitado", invitationId: "id", token: "top-secret", expiresAt: later.toDate().toISOString(), from: "invitaciones@plcocina.com" as const, templateVersion: 1 as const, tracking: { opens: false as const, clicks: false as const } };
    await expect(provider.send(message, "invite/id/lost")).rejects.toMatchObject({ code: "PROVIDER_RESPONSE_LOST", ambiguous: true });
    await expect(provider.send(message, "invite/id/lost")).resolves.toMatchObject({ messageId: expect.stringMatching(/^sim_/) });
    expect(provider.deliveries).toHaveLength(1);
  });

  it("treats elapsed invitations as expired using only the supplied server time", () => {
    const invitation = invitationDocumentSchema.parse({
      invitationId: "11111111-1111-4111-8111-111111111111", email: "outside@example.net", normalizedEmail: "outside@example.net",
      displayName: "Invitado", uid: "inv_uid", status: "active",
      token: { hash: "a".repeat(64), generation: 1, salt: "AAAAAAAAAAAAAAAAAAAAAA", keyVersion: 1, issuedAt: now, expiresAt: later },
      delivery: { provider: "simulated", status: "accepted", idempotencyKey: "invite/1", providerMessageId: "sim_1", templateVersion: 1, firstAttemptAt: now, retryUntil: later, sentAt: now, deliveredAt: null, failureCode: null },
      expiresAt: later, createdAt: now, createdBy: "admin", updatedAt: now, updatedBy: "admin", pendingOperationId: null,
      consumeOperationId: null, consumeLeaseExpiresAt: null, passwordSetAt: null, confirmationExpiresAt: null, deliveredAt: null,
      acceptedAt: null, revokedAt: null, revokedBy: null, revokeReason: null, expiredAt: null, resendCount: 0, lastSentAt: now, revision: 2, version: 2
    });
    expect(effectiveInvitationStatus(invitation, later.toMillis() - 1)).toBe("active");
    expect(effectiveInvitationStatus(invitation, later.toMillis())).toBe("expired");
  });
});
