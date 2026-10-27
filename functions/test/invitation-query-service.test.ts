import type { Firestore } from "firebase-admin/firestore";
import { Timestamp } from "firebase-admin/firestore";
import { describe, expect, it } from "vitest";
import { InvitationQueryService } from "../src/invitations/invitation-query-service.js";

class FakeSnapshot {
  constructor(readonly id: string, private readonly value?: Record<string, unknown>) {}
  get exists() { return this.value !== undefined; }
  data() { return this.value; }
}

class FakeQuery {
  private after: string | null = null;
  private maximum = 25;
  private email: string | null = null;
  constructor(private readonly records: Map<string, Record<string, unknown>>) {}
  orderBy() { return this; }
  startAfter(value: string) { this.after = value; return this; }
  limit(value: number) { this.maximum = value; return this; }
  where(_field: string, _operator: string, value: string) { this.email = value; return this; }
  doc(id: string) { return { get: async () => new FakeSnapshot(id, this.records.get(id)) }; }
  async get() {
    const docs = [...this.records.entries()]
      .filter(([id, record]) => (!this.after || id > this.after) && (!this.email || record.normalizedEmail === this.email))
      .sort(([left], [right]) => left.localeCompare(right))
      .slice(0, this.maximum)
      .map(([id, record]) => new FakeSnapshot(id, record));
    return { docs };
  }
}

class FakeFirestore {
  readonly writes: unknown[] = [];
  constructor(private readonly records: Map<string, Record<string, unknown>>) {}
  collection() { return new FakeQuery(this.records); }
}

const created = Timestamp.fromDate(new Date("2026-10-20T12:00:00.000Z"));
const future = Timestamp.fromDate(new Date("2026-10-27T12:00:00.000Z"));
const past = Timestamp.fromDate(new Date("2026-10-21T12:00:00.000Z"));
const accepted = Timestamp.fromDate(new Date("2026-10-21T10:00:00.000Z"));

function invitation(id: string, email: string, overrides: Record<string, unknown> = {}) {
  return {
    invitationId: id,
    email,
    normalizedEmail: email.toLowerCase(),
    displayName: "Persona invitada",
    uid: `inv_${id.replaceAll("-", "")}`,
    status: "active",
    token: null,
    delivery: {
      provider: "simulated",
      status: "delivered",
      idempotencyKey: `delivery:${id}`,
      providerMessageId: null,
      templateVersion: 1,
      firstAttemptAt: created,
      retryUntil: future,
      sentAt: created,
      deliveredAt: created,
      failureCode: null
    },
    expiresAt: future,
    createdAt: created,
    createdBy: "admin-uid",
    updatedAt: created,
    updatedBy: "admin-uid",
    pendingOperationId: null,
    consumeOperationId: null,
    consumeLeaseExpiresAt: null,
    passwordSetAt: null,
    confirmationExpiresAt: null,
    deliveredAt: created,
    acceptedAt: null,
    revokedAt: null,
    revokedBy: null,
    revokeReason: null,
    expiredAt: null,
    resendCount: 0,
    lastSentAt: created,
    revision: 1,
    version: 2,
    ...overrides
  };
}

function setup() {
  const firstId = "11111111-1111-4111-8111-111111111111";
  const secondId = "22222222-2222-4222-8222-222222222222";
  const records = new Map<string, Record<string, unknown>>([
    [firstId, invitation(firstId, "first@plcocina.com", { expiresAt: past, delivery: { ...invitation(firstId, "first@plcocina.com").delivery as object, status: "bounced" } })],
    [secondId, invitation(secondId, "second@plcocina.com", { status: "revoked", acceptedAt: accepted, token: null, revokedAt: accepted, revokedBy: "admin-uid", revokeReason: "Solicitud cancelada" })]
  ]);
  const firestore = new FakeFirestore(records);
  return { firestore, service: new InvitationQueryService(firestore as unknown as Firestore, () => new Date("2026-10-22T12:00:00.000Z")) };
}

describe("administrative invitation queries", () => {
  it("paginates with an opaque cursor and performs no writes", async () => {
    const { firestore, service } = setup();
    const first = await service.list({ pageSize: "1" });
    expect(first.invitations).toHaveLength(1);
    expect(first.nextPageToken).toEqual(expect.any(String));
    const second = await service.list({ pageSize: "1", pageToken: first.nextPageToken! });
    expect(second.invitations[0]?.email).toBe("second@plcocina.com");
    expect(firestore.writes).toHaveLength(0);
  });

  it("searches by exact normalized email without pagination", async () => {
    const { service } = setup();
    const result = await service.list({ email: " FIRST@PLCOCINA.COM " });
    expect(result.invitations).toHaveLength(1);
    expect(result.invitations[0]?.email).toBe("first@plcocina.com");
    expect(result.nextPageToken).toBeNull();
  });

  it("returns effective expiration and keeps delivery separate from invitation status", async () => {
    const { service } = setup();
    const result = await service.get("11111111-1111-4111-8111-111111111111");
    expect(result).toMatchObject({ status: "expired", deliveryStatus: "bounced", acceptedAt: null });
  });

  it("returns revoked and accepted dates without sensitive fields", async () => {
    const { service } = setup();
    const result = await service.get("22222222-2222-4222-8222-222222222222");
    expect(result).toMatchObject({ status: "revoked", deliveryStatus: "delivered", acceptedAt: accepted.toDate().toISOString() });
    expect(result).not.toHaveProperty("token");
    expect(result).not.toHaveProperty("uid");
    expect(result).not.toHaveProperty("delivery");
    expect(result).not.toHaveProperty("revokeReason");
  });
});
