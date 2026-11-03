import { randomUUID } from "node:crypto";
import { Timestamp, type Firestore } from "firebase-admin/firestore";
import { describe, expect, it } from "vitest";
import { identityCreateInputSchema, identityUpdateInputSchema } from "../src/identities/identity-contracts.js";
import {
  googleWorkspaceUserV21DocumentSchema,
  identifierKeyHash,
  normalizeGoogleSubject,
  normalizeWorkspaceDomain,
  userV21DocumentSchema
} from "../src/identities/identity-models.js";
import { IdentityReservationService } from "../src/identities/identity-reservation-service.js";
import { IdentityBlockingService, type IdentityBlockingStore } from "../src/identities/identity-blocking-service.js";
import { userDocumentSchema } from "../src/models/admin-collections.js";

const now = Timestamp.fromDate(new Date("2026-11-03T16:00:00.000Z"));
const pepper = Buffer.alloc(32, 0x31);

function declaredGoogle(overrides: Record<string, unknown> = {}) {
  return {
    uid: "employee-google-1",
    displayName: "Empleado Workspace",
    status: "invited",
    authDisabled: true,
    invitationStatus: "pending",
    authMethod: "googleWorkspace",
    phoneE164: null,
    normalizedPhone: null,
    email: "employee@plcocina.com",
    normalizedEmail: "employee@plcocina.com",
    phoneVerifiedAt: null,
    emailVerifiedAt: null,
    googleWorkspace: {
      authorizedDomain: "plcocina.com",
      subject: null,
      linkingStatus: "declared",
      verificationStatus: "unverified",
      verifiedAt: null,
      linkedAt: null,
      verificationRevision: 1,
      operationId: null
    },
    activationStatus: "pending",
    credentialRevision: 1,
    authorizationRevision: 1,
    sessionValidAfter: now,
    createdAt: now,
    createdBy: "protected-admin",
    updatedAt: now,
    updatedBy: "protected-admin",
    revision: 1,
    pendingOperationId: null,
    identityContractVersion: "2.1",
    version: 2,
    ...overrides
  };
}

function linkedGoogle(overrides: Record<string, unknown> = {}) {
  return declaredGoogle({
    status: "active",
    authDisabled: false,
    invitationStatus: "accepted",
    emailVerifiedAt: now,
    googleWorkspace: {
      authorizedDomain: "plcocina.com",
      subject: "10769150350006150715113082367",
      linkingStatus: "linked",
      verificationStatus: "verified",
      verifiedAt: now,
      linkedAt: now,
      verificationRevision: 2,
      operationId: null
    },
    activationStatus: "active",
    credentialRevision: 2,
    revision: 2,
    ...overrides
  });
}

class FakeRef { constructor(readonly path: string) {} }
class FakeFirestore {
  readonly data = new Map<string, Record<string, unknown>>();
  collection(name: string) { return { doc: (id: string) => new FakeRef(`${name}/${id}`) }; }
  async runTransaction<T>(work: (transaction: ReturnType<FakeFirestore["transaction"]>) => Promise<T>) {
    return work(this.transaction());
  }
  transaction() {
    return {
      get: async (ref: FakeRef) => ({ exists: this.data.has(ref.path), data: () => this.data.get(ref.path) }),
      set: (ref: FakeRef, value: Record<string, unknown>) => this.data.set(ref.path, value),
      create: (ref: FakeRef, value: Record<string, unknown>) => {
        if (this.data.has(ref.path)) throw new Error("already exists");
        this.data.set(ref.path, value);
      }
    };
  }
}

describe("Google Workspace identity v2.1 contracts", () => {
  it("represents a declared pending identity without treating it as verified or linked", () => {
    const parsed = googleWorkspaceUserV21DocumentSchema.parse(declaredGoogle());
    expect(parsed.uid).toBe("employee-google-1");
    expect(parsed.googleWorkspace).toMatchObject({ subject: null, linkingStatus: "declared", verificationStatus: "unverified" });
  });

  it("accepts an active identity only after subject verification and linking", () => {
    const parsed = googleWorkspaceUserV21DocumentSchema.parse(linkedGoogle());
    expect(parsed.activationStatus).toBe("active");
    expect(parsed.googleWorkspace.subject).toBe("10769150350006150715113082367");
  });

  it("rejects active, incomplete, mismatched and administratively elevated identities", () => {
    expect(googleWorkspaceUserV21DocumentSchema.safeParse(declaredGoogle({
      status: "active", authDisabled: false, activationStatus: "active"
    })).success).toBe(false);
    expect(googleWorkspaceUserV21DocumentSchema.safeParse(linkedGoogle({
      googleWorkspace: { ...linkedGoogle().googleWorkspace as object, subject: null }
    })).success).toBe(false);
    expect(googleWorkspaceUserV21DocumentSchema.safeParse(declaredGoogle({ normalizedEmail: "other@plcocina.com" })).success).toBe(false);
    expect(googleWorkspaceUserV21DocumentSchema.safeParse(declaredGoogle({
      email: "employee@other.test", normalizedEmail: "employee@other.test"
    })).success).toBe(false);
    expect(googleWorkspaceUserV21DocumentSchema.safeParse(declaredGoogle({ super_admin: true })).success).toBe(false);
  });

  it("requires reconciliation state, operation and positive revisions to agree", () => {
    const operationId = randomUUID();
    const valid = declaredGoogle({
      activationStatus: "reconciliation_required",
      googleWorkspace: {
        authorizedDomain: "plcocina.com", subject: null,
        linkingStatus: "reconciliation_required", verificationStatus: "reconciliation_required",
        verifiedAt: null, linkedAt: null, verificationRevision: 3, operationId
      },
      pendingOperationId: operationId,
      revision: 3
    });
    expect(googleWorkspaceUserV21DocumentSchema.safeParse(valid).success).toBe(true);
    expect(googleWorkspaceUserV21DocumentSchema.safeParse(declaredGoogle({
      activationStatus: "reconciliation_required"
    })).success).toBe(false);
    expect(googleWorkspaceUserV21DocumentSchema.safeParse(declaredGoogle({ credentialRevision: 0 })).success).toBe(false);
  });

  it("normalizes declared email and Workspace domain without claiming verification", () => {
    const parsed = identityCreateInputSchema.parse({
      displayName: "Empleado", authMethod: "googleWorkspace", phone: null,
      email: " Employee@PLCOCINA.COM ", workspaceDomain: " PLCocina.COM "
    });
    expect(parsed).toMatchObject({ email: "employee@plcocina.com", workspaceDomain: "plcocina.com" });
    expect(normalizeWorkspaceDomain(" Sub.Example.COM ")).toBe("sub.example.com");
    expect(() => normalizeWorkspaceDomain("@plcocina.com")).toThrow("INVALID_WORKSPACE_DOMAIN");
    expect(normalizeGoogleSubject(" 10769150350006150715113082367 ")).toBe("10769150350006150715113082367");
  });

  it("rejects invalid method/identifier combinations and prevents UID changes through update contracts", () => {
    expect(identityCreateInputSchema.safeParse({
      displayName: "Empleado", authMethod: "googleWorkspace", phone: "+528112345678",
      email: "employee@plcocina.com", workspaceDomain: "plcocina.com"
    }).success).toBe(false);
    expect(identityCreateInputSchema.safeParse({
      displayName: "Empleado", authMethod: "googleWorkspace", phone: null,
      email: "employee@plcocina.com", workspaceDomain: "invalid_domain"
    }).success).toBe(false);
    expect(identityCreateInputSchema.safeParse({
      displayName: "Empleado", authMethod: "googleWorkspace", phone: null,
      email: "employee@other.test", workspaceDomain: "plcocina.com"
    }).success).toBe(false);
    expect(identityUpdateInputSchema.safeParse({ expectedRevision: 1, reason: "cambio", uid: "other-uid" }).success).toBe(false);
  });

  it("keeps SMS, Email Link and password v1 contracts compatible", () => {
    expect(identityCreateInputSchema.safeParse({ displayName: "SMS", authMethod: "sms", phone: "+528112345678", email: null }).success).toBe(true);
    expect(identityCreateInputSchema.safeParse({ displayName: "Email", authMethod: "email", phone: null, email: "user@example.test" }).success).toBe(true);
    expect(userV21DocumentSchema.safeParse({
      displayName: "SMS", status: "invited", authDisabled: true, invitationStatus: "pending",
      authMethod: "sms", phoneE164: "+528112345678", normalizedPhone: "+528112345678",
      email: null, normalizedEmail: null, phoneVerifiedAt: null, emailVerifiedAt: null,
      activationStatus: "pending", credentialRevision: 1, authorizationRevision: 1, sessionValidAfter: now,
      createdAt: now, createdBy: "admin", updatedAt: now, updatedBy: "admin", revision: 1,
      pendingOperationId: null, version: 2
    }).success).toBe(true);
    expect(userDocumentSchema.safeParse({
      email: "legacy@example.test", normalizedEmail: "legacy@example.test", displayName: "Legacy",
      status: "active", authDisabled: false, invitationStatus: "accepted", createdAt: now,
      createdBy: "admin", updatedAt: now, updatedBy: "admin", revision: 1,
      pendingOperationId: null, version: 1
    }).success).toBe(true);
  });

  it("preserves the protected Super Admin password-only invariant", async () => {
    const store: IdentityBlockingStore = {
      getProfile: async () => null,
      hasReconciliation: async () => false,
      hasValidV1Invitation: async () => false
    };
    const service = new IdentityBlockingService(store, "protected-admin", () => now);
    const admin = {
      uid: "protected-admin", email: "admin@plcocina.com", emailVerified: true,
      disabled: false, customClaims: { super_admin: true }
    };
    await expect(service.beforeSignIn(admin, { signInMethod: "password" })).resolves.toBeUndefined();
    await expect(service.beforeSignIn(admin, { providerId: "google.com" })).rejects.toMatchObject({ code: "SUPER_ADMIN_INVALID" });
  });
});

describe("Google subject reservations", () => {
  it("preserves exact subject semantics, replays idempotently and rejects a second UID", async () => {
    const db = new FakeFirestore();
    const service = new IdentityReservationService(db as unknown as Firestore, pepper, () => now);
    const operationId = randomUUID();
    const subject = "10769150350006150715113082367";
    const first = await service.reserve({ operationId, uid: "employee-google-1", kind: "googleSubject", value: subject });
    const replay = await service.reserve({ operationId, uid: "employee-google-1", kind: "googleSubject", value: ` ${subject} ` });
    expect(first.identifierHash).toBe(identifierKeyHash("googleSubject", subject, pepper));
    expect(replay.replayed).toBe(true);
    await expect(service.reserve({
      operationId: randomUUID(), uid: "employee-google-2", kind: "googleSubject", value: subject
    })).rejects.toMatchObject({ code: "IDENTIFIER_COLLISION" });
    expect(JSON.stringify([...db.data.values()])).not.toContain(subject);
  });

  it("rejects operation reuse with a different subject or UID", async () => {
    const db = new FakeFirestore();
    const service = new IdentityReservationService(db as unknown as Firestore, pepper, () => now);
    const operationId = randomUUID();
    await service.reserve({ operationId, uid: "stable-uid", kind: "googleSubject", value: "subject-1" });
    await expect(service.reserve({ operationId, uid: "stable-uid", kind: "googleSubject", value: "subject-2" }))
      .rejects.toMatchObject({ code: "IDEMPOTENCY_CONFLICT" });
  });
});
