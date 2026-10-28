import type { Firestore } from "firebase-admin/firestore";
import { Timestamp } from "firebase-admin/firestore";
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { AccessGrantService } from "../src/access-grants/access-grant-service.js";
import type { DirectoryUser, UserDirectory } from "../src/users/user-query-service.js";

type RecordValue = Record<string, unknown>;

class QueryDouble {
  private readonly filters: Array<[string, unknown]>;
  private maximum = Number.MAX_SAFE_INTEGER;
  private after: [number, string] | null = null;

  constructor(private readonly db: FirestoreDouble, private readonly collectionName: string, filters: Array<[string, unknown]> = []) {
    this.filters = filters;
  }

  where(field: string, operator: string, value: unknown) {
    if (operator !== "==") throw new Error("unsupported operator");
    return new QueryDouble(this.db, this.collectionName, [...this.filters, [field, value]]);
  }

  orderBy() { return this; }
  limit(value: number) { this.maximum = value; this.db.lastLimit = value; return this; }
  startAfter(updatedAt: Timestamp, grantId: string) { this.after = [updatedAt.toMillis(), grantId]; return this; }

  async get() {
    const docs = [...this.db.data.entries()]
      .filter(([path, value]) => path.startsWith(`${this.collectionName}/`) && this.filters.every(([field, expected]) => value[field] === expected))
      .map(([path, value]) => ({ path, value, id: path.split("/").at(-1)! }))
      .sort((left, right) => {
        const time = (right.value.updatedAt as Timestamp).toMillis() - (left.value.updatedAt as Timestamp).toMillis();
        return time || right.id.localeCompare(left.id);
      })
      .filter(({ id, value }) => !this.after
        || (value.updatedAt as Timestamp).toMillis() < this.after[0]
        || ((value.updatedAt as Timestamp).toMillis() === this.after[0] && id < this.after[1]))
      .slice(0, this.maximum)
      .map(({ path }) => this.db.snapshot(path));
    return { docs };
  }
}

class FirestoreDouble {
  readonly data = new Map<string, RecordValue>();
  lastLimit = 0;
  collection(name: string) {
    return {
      doc: (id: string) => ({ get: async () => this.snapshot(`${name}/${id}`) }),
      where: (field: string, operator: string, value: unknown) => new QueryDouble(this, name).where(field, operator, value)
    };
  }
  snapshot(path: string) {
    const value = this.data.get(path);
    return { id: path.split("/").at(-1)!, exists: value !== undefined, data: () => value };
  }
}

const base = Timestamp.fromDate(new Date("2026-10-28T12:00:00.000Z"));
const user: DirectoryUser = {
  uid: "user-1", email: "user@plcocina.com", displayName: "User", emailVerified: true, disabled: false,
  metadata: { creationTime: base.toDate().toISOString() }
};

function directory(): UserDirectory {
  return {
    getUser: async (uid) => {
      if (uid !== user.uid) throw Object.assign(new Error("missing"), { code: "auth/user-not-found" });
      return user;
    },
    listUsers: async () => ({ users: [user] }), getUserByEmail: async () => user,
    getUsers: async () => ({ users: [user] }), updateUser: async () => user,
    revokeRefreshTokens: async () => undefined, createUser: async () => user
  };
}

function setup(grants: Array<{ app: string; status: "active" | "revoked"; offset: number }> = []) {
  const db = new FirestoreDouble();
  db.data.set("users/user-1", {
    email: user.email, normalizedEmail: user.email, displayName: "User", status: "active", authDisabled: false,
    invitationStatus: "accepted", createdAt: base, createdBy: "admin", updatedAt: base, updatedBy: "admin",
    revision: 1, pendingOperationId: null, version: 1
  });
  db.data.set("applications/app-main", {
    appId: "app-main", slug: "app-main", name: "Main", normalizedName: "main", description: "", category: "Ops",
    normalizedCategory: "ops", launchUrl: "https://main.example.com/", normalizedLaunchUrl: "https://main.example.com/",
    status: "active", accessLevel: "private", iconKey: null, displayOrder: 0, createdAt: base, createdBy: "admin",
    updatedAt: base, updatedBy: "admin", revision: 1, version: 1
  });
  for (const grant of grants) {
    const updatedAt = Timestamp.fromMillis(base.toMillis() + grant.offset);
    const id = createHash("sha256").update(grant.app).digest("hex");
    db.data.set(`accessGrants/${id}`, {
      userId: user.uid, applicationId: grant.app, status: grant.status, createdAt: base, createdBy: "admin",
      updatedAt, updatedBy: "admin", revokedAt: grant.status === "revoked" ? updatedAt : null,
      revokedBy: grant.status === "revoked" ? "admin" : null,
      revokeReason: grant.status === "revoked" ? "No longer required" : null, revision: 1, version: 1
    });
  }
  return { db, service: new AccessGrantService(db as unknown as Firestore, directory()) };
}

describe("access grant pagination", () => {
  const grants = [
    { app: "app-a", status: "active" as const, offset: 3000 },
    { app: "app-b", status: "revoked" as const, offset: 2000 },
    { app: "app-c", status: "active" as const, offset: 2000 },
    { app: "app-d", status: "revoked" as const, offset: 1000 },
    { app: "app-e", status: "active" as const, offset: 0 }
  ];

  it("returns first, intermediate and final pages with a deterministic tie-breaker", async () => {
    const { service } = setup(grants);
    const first = await service.listForUser(user.uid, { limit: "2" });
    expect(first.accessGrants.map((grant) => grant.applicationId)).toEqual(["app-a", "app-b"]);
    expect(first.nextCursor).toBeTypeOf("string");
    const middle = await service.listForUser(user.uid, { limit: 2, cursor: first.nextCursor });
    expect(middle.accessGrants.map((grant) => grant.applicationId)).toEqual(["app-c", "app-d"]);
    expect(middle.nextCursor).toBeTypeOf("string");
    const last = await service.listForUser(user.uid, { limit: 2, cursor: middle.nextCursor });
    expect(last).toMatchObject({ accessGrants: [{ applicationId: "app-e" }] });
    expect(last).not.toHaveProperty("nextCursor");
  });

  it("filters active and revoked grants before paginating", async () => {
    const { service } = setup(grants);
    const active = await service.listForUser(user.uid, { status: "active", limit: 100 });
    const revoked = await service.listForUser(user.uid, { status: "revoked", limit: 100 });
    expect(active.accessGrants.map((grant) => grant.status)).toEqual(["active", "active", "active"]);
    expect(revoked.accessGrants.map((grant) => grant.status)).toEqual(["revoked", "revoked"]);
  });

  it("uses the same pagination contract for application grants", async () => {
    const { db, service } = setup(grants);
    for (const value of db.data.values()) {
      if (value.userId === user.uid) value.applicationId = "app-main";
    }
    const first = await service.listForApplication("app-main", { status: "active", limit: 2 });
    expect(first.accessGrants).toHaveLength(2);
    expect(first.nextCursor).toBeTypeOf("string");
    const last = await service.listForApplication("app-main", { status: "active", limit: 2, cursor: first.nextCursor });
    expect(last.accessGrants).toHaveLength(1);
    expect(last).not.toHaveProperty("nextCursor");
  });

  it("enforces minimum and maximum limits and reads one lookahead document", async () => {
    const { db, service } = setup(grants);
    await service.listForUser(user.uid, { limit: 1 });
    expect(db.lastLimit).toBe(2);
    await service.listForUser(user.uid, { limit: 100 });
    expect(db.lastLimit).toBe(101);
    await expect(service.listForUser(user.uid, { limit: 0 })).rejects.toMatchObject({ status: 400, code: "VALIDATION_ERROR" });
    await expect(service.listForUser(user.uid, { limit: 101 })).rejects.toMatchObject({ status: 400, code: "VALIDATION_ERROR" });
  });

  it("rejects malformed, wrong-version and cross-filter cursors", async () => {
    const { service } = setup(grants);
    await expect(service.listForUser(user.uid, { cursor: "not+base64" })).rejects.toMatchObject({ status: 400 });
    const wrongVersionBytes = Buffer.alloc(73);
    wrongVersionBytes.writeUInt8(2, 0);
    const wrongVersion = wrongVersionBytes.toString("base64url");
    await expect(service.listForUser(user.uid, { cursor: wrongVersion })).rejects.toMatchObject({ status: 400 });
    const active = await service.listForUser(user.uid, { status: "active", limit: 1 });
    await expect(service.listForUser(user.uid, { status: "revoked", cursor: active.nextCursor })).rejects.toMatchObject({ status: 400 });
    await expect(service.listForApplication("app-main", { cursor: active.nextCursor })).rejects.toMatchObject({ status: 400 });
  });

  it("returns an empty final page without a cursor", async () => {
    const { service } = setup();
    await expect(service.listForUser(user.uid)).resolves.toEqual({ accessGrants: [] });
    await expect(service.listForApplication("app-main")).resolves.toEqual({ accessGrants: [] });
  });
});
