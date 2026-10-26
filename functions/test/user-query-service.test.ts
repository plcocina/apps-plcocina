import type { Firestore } from "firebase-admin/firestore";
import { Timestamp } from "firebase-admin/firestore";
import { describe, expect, it, vi } from "vitest";
import { UserQueryService, type DirectoryUser, type UserDirectory } from "../src/users/user-query-service.js";

class FakeSnapshot {
  constructor(readonly id: string, private readonly value?: Record<string, unknown>) {}
  get exists() { return this.value !== undefined; }
  data() { return this.value; }
}

class FakeQuery {
  private after: string | null = null;
  private maximum = 50;
  private email: string | null = null;
  constructor(private readonly profiles: Map<string, Record<string, unknown>>) {}
  orderBy() { return this; }
  where(_field: string, _operator: string, value: string) { this.email = value; return this; }
  startAfter(value: string) { this.after = value; return this; }
  limit(value: number) { this.maximum = value; return this; }
  doc(uid: string) { return { id: uid, get: async () => new FakeSnapshot(uid, this.profiles.get(uid)) }; }
  async get() {
    const docs = [...this.profiles.entries()]
      .filter(([uid, profile]) => (!this.after || uid > this.after) && (!this.email || profile.normalizedEmail === this.email))
      .sort(([left], [right]) => left.localeCompare(right))
      .slice(0, this.maximum)
      .map(([uid, profile]) => new FakeSnapshot(uid, profile));
    return { docs, empty: docs.length === 0 };
  }
}

class FakeFirestore {
  constructor(readonly profiles: Map<string, Record<string, unknown>>) {}
  collection() { return new FakeQuery(this.profiles); }
  async getAll(...refs: Array<{ id: string }>) { return refs.map((ref) => new FakeSnapshot(ref.id, this.profiles.get(ref.id))); }
}

const now = Timestamp.fromDate(new Date("2026-10-22T18:00:00.000Z"));

function profile(email: string, overrides: Record<string, unknown> = {}) {
  return {
    email,
    normalizedEmail: email.toLowerCase(),
    displayName: "Perfil",
    status: "active",
    authDisabled: false,
    invitationStatus: "accepted",
    createdAt: now,
    createdBy: "admin-uid",
    updatedAt: now,
    updatedBy: "admin-uid",
    version: 1,
    ...overrides
  };
}

function authUser(uid: string, email: string, overrides: Partial<DirectoryUser> = {}): DirectoryUser {
  return {
    uid,
    email,
    displayName: "Usuario",
    emailVerified: true,
    disabled: false,
    metadata: { creationTime: "2026-10-01T00:00:00.000Z", lastSignInTime: "2026-10-20T00:00:00.000Z" },
    ...overrides
  };
}

function setup() {
  const admin = authUser("a-admin", "admin@plcocina.com", { customClaims: { super_admin: true, internal: "secret" } });
  const common = authUser("b-common", "user@plcocina.com");
  const authUsers = [admin, common];
  const directory: UserDirectory = {
    listUsers: vi.fn(async (_size, token) => token === "auth-2" ? { users: [common] } : { users: [admin], pageToken: "auth-2" }),
    getUser: vi.fn(async (uid) => {
      const user = authUsers.find((item) => item.uid === uid);
      if (!user) throw Object.assign(new Error("missing"), { code: "auth/user-not-found" });
      return user;
    }),
    getUserByEmail: vi.fn(async (email) => {
      const user = authUsers.find((item) => item.email === email);
      if (!user) throw Object.assign(new Error("missing"), { code: "auth/user-not-found" });
      return user;
    }),
    getUsers: vi.fn(async (identifiers) => ({ users: authUsers.filter((user) => identifiers.some((item) => item.uid === user.uid)) })),
    updateUser: vi.fn(),
    revokeRefreshTokens: vi.fn(),
    createUser: vi.fn()
  };
  const profiles = new Map<string, Record<string, unknown>>([
    ["a-admin", profile("admin@plcocina.com")],
    ["z-orphan", profile("orphan@plcocina.com")]
  ]);
  return { directory, service: new UserQueryService(directory, new FakeFirestore(profiles) as unknown as Firestore) };
}

describe("administrative user queries", () => {
  it("paginates Authentication and reports missing and orphan profiles without writing", async () => {
    const { service } = setup();
    const first = await service.list({ pageSize: "1" });
    expect(first.users).toHaveLength(1);
    expect(first.users[0]).toMatchObject({ uid: "a-admin", integrity: "linked", isProtected: true });
    expect(first.nextPageToken).toEqual(expect.any(String));

    const second = await service.list({ pageSize: "1", pageToken: first.nextPageToken! });
    expect(second.users).toEqual(expect.arrayContaining([
      expect.objectContaining({ uid: "b-common", integrity: "missing_profile" }),
      expect.objectContaining({ uid: "z-orphan", integrity: "orphan_profile", emailVerified: null })
    ]));
  });

  it("performs an exact normalized email lookup without listing all users", async () => {
    const { directory, service } = setup();
    const result = await service.list({ email: " ADMIN@PLCOCINA.COM " });
    expect(result.users).toHaveLength(1);
    expect(result.users[0]?.uid).toBe("a-admin");
    expect(directory.getUserByEmail).toHaveBeenCalledWith("admin@plcocina.com");
    expect(directory.listUsers).not.toHaveBeenCalled();
  });

  it("finds an orphan profile by exact email when Authentication has no account", async () => {
    const { directory, service } = setup();
    const result = await service.list({ email: "orphan@plcocina.com" });
    expect(result.users).toEqual([expect.objectContaining({ uid: "z-orphan", integrity: "orphan_profile" })]);
    expect(directory.listUsers).not.toHaveBeenCalled();
  });

  it("returns a sanitized projection and never exposes claims or password fields", async () => {
    const { service } = setup();
    const result = await service.get("a-admin");
    expect(result.isProtected).toBe(true);
    expect(result).not.toHaveProperty("customClaims");
    expect(result).not.toHaveProperty("passwordHash");
    expect(result.profile).toEqual({
      status: "active",
      authDisabled: false,
      invitationStatus: "accepted",
      createdAt: "2026-10-22T18:00:00.000Z",
      updatedAt: "2026-10-22T18:00:00.000Z",
      revision: 1,
      version: 1
    });
  });

  it("returns an orphan profile by uid and does not repair it", async () => {
    const { service } = setup();
    await expect(service.get("z-orphan")).resolves.toMatchObject({ uid: "z-orphan", integrity: "orphan_profile" });
  });

  it("rejects malformed cursors and page sizes", async () => {
    const { service } = setup();
    await expect(service.list({ pageSize: "101" })).rejects.toMatchObject({ code: "VALIDATION_ERROR" });
    await expect(service.list({ pageToken: "not-a-cursor" })).rejects.toMatchObject({ code: "VALIDATION_ERROR" });
  });

  it("maps a rejected Authentication page token to a validation error", async () => {
    const { directory, service } = setup();
    vi.mocked(directory.listUsers).mockRejectedValueOnce(Object.assign(new Error("bad page token"), { code: "auth/invalid-page-token" }));
    const cursor = Buffer.from(JSON.stringify({ authPageToken: "bad", profileAfter: null })).toString("base64url");
    await expect(service.list({ pageToken: cursor })).rejects.toMatchObject({ code: "VALIDATION_ERROR", status: 400 });
  });
});
