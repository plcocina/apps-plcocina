import { randomUUID } from "node:crypto";
import { deleteApp, initializeApp } from "firebase-admin/app";
import { getFirestore, Timestamp, type Firestore } from "firebase-admin/firestore";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { accessGrantId, AccessGrantService, type AccessGrantResult } from "../src/access-grants/access-grant-service.js";
import type { AdminPrincipal } from "../src/auth/require-super-admin.js";
import type { ApplicationDocument, UserDocument } from "../src/models/admin-collections.js";
import type { DirectoryUser, UserDirectory } from "../src/users/user-query-service.js";

const principal: AdminPrincipal = {
  uid: "concurrency-admin",
  email: "admin@plcocina.test",
  authTime: 1,
  issuedAt: 1,
  superAdmin: true
};

let firebaseApp: ReturnType<typeof initializeApp>;
let db: Firestore;

beforeAll(() => {
  if (!process.env.FIRESTORE_EMULATOR_HOST) throw new Error("Esta prueba requiere Firestore Emulator.");
  firebaseApp = initializeApp({ projectId: "demo-plcocina-apps" }, `access-grants-${randomUUID()}`);
  db = getFirestore(firebaseApp);
});

afterAll(async () => { await deleteApp(firebaseApp); });

function fixtureDirectory(user: DirectoryUser): UserDirectory {
  return {
    getUser: async (uid) => {
      if (uid !== user.uid) throw Object.assign(new Error("missing"), { code: "auth/user-not-found" });
      return user;
    },
    listUsers: async () => ({ users: [user] }),
    getUserByEmail: async () => user,
    getUsers: async () => ({ users: [user] }),
    updateUser: async () => user,
    revokeRefreshTokens: async () => undefined,
    createUser: async () => user
  };
}

async function fixture() {
  const suffix = randomUUID().replaceAll("-", "");
  const userId = `user-${suffix}`;
  const applicationId = `app-${suffix}`;
  const email = `${suffix}@plcocina.test`;
  const now = Timestamp.now();
  const user: UserDocument = {
    email, normalizedEmail: email, displayName: "Concurrency User", status: "active",
    authDisabled: false, invitationStatus: "accepted", createdAt: now, createdBy: principal.uid,
    updatedAt: now, updatedBy: principal.uid, revision: 1, pendingOperationId: null, version: 1
  };
  const authUser: DirectoryUser = {
    uid: userId, email, displayName: user.displayName, emailVerified: true, disabled: false,
    metadata: { creationTime: now.toDate().toISOString() }
  };
  const application: ApplicationDocument = {
    appId: applicationId, slug: applicationId, name: "Concurrency App", normalizedName: "concurrency app",
    description: "", category: "Tests", normalizedCategory: "tests",
    launchUrl: `https://${applicationId}.example.com/`, normalizedLaunchUrl: `https://${applicationId}.example.com/`,
    status: "active", accessLevel: "private", iconKey: null, displayOrder: 0,
    createdAt: now, createdBy: principal.uid, updatedAt: now, updatedBy: principal.uid, revision: 1, version: 1
  };
  await Promise.all([
    db.collection("users").doc(userId).set(user),
    db.collection("applications").doc(applicationId).set(application)
  ]);
  const directory = fixtureDirectory(authUser);
  return {
    userId,
    applicationId,
    left: new AccessGrantService(db, directory),
    right: new AccessGrantService(db, directory)
  };
}

function execute(service: AccessGrantService, input: {
  action: "grant" | "revoke";
  userId: string;
  applicationId: string;
  expectedRevision: number;
  idempotencyKey?: string;
}) {
  return service.execute({
    action: input.action,
    userId: input.userId,
    applicationId: input.applicationId,
    body: input.action === "revoke"
      ? { expectedRevision: input.expectedRevision, reason: "Concurrency test revocation" }
      : { expectedRevision: input.expectedRevision },
    idempotencyKey: input.idempotencyKey ?? randomUUID(),
    principal,
    requestId: randomUUID()
  });
}

async function state(userId: string, applicationId: string) {
  const [grant, allGrants, audits, operations] = await Promise.all([
    db.collection("accessGrants").doc(accessGrantId(userId, applicationId)).get(),
    db.collection("accessGrants").where("userId", "==", userId).get(),
    db.collection("auditEvents").where("targetUid", "==", userId).get(),
    db.collection("adminOperations").where("targetUid", "==", userId).get()
  ]);
  return {
    grant: grant.data(),
    grantCount: allGrants.docs.filter((doc) => doc.data().applicationId === applicationId).length,
    auditCount: audits.docs.filter((doc) => doc.data().appId === applicationId && doc.data().resourceType === "accessGrant").length,
    operations: operations.docs.filter((doc) => doc.data().appId === applicationId).map((doc) => doc.data())
  };
}

function fulfilled(results: PromiseSettledResult<AccessGrantResult>[]) {
  return results.filter((result): result is PromiseFulfilledResult<AccessGrantResult> => result.status === "fulfilled");
}

function rejectedCodes(results: PromiseSettledResult<AccessGrantResult>[]) {
  return results.filter((result): result is PromiseRejectedResult => result.status === "rejected")
    .map((result) => result.reason?.code);
}

describe("access grant concurrency with Firestore Emulator", () => {
  it("serializes simultaneous grant vs grant over a missing grant", async () => {
    const test = await fixture();
    const results = await Promise.allSettled([
      execute(test.left, { ...test, action: "grant", expectedRevision: 0 }),
      execute(test.right, { ...test, action: "grant", expectedRevision: 0 })
    ]);
    expect(fulfilled(results)).toHaveLength(1);
    expect(rejectedCodes(results)).toEqual(["REVISION_CONFLICT"]);
    expect(await state(test.userId, test.applicationId)).toMatchObject({
      grant: { status: "active", revision: 1 }, grantCount: 1, auditCount: 1, operations: [expect.objectContaining({ status: "completed" })]
    });
  });

  it("serializes simultaneous revoke vs revoke and preserves a later no-op", async () => {
    const test = await fixture();
    await execute(test.left, { ...test, action: "grant", expectedRevision: 0 });
    const results = await Promise.allSettled([
      execute(test.left, { ...test, action: "revoke", expectedRevision: 1 }),
      execute(test.right, { ...test, action: "revoke", expectedRevision: 1 })
    ]);
    expect(fulfilled(results)).toHaveLength(1);
    expect(rejectedCodes(results)).toEqual(["REVISION_CONFLICT"]);
    const noOp = await execute(test.left, { ...test, action: "revoke", expectedRevision: 2 });
    expect(noOp).toMatchObject({ changed: false, revision: 2 });
    const current = await state(test.userId, test.applicationId);
    expect(current).toMatchObject({ grant: { status: "revoked", revision: 2 }, grantCount: 1, auditCount: 2 });
    expect(current.operations).toHaveLength(3);
  });

  it("linearizes simultaneous grant vs revoke without duplicating state changes", async () => {
    const test = await fixture();
    await execute(test.left, { ...test, action: "grant", expectedRevision: 0 });
    const results = await Promise.allSettled([
      execute(test.left, { ...test, action: "grant", expectedRevision: 1 }),
      execute(test.right, { ...test, action: "revoke", expectedRevision: 1 })
    ]);
    expect(fulfilled(results).some((result) => result.value.status === "revoked" && result.value.changed)).toBe(true);
    expect(rejectedCodes(results).every((code) => code === "REVISION_CONFLICT")).toBe(true);
    const current = await state(test.userId, test.applicationId);
    expect(current).toMatchObject({ grant: { status: "revoked", revision: 2 }, grantCount: 1, auditCount: 2 });
    expect(current.operations.length).toBeGreaterThanOrEqual(2);
    expect(current.operations.length).toBeLessThanOrEqual(3);
  });

  it("returns one stored result for the same simultaneous Idempotency-Key", async () => {
    const test = await fixture();
    const idempotencyKey = randomUUID();
    const results = await Promise.all([
      execute(test.left, { ...test, action: "grant", expectedRevision: 0, idempotencyKey }),
      execute(test.right, { ...test, action: "grant", expectedRevision: 0, idempotencyKey })
    ]);
    expect(results[0]).toEqual(results[1]);
    const current = await state(test.userId, test.applicationId);
    expect(current).toMatchObject({ grant: { status: "active", revision: 1 }, grantCount: 1, auditCount: 1 });
    expect(current.operations).toHaveLength(1);
    expect(current.operations[0]?.result).toEqual(results[0]);
  });

  it("allows exactly one distinct key with the same expectedRevision", async () => {
    const test = await fixture();
    const results = await Promise.allSettled([
      execute(test.left, { ...test, action: "grant", expectedRevision: 0, idempotencyKey: randomUUID() }),
      execute(test.right, { ...test, action: "grant", expectedRevision: 0, idempotencyKey: randomUUID() })
    ]);
    expect(fulfilled(results)).toHaveLength(1);
    expect(rejectedCodes(results)).toEqual(["REVISION_CONFLICT"]);
    expect((await state(test.userId, test.applicationId)).operations).toHaveLength(1);
  });

  it("returns controlled conflicts for concurrent stale revisions", async () => {
    const test = await fixture();
    await execute(test.left, { ...test, action: "grant", expectedRevision: 0 });
    await execute(test.left, { ...test, action: "revoke", expectedRevision: 1 });
    const results = await Promise.allSettled([
      execute(test.left, { ...test, action: "grant", expectedRevision: 1 }),
      execute(test.right, { ...test, action: "revoke", expectedRevision: 1 })
    ]);
    expect(fulfilled(results)).toHaveLength(0);
    expect(rejectedCodes(results).sort()).toEqual(["REVISION_CONFLICT", "REVISION_CONFLICT"]);
    expect(await state(test.userId, test.applicationId)).toMatchObject({
      grant: { status: "revoked", revision: 2 }, grantCount: 1, auditCount: 2
    });
  });
});
