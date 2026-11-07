import { randomUUID } from "node:crypto";
import { deleteApp, initializeApp } from "firebase-admin/app";
import { Timestamp, getFirestore, type Firestore } from "firebase-admin/firestore";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createTrustedAuthChallengeContext } from "../src/identities/identity-auth-challenge-contracts.js";
import { generateAuthChallengeSecrets, hashAuthChallengeSecret } from "../src/identities/identity-auth-challenge-crypto.js";
import {
  AuthChallengePersistenceService,
  type AuthChallengeCreationResult
} from "../src/identities/identity-auth-challenge-service.js";

let app: ReturnType<typeof initializeApp>;
let db: Firestore;
const adminUid = "protected-admin";
const initialTime = Date.parse("2026-11-06T18:00:00.000Z");

beforeAll(() => {
  if (!process.env.FIRESTORE_EMULATOR_HOST) throw new Error("Esta prueba requiere Firestore Emulator.");
  app = initializeApp({ projectId: "demo-plcocina-apps" }, `auth-challenge-${randomUUID()}`);
  db = getFirestore(app);
});

afterAll(async () => { await deleteApp(app); });

function fixture(overrides: Record<string, unknown> = {}) {
  const uid = `user-${randomUUID()}`;
  return {
    trustedOperatorUid: adminUid,
    expectedInternalUid: uid,
    expectedFirebaseUid: uid,
    coordinationOperationId: randomUUID(),
    authorizationId: randomUUID(),
    googleSubjectHash: null,
    trustedSessionId: `session-${randomUUID()}`,
    lifetimeMs: 300_000,
    ...overrides
  };
}

function lookup(created: AuthChallengeCreationResult, input: ReturnType<typeof fixture>) {
  return {
    trustedOperatorUid: adminUid,
    challengeId: created.document.challengeId,
    expectedInternalUid: input.expectedInternalUid,
    expectedFirebaseUid: input.expectedFirebaseUid,
    coordinationOperationId: input.coordinationOperationId,
    authorizationId: input.authorizationId,
    trustedSessionId: input.trustedSessionId,
    googleSubjectHash: input.googleSubjectHash as string | null
  };
}

function context(created: AuthChallengeCreationResult, input: ReturnType<typeof fixture>,
  overrides: Record<string, unknown> = {}) {
  return createTrustedAuthChallengeContext({
    expectedInternalUid: input.expectedInternalUid,
    expectedFirebaseUid: input.expectedFirebaseUid,
    coordinationOperationId: input.coordinationOperationId,
    authorizationId: input.authorizationId,
    trustedSessionId: input.trustedSessionId,
    nonce: created.oneTimeSecrets.nonce,
    state: created.oneTimeSecrets.state,
    expectedRevision: created.document.revision,
    verifiedGoogleIdentity: null,
    ...overrides
  });
}

function service(nowMs = initialTime, generator = generateAuthChallengeSecrets) {
  return new AuthChallengePersistenceService(db, adminUid, () => Timestamp.fromMillis(nowMs), generator);
}

async function rejected(work: Promise<unknown>, code: string) {
  await expect(work).rejects.toMatchObject({ code });
}

describe("persistent transactional auth challenges", () => {
  it("creates transactionally and returns secrets only in the one-time result", async () => {
    const input = fixture();
    const created = await service().create(input);
    const stored = (await db.collection("identityAuthChallenges").doc(created.document.challengeId).get()).data();
    expect(created.document).toMatchObject({ state: "issued", revision: 1, expectedFirebaseUid: input.expectedFirebaseUid });
    expect(created.oneTimeSecrets.nonce).not.toBe(created.oneTimeSecrets.state);
    expect(stored).toMatchObject({ nonceHash: hashAuthChallengeSecret(created.oneTimeSecrets.nonce),
      stateHash: hashAuthChallengeSecret(created.oneTimeSecrets.state) });
    expect(stored).not.toHaveProperty("nonce");
    expect(stored).not.toHaveProperty("state", created.oneTimeSecrets.state);
    expect(JSON.stringify(stored)).not.toContain(created.oneTimeSecrets.nonce);
    expect(JSON.stringify(stored)).not.toContain(created.oneTimeSecrets.state);
  });

  it("rejects a generated identifier collision without overwriting the original", async () => {
    const secrets = generateAuthChallengeSecrets();
    const fixed = () => secrets;
    const first = fixture();
    await service(initialTime, fixed).create(first);
    await rejected(service(initialTime, fixed).create(fixture()), "CHALLENGE_ID_CONFLICT");
    expect((await db.collection("identityAuthChallenges").doc(secrets.challengeId).get()).data()).toMatchObject({
      expectedFirebaseUid: first.expectedFirebaseUid, revision: 1
    });
  });

  it("retrieves state only under the complete trusted context and never returns secrets", async () => {
    const input = fixture();
    const created = await service().create(input);
    const state = await service().get(lookup(created, input));
    expect(state).toEqual(created.document);
    expect(state).not.toHaveProperty("nonce");
    await rejected(service().get({ ...lookup(created, input), trustedSessionId: `other-${randomUUID()}` }), "CONTEXT_MISMATCH");
  });

  it("allows exactly one concurrent consumption and increments revision once", async () => {
    const input = fixture();
    const created = await service().create(input);
    const run = () => service(initialTime + 1_000).consume({ trustedOperatorUid: adminUid,
      challengeId: created.document.challengeId, context: context(created, input) });
    const results = await Promise.allSettled([run(), run()]);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((result) => result.status === "rejected")).toHaveLength(1);
    const final = await service().get(lookup(created, input));
    expect(final).toMatchObject({ state: "consumed", revision: 2 });
  });

  it("rejects replay and conflicting contexts without additional writes", async () => {
    const input = fixture();
    const created = await service().create(input);
    await service(initialTime + 1_000).consume({ trustedOperatorUid: adminUid,
      challengeId: created.document.challengeId, context: context(created, input) });
    await rejected(service(initialTime + 2_000).consume({ trustedOperatorUid: adminUid,
      challengeId: created.document.challengeId, context: context(created, input) }), "REPLAY_DETECTED");
    expect((await service().get(lookup(created, input))).revision).toBe(2);

    const otherInput = fixture();
    const other = await service().create(otherInput);
    await rejected(service().consume({ trustedOperatorUid: adminUid, challengeId: other.document.challengeId,
      context: context(other, otherInput, { authorizationId: randomUUID() }) }), "AUTHORIZATION_MISMATCH");
    expect(await service().get(lookup(other, otherInput))).toMatchObject({ state: "issued", revision: 1 });
  });

  it("rejects stale revisions, nonexistent challenges, and malformed documents without partial writes", async () => {
    const input = fixture();
    const created = await service().create(input);
    await rejected(service().consume({ trustedOperatorUid: adminUid, challengeId: created.document.challengeId,
      context: context(created, input, { expectedRevision: 2 }) }), "REVISION_CONFLICT");
    await rejected(service().consume({ trustedOperatorUid: adminUid, challengeId: randomUUID(),
      context: context(created, input) }), "CHALLENGE_NOT_FOUND");
    const malformedId = randomUUID();
    await db.collection("identityAuthChallenges").doc(malformedId).set({ challengeId: malformedId, state: "issued" });
    await rejected(service().consume({ trustedOperatorUid: adminUid, challengeId: malformedId,
      context: context(created, input) }), "CHALLENGE_MALFORMED");
    expect(await service().get(lookup(created, input))).toMatchObject({ state: "issued", revision: 1 });
  });

  it("permits exactly one winner between consumption and authorized revocation", async () => {
    const input = fixture();
    const created = await service().create(input);
    const common = lookup(created, input);
    const results = await Promise.allSettled([
      service(initialTime + 1_000).consume({ trustedOperatorUid: adminUid, challengeId: created.document.challengeId,
        context: context(created, input) }),
      service(initialTime + 1_000).revoke({ ...common, expectedRevision: 1 })
    ]);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(["consumed", "revoked"]).toContain((await service().get(common)).state);
    expect((await service().get(common)).revision).toBe(2);
  });

  it("prevents revoked and expired challenges from being consumed", async () => {
    const revokedInput = fixture();
    const revoked = await service().create(revokedInput);
    await service(initialTime + 1_000).revoke({ ...lookup(revoked, revokedInput), expectedRevision: 1 });
    await rejected(service(initialTime + 2_000).consume({ trustedOperatorUid: adminUid,
      challengeId: revoked.document.challengeId, context: context(revoked, revokedInput) }), "CHALLENGE_REVOKED");

    const expiredInput = fixture({ lifetimeMs: 1_000 });
    const expired = await service().create(expiredInput);
    await rejected(service(initialTime + 1_000).consume({ trustedOperatorUid: adminUid,
      challengeId: expired.document.challengeId, context: context(expired, expiredInput) }), "CHALLENGE_EXPIRED");
    expect(await service().get(lookup(expired, expiredInput))).toMatchObject({ state: "issued", revision: 1 });
    const materialized = await service(initialTime + 1_000).expire({ ...lookup(expired, expiredInput), expectedRevision: 1 });
    expect(materialized).toMatchObject({ state: "expired", revision: 2 });
  });

  it("resolves consumption versus expiration atomically", async () => {
    const input = fixture({ lifetimeMs: 1_000 });
    const created = await service().create(input);
    const results = await Promise.allSettled([
      service(initialTime + 1_000).consume({ trustedOperatorUid: adminUid, challengeId: created.document.challengeId,
        context: context(created, input) }),
      service(initialTime + 1_000).expire({ ...lookup(created, input), expectedRevision: 1 })
    ]);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(await service().get(lookup(created, input))).toMatchObject({ state: "expired", revision: 2 });
  });

  it("validates optional trusted Google subject binding", async () => {
    const subjectHash = hashAuthChallengeSecret(generateAuthChallengeSecrets().nonce);
    const input = fixture({ googleSubjectHash: subjectHash });
    const created = await service().create(input);
    await rejected(service().consume({ trustedOperatorUid: adminUid, challengeId: created.document.challengeId,
      context: context(created, input) }), "GOOGLE_PROOF_REQUIRED");
    const verified = context(created, input, { verifiedGoogleIdentity: {
      subject: "google-subject", nonceVerified: true, googleSubjectHash: subjectHash
    } });
    expect(await service().consume({ trustedOperatorUid: adminUid,
      challengeId: created.document.challengeId, context: verified })).toMatchObject({ state: "consumed", revision: 2 });
  });

  it("protects Super Admin and rejects unauthorized internal callers", async () => {
    await rejected(service().create(fixture({ expectedInternalUid: adminUid, expectedFirebaseUid: adminUid })),
      "SUPER_ADMIN_FORBIDDEN");
    await rejected(service().create(fixture({ trustedOperatorUid: "other-admin" })), "TRUSTED_CONTEXT_MISMATCH");
  });

  it("does not create grants, profiles, users, claims, or audit evidence", async () => {
    const input = fixture();
    const created = await service().create(input);
    await service().consume({ trustedOperatorUid: adminUid, challengeId: created.document.challengeId,
      context: context(created, input) });
    expect((await db.collection("accessGrants").where("userId", "==", input.expectedFirebaseUid).get()).empty).toBe(true);
    expect((await db.collection("users").doc(input.expectedFirebaseUid).get()).exists).toBe(false);
    expect((await db.collection("auditEvents").where("resourceId", "==", input.expectedFirebaseUid).get()).empty).toBe(true);
  });
});
