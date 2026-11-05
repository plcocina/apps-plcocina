import { createHash, randomUUID } from "node:crypto";
import { Timestamp } from "firebase-admin/firestore";
import { describe, expect, it } from "vitest";
import { createTrustedNonceContext } from "../src/identities/google-token-verifier.js";
import {
  authChallengeDocumentSchema,
  createTrustedAuthChallengeContext,
  evaluateAuthChallenge
} from "../src/identities/identity-auth-challenge-contracts.js";
import {
  AuthChallengeCryptoError,
  authChallengeSecretEntropyBits,
  generateAuthChallengeSecrets,
  hashAuthChallengeSecret,
  verifyAuthChallengeSecret
} from "../src/identities/identity-auth-challenge-crypto.js";

const now = Timestamp.fromDate(new Date("2026-11-05T20:00:00.000Z"));

function fixture(overrides: Record<string, unknown> = {}) {
  const secrets = generateAuthChallengeSecrets();
  const uid = `user-${randomUUID()}`;
  const subjectHash = createHash("sha256").update(`subject-${randomUUID()}`).digest("hex");
  const challenge = {
    challengeId: secrets.challengeId,
    expectedInternalUid: uid,
    expectedFirebaseUid: uid,
    coordinationOperationId: randomUUID(),
    authorizationId: randomUUID(),
    googleSubjectHash: subjectHash,
    trustedSessionId: `session.${randomUUID()}`,
    nonceHash: hashAuthChallengeSecret(secrets.nonce),
    stateHash: hashAuthChallengeSecret(secrets.state),
    issuedAt: now,
    expiresAt: Timestamp.fromMillis(now.toMillis() + 5 * 60_000),
    state: "issued",
    stateChangedAt: null,
    revision: 1,
    version: 1,
    ...overrides
  };
  const context = {
    expectedInternalUid: challenge.expectedInternalUid,
    expectedFirebaseUid: challenge.expectedFirebaseUid,
    coordinationOperationId: challenge.coordinationOperationId,
    authorizationId: challenge.authorizationId,
    trustedSessionId: challenge.trustedSessionId,
    nonce: secrets.nonce,
    state: secrets.state,
    expectedRevision: challenge.revision,
    verifiedGoogleIdentity: challenge.googleSubjectHash === null ? null : {
      subject: `google-subject-${randomUUID()}`,
      nonceVerified: true,
      googleSubjectHash: challenge.googleSubjectHash
    }
  };
  return { secrets, challenge, context };
}

function evaluate(value: ReturnType<typeof fixture>, contextOverrides: Record<string, unknown> = {}) {
  return evaluateAuthChallenge({ challenge: value.challenge,
    context: createTrustedAuthChallengeContext({ ...value.context, ...contextOverrides }),
    now: Timestamp.fromMillis(now.toMillis() + 1_000) });
}

async function rejected(work: () => unknown, code: string) {
  expect(work).toThrow(expect.objectContaining({ code }));
}

describe("auth challenge cryptography", () => {
  it("generates independent canonical challenge, nonce and state values", () => {
    const generated = generateAuthChallengeSecrets();
    expect(generated.challengeId).toMatch(/^[0-9a-f-]{36}$/);
    expect(generated.nonce).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(generated.state).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(generated.nonce).not.toBe(generated.state);
  });

  it("uses 256 bits for each bearer secret", () => {
    expect(authChallengeSecretEntropyBits).toBe(256);
    const generated = generateAuthChallengeSecrets();
    expect(Buffer.from(generated.nonce, "base64url")).toHaveLength(32);
    expect(Buffer.from(generated.state, "base64url")).toHaveLength(32);
  });

  it("produces unique values across repeated synthetic generations", () => {
    const values = Array.from({ length: 64 }, generateAuthChallengeSecrets);
    expect(new Set(values.map((value) => value.challengeId))).toHaveLength(64);
    expect(new Set(values.map((value) => value.nonce))).toHaveLength(64);
    expect(new Set(values.map((value) => value.state))).toHaveLength(64);
  });

  it("hashes the canonical bearer value with SHA-256", () => {
    const { nonce } = generateAuthChallengeSecrets();
    expect(hashAuthChallengeSecret(nonce)).toBe(createHash("sha256").update(nonce, "utf8").digest("hex"));
  });

  it("compares matching and different secrets safely", () => {
    const first = generateAuthChallengeSecrets();
    const second = generateAuthChallengeSecrets();
    expect(verifyAuthChallengeSecret(first.nonce, hashAuthChallengeSecret(first.nonce))).toBe(true);
    expect(verifyAuthChallengeSecret(second.nonce, hashAuthChallengeSecret(first.nonce))).toBe(false);
  });

  it("rejects padded, short and malformed bearer values", () => {
    const { nonce } = generateAuthChallengeSecrets();
    for (const malformed of [`${nonce}=`, nonce.slice(1), `${nonce.slice(0, -1)}+`]) {
      expect(() => hashAuthChallengeSecret(malformed)).toThrow(AuthChallengeCryptoError);
    }
  });

  it("rejects a malformed persisted hash", () => {
    expect(() => verifyAuthChallengeSecret(generateAuthChallengeSecrets().nonce, "not-a-hash"))
      .toThrow(expect.objectContaining({ code: "HASH_MALFORMED" }));
  });

  it("is directly compatible with the trusted E3B nonce context", () => {
    const { nonce } = generateAuthChallengeSecrets();
    expect(createTrustedNonceContext(nonce).expectedNonce).toBe(nonce);
  });
});

describe("strict auth challenge contract", () => {
  it("accepts a valid issued challenge without secrets or tokens", () => {
    const value = fixture();
    expect(authChallengeDocumentSchema.parse(value.challenge)).toEqual(value.challenge);
    expect(JSON.stringify(value.challenge)).not.toContain(value.secrets.nonce);
    expect(JSON.stringify(value.challenge)).not.toContain(value.secrets.state);
  });

  it("rejects different internal and Firebase UIDs", () => {
    const value = fixture({ expectedFirebaseUid: `other-${randomUUID()}` });
    expect(authChallengeDocumentSchema.safeParse(value.challenge).success).toBe(false);
  });

  it("rejects excessive or non-positive lifetime", () => {
    expect(authChallengeDocumentSchema.safeParse(fixture({ expiresAt: now }).challenge).success).toBe(false);
    expect(authChallengeDocumentSchema.safeParse(fixture({
      expiresAt: Timestamp.fromMillis(now.toMillis() + 16 * 60_000)
    }).challenge).success).toBe(false);
  });

  it("rejects unknown fields including token material", () => {
    const value = fixture();
    expect(authChallengeDocumentSchema.safeParse({ ...value.challenge, idToken: "forbidden" }).success).toBe(false);
  });

  it("requires transition timestamps only for non-issued states", () => {
    expect(authChallengeDocumentSchema.safeParse(fixture({ state: "revoked" }).challenge).success).toBe(false);
    expect(authChallengeDocumentSchema.safeParse(fixture({ state: "issued", stateChangedAt: now }).challenge).success).toBe(false);
  });
});

describe("pure fail-closed challenge validation", () => {
  it("validates a current challenge without consuming it", () => {
    const value = fixture();
    expect(evaluate(value)).toEqual({ decision: "valid", challengeId: value.challenge.challengeId,
      revision: 1, nonceVerified: true, stateVerified: true, consumed: false });
    expect(value.challenge.state).toBe("issued");
  });

  it("validates a challenge without a pre-bound subject", () => {
    const value = fixture({ googleSubjectHash: null });
    expect(evaluate(value, { verifiedGoogleIdentity: null }).decision).toBe("valid");
  });

  it("rejects temporal and explicit expiration", async () => {
    const temporal = fixture({ expiresAt: Timestamp.fromMillis(now.toMillis() + 500) });
    await rejected(() => evaluate(temporal), "CHALLENGE_EXPIRED");
    const expired = fixture({ state: "expired", stateChangedAt: now });
    await rejected(() => evaluate(expired), "CHALLENGE_EXPIRED");
  });

  it("rejects revoked and consumed challenges", async () => {
    await rejected(() => evaluate(fixture({ state: "revoked", stateChangedAt: now })), "CHALLENGE_REVOKED");
    await rejected(() => evaluate(fixture({ state: "consumed", stateChangedAt: now })), "REPLAY_DETECTED");
  });

  it("rejects a different UID", async () => {
    const value = fixture();
    await rejected(() => evaluate(value, { expectedInternalUid: `other-${randomUUID()}`, expectedFirebaseUid: `other-${randomUUID()}` }), "UID_MISMATCH");
  });

  it("rejects different operation and authorization bindings", async () => {
    const value = fixture();
    await rejected(() => evaluate(value, { coordinationOperationId: randomUUID() }), "OPERATION_MISMATCH");
    await rejected(() => evaluate(value, { authorizationId: randomUUID() }), "AUTHORIZATION_MISMATCH");
  });

  it("rejects a different trusted session", async () => {
    const value = fixture();
    await rejected(() => evaluate(value, { trustedSessionId: `session.${randomUUID()}` }), "SESSION_MISMATCH");
  });

  it("rejects wrong nonce and state independently", async () => {
    const value = fixture();
    await rejected(() => evaluate(value, { nonce: generateAuthChallengeSecrets().nonce }), "NONCE_MISMATCH");
    await rejected(() => evaluate(value, { state: generateAuthChallengeSecrets().state }), "STATE_MISMATCH");
  });

  it("rejects an obsolete revision", async () => {
    const value = fixture();
    await rejected(() => evaluate(value, { expectedRevision: 2 }), "REVISION_CONFLICT");
  });

  it("requires verified E3B binding for a pre-bound subject", async () => {
    const value = fixture();
    await rejected(() => evaluate(value, { verifiedGoogleIdentity: null }), "GOOGLE_PROOF_REQUIRED");
    await rejected(() => evaluate(value, { verifiedGoogleIdentity: {
      subject: "different-subject", nonceVerified: true,
      googleSubjectHash: createHash("sha256").update("different").digest("hex")
    } }), "SUBJECT_MISMATCH");
  });

  it("rejects raw client context without the internal trust marker", async () => {
    const value = fixture();
    await rejected(() => evaluateAuthChallenge({ challenge: value.challenge,
      context: value.context as never, now: Timestamp.fromMillis(now.toMillis() + 1_000) }), "UNTRUSTED_CONTEXT");
  });

  it("has no activation, grant, claim, persistence or mutation effect", () => {
    const value = fixture();
    const before = structuredClone(value.challenge);
    evaluate(value);
    expect(value.challenge).toEqual(before);
    expect(JSON.stringify(value.challenge)).not.toMatch(/accessGrant|customClaim|active|firebaseAuth/i);
  });
});
