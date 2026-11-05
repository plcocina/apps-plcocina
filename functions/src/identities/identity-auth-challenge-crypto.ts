import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";

const SECRET_BYTES = 32;
const CANONICAL_SECRET_LENGTH = 43;
const HASH_PATTERN = /^[a-f0-9]{64}$/;
const SECRET_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export type AuthChallengeSecrets = Readonly<{
  challengeId: string;
  nonce: string;
  state: string;
}>;

export type AuthChallengeCryptoErrorCode = "SECRET_MALFORMED" | "HASH_MALFORMED";

export class AuthChallengeCryptoError extends Error {
  constructor(readonly code: AuthChallengeCryptoErrorCode) {
    super("Auth challenge cryptographic input rejected");
    this.name = "AuthChallengeCryptoError";
  }
}

function assertCanonicalSecret(value: string): Buffer {
  if (typeof value !== "string" || value.length !== CANONICAL_SECRET_LENGTH || !SECRET_PATTERN.test(value)) {
    throw new AuthChallengeCryptoError("SECRET_MALFORMED");
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.length !== SECRET_BYTES || decoded.toString("base64url") !== value) {
    throw new AuthChallengeCryptoError("SECRET_MALFORMED");
  }
  return decoded;
}

export function generateAuthChallengeSecrets(): AuthChallengeSecrets {
  return Object.freeze({
    challengeId: randomUUID(),
    nonce: randomBytes(SECRET_BYTES).toString("base64url"),
    state: randomBytes(SECRET_BYTES).toString("base64url")
  });
}

export function hashAuthChallengeSecret(value: string): string {
  assertCanonicalSecret(value);
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export function verifyAuthChallengeSecret(value: string, expectedHash: string): boolean {
  assertCanonicalSecret(value);
  if (typeof expectedHash !== "string" || !HASH_PATTERN.test(expectedHash)) {
    throw new AuthChallengeCryptoError("HASH_MALFORMED");
  }
  const actual = Buffer.from(hashAuthChallengeSecret(value), "hex");
  const expected = Buffer.from(expectedHash, "hex");
  return timingSafeEqual(actual, expected);
}

export const authChallengeSecretEntropyBits = SECRET_BYTES * 8;
