import { generateKeyPairSync, sign } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  createTrustedNonceContext,
  GoogleAuthLibraryJwtCryptographicVerifier,
  GoogleIdentityTokenVerifier,
  GoogleTokenVerificationError,
  type GoogleCertificateSource,
  type GoogleTokenVerifierConfig
} from "../src/identities/google-token-verifier.js";

const now = new Date();
const nowSeconds = Math.floor(now.getTime() / 1000);
const keyId = "controlled-test-key";
const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();

const config: GoogleTokenVerifierConfig = {
  allowedIssuers: ["accounts.google.com", "https://accounts.google.com"],
  allowedAudiences: ["approved-client.apps.googleusercontent.com"],
  allowedAuthorizedParties: ["approved-client.apps.googleusercontent.com"],
  allowedWorkspaceDomains: ["plcocina.com"],
  requireAuthorizedParty: false,
  clockSkewSeconds: 60,
  maxTokenLifetimeSeconds: 3_600
};

const validPayload = {
  iss: "https://accounts.google.com",
  aud: "approved-client.apps.googleusercontent.com",
  sub: "google-subject_123",
  email: "employee@plcocina.com",
  email_verified: true,
  hd: "plcocina.com",
  iat: nowSeconds - 30,
  exp: nowSeconds + 900
};

function encode(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function token(payload: Record<string, unknown> = validPayload, options: { kid?: string; alg?: string } = {}): string {
  const header = encode({ alg: options.alg ?? "RS256", typ: "JWT", kid: options.kid ?? keyId });
  const body = encode(payload);
  const signature = sign("RSA-SHA256", Buffer.from(`${header}.${body}`), privateKey).toString("base64url");
  return `${header}.${body}.${signature}`;
}

class StaticCertificateSource implements GoogleCertificateSource {
  calls: boolean[] = [];

  constructor(private readonly certificates: Readonly<Record<string, string>> = { [keyId]: publicKeyPem }) {}

  async getCertificates(forceRefresh: boolean): Promise<Readonly<Record<string, string>>> {
    this.calls.push(forceRefresh);
    return this.certificates;
  }
}

function verifier(
  certificateSource: GoogleCertificateSource = new StaticCertificateSource(),
  override: Partial<GoogleTokenVerifierConfig> = {}
): GoogleIdentityTokenVerifier {
  return new GoogleIdentityTokenVerifier(
    { ...config, ...override },
    certificateSource,
    new GoogleAuthLibraryJwtCryptographicVerifier(),
    () => now
  );
}

async function expectCode(promise: Promise<unknown>, code: string): Promise<void> {
  await expect(promise).rejects.toMatchObject({ code, message: "Google identity token verification failed" });
}

describe("GoogleIdentityTokenVerifier", () => {
  it("verifies a legitimately signed Google Workspace identity without linking or authorization fields", async () => {
    const result = await verifier().verify({ idToken: token() });
    expect(result).toEqual({
      issuer: "https://accounts.google.com",
      audience: config.allowedAudiences[0],
      authorizedParty: null,
      subject: validPayload.sub,
      email: validPayload.email,
      emailVerified: true,
      hostedDomain: validPayload.hd,
      issuedAt: new Date(validPayload.iat * 1000),
      expiresAt: new Date(validPayload.exp * 1000),
      nonceVerified: false
    });
    expect(result).not.toHaveProperty("uid");
    expect(result).not.toHaveProperty("accessGrants");
    expect(result).not.toHaveProperty("customClaims");
    expect(result).not.toHaveProperty("linked");
  });

  it("rejects an altered signature", async () => {
    const signed = token();
    await expectCode(verifier().verify({ idToken: `${signed.slice(0, -2)}aa` }), "SIGNATURE_INVALID");
  });

  it("refreshes once and rejects an unknown key", async () => {
    const source = new StaticCertificateSource({});
    await expectCode(verifier(source).verify({ idToken: token(validPayload, { kid: "unknown" }) }), "KEY_ID_UNKNOWN");
    expect(source.calls).toEqual([false, true]);
  });

  it("rejects an expired token", async () => {
    await expectCode(verifier().verify({ idToken: token({ ...validPayload, iat: nowSeconds - 800, exp: nowSeconds - 400 }) }), "TOKEN_EXPIRED");
  });

  it("rejects a future issued-at outside the bounded skew", async () => {
    await expectCode(verifier().verify({ idToken: token({ ...validPayload, iat: nowSeconds + 120, exp: nowSeconds + 900 }) }), "ISSUED_AT_INVALID");
  });

  it("rejects an incorrect issuer", async () => {
    await expectCode(verifier().verify({ idToken: token({ ...validPayload, iss: "https://securetoken.google.com/demo" }) }), "ISSUER_NOT_ALLOWED");
  });

  it("rejects an unauthorized audience", async () => {
    await expectCode(verifier().verify({ idToken: token({ ...validPayload, aud: "other.apps.googleusercontent.com" }) }), "AUDIENCE_NOT_ALLOWED");
  });

  it("rejects an invalid subject", async () => {
    await expectCode(verifier().verify({ idToken: token({ ...validPayload, sub: "invalid subject" }) }), "SUBJECT_INVALID");
  });

  it("rejects an unverified email", async () => {
    await expectCode(verifier().verify({ idToken: token({ ...validPayload, email_verified: false }) }), "EMAIL_NOT_VERIFIED");
  });

  it("rejects missing and unauthorized hosted domains", async () => {
    const { hd: _removed, ...withoutDomain } = validPayload;
    await expectCode(verifier().verify({ idToken: token(withoutDomain) }), "HOSTED_DOMAIN_MISSING");
    await expectCode(verifier().verify({ idToken: token({ ...validPayload, hd: "attacker.example" }) }), "HOSTED_DOMAIN_NOT_ALLOWED");
  });

  it("rejects an email domain inconsistent with the signed hosted domain", async () => {
    await expectCode(verifier().verify({ idToken: token({ ...validPayload, email: "employee@example.com" }) }), "IDENTITY_CLAIMS_INCONSISTENT");
  });

  it("validates authorized-party policy when required", async () => {
    await expectCode(verifier(undefined, { requireAuthorizedParty: true }).verify({ idToken: token() }), "AUTHORIZED_PARTY_NOT_ALLOWED");
    await expectCode(verifier().verify({ idToken: token({ ...validPayload, azp: "attacker.apps.googleusercontent.com" }) }), "AUTHORIZED_PARTY_NOT_ALLOWED");
    const result = await verifier(undefined, { requireAuthorizedParty: true }).verify({
      idToken: token({ ...validPayload, azp: config.allowedAuthorizedParties[0] })
    });
    expect(result.authorizedParty).toBe(config.allowedAuthorizedParties[0]);
  });

  it("requires, compares and confirms nonce only with a trusted nonce context", async () => {
    const context = createTrustedNonceContext("server-generated-nonce-123456");
    await expectCode(verifier().verify({ idToken: token(), nonceContext: context }), "NONCE_REQUIRED");
    await expectCode(verifier().verify({ idToken: token({ ...validPayload, nonce: "wrong-nonce-123456789" }), nonceContext: context }), "NONCE_INVALID");
    const result = await verifier().verify({
      idToken: token({ ...validPayload, nonce: context.expectedNonce }),
      nonceContext: context
    });
    expect(result.nonceVerified).toBe(true);
  });

  it("rejects malformed tokens and algorithms outside RS256", async () => {
    await expectCode(verifier().verify({ idToken: "not-a-jwt" }), "TOKEN_MALFORMED");
    await expectCode(verifier().verify({ idToken: token(validPayload, { alg: "HS256" }) }), "ALGORITHM_NOT_ALLOWED");
  });

  it("rejects permissive, incomplete and excessive-skew configuration", () => {
    expect(() => verifier(undefined, { allowedAudiences: [] })).toThrowError(GoogleTokenVerificationError);
    expect(() => verifier(undefined, { allowedWorkspaceDomains: [] })).toThrowError(GoogleTokenVerificationError);
    expect(() => verifier(undefined, { allowedAuthorizedParties: [] })).toThrowError(GoogleTokenVerificationError);
    expect(() => verifier(undefined, { allowedWorkspaceDomains: ["PLCocina.com"] })).toThrowError(GoogleTokenVerificationError);
    expect(() => verifier(undefined, { clockSkewSeconds: 61 })).toThrowError(GoogleTokenVerificationError);
    expect(() => new GoogleIdentityTokenVerifier(
      { ...config, requireAuthorizedParty: undefined as unknown as boolean },
      new StaticCertificateSource()
    )).toThrowError(GoogleTokenVerificationError);
  });

  it("fails closed when certificate retrieval is unavailable", async () => {
    const unavailable: GoogleCertificateSource = {
      getCertificates: async () => {
        throw new GoogleTokenVerificationError("KEY_FETCH_FAILED");
      }
    };
    await expectCode(verifier(unavailable).verify({ idToken: token() }), "KEY_FETCH_FAILED");
  });

  it("rejects a correctly signed Firebase-shaped ID token as token confusion", async () => {
    await expectCode(verifier().verify({
      idToken: token({
        ...validPayload,
        iss: "https://securetoken.google.com/demo-plcocina-apps",
        aud: "demo-plcocina-apps",
        firebase: { sign_in_provider: "google.com" }
      })
    }), "ISSUER_NOT_ALLOWED");
  });
});
