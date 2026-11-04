import { timingSafeEqual } from "node:crypto";
import { OAuth2Client, type LoginTicket } from "google-auth-library";
import {
  normalizeGoogleSubject,
  normalizeIdentityEmail,
  normalizeWorkspaceDomain
} from "./identity-models.js";

const GOOGLE_ISSUERS = new Set(["accounts.google.com", "https://accounts.google.com"]);
const MAX_TOKEN_BYTES = 16_384;
const MAX_CLOCK_SKEW_SECONDS = 60;
const DEFAULT_MAX_TOKEN_LIFETIME_SECONDS = 3_600;
const trustedNonceMarker: unique symbol = Symbol("trustedNonceContext");

export type GoogleTokenVerificationErrorCode =
  | "TOKEN_MISSING"
  | "TOKEN_MALFORMED"
  | "TOKEN_TOO_LARGE"
  | "SIGNATURE_INVALID"
  | "ALGORITHM_NOT_ALLOWED"
  | "KEY_ID_UNKNOWN"
  | "KEY_FETCH_FAILED"
  | "KEY_SET_INVALID"
  | "ISSUER_NOT_ALLOWED"
  | "AUDIENCE_NOT_ALLOWED"
  | "AUTHORIZED_PARTY_NOT_ALLOWED"
  | "TOKEN_EXPIRED"
  | "ISSUED_AT_INVALID"
  | "SUBJECT_INVALID"
  | "EMAIL_INVALID"
  | "EMAIL_NOT_VERIFIED"
  | "HOSTED_DOMAIN_MISSING"
  | "HOSTED_DOMAIN_NOT_ALLOWED"
  | "IDENTITY_CLAIMS_INCONSISTENT"
  | "NONCE_REQUIRED"
  | "NONCE_INVALID"
  | "VERIFIER_MISCONFIGURED"
  | "VERIFICATION_UNAVAILABLE";

export class GoogleTokenVerificationError extends Error {
  constructor(readonly code: GoogleTokenVerificationErrorCode) {
    super("Google identity token verification failed");
    this.name = "GoogleTokenVerificationError";
  }
}

export type TrustedNonceContext = {
  readonly expectedNonce: string;
  readonly [trustedNonceMarker]: true;
};

export function createTrustedNonceContext(expectedNonce: string): TrustedNonceContext {
  if (typeof expectedNonce !== "string" || expectedNonce.length < 16 || expectedNonce.length > 512) {
    throw new GoogleTokenVerificationError("VERIFIER_MISCONFIGURED");
  }
  return Object.freeze({ expectedNonce, [trustedNonceMarker]: true as const });
}

export type VerifyGoogleIdTokenInput = {
  idToken: string;
  nonceContext?: TrustedNonceContext;
};

export type VerifiedGoogleIdentity = {
  issuer: "accounts.google.com" | "https://accounts.google.com";
  audience: string;
  authorizedParty: string | null;
  subject: string;
  email: string;
  emailVerified: true;
  hostedDomain: string;
  issuedAt: Date;
  expiresAt: Date;
  nonceVerified: boolean;
};

export type GoogleTokenVerifierConfig = {
  allowedIssuers: readonly string[];
  allowedAudiences: readonly string[];
  allowedAuthorizedParties: readonly string[];
  allowedWorkspaceDomains: readonly string[];
  requireAuthorizedParty: boolean;
  clockSkewSeconds?: number;
  maxTokenLifetimeSeconds?: number;
};

export interface GoogleCertificateSource {
  getCertificates(forceRefresh: boolean): Promise<Readonly<Record<string, string>>>;
}

export interface GoogleJwtCryptographicVerifier {
  verify(
    idToken: string,
    certificates: Readonly<Record<string, string>>,
    maxTokenLifetimeSeconds: number
  ): Promise<Record<string, unknown>>;
}

export class GoogleAuthLibraryCertificateSource implements GoogleCertificateSource {
  private client = new OAuth2Client();

  async getCertificates(forceRefresh: boolean): Promise<Readonly<Record<string, string>>> {
    if (forceRefresh) this.client = new OAuth2Client();
    try {
      const response = await this.client.getFederatedSignonCertsAsync();
      const entries = Object.entries(response.certs);
      if (entries.length === 0 || entries.some(([, value]) => typeof value !== "string")) {
        throw new GoogleTokenVerificationError("KEY_SET_INVALID");
      }
      return Object.freeze(Object.fromEntries(entries) as Record<string, string>);
    } catch (error) {
      if (error instanceof GoogleTokenVerificationError) throw error;
      throw new GoogleTokenVerificationError("KEY_FETCH_FAILED");
    }
  }
}

export class GoogleAuthLibraryJwtCryptographicVerifier implements GoogleJwtCryptographicVerifier {
  private readonly client = new OAuth2Client();

  async verify(
    idToken: string,
    certificates: Readonly<Record<string, string>>,
    maxTokenLifetimeSeconds: number
  ): Promise<Record<string, unknown>> {
    let ticket: LoginTicket;
    try {
      ticket = await this.client.verifySignedJwtWithCertsAsync(
        idToken,
        certificates as Record<string, string>,
        undefined,
        undefined,
        maxTokenLifetimeSeconds
      );
    } catch (error) {
      const message = error instanceof Error ? error.message : "";
      if (message.includes("used too late")) throw new GoogleTokenVerificationError("TOKEN_EXPIRED");
      if (message.includes("used too early") || message.includes("Expiration time too far")) {
        throw new GoogleTokenVerificationError("ISSUED_AT_INVALID");
      }
      if (message.includes("signature")) throw new GoogleTokenVerificationError("SIGNATURE_INVALID");
      if (message.includes("segments") || message.includes("parse token") || message.includes("issue time") || message.includes("expiration time")) {
        throw new GoogleTokenVerificationError("TOKEN_MALFORMED");
      }
      throw new GoogleTokenVerificationError("VERIFICATION_UNAVAILABLE");
    }
    const payload = ticket.getPayload();
    if (!payload || typeof payload !== "object") throw new GoogleTokenVerificationError("TOKEN_MALFORMED");
    return payload as unknown as Record<string, unknown>;
  }
}

type ValidatedConfig = {
  allowedIssuers: ReadonlySet<string>;
  allowedAudiences: ReadonlySet<string>;
  allowedAuthorizedParties: ReadonlySet<string>;
  allowedWorkspaceDomains: ReadonlySet<string>;
  requireAuthorizedParty: boolean;
  clockSkewSeconds: number;
  maxTokenLifetimeSeconds: number;
};

function requireUniqueNonEmpty(values: readonly string[]): string[] {
  if (!Array.isArray(values) || values.length === 0 || values.some((value) => typeof value !== "string" || value.trim() !== value || value.length === 0)) {
    throw new GoogleTokenVerificationError("VERIFIER_MISCONFIGURED");
  }
  const unique = [...new Set(values)];
  if (unique.length !== values.length) throw new GoogleTokenVerificationError("VERIFIER_MISCONFIGURED");
  return unique;
}

function validateConfig(config: GoogleTokenVerifierConfig): ValidatedConfig {
  if (!config || typeof config.requireAuthorizedParty !== "boolean") {
    throw new GoogleTokenVerificationError("VERIFIER_MISCONFIGURED");
  }
  const issuers = requireUniqueNonEmpty(config.allowedIssuers);
  if (issuers.some((issuer) => !GOOGLE_ISSUERS.has(issuer))) {
    throw new GoogleTokenVerificationError("VERIFIER_MISCONFIGURED");
  }
  const audiences = requireUniqueNonEmpty(config.allowedAudiences);
  const authorizedParties = requireUniqueNonEmpty(config.allowedAuthorizedParties);
  let domains: string[];
  try {
    domains = requireUniqueNonEmpty(config.allowedWorkspaceDomains).map((domain) => {
      const normalized = normalizeWorkspaceDomain(domain);
      if (normalized !== domain) throw new Error("not canonical");
      return normalized;
    });
  } catch {
    throw new GoogleTokenVerificationError("VERIFIER_MISCONFIGURED");
  }
  if (new Set(domains).size !== domains.length) throw new GoogleTokenVerificationError("VERIFIER_MISCONFIGURED");

  const clockSkewSeconds = config.clockSkewSeconds ?? MAX_CLOCK_SKEW_SECONDS;
  if (!Number.isInteger(clockSkewSeconds) || clockSkewSeconds < 0 || clockSkewSeconds > MAX_CLOCK_SKEW_SECONDS) {
    throw new GoogleTokenVerificationError("VERIFIER_MISCONFIGURED");
  }
  const maxTokenLifetimeSeconds = config.maxTokenLifetimeSeconds ?? DEFAULT_MAX_TOKEN_LIFETIME_SECONDS;
  if (!Number.isInteger(maxTokenLifetimeSeconds) || maxTokenLifetimeSeconds < 60 || maxTokenLifetimeSeconds > 86_400) {
    throw new GoogleTokenVerificationError("VERIFIER_MISCONFIGURED");
  }
  return {
    allowedIssuers: new Set(issuers),
    allowedAudiences: new Set(audiences),
    allowedAuthorizedParties: new Set(authorizedParties),
    allowedWorkspaceDomains: new Set(domains),
    requireAuthorizedParty: config.requireAuthorizedParty,
    clockSkewSeconds,
    maxTokenLifetimeSeconds
  };
}

function decodeProtectedHeader(idToken: string): { kid: string; alg: string } {
  const segments = idToken.split(".");
  if (segments.length !== 3 || segments.some((segment) => segment.length === 0)) {
    throw new GoogleTokenVerificationError("TOKEN_MALFORMED");
  }
  try {
    const header = JSON.parse(Buffer.from(segments[0]!, "base64url").toString("utf8")) as unknown;
    if (!header || typeof header !== "object") throw new Error("invalid");
    const record = header as Record<string, unknown>;
    if (typeof record.kid !== "string" || record.kid.length === 0 || record.kid.length > 256) {
      throw new GoogleTokenVerificationError("KEY_ID_UNKNOWN");
    }
    if (typeof record.alg !== "string") throw new GoogleTokenVerificationError("ALGORITHM_NOT_ALLOWED");
    return { kid: record.kid, alg: record.alg };
  } catch (error) {
    if (error instanceof GoogleTokenVerificationError) throw error;
    throw new GoogleTokenVerificationError("TOKEN_MALFORMED");
  }
}

function numericClaim(payload: Record<string, unknown>, name: "iat" | "exp"): number {
  const value = payload[name];
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    throw new GoogleTokenVerificationError(name === "exp" ? "TOKEN_EXPIRED" : "ISSUED_AT_INVALID");
  }
  return value;
}

function secureEqual(actual: string, expected: string): boolean {
  const actualBuffer = Buffer.from(actual, "utf8");
  const expectedBuffer = Buffer.from(expected, "utf8");
  return actualBuffer.length === expectedBuffer.length && timingSafeEqual(actualBuffer, expectedBuffer);
}

export class GoogleIdentityTokenVerifier {
  private readonly config: ValidatedConfig;

  constructor(
    config: GoogleTokenVerifierConfig,
    private readonly certificates: GoogleCertificateSource = new GoogleAuthLibraryCertificateSource(),
    private readonly cryptographicVerifier: GoogleJwtCryptographicVerifier = new GoogleAuthLibraryJwtCryptographicVerifier(),
    private readonly now: () => Date = () => new Date()
  ) {
    this.config = validateConfig(config);
  }

  async verify(input: VerifyGoogleIdTokenInput): Promise<VerifiedGoogleIdentity> {
    if (!input || typeof input.idToken !== "string" || input.idToken.length === 0) {
      throw new GoogleTokenVerificationError("TOKEN_MISSING");
    }
    if (Buffer.byteLength(input.idToken, "utf8") > MAX_TOKEN_BYTES) {
      throw new GoogleTokenVerificationError("TOKEN_TOO_LARGE");
    }
    if (input.nonceContext !== undefined && input.nonceContext[trustedNonceMarker] !== true) {
      throw new GoogleTokenVerificationError("VERIFIER_MISCONFIGURED");
    }

    const header = decodeProtectedHeader(input.idToken);
    if (header.alg !== "RS256") throw new GoogleTokenVerificationError("ALGORITHM_NOT_ALLOWED");

    let certificateSet = await this.certificates.getCertificates(false);
    if (!Object.prototype.hasOwnProperty.call(certificateSet, header.kid)) {
      certificateSet = await this.certificates.getCertificates(true);
      if (!Object.prototype.hasOwnProperty.call(certificateSet, header.kid)) {
        throw new GoogleTokenVerificationError("KEY_ID_UNKNOWN");
      }
    }
    const certificate = certificateSet[header.kid];
    if (typeof certificate !== "string" || certificate.length === 0) {
      throw new GoogleTokenVerificationError("KEY_SET_INVALID");
    }

    const payload = await this.cryptographicVerifier.verify(
      input.idToken,
      { [header.kid]: certificate },
      this.config.maxTokenLifetimeSeconds
    );

    const issuer = payload.iss;
    if (typeof issuer !== "string" || !this.config.allowedIssuers.has(issuer)) {
      throw new GoogleTokenVerificationError("ISSUER_NOT_ALLOWED");
    }
    const audience = payload.aud;
    if (typeof audience !== "string" || !this.config.allowedAudiences.has(audience)) {
      throw new GoogleTokenVerificationError("AUDIENCE_NOT_ALLOWED");
    }

    const nowSeconds = Math.floor(this.now().getTime() / 1000);
    if (!Number.isSafeInteger(nowSeconds)) throw new GoogleTokenVerificationError("VERIFICATION_UNAVAILABLE");
    const issuedAt = numericClaim(payload, "iat");
    const expiresAt = numericClaim(payload, "exp");
    if (issuedAt > nowSeconds + this.config.clockSkewSeconds
      || expiresAt <= issuedAt
      || expiresAt - issuedAt > this.config.maxTokenLifetimeSeconds) {
      throw new GoogleTokenVerificationError("ISSUED_AT_INVALID");
    }
    if (nowSeconds > expiresAt + this.config.clockSkewSeconds) {
      throw new GoogleTokenVerificationError("TOKEN_EXPIRED");
    }

    let subject: string;
    try {
      if (typeof payload.sub !== "string") throw new Error("invalid");
      subject = normalizeGoogleSubject(payload.sub);
      if (subject !== payload.sub) throw new Error("not canonical");
    } catch {
      throw new GoogleTokenVerificationError("SUBJECT_INVALID");
    }

    if (payload.email_verified !== true) throw new GoogleTokenVerificationError("EMAIL_NOT_VERIFIED");
    let email: string;
    try {
      if (typeof payload.email !== "string") throw new Error("invalid");
      email = normalizeIdentityEmail(payload.email);
      if (email !== payload.email) throw new Error("not canonical");
    } catch {
      throw new GoogleTokenVerificationError("EMAIL_INVALID");
    }

    if (typeof payload.hd !== "string") throw new GoogleTokenVerificationError("HOSTED_DOMAIN_MISSING");
    let hostedDomain: string;
    try {
      hostedDomain = normalizeWorkspaceDomain(payload.hd);
      if (hostedDomain !== payload.hd) throw new Error("not canonical");
    } catch {
      throw new GoogleTokenVerificationError("HOSTED_DOMAIN_NOT_ALLOWED");
    }
    if (!this.config.allowedWorkspaceDomains.has(hostedDomain)) {
      throw new GoogleTokenVerificationError("HOSTED_DOMAIN_NOT_ALLOWED");
    }
    const emailDomain = email.slice(email.lastIndexOf("@") + 1);
    if (emailDomain !== hostedDomain) throw new GoogleTokenVerificationError("IDENTITY_CLAIMS_INCONSISTENT");

    const azp = payload.azp;
    if (azp !== undefined && (typeof azp !== "string" || !this.config.allowedAuthorizedParties.has(azp))) {
      throw new GoogleTokenVerificationError("AUTHORIZED_PARTY_NOT_ALLOWED");
    }
    if (this.config.requireAuthorizedParty && typeof azp !== "string") {
      throw new GoogleTokenVerificationError("AUTHORIZED_PARTY_NOT_ALLOWED");
    }

    let nonceVerified = false;
    if (input.nonceContext !== undefined) {
      if (typeof payload.nonce !== "string") throw new GoogleTokenVerificationError("NONCE_REQUIRED");
      if (!secureEqual(payload.nonce, input.nonceContext.expectedNonce)) {
        throw new GoogleTokenVerificationError("NONCE_INVALID");
      }
      nonceVerified = true;
    }

    return Object.freeze({
      issuer: issuer as VerifiedGoogleIdentity["issuer"],
      audience,
      authorizedParty: typeof azp === "string" ? azp : null,
      subject,
      email,
      emailVerified: true,
      hostedDomain,
      issuedAt: new Date(issuedAt * 1000),
      expiresAt: new Date(expiresAt * 1000),
      nonceVerified
    });
  }
}
