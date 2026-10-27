import { createHmac, timingSafeEqual } from "node:crypto";
import { InvitationEmailProviderError, type InvitationEmail, type InvitationEmailProvider, type InvitationEmailResult } from "./invitation-email-provider.js";

const RESEND_ENDPOINT = "https://api.resend.com/emails";
const ACCEPT_INVITATION_URL = "https://apps.plcocina.com/accept-invitation/";
const MAX_IDEMPOTENCY_KEY_LENGTH = 256;

type FetchLike = typeof fetch;

export type ResendProviderOptions = {
  enabled?: boolean;
  apiKey?: string;
  fetchImpl?: FetchLike;
  timeoutMs?: number;
  now?: () => Date;
};

function escapeHtml(value: string) {
  return value.replace(/[&<>'"]/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;"
  })[character]!);
}

export function buildInvitationLink(invitationId: string, token: string) {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(invitationId)) {
    throw new Error("INVALID_INVITATION_ID");
  }
  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) throw new Error("INVALID_INVITATION_TOKEN");
  return `${ACCEPT_INVITATION_URL}#invitationId=${encodeURIComponent(invitationId)}&token=${encodeURIComponent(token)}`;
}

export class ResendInvitationEmailProvider implements InvitationEmailProvider {
  readonly name = "resend" as const;
  readonly configured: boolean;
  private readonly apiKey: string | undefined;
  private readonly fetchImpl: FetchLike;
  private readonly timeoutMs: number;
  private readonly now: () => Date;

  constructor(options: ResendProviderOptions = {}) {
    this.configured = options.enabled === true && typeof options.apiKey === "string" && options.apiKey.length > 0;
    this.apiKey = options.apiKey;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.timeoutMs = options.timeoutMs ?? 10_000;
    this.now = options.now ?? (() => new Date());
  }

  async send(message: InvitationEmail, idempotencyKey: string): Promise<InvitationEmailResult> {
    if (!this.configured || !this.apiKey) throw new Error("El proveedor Resend está deshabilitado.");
    if (idempotencyKey.length < 1 || idempotencyKey.length > MAX_IDEMPOTENCY_KEY_LENGTH) {
      throw new InvitationEmailProviderError("PROVIDER_IDEMPOTENCY_CONFLICT", false);
    }
    const link = buildInvitationLink(message.invitationId, message.token);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let response: Response;
    try {
      response = await this.fetchImpl(RESEND_ENDPOINT, {
        method: "POST",
        headers: {
          authorization: `Bearer ${this.apiKey}`,
          "content-type": "application/json",
          "idempotency-key": idempotencyKey
        },
        body: JSON.stringify({
          from: `APPS PL COCINA <${message.from}>`,
          to: [message.to],
          subject: "Activa tu cuenta de APPS PL COCINA",
          text: `Hola ${message.displayName},\n\nActiva tu cuenta antes de ${message.expiresAt}:\n${link}\n\nSi no solicitaste esta invitación, ignora este mensaje.`,
          html: `<p>Hola ${escapeHtml(message.displayName)},</p><p>Activa tu cuenta de APPS PL COCINA:</p><p><a href="${escapeHtml(link)}">Activar cuenta</a></p><p>El enlace vence el ${escapeHtml(message.expiresAt)}.</p>`
        }),
        signal: controller.signal
      });
    } catch (error) {
      if (error instanceof Error && error.name === "AbortError") {
        throw new InvitationEmailProviderError("PROVIDER_TIMEOUT", true);
      }
      throw new InvitationEmailProviderError("PROVIDER_NETWORK_ERROR", true);
    } finally {
      clearTimeout(timer);
    }
    if (response.status === 409) throw new InvitationEmailProviderError("PROVIDER_IDEMPOTENCY_CONFLICT", true);
    if (!response.ok) throw new InvitationEmailProviderError("PROVIDER_REJECTED", false);
    const payload = await response.json().catch(() => null) as { id?: unknown } | null;
    if (!payload || typeof payload.id !== "string" || payload.id.length < 1 || payload.id.length > 256) {
      throw new InvitationEmailProviderError("PROVIDER_INVALID_RESPONSE", true);
    }
    return { messageId: payload.id, acceptedAt: this.now() };
  }
}

export type ResendWebhookHeaders = { id: string; timestamp: string; signature: string };
export interface WebhookReplayStore {
  claim(eventId: string, expiresAt: Date): Promise<boolean>;
  complete?(eventId: string): Promise<void>;
  release?(eventId: string): Promise<void>;
}

function decodeWebhookSecret(secret: string) {
  const encoded = secret.startsWith("whsec_") ? secret.slice(6) : secret;
  const decoded = Buffer.from(encoded, "base64");
  if (decoded.length < 16) throw new Error("INVALID_WEBHOOK_SECRET");
  return decoded;
}

export async function verifyResendWebhook(input: {
  rawBody: string;
  headers: ResendWebhookHeaders;
  secret: string;
  replayStore: WebhookReplayStore;
  now?: () => Date;
  toleranceSeconds?: number;
}) {
  if (!/^msg_[A-Za-z0-9_-]+$/.test(input.headers.id)) throw new Error("INVALID_WEBHOOK_ID");
  const now = input.now?.() ?? new Date();
  const timestampSeconds = Number(input.headers.timestamp);
  const toleranceSeconds = input.toleranceSeconds ?? 300;
  if (!Number.isSafeInteger(timestampSeconds) || Math.abs(Math.floor(now.getTime() / 1000) - timestampSeconds) > toleranceSeconds) {
    throw new Error("STALE_WEBHOOK");
  }
  const expected = createHmac("sha256", decodeWebhookSecret(input.secret))
    .update(`${input.headers.id}.${input.headers.timestamp}.${input.rawBody}`, "utf8")
    .digest();
  const candidates = input.headers.signature.split(/\s+/).flatMap((part) => {
    const [version, signature] = part.split(",", 2);
    if (version !== "v1" || !signature) return [];
    try { return [Buffer.from(signature, "base64")]; } catch { return []; }
  });
  if (!candidates.some((candidate) => candidate.length === expected.length && timingSafeEqual(candidate, expected))) {
    throw new Error("INVALID_WEBHOOK_SIGNATURE");
  }
  const claimed = await input.replayStore.claim(input.headers.id, new Date(now.getTime() + toleranceSeconds * 1000));
  if (!claimed) throw new Error("WEBHOOK_REPLAYED");
  return JSON.parse(input.rawBody) as unknown;
}
