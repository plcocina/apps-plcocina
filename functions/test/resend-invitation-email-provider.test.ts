import { createHmac } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { InvitationEmailProviderError, type InvitationEmail } from "../src/invitations/invitation-email-provider.js";
import {
  buildInvitationLink,
  ResendInvitationEmailProvider,
  verifyResendWebhook,
  type WebhookReplayStore
} from "../src/invitations/resend-invitation-email-provider.js";

const invitationId = "26a38ad9-9fa5-4f6b-8f60-b3b3988d7801";
const token = "A".repeat(43);
const message: InvitationEmail = {
  to: "invitado@example.test",
  displayName: "Invitado <seguro>",
  invitationId,
  token,
  expiresAt: "2026-10-26T12:00:00.000Z",
  from: "invitaciones@plcocina.com",
  templateVersion: 1,
  tracking: { opens: false, clicks: false }
};

function response(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

describe("ResendInvitationEmailProvider", () => {
  it("permanece deshabilitado por defecto y no realiza solicitudes", async () => {
    const fetchImpl = vi.fn();
    const provider = new ResendInvitationEmailProvider({ fetchImpl: fetchImpl as typeof fetch });
    expect(provider.configured).toBe(false);
    await expect(provider.send(message, `invitation/${invitationId}/generation/1`)).rejects.toThrow("deshabilitado");
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("construye exclusivamente el enlace aprobado con secretos en el fragmento", () => {
    const link = buildInvitationLink(invitationId, token);
    expect(link).toBe(`https://apps.plcocina.com/accept-invitation/#invitationId=${invitationId}&token=${token}`);
    expect(new URL(link).search).toBe("");
    expect(new URL(link).hash).toContain(token);
  });

  it("envía el contrato REST con idempotencia estable y sin opciones de tracking", async () => {
    const fetchImpl = vi.fn(async () => response(200, { id: "email_123" }));
    const provider = new ResendInvitationEmailProvider({
      enabled: true, apiKey: "re_test_only", fetchImpl: fetchImpl as typeof fetch,
      now: () => new Date("2026-10-23T12:00:00.000Z")
    });
    const key = `invitation/${invitationId}/generation/1`;
    await expect(provider.send(message, key)).resolves.toEqual({ messageId: "email_123", acceptedAt: new Date("2026-10-23T12:00:00.000Z") });
    const [url, init] = fetchImpl.mock.calls[0]!;
    expect(url).toBe("https://api.resend.com/emails");
    expect(init?.headers).toMatchObject({ "idempotency-key": key, authorization: "Bearer re_test_only" });
    const body = JSON.parse(String(init?.body));
    expect(body.from).toBe("APPS PL COCINA <invitaciones@plcocina.com>");
    expect(body.to).toEqual([message.to]);
    expect(body.text).toContain(buildInvitationLink(invitationId, token));
    expect(body.html).toContain("Invitado &lt;seguro&gt;");
    expect(JSON.stringify(body)).not.toMatch(/open_tracking|click_tracking|tracking/i);
  });

  it.each([
    [409, "PROVIDER_IDEMPOTENCY_CONFLICT", true],
    [422, "PROVIDER_REJECTED", false]
  ] as const)("clasifica HTTP %s", async (status, code, ambiguous) => {
    const provider = new ResendInvitationEmailProvider({ enabled: true, apiKey: "test", fetchImpl: vi.fn(async () => response(status, { message: "error" })) as typeof fetch });
    const result = provider.send(message, `invitation/${invitationId}/generation/1`);
    await expect(result).rejects.toMatchObject({ code, ambiguous });
  });

  it("trata una respuesta exitosa inválida como ambigua", async () => {
    const provider = new ResendInvitationEmailProvider({ enabled: true, apiKey: "test", fetchImpl: vi.fn(async () => response(200, {})) as typeof fetch });
    await expect(provider.send(message, "key")).rejects.toMatchObject({ code: "PROVIDER_INVALID_RESPONSE", ambiguous: true });
  });

  it("clasifica timeout y fallo de red como resultados ambiguos", async () => {
    const timeoutFetch = vi.fn((_url: unknown, init?: RequestInit) => new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
    }));
    const timed = new ResendInvitationEmailProvider({ enabled: true, apiKey: "test", fetchImpl: timeoutFetch as typeof fetch, timeoutMs: 1 });
    await expect(timed.send(message, "timeout-key")).rejects.toMatchObject({ code: "PROVIDER_TIMEOUT", ambiguous: true });

    const network = new ResendInvitationEmailProvider({ enabled: true, apiKey: "test", fetchImpl: vi.fn(async () => { throw new Error("offline"); }) as typeof fetch });
    await expect(network.send(message, "network-key")).rejects.toMatchObject({ code: "PROVIDER_NETWORK_ERROR", ambiguous: true });
  });

  it("no expone token ni clave en errores", async () => {
    const provider = new ResendInvitationEmailProvider({ enabled: true, apiKey: "re_super_secret", fetchImpl: vi.fn(async () => response(409, {})) as typeof fetch });
    const error = await provider.send(message, "same-key").catch((cause: unknown) => cause);
    expect(error).toBeInstanceOf(InvitationEmailProviderError);
    expect(String(error)).not.toContain(token);
    expect(String(error)).not.toContain("re_super_secret");
  });
});

describe("verificación contractual de webhooks Resend", () => {
  const now = new Date("2026-10-23T12:00:00.000Z");
  const timestamp = String(Math.floor(now.getTime() / 1000));
  const rawBody = JSON.stringify({ type: "email.delivered", data: { email_id: "email_123" } });
  const secretBytes = Buffer.alloc(32, 7);
  const secret = `whsec_${secretBytes.toString("base64")}`;
  const id = "msg_event123";
  const signature = createHmac("sha256", secretBytes).update(`${id}.${timestamp}.${rawBody}`).digest("base64");

  it("verifica el cuerpo crudo y reclama el evento una sola vez", async () => {
    const claimed = new Set<string>();
    const replayStore: WebhookReplayStore = { claim: async (eventId) => claimed.has(eventId) ? false : Boolean(claimed.add(eventId)) };
    const input = { rawBody, headers: { id, timestamp, signature: `v1,${signature}` }, secret, replayStore, now: () => now };
    await expect(verifyResendWebhook(input)).resolves.toEqual(JSON.parse(rawBody));
    await expect(verifyResendWebhook(input)).rejects.toThrow("WEBHOOK_REPLAYED");
  });

  it("rechaza firmas inválidas y timestamps fuera de tolerancia antes de reservar", async () => {
    const replayStore: WebhookReplayStore = { claim: vi.fn(async () => true) };
    await expect(verifyResendWebhook({ rawBody, headers: { id, timestamp, signature: "v1,bad" }, secret, replayStore, now: () => now })).rejects.toThrow("INVALID_WEBHOOK_SIGNATURE");
    await expect(verifyResendWebhook({ rawBody, headers: { id, timestamp: "1", signature: `v1,${signature}` }, secret, replayStore, now: () => now })).rejects.toThrow("STALE_WEBHOOK");
    expect(replayStore.claim).not.toHaveBeenCalled();
  });
});
