import { createHash } from "node:crypto";

export type InvitationEmail = {
  to: string;
  displayName: string;
  invitationId: string;
  token: string;
  expiresAt: string;
  from: "invitaciones@plcocina.com";
  templateVersion: 1;
  tracking: { opens: false; clicks: false };
};

export type InvitationEmailResult = { messageId: string; acceptedAt: Date };
export type SimulatedDeliveryOutcome = "accepted" | "rejected" | "timeout" | "network_error" | "response_lost";

export class InvitationEmailProviderError extends Error {
  constructor(
    readonly code: "PROVIDER_REJECTED" | "PROVIDER_TIMEOUT" | "PROVIDER_NETWORK_ERROR" | "PROVIDER_RESPONSE_LOST" | "PROVIDER_IDEMPOTENCY_CONFLICT" | "PROVIDER_INVALID_RESPONSE",
    readonly ambiguous: boolean
  ) {
    super(code);
    this.name = "InvitationEmailProviderError";
  }
}

export interface InvitationEmailProvider {
  readonly name: "simulated" | "resend";
  readonly configured: boolean;
  send(message: InvitationEmail, idempotencyKey: string): Promise<InvitationEmailResult>;
}

export class DisabledInvitationEmailProvider implements InvitationEmailProvider {
  readonly name = "simulated" as const;
  readonly configured = false;
  async send(): Promise<InvitationEmailResult> {
    throw new Error("El proveedor de invitaciones no está configurado.");
  }
}

export class SimulatedInvitationEmailProvider implements InvitationEmailProvider {
  readonly name = "simulated" as const;
  readonly configured = true;
  readonly deliveries: Array<{ message: InvitationEmail; idempotencyKey: string; result: InvitationEmailResult }> = [];
  private readonly requests = new Map<string, { payloadHash: string; result: InvitationEmailResult }>();
  private readonly outcomes: SimulatedDeliveryOutcome[] = [];

  constructor(private readonly now: () => Date = () => new Date()) {}

  queueOutcome(...outcomes: SimulatedDeliveryOutcome[]) {
    this.outcomes.push(...outcomes);
  }

  async send(message: InvitationEmail, idempotencyKey: string): Promise<InvitationEmailResult> {
    const payloadHash = createHash("sha256").update(JSON.stringify(message)).digest("hex");
    const previous = this.requests.get(idempotencyKey);
    if (previous) {
      if (previous.payloadHash !== payloadHash) throw new Error("SIMULATED_IDEMPOTENCY_CONFLICT");
      return previous.result;
    }
    const outcome = this.outcomes.shift() ?? "accepted";
    if (outcome === "rejected") throw new InvitationEmailProviderError("PROVIDER_REJECTED", false);
    if (outcome === "timeout") throw new InvitationEmailProviderError("PROVIDER_TIMEOUT", true);
    if (outcome === "network_error") throw new InvitationEmailProviderError("PROVIDER_NETWORK_ERROR", false);
    const result = {
      messageId: `sim_${createHash("sha256").update(idempotencyKey).digest("hex").slice(0, 24)}`,
      acceptedAt: this.now()
    };
    this.requests.set(idempotencyKey, { payloadHash, result });
    this.deliveries.push({ message, idempotencyKey, result });
    if (outcome === "response_lost") throw new InvitationEmailProviderError("PROVIDER_RESPONSE_LOST", true);
    return result;
  }
}
