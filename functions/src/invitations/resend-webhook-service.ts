import { createHash, randomUUID } from "node:crypto";
import { Timestamp, type Firestore } from "firebase-admin/firestore";
import { z } from "zod";
import { invitationDocumentSchema } from "../models/admin-collections.js";
import { verifyResendWebhook, type ResendWebhookHeaders, type WebhookReplayStore } from "./resend-invitation-email-provider.js";

const webhookSchema = z.object({
  type: z.enum(["email.sent", "email.delivered", "email.delivery_delayed", "email.bounced", "email.complained", "email.failed"]),
  data: z.object({ email_id: z.string().min(1).max(256) }).passthrough()
}).passthrough();

const deliveryStatus = {
  "email.sent": "accepted",
  "email.delivered": "delivered",
  "email.delivery_delayed": "delayed",
  "email.bounced": "bounced",
  "email.complained": "complained",
  "email.failed": "failed"
} as const;

export class ResendWebhookService {
  constructor(
    private readonly db: Firestore,
    private readonly replayStore: WebhookReplayStore,
    private readonly secret: string,
    private readonly now: () => Timestamp = () => Timestamp.now()
  ) {}

  async receive(rawBody: Buffer, headers: ResendWebhookHeaders) {
    if (!Buffer.isBuffer(rawBody)) throw new Error("RAW_BODY_REQUIRED");
    try {
      const event = webhookSchema.parse(await verifyResendWebhook({
        rawBody: rawBody.toString("utf8"), headers, secret: this.secret, replayStore: this.replayStore,
        now: () => this.now().toDate()
      }));
      const matches = await this.db.collection("invitations")
        .where("delivery.providerMessageId", "==", event.data.email_id)
        .limit(2)
        .get();
      if (matches.empty) {
        await this.replayStore.complete?.(headers.id);
        return { accepted: true as const, matched: false as const };
      }
      if (matches.size !== 1) throw new Error("AMBIGUOUS_PROVIDER_MESSAGE_ID");
      const reference = matches.docs[0]!.ref;
      const auditReference = this.db.collection("auditEvents").doc(`resend_${createHash("sha256").update(headers.id).digest("hex")}`);
      const timestamp = this.now();
      await this.db.runTransaction(async (transaction) => {
        const [snapshot, auditSnapshot] = await Promise.all([transaction.get(reference), transaction.get(auditReference)]);
        if (auditSnapshot.exists) return;
        const invitation = invitationDocumentSchema.parse(snapshot.data());
        if (invitation.delivery.provider !== "resend" || invitation.delivery.providerMessageId !== event.data.email_id) {
          throw new Error("PROVIDER_MESSAGE_MISMATCH");
        }
        const status = deliveryStatus[event.type];
        const deliveredAt = status === "delivered" ? timestamp : invitation.delivery.deliveredAt;
        transaction.update(reference, {
          delivery: { ...invitation.delivery, status, deliveredAt },
          deliveredAt,
          updatedAt: timestamp
        });
        transaction.create(auditReference, {
          occurredAt: timestamp, actorType: "provider", actorUid: null, actorEmail: null,
          providerEventId: headers.id, action: `invitation.${status}`, resourceType: "invitation",
          resourceId: invitation.invitationId, targetUid: invitation.uid, appId: null,
          before: { deliveryStatus: invitation.delivery.status }, after: { deliveryStatus: status },
          reason: null, requestId: randomUUID(), source: "admin-api", result: "success", version: 1
        });
      });
      await this.replayStore.complete?.(headers.id);
      return { accepted: true as const, matched: true as const };
    } catch (error) {
      if (error instanceof Error && error.message !== "WEBHOOK_REPLAYED") {
        await this.replayStore.release?.(headers.id).catch(() => undefined);
      }
      throw error;
    }
  }
}
