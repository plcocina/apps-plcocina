import { createHash } from "node:crypto";
import { Timestamp, type Firestore } from "firebase-admin/firestore";
import { webhookReplayEventDocumentSchema } from "../models/admin-collections.js";
import type { WebhookReplayStore } from "./resend-invitation-email-provider.js";

function eventDocumentId(eventId: string) {
  return createHash("sha256").update(eventId, "utf8").digest("hex");
}

export class FirestoreWebhookReplayStore implements WebhookReplayStore {
  constructor(
    private readonly db: Firestore,
    private readonly now: () => Timestamp = () => Timestamp.now(),
    private readonly retentionMs = 24 * 60 * 60_000,
    private readonly leaseMs = 5 * 60_000
  ) {}

  async claim(eventId: string, signatureExpiresAt: Date): Promise<boolean> {
    if (!/^msg_[A-Za-z0-9_-]{1,240}$/.test(eventId)) throw new Error("INVALID_WEBHOOK_ID");
    const reference = this.db.collection("webhookReplayEvents").doc(eventDocumentId(eventId));
    return this.db.runTransaction(async (transaction) => {
      const claimedAt = this.now();
      const snapshot = await transaction.get(reference);
      if (snapshot.exists) {
        const existing = webhookReplayEventDocumentSchema.parse(snapshot.data());
        if (existing.status === "completed") return false;
        if (existing.status === "processing" && existing.leaseExpiresAt.toMillis() > claimedAt.toMillis()) return false;
        transaction.update(reference, {
          status: "processing", attempts: existing.attempts + 1, updatedAt: claimedAt,
          leaseExpiresAt: Timestamp.fromMillis(claimedAt.toMillis() + this.leaseMs)
        });
        return true;
      }
      const expiresAt = Timestamp.fromMillis(Math.max(
        claimedAt.toMillis() + this.retentionMs,
        signatureExpiresAt.getTime()
      ));
      transaction.create(reference, webhookReplayEventDocumentSchema.parse({
        eventIdHash: eventDocumentId(eventId),
        provider: "resend",
        status: "processing",
        attempts: 1,
        claimedAt,
        updatedAt: claimedAt,
        leaseExpiresAt: Timestamp.fromMillis(claimedAt.toMillis() + this.leaseMs),
        completedAt: null,
        expiresAt,
        version: 1
      }));
      return true;
    });
  }

  async complete(eventId: string) {
    await this.transition(eventId, "completed");
  }

  async release(eventId: string) {
    await this.transition(eventId, "retryable");
  }

  private async transition(eventId: string, status: "completed" | "retryable") {
    const reference = this.db.collection("webhookReplayEvents").doc(eventDocumentId(eventId));
    await this.db.runTransaction(async (transaction) => {
      const snapshot = await transaction.get(reference);
      if (!snapshot.exists) throw new Error("WEBHOOK_CLAIM_NOT_FOUND");
      const existing = webhookReplayEventDocumentSchema.parse(snapshot.data());
      if (existing.status === "completed") return;
      const timestamp = this.now();
      transaction.update(reference, {
        status,
        updatedAt: timestamp,
        leaseExpiresAt: timestamp,
        completedAt: status === "completed" ? timestamp : null
      });
    });
  }
}
