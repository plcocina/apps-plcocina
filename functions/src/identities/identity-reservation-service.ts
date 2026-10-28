import { createHash } from "node:crypto";
import { Timestamp, type Firestore } from "firebase-admin/firestore";
import { z } from "zod";
import {
  identifierKeyHash,
  identityIdentifierKeyDocumentSchema,
  identityReservationOperationSchema,
  normalizeIdentityEmail,
  normalizePhoneE164,
  type IdentityIdentifierKind
} from "./identity-models.js";

const uidSchema = z.string().min(1).max(128).refine((value) => !value.includes("/"));
const operationIdSchema = z.string().uuid();

export class IdentityReservationError extends Error {
  constructor(readonly code: "IDENTIFIER_COLLISION" | "IDEMPOTENCY_CONFLICT", message: string) {
    super(message);
    this.name = "IdentityReservationError";
  }
}

export type IdentityReservationResult = {
  operationId: string;
  uid: string;
  kind: IdentityIdentifierKind;
  identifierHash: string;
  state: "reserved";
  replayed: boolean;
};

function canonicalInputHash(input: { uid: string; kind: IdentityIdentifierKind; identifierHash: string }): string {
  return createHash("sha256").update(JSON.stringify(input)).digest("hex");
}

export class IdentityReservationService {
  constructor(
    private readonly db: Firestore,
    private readonly pepper: Buffer,
    private readonly now: () => Timestamp = () => Timestamp.now()
  ) {
    if (pepper.length < 32) throw new Error("IDENTIFIER_PEPPER_TOO_SHORT");
  }

  async reserve(input: {
    operationId: string;
    uid: string;
    kind: IdentityIdentifierKind;
    value: string;
  }): Promise<IdentityReservationResult> {
    const operationId = operationIdSchema.parse(input.operationId);
    const uid = uidSchema.parse(input.uid);
    const normalized = input.kind === "email"
      ? normalizeIdentityEmail(input.value)
      : normalizePhoneE164(input.value);
    const identifierHash = identifierKeyHash(input.kind, normalized, this.pepper);
    const inputHash = canonicalInputHash({ uid, kind: input.kind, identifierHash });
    const keyRef = this.db.collection("authIdentifierKeys").doc(identifierHash);
    const operationRef = this.db.collection("identityOperations").doc(operationId);

    return this.db.runTransaction(async (transaction) => {
      const [operationSnapshot, keySnapshot] = await Promise.all([
        transaction.get(operationRef),
        transaction.get(keyRef)
      ]);

      if (operationSnapshot.exists) {
        const operation = identityReservationOperationSchema.safeParse(operationSnapshot.data());
        if (!operation.success
          || operation.data.inputHash !== inputHash
          || operation.data.uid !== uid
          || operation.data.kind !== input.kind
          || operation.data.identifierHash !== identifierHash) {
          throw new IdentityReservationError("IDEMPOTENCY_CONFLICT", "La operación ya fue utilizada con otros datos.");
        }
        return { operationId, uid, kind: input.kind, identifierHash, state: "reserved", replayed: true };
      }

      if (keySnapshot.exists) {
        const key = identityIdentifierKeyDocumentSchema.safeParse(keySnapshot.data());
        if (!key.success || key.data.state !== "released") {
          throw new IdentityReservationError("IDENTIFIER_COLLISION", "El identificador ya está reservado.");
        }
      }

      const timestamp = this.now();
      const key = identityIdentifierKeyDocumentSchema.parse({
        kind: input.kind,
        identifierHash,
        uid,
        state: "reserved",
        operationId,
        createdAt: keySnapshot.exists
          ? identityIdentifierKeyDocumentSchema.parse(keySnapshot.data()).createdAt
          : timestamp,
        updatedAt: timestamp,
        releasedAt: null,
        version: 1
      });
      const operation = identityReservationOperationSchema.parse({
        operationId,
        type: "identity.identifier_reserve",
        uid,
        kind: input.kind,
        identifierHash,
        inputHash,
        status: "completed",
        result: { identifierHash, state: "reserved" },
        createdAt: timestamp,
        completedAt: timestamp,
        version: 1
      });

      transaction.set(keyRef, key);
      transaction.create(operationRef, operation);
      return { operationId, uid, kind: input.kind, identifierHash, state: "reserved", replayed: false };
    });
  }
}
