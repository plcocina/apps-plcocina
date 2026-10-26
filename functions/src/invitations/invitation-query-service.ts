import { Buffer } from "node:buffer";
import { FieldPath, type DocumentSnapshot, type Firestore, type QueryDocumentSnapshot } from "firebase-admin/firestore";
import { z } from "zod";
import { ApiError } from "../http/errors.js";
import { invitationDocumentSchema, type InvitationDocument } from "../models/admin-collections.js";
import { effectiveInvitationStatus } from "./invitation-transitions.js";

const emailSchema = z.string().trim().email().max(254).transform((value) => value.toLowerCase());
const invitationIdSchema = z.string().uuid();
const cursorSchema = z.object({ after: invitationIdSchema }).strict();

function encodeCursor(after: string): string {
  return Buffer.from(JSON.stringify({ after }), "utf8").toString("base64url");
}

function decodeCursor(value: string | undefined): string | null {
  if (!value) return null;
  if (value.length > 1024) throw new ApiError(400, "VALIDATION_ERROR", "El cursor no es válido.");
  try {
    return cursorSchema.parse(JSON.parse(Buffer.from(value, "base64url").toString("utf8"))).after;
  } catch {
    throw new ApiError(400, "VALIDATION_ERROR", "El cursor no es válido.");
  }
}

function iso(value: FirebaseFirestore.Timestamp | null): string | null {
  return value ? value.toDate().toISOString() : null;
}

export function administrativeInvitation(invitation: InvitationDocument, now: number) {
  return {
    invitationId: invitation.invitationId,
    email: invitation.email,
    displayName: invitation.displayName,
    status: effectiveInvitationStatus(invitation, now),
    deliveryStatus: invitation.delivery.status,
    createdAt: iso(invitation.createdAt),
    expiresAt: iso(invitation.expiresAt),
    acceptedAt: iso(invitation.acceptedAt),
    revision: invitation.revision
  };
}

function parseSnapshot(snapshot: DocumentSnapshot | QueryDocumentSnapshot, now: number) {
  const parsed = invitationDocumentSchema.safeParse(snapshot.data());
  if (!parsed.success) throw new ApiError(500, "INTERNAL_ERROR", "No fue posible consultar la invitación.");
  return administrativeInvitation(parsed.data, now);
}

export class InvitationQueryService {
  constructor(private readonly db: Firestore, private readonly now: () => Date = () => new Date()) {}

  async list(input: { pageSize?: string; pageToken?: string; email?: string }) {
    if (input.email !== undefined) {
      if (input.pageToken !== undefined || input.pageSize !== undefined) {
        throw new ApiError(400, "VALIDATION_ERROR", "La consulta por correo no admite paginación.");
      }
      const email = emailSchema.safeParse(input.email);
      if (!email.success) throw new ApiError(400, "VALIDATION_ERROR", "El correo electrónico no es válido.");
      const snapshot = await this.db.collection("invitations").where("normalizedEmail", "==", email.data).limit(20).get();
      return { invitations: snapshot.docs.map((doc) => parseSnapshot(doc, this.now().getTime())), nextPageToken: null };
    }

    const pageSize = input.pageSize === undefined ? 25 : Number(input.pageSize);
    if (!Number.isInteger(pageSize) || pageSize < 1 || pageSize > 100) {
      throw new ApiError(400, "VALIDATION_ERROR", "El tamaño de página debe estar entre 1 y 100.");
    }
    const after = decodeCursor(input.pageToken);
    let query = this.db.collection("invitations").orderBy(FieldPath.documentId()).limit(pageSize + 1);
    if (after) query = query.startAfter(after);
    const snapshot = await query.get();
    const page = snapshot.docs.slice(0, pageSize);
    return {
      invitations: page.map((doc) => parseSnapshot(doc, this.now().getTime())),
      nextPageToken: snapshot.docs.length > pageSize && page.length ? encodeCursor(page.at(-1)!.id) : null
    };
  }

  async get(invitationIdInput: string) {
    const invitationId = invitationIdSchema.safeParse(invitationIdInput);
    if (!invitationId.success) throw new ApiError(400, "VALIDATION_ERROR", "El identificador de invitación no es válido.");
    const snapshot = await this.db.collection("invitations").doc(invitationId.data).get();
    if (!snapshot.exists) throw new ApiError(404, "NOT_FOUND", "La invitación no existe.");
    return parseSnapshot(snapshot, this.now().getTime());
  }
}
