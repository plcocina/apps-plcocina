import type { InvitationDocument } from "../models/admin-collections.js";

export type InvitationStatus = InvitationDocument["status"];

const TRANSITIONS: Readonly<Record<InvitationStatus, ReadonlySet<InvitationStatus>>> = {
  provisioning: new Set(["pending_delivery", "reconciliation_required", "revoked"]),
  pending_delivery: new Set(["active", "reconciliation_required", "expired", "revoked"]),
  active: new Set(["accepting", "pending_delivery", "expired", "revoked"]),
  accepting: new Set(["active", "password_set", "reconciliation_required", "revoked"]),
  password_set: new Set(["accepted", "expired", "revoked", "reconciliation_required"]),
  accepted: new Set(),
  expired: new Set(["pending_delivery"]),
  revoked: new Set(),
  reconciliation_required: new Set(["provisioning", "pending_delivery", "active", "accepting", "password_set", "expired", "revoked"])
};

export function canTransitionInvitation(from: InvitationStatus, to: InvitationStatus): boolean {
  return from === to || TRANSITIONS[from].has(to);
}

const EXPIRABLE = new Set<InvitationStatus>(["provisioning", "pending_delivery", "active", "password_set", "reconciliation_required"]);

export function effectiveInvitationStatus(invitation: InvitationDocument, serverNow: Date | number): InvitationStatus {
  const nowMillis = serverNow instanceof Date ? serverNow.getTime() : serverNow;
  const deadline = invitation.status === "password_set" && invitation.confirmationExpiresAt
    ? invitation.confirmationExpiresAt.toMillis()
    : invitation.expiresAt.toMillis();
  return EXPIRABLE.has(invitation.status) && deadline <= nowMillis ? "expired" : invitation.status;
}
