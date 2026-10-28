import { activationStatusSchema, type ActivationStatus } from "./identity-models.js";

const ALLOWED_TRANSITIONS: Readonly<Record<ActivationStatus, ReadonlySet<ActivationStatus>>> = {
  pending: new Set(["auth_enabled_pending_proof", "recovery_required", "reconciliation_required"]),
  auth_enabled_pending_proof: new Set(["active", "pending", "recovery_required", "reconciliation_required"]),
  active: new Set(["recovery_required", "reconciliation_required"]),
  recovery_required: new Set(["pending", "auth_enabled_pending_proof", "reconciliation_required"]),
  reconciliation_required: new Set(["pending", "recovery_required"])
};

export function canTransitionIdentity(from: ActivationStatus, to: ActivationStatus): boolean {
  return ALLOWED_TRANSITIONS[from].has(to);
}

export function assertIdentityTransition(fromInput: unknown, toInput: unknown): void {
  const from = activationStatusSchema.parse(fromInput);
  const to = activationStatusSchema.parse(toInput);
  if (!canTransitionIdentity(from, to)) throw new Error(`IDENTITY_TRANSITION_REJECTED:${from}:${to}`);
}
