import { Timestamp, type Firestore } from "firebase-admin/firestore";
import {
  adminOperationDocumentSchema,
  invitationDocumentSchema,
  userProfileDocumentSchema,
  type UserProfileDocument
} from "../models/admin-collections.js";
import { normalizeIdentityEmail, normalizePhoneE164 } from "./identity-models.js";

export const ACTIVATION_PROOF_WINDOW_MS = 15 * 60_000;

export type BlockingAuthUser = {
  uid: string;
  email?: string;
  phoneNumber?: string;
  emailVerified: boolean;
  disabled: boolean;
  customClaims?: Record<string, unknown>;
};

export type BlockingAuthContext = {
  signInMethod?: string;
  providerId?: string;
};

export interface IdentityBlockingStore {
  getProfile(uid: string): Promise<UserProfileDocument | null>;
  hasReconciliation(uid: string, pendingOperationId: string | null): Promise<boolean>;
  hasValidV1Invitation(uid: string, normalizedEmail: string, now: Timestamp): Promise<boolean>;
}

export class FirestoreIdentityBlockingStore implements IdentityBlockingStore {
  constructor(private readonly db: Firestore) {}

  async getProfile(uid: string): Promise<UserProfileDocument | null> {
    const snapshot = await this.db.collection("users").doc(uid).get();
    if (!snapshot.exists) return null;
    const parsed = userProfileDocumentSchema.safeParse(snapshot.data());
    if (!parsed.success) throw new IdentityBlockingError("PROFILE_INVALID");
    return parsed.data;
  }

  async hasReconciliation(uid: string, pendingOperationId: string | null): Promise<boolean> {
    if (pendingOperationId) {
      const snapshot = await this.db.collection("adminOperations").doc(pendingOperationId).get();
      if (!snapshot.exists) return true;
      const operation = adminOperationDocumentSchema.safeParse(snapshot.data());
      if (!operation.success || operation.data.targetUid !== uid || operation.data.status !== "completed") return true;
    }
    const snapshot = await this.db.collection("adminOperations")
      .where("targetUid", "==", uid)
      .where("status", "==", "reconciliation_required")
      .limit(1)
      .get();
    return !snapshot.empty;
  }

  async hasValidV1Invitation(uid: string, normalizedEmail: string, now: Timestamp): Promise<boolean> {
    const snapshot = await this.db.collection("invitations").where("uid", "==", uid).limit(10).get();
    return snapshot.docs.some((document) => {
      const parsed = invitationDocumentSchema.safeParse(document.data());
      return parsed.success
        && parsed.data.normalizedEmail === normalizedEmail
        && parsed.data.status === "password_set"
        && parsed.data.confirmationExpiresAt !== null
        && parsed.data.confirmationExpiresAt.toMillis() > now.toMillis()
        && parsed.data.pendingOperationId === null;
    });
  }
}

type BlockingCode =
  | "CREATE_NOT_PREPROVISIONED"
  | "USER_NOT_AUTHORIZED"
  | "PROFILE_INVALID"
  | "ACCOUNT_DISABLED"
  | "METHOD_NOT_ALLOWED"
  | "IDENTIFIER_MISMATCH"
  | "ACTIVATION_EXPIRED"
  | "RECONCILIATION_REQUIRED"
  | "SUPER_ADMIN_INVALID"
  | "ADMIN_CLAIM_FORBIDDEN"
  | "STATE_READ_FAILED";

export class IdentityBlockingError extends Error {
  constructor(readonly code: BlockingCode) {
    super("No fue posible autorizar la operación de identidad.");
    this.name = "IdentityBlockingError";
  }
}

function method(context: BlockingAuthContext): string | null {
  return context.signInMethod ?? context.providerId ?? null;
}

function assertEmployeeHasNoAdminClaim(user: BlockingAuthUser): void {
  if (user.customClaims?.super_admin === true) throw new IdentityBlockingError("ADMIN_CLAIM_FORBIDDEN");
}

export class IdentityBlockingService {
  constructor(
    private readonly store: IdentityBlockingStore,
    private readonly protectedSuperAdminUid: string,
    private readonly now: () => Timestamp = () => Timestamp.now()
  ) {
    if (!protectedSuperAdminUid || protectedSuperAdminUid.includes("/") || protectedSuperAdminUid.length > 128) {
      throw new Error("PROTECTED_SUPER_ADMIN_UID_REQUIRED");
    }
  }

  beforeCreate(_user: BlockingAuthUser): never {
    // Admin SDK preprovisioning bypasses blocking triggers. Every client-side creation is denied.
    throw new IdentityBlockingError("CREATE_NOT_PREPROVISIONED");
  }

  async beforeSignIn(user: BlockingAuthUser, context: BlockingAuthContext): Promise<void> {
    if (user.uid === this.protectedSuperAdminUid) {
      this.assertProtectedSuperAdmin(user, context);
      return;
    }
    assertEmployeeHasNoAdminClaim(user);
    if (user.disabled) throw new IdentityBlockingError("ACCOUNT_DISABLED");

    let profile: UserProfileDocument | null;
    try {
      profile = await this.store.getProfile(user.uid);
    } catch (error) {
      if (error instanceof IdentityBlockingError) throw error;
      throw new IdentityBlockingError("STATE_READ_FAILED");
    }
    if (!profile) throw new IdentityBlockingError("USER_NOT_AUTHORIZED");

    try {
      if (await this.store.hasReconciliation(user.uid, profile.pendingOperationId)) {
        throw new IdentityBlockingError("RECONCILIATION_REQUIRED");
      }
    } catch (error) {
      if (error instanceof IdentityBlockingError) throw error;
      throw new IdentityBlockingError("STATE_READ_FAILED");
    }

    if (profile.version === 1) {
      await this.validateV1(user, context, profile);
      return;
    }
    this.validateV2(user, context, profile);
  }

  private assertProtectedSuperAdmin(user: BlockingAuthUser, context: BlockingAuthContext): void {
    if (user.disabled
      || user.customClaims?.super_admin !== true
      || !user.email
      || !user.emailVerified
      || method(context) !== "password") {
      throw new IdentityBlockingError("SUPER_ADMIN_INVALID");
    }
  }

  private async validateV1(
    user: BlockingAuthUser,
    context: BlockingAuthContext,
    profile: Extract<UserProfileDocument, { version: 1 }>
  ): Promise<void> {
    if (method(context) !== "password") throw new IdentityBlockingError("METHOD_NOT_ALLOWED");
    if (!user.email || normalizeIdentityEmail(user.email) !== profile.normalizedEmail) {
      throw new IdentityBlockingError("IDENTIFIER_MISMATCH");
    }
    if (profile.status === "active" && profile.invitationStatus === "accepted" && !profile.authDisabled) return;
    if (profile.status !== "invited" || profile.invitationStatus !== "pending" || !profile.authDisabled) {
      throw new IdentityBlockingError("ACCOUNT_DISABLED");
    }
    try {
      if (await this.store.hasValidV1Invitation(user.uid, profile.normalizedEmail, this.now())) return;
    } catch {
      throw new IdentityBlockingError("STATE_READ_FAILED");
    }
    throw new IdentityBlockingError("ACTIVATION_EXPIRED");
  }

  private validateV2(
    user: BlockingAuthUser,
    context: BlockingAuthContext,
    profile: Extract<UserProfileDocument, { version: 2 }>
  ): void {
    if (profile.activationStatus === "reconciliation_required" || profile.activationStatus === "recovery_required") {
      throw new IdentityBlockingError("RECONCILIATION_REQUIRED");
    }
    if (profile.status === "disabled" || profile.authDisabled) throw new IdentityBlockingError("ACCOUNT_DISABLED");
    if (profile.activationStatus !== "active" && profile.activationStatus !== "auth_enabled_pending_proof") {
      throw new IdentityBlockingError("USER_NOT_AUTHORIZED");
    }
    if (profile.authMethod === "sms") {
      if (method(context) !== "phone") throw new IdentityBlockingError("METHOD_NOT_ALLOWED");
      if (!user.phoneNumber || normalizePhoneE164(user.phoneNumber) !== profile.normalizedPhone) {
        throw new IdentityBlockingError("IDENTIFIER_MISMATCH");
      }
      if (profile.activationStatus === "active" && !profile.phoneVerifiedAt) {
        throw new IdentityBlockingError("PROFILE_INVALID");
      }
    } else {
      if (method(context) !== "emailLink") throw new IdentityBlockingError("METHOD_NOT_ALLOWED");
      if (!user.email || !user.emailVerified || normalizeIdentityEmail(user.email) !== profile.normalizedEmail) {
        throw new IdentityBlockingError("IDENTIFIER_MISMATCH");
      }
      if (profile.activationStatus === "active" && !profile.emailVerifiedAt) {
        throw new IdentityBlockingError("PROFILE_INVALID");
      }
    }
    if (profile.activationStatus === "auth_enabled_pending_proof") {
      const now = this.now().toMillis();
      const startsAt = profile.sessionValidAfter.toMillis();
      if (now < startsAt || now > startsAt + ACTIVATION_PROOF_WINDOW_MS) {
        throw new IdentityBlockingError("ACTIVATION_EXPIRED");
      }
    }
  }
}
