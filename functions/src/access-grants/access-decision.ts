import type { DirectoryUser } from "../users/user-query-service.js";
import type { AccessGrantDocument, ApplicationDocument, UserDocument } from "../models/admin-collections.js";

export type AccessDecisionReason =
  | "ALLOWED_PUBLIC"
  | "ALLOWED_GRANT"
  | "USER_INVALID"
  | "APPLICATION_INACTIVE"
  | "GRANT_REQUIRED";

export function decideApplicationAccess(input: {
  authUser: DirectoryUser | null;
  user: UserDocument | null;
  application: ApplicationDocument | null;
  grant: AccessGrantDocument | null;
}): { allowed: boolean; reason: AccessDecisionReason } {
  const { authUser, user, application, grant } = input;
  const validUser = Boolean(
    authUser
    && user
    && !authUser.disabled
    && user.status === "active"
    && !user.authDisabled
    && typeof authUser.email === "string"
    && user.normalizedEmail === authUser.email.toLowerCase()
  );
  if (!validUser) return { allowed: false, reason: "USER_INVALID" };
  if (!application || application.status !== "active") return { allowed: false, reason: "APPLICATION_INACTIVE" };
  if (application.accessLevel === "public") return { allowed: true, reason: "ALLOWED_PUBLIC" };
  if (
    grant?.status === "active"
    && grant.userId === authUser!.uid
    && grant.applicationId === application.appId
  ) return { allowed: true, reason: "ALLOWED_GRANT" };
  return { allowed: false, reason: "GRANT_REQUIRED" };
}
