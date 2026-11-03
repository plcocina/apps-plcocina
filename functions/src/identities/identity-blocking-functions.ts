import { HttpsError, type AuthBlockingEvent } from "firebase-functions/v2/identity";
import { IdentityBlockingError, IdentityBlockingService, type BlockingAuthUser } from "./identity-blocking-service.js";

function userFrom(event: AuthBlockingEvent): BlockingAuthUser {
  if (!event.data) throw new HttpsError("permission-denied", "No fue posible autorizar la operación de identidad.");
  const user: BlockingAuthUser = {
    uid: event.data.uid,
    emailVerified: event.data.emailVerified,
    disabled: event.data.disabled
  };
  if (event.data.email) user.email = event.data.email;
  if (event.data.phoneNumber) user.phoneNumber = event.data.phoneNumber;
  if (event.data.customClaims) user.customClaims = event.data.customClaims;
  return user;
}

function deny(error: unknown): never {
  if (error instanceof HttpsError) throw error;
  if (error instanceof IdentityBlockingError) {
    throw new HttpsError("permission-denied", "No fue posible autorizar la operación de identidad.");
  }
  throw new HttpsError("internal", "No fue posible validar la identidad.");
}

// Fábricas aisladas: index.ts no las importa ni registra como triggers desplegables.
export function createBeforeCreateHandler(service: IdentityBlockingService) {
  return async (event: AuthBlockingEvent): Promise<void> => {
    try { service.beforeCreate(userFrom(event)); } catch (error) { deny(error); }
  };
}

export function createBeforeSignInHandler(service: IdentityBlockingService) {
  return async (event: AuthBlockingEvent): Promise<void> => {
    try {
      await service.beforeSignIn(userFrom(event), {
        ...(event.credential?.signInMethod ? { signInMethod: event.credential.signInMethod } : {}),
        ...(event.credential?.providerId ? { providerId: event.credential.providerId } : {})
      });
    } catch (error) { deny(error); }
  };
}
