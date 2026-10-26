import type { DecodedIdToken } from "firebase-admin/auth";
import type { NextFunction, Request, Response } from "express";
import { ApiError } from "../http/errors.js";
import { authErrorContract } from "../http/security.js";
import type { VerifyIdToken } from "./require-super-admin.js";

export type AuthenticatedPrincipal = {
  uid: string;
  email: string;
  superAdmin: boolean;
  decoded: DecodedIdToken;
};

export interface AuthenticatedRequest extends Request {
  authenticatedPrincipal?: AuthenticatedPrincipal;
}

function bearerToken(request: Request) {
  const match = request.header("authorization")?.match(/^Bearer ([^\s]+)$/);
  if (!match?.[1]) throw new ApiError(401, "AUTH_REQUIRED", "Se requiere una sesión válida.");
  return match[1];
}

export function requireAuthenticatedUser(verifyIdToken: VerifyIdToken) {
  return (request: AuthenticatedRequest, _response: Response, next: NextFunction): void => {
    void (async () => {
      try {
        const decoded = await verifyIdToken(bearerToken(request), true);
        if (typeof decoded.email !== "string") throw new ApiError(401, "TOKEN_INVALID", "La sesión no contiene una identidad válida.");
        request.authenticatedPrincipal = {
          uid: decoded.uid,
          email: decoded.email.toLowerCase(),
          superAdmin: decoded.super_admin === true,
          decoded
        };
        next();
      } catch (error) {
        if (error instanceof ApiError) return next(error);
        const code = typeof error === "object" && error !== null && "code" in error ? String(error.code) : undefined;
        const contract = authErrorContract(code);
        next(new ApiError(contract.status, contract.code, contract.message));
      }
    })();
  };
}
