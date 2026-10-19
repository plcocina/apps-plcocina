import type { DecodedIdToken } from "firebase-admin/auth";
import type { NextFunction, Request, Response } from "express";
import { ApiError } from "../http/errors.js";
import { authErrorContract } from "../http/security.js";

export type VerifyIdToken = (
  token: string,
  checkRevoked: boolean
) => Promise<DecodedIdToken>;

export type AdminPrincipal = {
  uid: string;
  email: string | null;
  authTime: number;
  issuedAt: number;
  superAdmin: true;
};

export interface AdminRequest extends Request {
  adminPrincipal?: AdminPrincipal;
}

function bearerToken(request: Request): string {
  const authorization = request.header("authorization");
  const match = authorization?.match(/^Bearer ([^\s]+)$/);
  if (!match?.[1]) {
    throw new ApiError(401, "AUTH_REQUIRED", "Se requiere una sesión administrativa.");
  }
  return match[1];
}

export function requireSuperAdmin(verifyIdToken: VerifyIdToken) {
  return (request: AdminRequest, _response: Response, next: NextFunction): void => {
    void (async () => {
      try {
        const decoded = await verifyIdToken(bearerToken(request), true);
        if (decoded.super_admin !== true) {
          throw new ApiError(403, "ADMIN_REQUIRED", "La cuenta no tiene autorización administrativa.");
        }

        request.adminPrincipal = {
          uid: decoded.uid,
          email: typeof decoded.email === "string" ? decoded.email : null,
          authTime: decoded.auth_time,
          issuedAt: decoded.iat,
          superAdmin: true
        };
        next();
      } catch (error) {
        if (error instanceof ApiError) {
          next(error);
          return;
        }

        const code = typeof error === "object" && error !== null && "code" in error
          ? String(error.code)
          : undefined;
        const contract = authErrorContract(code);
        next(new ApiError(contract.status, contract.code, contract.message));
      }
    })();
  };
}
