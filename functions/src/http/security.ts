import type { NextFunction, Request, Response } from "express";
import type { ErrorCode } from "./contracts.js";
import { sendError } from "./errors.js";
import { requestIdFrom } from "./request-context.js";

export function securityHeaders(
  _request: Request,
  response: Response,
  next: NextFunction
): void {
  response.setHeader("Cache-Control", "no-store, max-age=0");
  response.setHeader("Pragma", "no-cache");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("X-Frame-Options", "DENY");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
  next();
}

export function restrictedCors(origins: ReadonlySet<string>) {
  return (request: Request, response: Response, next: NextFunction): void => {
    const origin = request.header("origin");
    response.vary("Origin");

    if (origin && !origins.has(origin)) {
      sendError(
        response,
        requestIdFrom(response),
        403,
        "ORIGIN_FORBIDDEN",
        "El origen de la solicitud no está autorizado."
      );
      return;
    }

    if (origin) {
      response.setHeader("Access-Control-Allow-Origin", origin);
      response.setHeader("Access-Control-Allow-Methods", "GET,POST,PATCH,OPTIONS");
      response.setHeader("Access-Control-Allow-Headers", "Authorization,Content-Type,X-Request-ID");
      response.setHeader("Access-Control-Max-Age", "600");
    }

    if (request.method === "OPTIONS") {
      response.status(204).end();
      return;
    }

    next();
  };
}

export function authErrorContract(code: string | undefined): {
  status: number;
  code: ErrorCode;
  message: string;
} {
  if (code === "auth/id-token-expired") {
    return { status: 401, code: "TOKEN_EXPIRED", message: "La sesión expiró." };
  }
  if (code === "auth/id-token-revoked" || code === "auth/user-disabled") {
    return { status: 401, code: "TOKEN_REVOKED", message: "La sesión fue revocada." };
  }
  return { status: 401, code: "TOKEN_INVALID", message: "La sesión no es válida." };
}
