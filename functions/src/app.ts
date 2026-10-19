import express, { type Response } from "express";
import type { DecodedIdToken } from "firebase-admin/auth";
import { requireSuperAdmin, type AdminRequest, type VerifyIdToken } from "./auth/require-super-admin.js";
import { ADMIN_API_VERSION, REGION } from "./config.js";
import { healthResponseSchema, meResponseSchema } from "./http/contracts.js";
import { ApiError, errorHandler } from "./http/errors.js";
import { requestContext, requestIdFrom } from "./http/request-context.js";
import { restrictedCors, securityHeaders } from "./http/security.js";

export type AdminApiDependencies = {
  verifyIdToken: VerifyIdToken;
  origins: ReadonlySet<string>;
  now?: () => Date;
};

function principalFrom(request: AdminRequest) {
  if (!request.adminPrincipal) {
    throw new ApiError(500, "INTERNAL_ERROR", "No fue posible completar la solicitud.");
  }
  return request.adminPrincipal;
}

function sendValidated(
  response: Response,
  schema: typeof healthResponseSchema | typeof meResponseSchema,
  body: unknown
): void {
  response.status(200).json(schema.parse(body));
}

export function createAdminApp(dependencies: AdminApiDependencies) {
  const app = express();
  const now = dependencies.now ?? (() => new Date());
  const authenticate = requireSuperAdmin(dependencies.verifyIdToken);

  app.disable("x-powered-by");
  app.use(requestContext);
  app.use(securityHeaders);
  app.use(restrictedCors(dependencies.origins));
  app.use(express.json({ limit: "16kb", strict: true }));

  app.get("/api/admin/health", authenticate, (request: AdminRequest, response) => {
    principalFrom(request);
    sendValidated(response, healthResponseSchema, {
      ok: true,
      data: {
        status: "ok",
        service: "admin-api",
        version: ADMIN_API_VERSION,
        region: REGION,
        checkedAt: now().toISOString()
      },
      requestId: requestIdFrom(response)
    });
  });

  app.get("/api/admin/me", authenticate, (request: AdminRequest, response) => {
    const principal = principalFrom(request);
    sendValidated(response, meResponseSchema, {
      ok: true,
      data: principal,
      requestId: requestIdFrom(response)
    });
  });

  app.all(["/api/admin/health", "/api/admin/me"], (_request, _response, next) => {
    next(new ApiError(405, "METHOD_NOT_ALLOWED", "El método HTTP no está permitido."));
  });

  app.all("/api/admin/{*path}", (_request, _response, next) => {
    next(new ApiError(404, "NOT_FOUND", "La ruta solicitada no existe."));
  });

  app.use((_request, _response, next) => {
    next(new ApiError(404, "NOT_FOUND", "La ruta solicitada no existe."));
  });

  app.use(errorHandler);
  return app;
}

export type { DecodedIdToken };
