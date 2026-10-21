import express, { type Response } from "express";
import type { DecodedIdToken } from "firebase-admin/auth";
import type { Firestore } from "firebase-admin/firestore";
import { ApplicationService, publicApplication } from "./applications/application-service.js";
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
  firestore?: Firestore;
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
  const applications = dependencies.firestore ? new ApplicationService(dependencies.firestore) : null;

  function applicationService(): ApplicationService {
    if (!applications) throw new ApiError(503, "INTERNAL_ERROR", "El servicio de aplicaciones no está disponible.");
    return applications;
  }

  function appId(value: string): string {
    if (!/^[a-zA-Z0-9_-]{1,128}$/.test(value)) throw new ApiError(400, "VALIDATION_ERROR", "El identificador no es válido.");
    return value;
  }

  function routeParam(value: string | string[] | undefined): string {
    return appId(typeof value === "string" ? value : "");
  }

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

  app.get("/api/admin/applications", authenticate, async (request: AdminRequest, response, next) => {
    try {
      principalFrom(request);
      const filters: { q?: string; status?: string; accessLevel?: string; category?: string } = {};
      if (typeof request.query.q === "string") filters.q = request.query.q;
      if (typeof request.query.status === "string") filters.status = request.query.status;
      if (typeof request.query.accessLevel === "string") filters.accessLevel = request.query.accessLevel;
      if (typeof request.query.category === "string") filters.category = request.query.category;
      const data = await applicationService().list(filters);
      response.status(200).json({ ok: true, data, requestId: requestIdFrom(response) });
    } catch (error) { next(error); }
  });

  app.post("/api/admin/applications", authenticate, async (request: AdminRequest, response, next) => {
    try {
      const data = await applicationService().create(request.body, principalFrom(request), requestIdFrom(response));
      response.status(201).json({ ok: true, data, requestId: requestIdFrom(response) });
    } catch (error) { next(error); }
  });

  app.get("/api/admin/applications/:appId", authenticate, async (request: AdminRequest, response, next) => {
    try {
      principalFrom(request);
      const data = await applicationService().get(routeParam(request.params.appId));
      response.status(200).json({ ok: true, data, requestId: requestIdFrom(response) });
    } catch (error) { next(error); }
  });

  app.patch("/api/admin/applications/:appId", authenticate, async (request: AdminRequest, response, next) => {
    try {
      const data = await applicationService().update(routeParam(request.params.appId), request.body, principalFrom(request), requestIdFrom(response));
      response.status(200).json({ ok: true, data, requestId: requestIdFrom(response) });
    } catch (error) { next(error); }
  });

  for (const [action, target] of [["activate", "active"], ["deactivate", "inactive"], ["archive", "archived"]] as const) {
    app.post(`/api/admin/applications/:appId/${action}`, authenticate, async (request: AdminRequest, response, next) => {
      try {
        const data = await applicationService().changeStatus(routeParam(request.params.appId), target, request.body, principalFrom(request), requestIdFrom(response));
        response.status(200).json({ ok: true, data, requestId: requestIdFrom(response) });
      } catch (error) { next(error); }
    });
  }

  app.get("/api/catalog/applications", async (_request, response, next) => {
    try {
      const records = await applicationService().list({ publicOnly: true });
      response.status(200).json({ ok: true, data: records.sort((a, b) => a.displayOrder - b.displayOrder).map(publicApplication), requestId: requestIdFrom(response) });
    } catch (error) { next(error); }
  });

  app.all(["/api/admin/applications", "/api/admin/applications/:appId", "/api/admin/applications/:appId/:action"], (_request, _response, next) => {
    next(new ApiError(405, "METHOD_NOT_ALLOWED", "El método HTTP no está permitido."));
  });

  app.all(["/api/admin/health", "/api/admin/me", "/api/catalog/applications"], (_request, _response, next) => {
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
