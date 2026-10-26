import express, { type Response } from "express";
import type { DecodedIdToken } from "firebase-admin/auth";
import type { Firestore } from "firebase-admin/firestore";
import { Timestamp } from "firebase-admin/firestore";
import { ApplicationService, publicApplication } from "./applications/application-service.js";
import { requireSuperAdmin, type AdminRequest, type VerifyIdToken } from "./auth/require-super-admin.js";
import { ADMIN_API_VERSION, REGION } from "./config.js";
import { healthResponseSchema, invitationResponseSchema, meResponseSchema, userResponseSchema, usersListResponseSchema } from "./http/contracts.js";
import { ApiError, errorHandler } from "./http/errors.js";
import { requestContext, requestIdFrom } from "./http/request-context.js";
import { requireHttps, restrictedCors, securityHeaders } from "./http/security.js";
import { UserQueryService, type UserDirectory } from "./users/user-query-service.js";
import { UserControlService, type UserControlAction } from "./users/user-control-service.js";
import { userOperationResponseSchema } from "./http/contracts.js";
import { InvitationService } from "./invitations/invitation-service.js";
import { DisabledInvitationEmailProvider, type InvitationEmailProvider } from "./invitations/invitation-email-provider.js";
import type { InvitationTokenKeyring } from "./invitations/invitation-token.js";
import { InvitationAcceptanceService } from "./invitations/invitation-acceptance-service.js";
import { requireAuthenticatedUser, type AuthenticatedRequest } from "./auth/require-authenticated-user.js";
import { invitationConfirmationResponseSchema, invitationValidationResponseSchema, passwordEstablishmentResponseSchema } from "./http/contracts.js";
import { ResendWebhookService } from "./invitations/resend-webhook-service.js";
import type { WebhookReplayStore } from "./invitations/resend-invitation-email-provider.js";

export type AdminApiDependencies = {
  verifyIdToken: VerifyIdToken;
  origins: ReadonlySet<string>;
  now?: () => Date;
  firestore?: Firestore;
  userDirectory?: UserDirectory;
  protectedSuperAdminUid?: string | null;
  invitationTokens?: InvitationTokenKeyring | null;
  invitationEmailProvider?: InvitationEmailProvider;
  resendWebhook?: { enabled: boolean; secret?: string; replayStore?: WebhookReplayStore };
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
  const authenticateUser = requireAuthenticatedUser(dependencies.verifyIdToken);
  const applications = dependencies.firestore ? new ApplicationService(dependencies.firestore) : null;
  const users = dependencies.firestore && dependencies.userDirectory ? new UserQueryService(dependencies.userDirectory, dependencies.firestore) : null;
  const userControl = dependencies.firestore && dependencies.userDirectory
    ? new UserControlService(dependencies.userDirectory, dependencies.firestore, dependencies.protectedSuperAdminUid ?? null)
    : null;
  const invitations = dependencies.firestore && dependencies.userDirectory
    ? new InvitationService(
      dependencies.userDirectory,
      dependencies.firestore,
      dependencies.invitationTokens ?? null,
      dependencies.invitationEmailProvider ?? new DisabledInvitationEmailProvider(),
      dependencies.protectedSuperAdminUid ?? null
    )
    : null;
  const invitationAcceptance = dependencies.firestore && dependencies.userDirectory
    ? new InvitationAcceptanceService(
      dependencies.userDirectory, dependencies.firestore, dependencies.invitationTokens ?? null,
      dependencies.protectedSuperAdminUid ?? null, () => Timestamp.fromDate(now())
    )
    : null;
  const resendWebhook = dependencies.resendWebhook?.enabled === true
    && dependencies.firestore
    && dependencies.resendWebhook.secret
    && dependencies.resendWebhook.replayStore
    ? new ResendWebhookService(dependencies.firestore, dependencies.resendWebhook.replayStore, dependencies.resendWebhook.secret, () => Timestamp.fromDate(now()))
    : null;

  function applicationService(): ApplicationService {
    if (!applications) throw new ApiError(503, "INTERNAL_ERROR", "El servicio de aplicaciones no está disponible.");
    return applications;
  }

  function userService(): UserQueryService {
    if (!users) throw new ApiError(503, "INTERNAL_ERROR", "El servicio de usuarios no está disponible.");
    return users;
  }

  function userControlService(): UserControlService {
    if (!userControl) throw new ApiError(503, "INTERNAL_ERROR", "El control de cuentas no está disponible.");
    return userControl;
  }

  function invitationService(): InvitationService {
    if (!invitations) throw new ApiError(503, "INTERNAL_ERROR", "El servicio de invitaciones no está disponible.");
    return invitations;
  }

  function invitationAcceptanceService(): InvitationAcceptanceService {
    if (!invitationAcceptance) throw new ApiError(503, "INTERNAL_ERROR", "El servicio de aceptación no está disponible.");
    return invitationAcceptance;
  }

  function sourceIdentifier(request: express.Request) {
    return `${request.ip ?? "unknown"}|${request.header("user-agent") ?? "unknown"}`;
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

  app.post("/api/webhooks/resend", requireHttps, express.raw({ type: "application/json", limit: "64kb" }), async (request, response, next) => {
    try {
      if (!resendWebhook) throw new ApiError(503, "INTERNAL_ERROR", "El receptor de eventos no está habilitado.");
      if (!Buffer.isBuffer(request.body)) throw new ApiError(400, "VALIDATION_ERROR", "La solicitud no es válida.");
      const id = request.header("svix-id") ?? "";
      const timestamp = request.header("svix-timestamp") ?? "";
      const signature = request.header("svix-signature") ?? "";
      try {
        const data = await resendWebhook.receive(request.body, { id, timestamp, signature });
        response.status(200).json({ ok: true, data, requestId: requestIdFrom(response) });
      } catch (error) {
        if (error instanceof Error && error.message === "WEBHOOK_REPLAYED") {
          response.status(200).json({ ok: true, data: { accepted: true, duplicate: true }, requestId: requestIdFrom(response) });
          return;
        }
        const invalid = error instanceof Error && (
          error.name === "ZodError"
          || ["RAW_BODY_REQUIRED", "INVALID_WEBHOOK_ID", "INVALID_WEBHOOK_SECRET", "STALE_WEBHOOK", "INVALID_WEBHOOK_SIGNATURE"].includes(error.message)
        );
        if (invalid) throw new ApiError(400, "VALIDATION_ERROR", "El evento no es válido.");
        throw new ApiError(503, "INTERNAL_ERROR", "El evento quedó pendiente de reintento seguro.");
      }
    } catch (error) { next(error); }
  });

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

  app.get("/api/admin/users", authenticate, async (request: AdminRequest, response, next) => {
    try {
      principalFrom(request);
      const input: { pageSize?: string; pageToken?: string; email?: string } = {};
      if (typeof request.query.pageSize === "string") input.pageSize = request.query.pageSize;
      if (typeof request.query.pageToken === "string") input.pageToken = request.query.pageToken;
      if (typeof request.query.email === "string") input.email = request.query.email;
      const data = await userService().list(input);
      response.status(200).json(usersListResponseSchema.parse({ ok: true, data, requestId: requestIdFrom(response) }));
    } catch (error) { next(error); }
  });

  app.get("/api/admin/users/:uid", authenticate, async (request: AdminRequest, response, next) => {
    try {
      principalFrom(request);
      const value = typeof request.params.uid === "string" ? request.params.uid : "";
      const data = await userService().get(value);
      response.status(200).json(userResponseSchema.parse({ ok: true, data, requestId: requestIdFrom(response) }));
    } catch (error) { next(error); }
  });

  for (const action of ["suspend", "reactivate", "revoke-sessions"] as const satisfies readonly UserControlAction[]) {
    app.post(`/api/admin/users/:uid/${action}`, authenticate, async (request: AdminRequest, response, next) => {
      try {
        const data = await userControlService().execute({
          action,
          uid: typeof request.params.uid === "string" ? request.params.uid : "",
          body: request.body,
          idempotencyKey: request.header("Idempotency-Key"),
          principal: principalFrom(request),
          requestId: requestIdFrom(response)
        });
        response.status(200).json(userOperationResponseSchema.parse({ ok: true, data, requestId: requestIdFrom(response) }));
      } catch (error) { next(error); }
    });
  }

  app.post("/api/admin/invitations", authenticate, async (request: AdminRequest, response, next) => {
    try {
      const data = await invitationService().create({
        body: request.body,
        idempotencyKey: request.header("Idempotency-Key"),
        principal: principalFrom(request),
        requestId: requestIdFrom(response)
      });
      response.status(201).json(invitationResponseSchema.parse({ ok: true, data, requestId: requestIdFrom(response) }));
    } catch (error) { next(error); }
  });

  app.post("/api/admin/invitations/:invitationId/resend", authenticate, async (request: AdminRequest, response, next) => {
    try {
      const data = await invitationService().resend({
        invitationId: routeParam(request.params.invitationId), body: request.body,
        idempotencyKey: request.header("Idempotency-Key"), principal: principalFrom(request), requestId: requestIdFrom(response)
      });
      response.status(200).json(invitationResponseSchema.parse({ ok: true, data, requestId: requestIdFrom(response) }));
    } catch (error) { next(error); }
  });

  app.post("/api/admin/invitations/:invitationId/revoke", authenticate, async (request: AdminRequest, response, next) => {
    try {
      const data = await invitationService().revoke({
        invitationId: routeParam(request.params.invitationId), body: request.body,
        idempotencyKey: request.header("Idempotency-Key"), principal: principalFrom(request), requestId: requestIdFrom(response)
      });
      response.status(200).json(invitationResponseSchema.parse({ ok: true, data, requestId: requestIdFrom(response) }));
    } catch (error) { next(error); }
  });

  app.post("/api/invitations/validate", async (request, response, next) => {
    try {
      const data = await invitationAcceptanceService().validate(request.body, sourceIdentifier(request));
      response.status(200).json(invitationValidationResponseSchema.parse({ ok: true, data, requestId: requestIdFrom(response) }));
    } catch (error) { next(error); }
  });

  app.post("/api/invitations/establish-password", requireHttps, async (request, response, next) => {
    try {
      const data = await invitationAcceptanceService().establishPassword(request.body, sourceIdentifier(request), requestIdFrom(response));
      response.status(200).json(passwordEstablishmentResponseSchema.parse({ ok: true, data, requestId: requestIdFrom(response) }));
    } catch (error) { next(error); }
  });

  app.post("/api/invitations/:invitationId/confirm", authenticateUser, async (request: AuthenticatedRequest, response, next) => {
    try {
      if (!request.authenticatedPrincipal) throw new ApiError(401, "AUTH_REQUIRED", "Se requiere una sesión válida.");
      const data = await invitationAcceptanceService().confirm(routeParam(request.params.invitationId), request.authenticatedPrincipal, requestIdFrom(response));
      response.status(200).json(invitationConfirmationResponseSchema.parse({ ok: true, data, requestId: requestIdFrom(response) }));
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

  app.all(["/api/admin/applications", "/api/admin/applications/:appId", "/api/admin/applications/:appId/:action", "/api/admin/users", "/api/admin/users/:uid", "/api/admin/users/:uid/:action", "/api/admin/invitations", "/api/admin/invitations/:invitationId/:action"], (_request, _response, next) => {
    next(new ApiError(405, "METHOD_NOT_ALLOWED", "El método HTTP no está permitido."));
  });

  app.all(["/api/invitations/validate", "/api/invitations/establish-password", "/api/invitations/:invitationId/confirm"], (_request, _response, next) => {
    next(new ApiError(405, "METHOD_NOT_ALLOWED", "El método HTTP no está permitido."));
  });

  app.all("/api/webhooks/resend", (_request, _response, next) => {
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
