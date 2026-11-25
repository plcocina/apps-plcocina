import express, { type Response } from "express";
import { z } from "zod";
import type { DecodedIdToken } from "firebase-admin/auth";
import type { Firestore } from "firebase-admin/firestore";
import { Timestamp } from "firebase-admin/firestore";
import { ApplicationService, publicApplication } from "./applications/application-service.js";
import { requireSuperAdmin, type AdminPrincipal, type AdminRequest, type VerifyIdToken } from "./auth/require-super-admin.js";
import { ADMIN_API_VERSION, REGION } from "./config.js";
import { accessGrantsListResponseSchema, healthResponseSchema, invitationDetailResponseSchema, invitationResponseSchema, invitationsListResponseSchema, meResponseSchema, userResponseSchema, usersListResponseSchema } from "./http/contracts.js";
import { ApiError, errorHandler } from "./http/errors.js";
import { requestContext, requestIdFrom } from "./http/request-context.js";
import { requireHttps, restrictedCors, securityHeaders } from "./http/security.js";
import { UserQueryService, type UserDirectory } from "./users/user-query-service.js";
import { UserControlService, type UserControlAction } from "./users/user-control-service.js";
import { userOperationResponseSchema } from "./http/contracts.js";
import { InvitationService } from "./invitations/invitation-service.js";
import { DisabledInvitationEmailProvider, SimulatedInvitationEmailProvider, type InvitationEmailProvider } from "./invitations/invitation-email-provider.js";
import type { InvitationTokenKeyring } from "./invitations/invitation-token.js";
import { InvitationAcceptanceService } from "./invitations/invitation-acceptance-service.js";
import { requireAuthenticatedUser, type AuthenticatedRequest } from "./auth/require-authenticated-user.js";
import { invitationConfirmationResponseSchema, invitationValidationResponseSchema, passwordEstablishmentResponseSchema } from "./http/contracts.js";
import { ResendWebhookService } from "./invitations/resend-webhook-service.js";
import type { WebhookReplayStore } from "./invitations/resend-invitation-email-provider.js";
import { InvitationQueryService } from "./invitations/invitation-query-service.js";
import { AccessGrantService } from "./access-grants/access-grant-service.js";
import type { InternalGoogleBootstrapComposition } from "./identities/identity-google-bootstrap-composition.js";
import { GoogleIdentityLinkError } from "./identities/identity-linking-service.js";
import type { IdentityLinkAuthorization } from "./identities/identity-linking-contracts.js";
import type { InvitationGoogleProofService } from "./identities/identity-invitation-google-proof-service.js";
import { GoogleBootstrapPreparationError, type GoogleBootstrapPreparationService } from "./identities/identity-google-bootstrap-preparation-service.js";
import { GoogleBootstrapChallengeDeliveryError, type GoogleBootstrapChallengeDeliveryService } from "./identities/identity-google-bootstrap-challenge-delivery-service.js";

export type AdminApiDependencies = {
  verifyIdToken: VerifyIdToken;
  origins: ReadonlySet<string>;
  now?: () => Date;
  firestore?: Firestore;
  userDirectory?: UserDirectory;
  protectedSuperAdminUid?: string | null;
  googleWorkspaceDomain?: string | null;
  invitationTokens?: InvitationTokenKeyring | null;
  invitationEmailProvider?: InvitationEmailProvider;
  localInvitationAccessEnabled?: boolean;
  resendWebhook?: { enabled: boolean; secret?: string; replayStore?: WebhookReplayStore };
  googleBootstrapComposition?: () => InternalGoogleBootstrapComposition;
  invitationGoogleProofService?: () => InvitationGoogleProofService;
  googleBootstrapPreparationService?: () => GoogleBootstrapPreparationService;
  googleBootstrapChallengeDeliveryService?: () => GoogleBootstrapChallengeDeliveryService;
  bindEmployeeInvitationAuthorization?: (input: {
    authorizationId: string;
    invitationId: string;
    principal: AdminPrincipal;
  }) => Promise<IdentityLinkAuthorization>;
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
  const accessGrants = dependencies.firestore && dependencies.userDirectory
    ? new AccessGrantService(dependencies.firestore, dependencies.userDirectory, () => Timestamp.fromDate(now()))
    : null;
  const userControl = dependencies.firestore && dependencies.userDirectory
    ? new UserControlService(dependencies.userDirectory, dependencies.firestore, dependencies.protectedSuperAdminUid ?? null)
    : null;
  const invitations = dependencies.firestore && dependencies.userDirectory
    ? new InvitationService(
      dependencies.userDirectory,
      dependencies.firestore,
      dependencies.invitationTokens ?? null,
      dependencies.invitationEmailProvider ?? new DisabledInvitationEmailProvider(),
      dependencies.protectedSuperAdminUid ?? null,
      undefined,
      dependencies.googleWorkspaceDomain ?? null
    )
    : null;
  const invitationQueries = dependencies.firestore ? new InvitationQueryService(dependencies.firestore, now) : null;
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

  function accessGrantService(): AccessGrantService {
    if (!accessGrants) throw new ApiError(503, "INTERNAL_ERROR", "El servicio de permisos no está disponible.");
    return accessGrants;
  }

  function invitationService(): InvitationService {
    if (!invitations) throw new ApiError(503, "INTERNAL_ERROR", "El servicio de invitaciones no está disponible.");
    return invitations;
  }

  function invitationQueryService(): InvitationQueryService {
    if (!invitationQueries) throw new ApiError(503, "INTERNAL_ERROR", "La consulta de invitaciones no está disponible.");
    return invitationQueries;
  }

  function invitationAcceptanceService(): InvitationAcceptanceService {
    if (!invitationAcceptance) throw new ApiError(503, "INTERNAL_ERROR", "El servicio de aceptación no está disponible.");
    return invitationAcceptance;
  }

  function invitationGoogleProofService(): InvitationGoogleProofService {
    if (!dependencies.invitationGoogleProofService) {
      throw new ApiError(503, "INTERNAL_ERROR", "La verificación Google no está disponible.");
    }
    try {
      return dependencies.invitationGoogleProofService();
    } catch {
      throw new ApiError(503, "INTERNAL_ERROR", "La verificación Google no está disponible.");
    }
  }

  function mapInvitationGoogleProofError(error: unknown, next: (error?: unknown) => void): void {
    const code = typeof error === "object" && error !== null && "code" in error ? String(error.code) : "";
    const name = error instanceof Error ? error.name : "";
    if (name === "ZodError") {
      next(new ApiError(400, "VALIDATION_ERROR", "La solicitud no es válida."));
      return;
    }
    if (["INVITATION_INVALID", "PROFILE_INVALID", "CORPORATE_EMAIL_REQUIRED", "GOOGLE_EMAIL_MISMATCH",
      "CHALLENGE_INVALID", "CHALLENGE_EXPIRED", "CHALLENGE_CONSUMED", "NONCE_INVALID", "NONCE_REQUIRED",
      "TOKEN_MISSING", "TOKEN_MALFORMED", "TOKEN_TOO_LARGE", "SIGNATURE_INVALID", "ALGORITHM_NOT_ALLOWED",
      "KEY_ID_UNKNOWN", "ISSUER_NOT_ALLOWED", "AUDIENCE_NOT_ALLOWED", "AUTHORIZED_PARTY_NOT_ALLOWED",
      "TOKEN_EXPIRED", "ISSUED_AT_INVALID", "SUBJECT_INVALID", "EMAIL_INVALID", "EMAIL_NOT_VERIFIED",
      "HOSTED_DOMAIN_MISSING", "HOSTED_DOMAIN_NOT_ALLOWED", "IDENTITY_CLAIMS_INCONSISTENT"].includes(code)) {
      const consumed = code === "CHALLENGE_CONSUMED";
      next(new ApiError(consumed ? 409 : 400, consumed ? "INVALID_STATE_TRANSITION" : "INVITATION_INVALID",
        consumed ? "La verificación ya fue utilizada." : "La invitación o la verificación no es válida."));
      return;
    }
    next(new ApiError(503, "INTERNAL_ERROR", "La verificación Google no está disponible."));
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

  app.post("/api/admin/identities/google-bootstrap/challenges", authenticate, async (request: AdminRequest, response, next) => {
    try {
      const principal = principalFrom(request);
      const body = z.object({ authorizationId: z.string().uuid(), idempotencyKey: z.string().uuid(),
        lifetimeMs: z.number().int().positive().max(15 * 60 * 1000).optional() }).strict().parse(request.body);
      if (!dependencies.googleBootstrapComposition) throw new Error("BOOTSTRAP_DEPENDENCY_UNAVAILABLE");
      response.setHeader("Cache-Control", "no-store, max-age=0");
      const challenge = await dependencies.googleBootstrapComposition().issue({ principal, ...body });
      response.status(200).json({ ok: true, data: challenge, requestId: requestIdFrom(response) });
    } catch (error) {
      if (error instanceof Error && error.message === "BOOTSTRAP_DEPENDENCY_UNAVAILABLE") {
        next(new ApiError(503, "INTERNAL_ERROR", "El servicio de bootstrap no está disponible."));
        return;
      }
      if (error instanceof Error && (error.name === "ZodError" || error.message.includes("AUTH_CONFIGURATION_INVALID")
        || error.message.includes("IDENTIFIER_PEPPER_TOO_SHORT"))) {
        next(new ApiError(400, "VALIDATION_ERROR", "La solicitud o configuración no es válida."));
        return;
      }
      next(error);
    }
  });

  app.post("/api/admin/identities/google-bootstrap/preparations", authenticate, async (request: AdminRequest, response, next) => {
    try {
      const principal = principalFrom(request);
      const body = z.object({ proofId: z.string().uuid() }).strict().parse(request.body);
      if (!dependencies.googleBootstrapPreparationService) {
        next(new ApiError(503, "INTERNAL_ERROR", "El servicio de preparación Google no está disponible."));
        return;
      }
      let service: GoogleBootstrapPreparationService;
      try { service = dependencies.googleBootstrapPreparationService(); }
      catch { throw new ApiError(503, "INTERNAL_ERROR", "El servicio de preparación Google no está disponible."); }
      const result = await service.prepare(body, principal);
      response.setHeader("Cache-Control", "no-store, max-age=0");
      response.status(200).json({ ok: true, data: { authorizationId: result.authorizationId, state: result.state },
        requestId: requestIdFrom(response) });
    } catch (error) {
      if (error instanceof z.ZodError) {
        next(new ApiError(400, "VALIDATION_ERROR", "La solicitud no es válida."));
        return;
      }
      if (error instanceof GoogleBootstrapPreparationError) {
        if (error.code === "ADMIN_REQUIRED") {
          next(new ApiError(403, "ADMIN_REQUIRED", "La cuenta no tiene autorización administrativa."));
          return;
        }
        if (error.code === "PROOF_NOT_FOUND") {
          next(new ApiError(404, "NOT_FOUND", "La prueba no está disponible."));
          return;
        }
        if (["PROOF_INVALID", "PROOF_EXPIRED", "INVITATION_INVALID", "PROFILE_INVALID", "CORPORATE_EMAIL_REQUIRED"].includes(error.code)) {
          next(new ApiError(400, "INVITATION_INVALID", "La prueba o invitación ya no es válida."));
          return;
        }
        next(new ApiError(409, "INVALID_STATE_TRANSITION", "La preparación no puede completarse con el estado actual."));
        return;
      }
      next(new ApiError(503, "INTERNAL_ERROR", "El servicio de preparación Google no está disponible."));
    }
  });

  app.post("/api/admin/identities/google-bootstrap/continue", authenticate, async (request: AdminRequest, response, next) => {
    try {
      const principal = principalFrom(request);
      const body = z.object({ invitationId: z.string().uuid(), idempotencyKey: z.string().uuid() }).strict().parse(request.body);
      if (dependencies.localInvitationAccessEnabled !== true || request.header("origin") !== "https://localhost:8443") {
        throw new ApiError(404, "NOT_FOUND", "La operación no está disponible.");
      }
      if (!dependencies.googleBootstrapPreparationService || !dependencies.googleBootstrapComposition) {
        throw new ApiError(503, "INTERNAL_ERROR", "La preparación Google no está disponible.");
      }
      const prepared = await dependencies.googleBootstrapPreparationService().prepareLatestForInvitation(body.invitationId, principal);
      const challenge = await dependencies.googleBootstrapComposition().issue({ principal,
        authorizationId: prepared.authorizationId, idempotencyKey: body.idempotencyKey });
      response.setHeader("Cache-Control", "no-store, max-age=0");
      response.status(200).json({ ok: true, data: { state: "challenge_issued", expiresAt: challenge.expiresAt instanceof Timestamp
        ? challenge.expiresAt.toDate().toISOString() : new Date(challenge.expiresAt).toISOString() },
        requestId: requestIdFrom(response) });
    } catch (error) {
      if (error instanceof GoogleBootstrapPreparationError && error.code === "PROOF_EXPIRED") {
        next(new ApiError(409, "INVALID_STATE_TRANSITION", "Es necesario repetir la verificación inicial con Google.")); return;
      }
      next(error);
    }
  });

  app.post("/api/admin/identities/google-bootstrap/authorizations", authenticate, async (request: AdminRequest, response, next) => {
    try {
      const principal = principalFrom(request);
      const body = z.object({ authorizationId: z.string().uuid(), invitationId: z.string().uuid() }).strict().parse(request.body);
      if (!dependencies.bindEmployeeInvitationAuthorization) {
        throw new ApiError(503, "INTERNAL_ERROR", "El servicio de autorización de identidad no está disponible.");
      }
      const authorization = await dependencies.bindEmployeeInvitationAuthorization({ ...body, principal });
      response.status(200).json({ ok: true, data: {
        authorizationId: authorization.authorizationId,
        operationId: authorization.operationId,
        invitationId: authorization.invitationId,
        state: authorization.state
      }, requestId: requestIdFrom(response) });
    } catch (error) {
      if (error instanceof z.ZodError) {
        next(new ApiError(400, "VALIDATION_ERROR", "La solicitud no es válida."));
        return;
      }
      if (error instanceof GoogleIdentityLinkError) {
        if (error.code === "INVITATION_NOT_FOUND") {
          next(new ApiError(404, "NOT_FOUND", "La invitación no existe."));
          return;
        }
        if (["INVITATION_NOT_ACTIVE", "INVITATION_UID_MISMATCH"].includes(error.code)) {
          next(new ApiError(400, "INVITATION_INVALID", "La invitación no es válida para esta autorización."));
          return;
        }
        if (["IDEMPOTENCY_CONFLICT", "AUTHORIZATION_INVITATION_CONFLICT"].includes(error.code)) {
          next(new ApiError(409, "IDEMPOTENCY_CONFLICT", "La autorización ya está vinculada a otra solicitud."));
          return;
        }
        if (error.code === "AUTHORIZATION_NOT_FOUND") {
          next(new ApiError(404, "NOT_FOUND", "La referencia de autorización no existe."));
          return;
        }
        next(new ApiError(409, "PROFILE_INCONSISTENT", "No se pudo verificar el contexto E4B2 persistido."));
        return;
      }
      next(error);
    }
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

  app.get("/api/admin/users/:userId/access-grants", authenticate, async (request: AdminRequest, response, next) => {
    try {
      principalFrom(request);
      const data = await accessGrantService().listForUser(routeParam(request.params.userId), {
        limit: request.query.limit, cursor: request.query.cursor, status: request.query.status
      });
      response.status(200).json(accessGrantsListResponseSchema.parse({ ok: true, data, requestId: requestIdFrom(response) }));
    } catch (error) { next(error); }
  });

  app.get("/api/admin/applications/:applicationId/access-grants", authenticate, async (request: AdminRequest, response, next) => {
    try {
      principalFrom(request);
      const data = await accessGrantService().listForApplication(routeParam(request.params.applicationId), {
        limit: request.query.limit, cursor: request.query.cursor, status: request.query.status
      });
      response.status(200).json(accessGrantsListResponseSchema.parse({ ok: true, data, requestId: requestIdFrom(response) }));
    } catch (error) { next(error); }
  });

  for (const action of ["grant", "revoke"] as const) {
    app.post(`/api/admin/users/:userId/access-grants/:applicationId/${action}`, authenticate, async (request: AdminRequest, response, next) => {
      try {
        const data = await accessGrantService().execute({
          action,
          userId: routeParam(request.params.userId),
          applicationId: routeParam(request.params.applicationId),
          body: request.body,
          idempotencyKey: request.header("Idempotency-Key"),
          principal: principalFrom(request),
          requestId: requestIdFrom(response)
        });
        response.status(200).json({ ok: true, data, requestId: requestIdFrom(response) });
      } catch (error) { next(error); }
    });
  }

  app.get("/api/admin/invitations", authenticate, async (request: AdminRequest, response, next) => {
    try {
      principalFrom(request);
      const input: { pageSize?: string; pageToken?: string; email?: string } = {};
      if (typeof request.query.pageSize === "string") input.pageSize = request.query.pageSize;
      if (typeof request.query.pageToken === "string") input.pageToken = request.query.pageToken;
      if (typeof request.query.email === "string") input.email = request.query.email;
      const data = await invitationQueryService().list(input);
      response.status(200).json(invitationsListResponseSchema.parse({ ok: true, data, requestId: requestIdFrom(response) }));
    } catch (error) { next(error); }
  });

  app.get("/api/admin/invitations/:invitationId", authenticate, async (request: AdminRequest, response, next) => {
    try {
      principalFrom(request);
      const data = await invitationQueryService().get(routeParam(request.params.invitationId));
      response.status(200).json(invitationDetailResponseSchema.parse({ ok: true, data, requestId: requestIdFrom(response) }));
    } catch (error) { next(error); }
  });

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

  app.post("/api/admin/invitations/:invitationId/open-test", authenticate, async (request: AdminRequest, response, next) => {
    try {
      principalFrom(request);
      if (dependencies.localInvitationAccessEnabled !== true
        || !(dependencies.invitationEmailProvider instanceof SimulatedInvitationEmailProvider)
        || request.header("origin") !== "https://localhost:8443") {
        throw new ApiError(404, "NOT_FOUND", "La invitación no está disponible.");
      }
      const data = await invitationService().simulatedInvitationLink(routeParam(request.params.invitationId));
      response.setHeader("Cache-Control", "no-store, max-age=0");
      response.setHeader("Referrer-Policy", "no-referrer");
      response.status(200).json({ ok: true, data, requestId: requestIdFrom(response) });
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

  app.post("/api/invitations/google-bootstrap/proof/start", requireHttps, async (request, response, next) => {
    try {
      const body = z.object({ invitationId: z.string().uuid(), token: z.string().regex(/^[A-Za-z0-9_-]{43}$/) }).strict().parse(request.body);
      const result = await invitationGoogleProofService().start(body);
      response.setHeader("Cache-Control", "no-store, max-age=0");
      response.status(200).json({ ok: true, data: { challengeId: result.challengeId, nonce: result.nonce,
        expiresAt: result.expiresAt.toDate().toISOString() }, requestId: requestIdFrom(response) });
    } catch (error) { mapInvitationGoogleProofError(error, next); }
  });

  app.post("/api/invitations/google-bootstrap/proof/verify", requireHttps, async (request, response, next) => {
    try {
      const body = z.object({ invitationId: z.string().uuid(), token: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
        challengeId: z.string().uuid(), nonce: z.string().min(16).max(512), googleIdToken: z.string().min(1).max(20_000) }).strict().parse(request.body);
      const result = await invitationGoogleProofService().verify(body);
      response.setHeader("Cache-Control", "no-store, max-age=0");
      response.status(200).json({ ok: true, data: { state: result.state, verifiedAt: result.verifiedAt.toDate().toISOString() },
        requestId: requestIdFrom(response) });
    } catch (error) { mapInvitationGoogleProofError(error, next); }
  });

  app.post("/api/invitations/google-bootstrap/challenge/recover", requireHttps, async (request, response, next) => {
    try {
      const body = z.object({ invitationId: z.string().uuid(), token: z.string().regex(/^[A-Za-z0-9_-]{43}$/) }).strict().parse(request.body);
      if (!dependencies.googleBootstrapChallengeDeliveryService) {
        throw new ApiError(503, "INTERNAL_ERROR", "El Challenge no está disponible.");
      }
      let service: GoogleBootstrapChallengeDeliveryService;
      try { service = dependencies.googleBootstrapChallengeDeliveryService(); }
      catch { throw new ApiError(503, "INTERNAL_ERROR", "El Challenge no está disponible."); }
      const result = await service.recover(body);
      response.setHeader("Cache-Control", "no-store, max-age=0");
      response.status(200).json({ ok: true, data: { challengeId: result.challengeId, nonce: result.nonce,
        state: result.state, expiresAt: result.expiresAt.toDate().toISOString() }, requestId: requestIdFrom(response) });
    } catch (error) {
      if (error instanceof z.ZodError) {
        next(new ApiError(400, "VALIDATION_ERROR", "La solicitud no es válida."));
        return;
      }
      if (error instanceof GoogleBootstrapChallengeDeliveryError) {
        if (error.code === "INVITATION_INVALID" || error.code === "PROOF_EXPIRED") {
          next(new ApiError(400, "INVITATION_INVALID", "La invitación o el Challenge no está disponible."));
          return;
        }
        if (error.code === "PROOF_NOT_FOUND" || error.code === "PREPARATION_NOT_FOUND" || error.code === "CHALLENGE_NOT_FOUND") {
          next(new ApiError(404, "NOT_FOUND", "El Challenge no está disponible."));
          return;
        }
        if (error.code === "CHALLENGE_EXPIRED" || error.code === "CHALLENGE_CONSUMED" || error.code === "CHALLENGE_AMBIGUOUS") {
          next(new ApiError(409, "INVALID_STATE_TRANSITION", "El Challenge ya no se puede recuperar."));
          return;
        }
        next(new ApiError(400, "INVITATION_INVALID", "La invitación o el Challenge no está disponible."));
        return;
      }
      next(new ApiError(503, "INTERNAL_ERROR", "El Challenge no está disponible."));
    }
  });

  app.post("/api/invitations/google-bootstrap/challenge/verify", requireHttps, async (request, response, next) => {
    try {
      const body = z.object({ invitationId: z.string().uuid(), token: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
        challengeId: z.string().uuid(), state: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
        googleIdToken: z.string().min(1).max(20_000) }).strict().parse(request.body);
      if (!dependencies.googleBootstrapChallengeDeliveryService || !dependencies.googleBootstrapComposition) {
        throw new ApiError(503, "INTERNAL_ERROR", "La verificación del Challenge no está disponible.");
      }
      let service: GoogleBootstrapChallengeDeliveryService;
      let composition: InternalGoogleBootstrapComposition;
      try {
        service = dependencies.googleBootstrapChallengeDeliveryService();
        composition = dependencies.googleBootstrapComposition();
      } catch {
        throw new ApiError(503, "INTERNAL_ERROR", "La verificación del Challenge no está disponible.");
      }
      const result = await service.verifyAndConsume(body, composition);
      response.setHeader("Cache-Control", "no-store, max-age=0");
      response.status(200).json({ ok: true, data: { state: result.state }, requestId: requestIdFrom(response) });
    } catch (error) {
      if (error instanceof z.ZodError) {
        next(new ApiError(400, "VALIDATION_ERROR", "La solicitud no es válida."));
        return;
      }
      if (error instanceof GoogleBootstrapChallengeDeliveryError) {
        if (error.code === "INVITATION_INVALID" || error.code === "PROOF_EXPIRED" || error.code === "GOOGLE_IDENTITY_INVALID") {
          next(new ApiError(400, "INVITATION_INVALID", "La invitación o la verificación no es válida."));
          return;
        }
        if (["PROOF_NOT_FOUND", "PREPARATION_NOT_FOUND", "CHALLENGE_NOT_FOUND"].includes(error.code)) {
          next(new ApiError(404, "NOT_FOUND", "El Challenge no está disponible."));
          return;
        }
        if (["CHALLENGE_EXPIRED", "CHALLENGE_CONSUMED", "CHALLENGE_AMBIGUOUS", "CHALLENGE_STATE_INVALID"].includes(error.code)) {
          next(new ApiError(409, "INVALID_STATE_TRANSITION", "El Challenge ya no se puede completar."));
          return;
        }
        if (error.code === "VERIFICATION_UNAVAILABLE") {
          next(new ApiError(503, "INTERNAL_ERROR", "La verificación Google no está disponible."));
          return;
        }
        next(new ApiError(400, "INVITATION_INVALID", "La invitación o la verificación no es válida."));
        return;
      }
      next(new ApiError(503, "INTERNAL_ERROR", "La verificación del Challenge no está disponible."));
    }
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

  app.all(["/api/admin/applications", "/api/admin/applications/:appId", "/api/admin/applications/:appId/:action", "/api/admin/applications/:applicationId/access-grants", "/api/admin/users", "/api/admin/users/:uid", "/api/admin/users/:uid/:action", "/api/admin/users/:userId/access-grants", "/api/admin/users/:userId/access-grants/:applicationId/:action", "/api/admin/invitations", "/api/admin/invitations/:invitationId", "/api/admin/invitations/:invitationId/:action"], (_request, _response, next) => {
    next(new ApiError(405, "METHOD_NOT_ALLOWED", "El método HTTP no está permitido."));
  });

  app.all(["/api/invitations/validate", "/api/invitations/google-bootstrap/proof/start",
    "/api/invitations/google-bootstrap/proof/verify", "/api/invitations/google-bootstrap/challenge/recover",
    "/api/invitations/google-bootstrap/challenge/verify",
    "/api/invitations/establish-password",
    "/api/invitations/:invitationId/confirm"], (_request, _response, next) => {
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
