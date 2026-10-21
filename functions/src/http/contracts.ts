import { z } from "zod";

const requestIdSchema = z.string().uuid();

export const errorCodeSchema = z.enum([
  "AUTH_REQUIRED",
  "TOKEN_INVALID",
  "TOKEN_EXPIRED",
  "TOKEN_REVOKED",
  "ADMIN_REQUIRED",
  "ORIGIN_FORBIDDEN",
  "NOT_FOUND",
  "METHOD_NOT_ALLOWED",
  "VALIDATION_ERROR",
  "DUPLICATE_APPLICATION",
  "REVISION_CONFLICT",
  "INVALID_STATE_TRANSITION",
  "INTERNAL_ERROR"
]);

export const errorResponseSchema = z.object({
  ok: z.literal(false),
  error: z.object({
    code: errorCodeSchema,
    message: z.string().min(1).max(240)
  }).strict(),
  requestId: requestIdSchema
}).strict();

export const healthResponseSchema = z.object({
  ok: z.literal(true),
  data: z.object({
    status: z.literal("ok"),
    service: z.literal("admin-api"),
    version: z.string().min(1),
    region: z.string().min(1),
    checkedAt: z.string().datetime()
  }).strict(),
  requestId: requestIdSchema
}).strict();

export const meResponseSchema = z.object({
  ok: z.literal(true),
  data: z.object({
    uid: z.string().min(1).max(128),
    email: z.string().email().nullable(),
    superAdmin: z.literal(true),
    authTime: z.number().int().nonnegative(),
    issuedAt: z.number().int().nonnegative()
  }).strict(),
  requestId: requestIdSchema
}).strict();

export type ErrorCode = z.infer<typeof errorCodeSchema>;
