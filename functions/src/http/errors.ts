import type { NextFunction, Request, Response } from "express";
import type { ErrorCode } from "./contracts.js";
import { errorResponseSchema } from "./contracts.js";
import { requestIdFrom } from "./request-context.js";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: ErrorCode,
    message: string
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export function sendError(
  response: Response,
  requestId: string,
  status: number,
  code: ErrorCode,
  message: string
): void {
  const body = errorResponseSchema.parse({
    ok: false,
    error: { code, message },
    requestId
  });
  response.status(status).json(body);
}

export function errorHandler(
  error: unknown,
  request: Request,
  response: Response,
  _next: NextFunction
): void {
  const requestId = requestIdFrom(response);
  if (error instanceof ApiError) {
    sendError(response, requestId, error.status, error.code, error.message);
    return;
  }

  console.error("Unhandled admin API error", { requestId, error });
  sendError(
    response,
    requestId,
    500,
    "INTERNAL_ERROR",
    "No fue posible completar la solicitud."
  );
}
