import { randomUUID } from "node:crypto";
import type { NextFunction, Request, Response } from "express";

const REQUEST_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function requestContext(
  request: Request,
  response: Response,
  next: NextFunction
): void {
  const incoming = request.header("x-request-id")?.trim();
  const requestId = incoming && REQUEST_ID_PATTERN.test(incoming) ? incoming : randomUUID();
  response.locals.requestId = requestId;
  response.setHeader("X-Request-ID", requestId);
  next();
}

export function requestIdFrom(response: Response): string {
  const value: unknown = response.locals.requestId;
  return typeof value === "string" && value.length > 0 ? value : randomUUID();
}
