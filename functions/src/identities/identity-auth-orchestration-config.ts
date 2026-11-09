import { defineList, defineSecret, defineString } from "firebase-functions/params";
import { protectedSuperAdminUid } from "../config.js";
import type { InternalAuthOrchestrationConfiguration } from "./identity-auth-orchestration-composition.js";
import { normalizeWorkspaceDomain } from "./identity-models.js";

export const googleAuthAudiencesParam = defineList("GOOGLE_AUTH_AUDIENCES");
export const googleAuthorizedPartiesParam = defineList("GOOGLE_AUTHORIZED_PARTIES");
export const googleWorkspaceDomainParam = defineString("GOOGLE_WORKSPACE_DOMAIN");
export const identifierPepperParam = defineSecret("IDENTIFIER_PEPPER_BASE64");

type RawInternalAuthConfiguration = Readonly<{
  googleAudiences: readonly string[];
  googleAuthorizedParties: readonly string[];
  googleWorkspaceDomain: string;
  identifierPepperBase64: string;
  protectedSuperAdminUid: string | null;
}>;

function requireUniqueValues(values: readonly string[]): string[] {
  if (!Array.isArray(values) || values.length === 0) throw new Error("AUTH_CONFIGURATION_INVALID");
  const normalized = values.map((value) => {
    if (typeof value !== "string" || value.length === 0 || value.trim() !== value) {
      throw new Error("AUTH_CONFIGURATION_INVALID");
    }
    return value;
  });
  if (new Set(normalized).size !== normalized.length) throw new Error("AUTH_CONFIGURATION_INVALID");
  return normalized;
}

function decodePepper(value: string): Buffer {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value) || value.length % 4 !== 0) {
    throw new Error("AUTH_CONFIGURATION_INVALID");
  }
  const pepper = Buffer.from(value, "base64");
  if (pepper.length < 32 || pepper.toString("base64") !== value) {
    throw new Error("AUTH_CONFIGURATION_INVALID");
  }
  return pepper;
}

export function resolveInternalAuthOrchestrationConfiguration(
  raw: RawInternalAuthConfiguration
): InternalAuthOrchestrationConfiguration {
  if (!raw || !raw.protectedSuperAdminUid
    || !/^[^/]{1,128}$/.test(raw.protectedSuperAdminUid)) {
    throw new Error("AUTH_CONFIGURATION_INVALID");
  }
  const domain = raw.googleWorkspaceDomain;
  if (typeof domain !== "string" || normalizeWorkspaceDomain(domain) !== domain) {
    throw new Error("AUTH_CONFIGURATION_INVALID");
  }
  return Object.freeze({
    googleTokenVerifier: Object.freeze({
      allowedIssuers: Object.freeze(["accounts.google.com", "https://accounts.google.com"]),
      allowedAudiences: Object.freeze(requireUniqueValues(raw.googleAudiences)),
      allowedAuthorizedParties: Object.freeze(requireUniqueValues(raw.googleAuthorizedParties)),
      allowedWorkspaceDomains: Object.freeze([domain]),
      requireAuthorizedParty: true
    }),
    identifierPepper: decodePepper(raw.identifierPepperBase64),
    protectedSuperAdminUid: raw.protectedSuperAdminUid
  });
}

export function internalAuthOrchestrationConfiguration(): InternalAuthOrchestrationConfiguration {
  return resolveInternalAuthOrchestrationConfiguration({
    googleAudiences: googleAuthAudiencesParam.value(),
    googleAuthorizedParties: googleAuthorizedPartiesParam.value(),
    googleWorkspaceDomain: googleWorkspaceDomainParam.value(),
    identifierPepperBase64: identifierPepperParam.value(),
    protectedSuperAdminUid: protectedSuperAdminUid()
  });
}
