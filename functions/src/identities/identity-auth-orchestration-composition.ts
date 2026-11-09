import { Timestamp, type Firestore } from "firebase-admin/firestore";
import {
  GoogleAuthLibraryJwtCryptographicVerifier,
  GoogleIdentityTokenVerifier,
  type GoogleCertificateSource,
  type GoogleJwtCryptographicVerifier,
  type GoogleTokenVerifierConfig
} from "./google-token-verifier.js";
import { IdentityAuthOrchestrationPersistenceService } from "./identity-auth-orchestration-service.js";

export type InternalAuthOrchestrationConfiguration = Readonly<{
  googleTokenVerifier: GoogleTokenVerifierConfig;
  identifierPepper: Buffer;
  protectedSuperAdminUid: string;
}>;

export type InternalAuthOrchestrationDependencies = Readonly<{
  certificates?: GoogleCertificateSource;
  cryptographicVerifier?: GoogleJwtCryptographicVerifier;
  now?: () => Date;
}>;

export function createInternalAuthOrchestrationService(
  db: Firestore,
  configuration: InternalAuthOrchestrationConfiguration,
  dependencies: InternalAuthOrchestrationDependencies = {}
): IdentityAuthOrchestrationPersistenceService {
  if (!configuration || !Buffer.isBuffer(configuration.identifierPepper)) {
    throw new Error("AUTH_ORCHESTRATION_CONFIGURATION_INVALID");
  }
  const now = dependencies.now ?? (() => new Date());
  const verifier = new GoogleIdentityTokenVerifier(
    configuration.googleTokenVerifier,
    dependencies.certificates,
    dependencies.cryptographicVerifier ?? new GoogleAuthLibraryJwtCryptographicVerifier(),
    now
  );
  return new IdentityAuthOrchestrationPersistenceService(
    db,
    verifier,
    configuration.identifierPepper,
    configuration.protectedSuperAdminUid,
    () => Timestamp.fromDate(now())
  );
}
