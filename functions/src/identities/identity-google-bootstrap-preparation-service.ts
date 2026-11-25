import { createHash } from "node:crypto";
import { Timestamp, type Firestore } from "firebase-admin/firestore";
import { z } from "zod";
import type { AdminPrincipal } from "../auth/require-super-admin.js";
import { invitationDocumentSchema, auditEventDocumentSchema } from "../models/admin-collections.js";
import { effectiveInvitationStatus } from "../invitations/invitation-transitions.js";
import { identityVerifiedGoogleProofSchema } from "./identity-invitation-google-proof-service.js";
import { AuthCoordinationPersistenceService } from "./identity-auth-coordination-service.js";
import { authCoordinationDocumentSchema } from "./identity-auth-coordination-contracts.js";
import { GoogleIdentityLinkingService } from "./identity-linking-service.js";
import { IdentityReservationService } from "./identity-reservation-service.js";
import { employeeInvitationLinkAuthorizationSchema } from "./identity-linking-contracts.js";
import { googleWorkspaceUserV21DocumentSchema, identifierKeyHash, normalizeIdentityEmail,
  normalizeGoogleSubject, normalizeWorkspaceDomain, userV2DocumentSchema } from "./identity-models.js";

const inputSchema = z.object({ proofId: z.string().uuid() }).strict();
const principalSchema = z.object({ uid: z.string().min(1), email: z.string().nullable(), authTime: z.number().int().nonnegative(),
  issuedAt: z.number().int().nonnegative(), superAdmin: z.literal(true) }).strict();
export const identityGoogleBootstrapPreparationPlanSchema = z.object({ proofId: z.string().uuid(), proofHash: z.string().regex(/^[a-f0-9]{64}$/), invitationId: z.string().uuid(),
  uid: z.string().min(1), subjectHash: z.string().regex(/^[a-f0-9]{64}$/), normalizedEmail: z.string().email(),
  credentialGeneration: z.number().int().positive(), verifiedProfileRevision: z.number().int().positive(),
  reservationOperationId: z.string().uuid(), authorizationId: z.string().uuid(), linkOperationId: z.string().uuid(),
  linkIdempotencyKey: z.string().uuid(), coordinationOperationId: z.string().uuid(), coordinationIdempotencyKey: z.string().uuid(),
  authorizationIssuedAt: z.instanceof(Timestamp), authorizationExpiresAt: z.instanceof(Timestamp), createdAt: z.instanceof(Timestamp),
  state: z.enum(["preparing", "prepared"]), preparedAt: z.instanceof(Timestamp).nullable(), version: z.literal(1) }).strict();

export class GoogleBootstrapPreparationError extends Error {
  constructor(readonly code: "ADMIN_REQUIRED" | "PROOF_NOT_FOUND" | "PROOF_INVALID" | "PROOF_EXPIRED" | "INVITATION_INVALID"
    | "PROFILE_INVALID" | "CORPORATE_EMAIL_REQUIRED" | "SUBJECT_CONFLICT" | "PLAN_CONFLICT" | "PREPARATION_EXPIRED"
    | "RESERVATION_CONFLICT" | "AUTHORIZATION_CONFLICT" | "PROFILE_CONFLICT" | "COORDINATION_CONFLICT") {
    super("Google bootstrap preparation rejected"); this.name = "GoogleBootstrapPreparationError";
  }
}

export type GoogleBootstrapPreparationServices = {
  reserve(input: { operationId: string; uid: string; kind: "googleSubject"; value: string }): ReturnType<IdentityReservationService["reserve"]>;
  persistEmployeeInvitationAuthorization(input: unknown, principal: AdminPrincipal): ReturnType<GoogleIdentityLinkingService["persistEmployeeInvitationAuthorization"]>;
  linkVerifiedIdentity(input: Parameters<GoogleIdentityLinkingService["linkVerifiedIdentity"]>[0]): ReturnType<GoogleIdentityLinkingService["linkVerifiedIdentity"]>;
  createCoordination(input: Parameters<AuthCoordinationPersistenceService["create"]>[0]): ReturnType<AuthCoordinationPersistenceService["create"]>;
};

function uuidFor(proofId: string, purpose: string): string {
  const bytes = Buffer.from(createHash("sha256").update(`apps-pl-cocina/b5-b5/${purpose}/v1\0${proofId}`).digest().subarray(0, 16));
  bytes[6] = (bytes[6]! & 0x0f) | 0x50; bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function canonicalHash(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

export function hashIdentityVerifiedGoogleProof(proof: z.infer<typeof identityVerifiedGoogleProofSchema>): string {
  return canonicalHash({ proofId: proof.proofId, invitationId: proof.invitationId, uid: proof.uid,
    subject: proof.subject, normalizedEmail: proof.normalizedEmail, credentialGeneration: proof.credentialGeneration,
    verifiedAt: proof.verifiedAt.toMillis(), validUntil: proof.validUntil.toMillis() });
}

export class GoogleBootstrapPreparationService {
  private readonly reservations: IdentityReservationService;
  private readonly linking: GoogleIdentityLinkingService;
  private readonly coordination: AuthCoordinationPersistenceService;
  private readonly services: GoogleBootstrapPreparationServices;

  constructor(private readonly db: Firestore, private readonly identifierPepper: Buffer,
    private readonly protectedSuperAdminUid: string, private readonly now: () => Timestamp = () => Timestamp.now(),
    services?: Partial<GoogleBootstrapPreparationServices>) {
    if (identifierPepper.length < 32) throw new Error("IDENTIFIER_PEPPER_TOO_SHORT");
    this.reservations = new IdentityReservationService(db, identifierPepper, now);
    this.linking = new GoogleIdentityLinkingService(db, identifierPepper, protectedSuperAdminUid, now);
    this.coordination = new AuthCoordinationPersistenceService(db, protectedSuperAdminUid, now);
    this.services = {
      reserve: this.reservations.reserve.bind(this.reservations),
      persistEmployeeInvitationAuthorization: this.linking.persistEmployeeInvitationAuthorization.bind(this.linking),
      linkVerifiedIdentity: this.linking.linkVerifiedIdentity.bind(this.linking),
      createCoordination: this.coordination.create.bind(this.coordination),
      ...services
    };
  }

  async prepare(input: unknown, principalInput: AdminPrincipal) {
    const value = inputSchema.parse(input); const principal = principalSchema.parse(principalInput);
    if (principal.superAdmin !== true || principal.uid !== this.protectedSuperAdminUid) throw new GoogleBootstrapPreparationError("ADMIN_REQUIRED");
    const evidence = await this.loadProof(value.proofId);
    const initial = await this.resolveCurrent(evidence);
    const plan = await this.ensurePlan(evidence, initial.profileRevision, initial.profileNeedsVerification, principal);
    this.assertPlan(plan, evidence);
    this.assertNotExpired(plan);

    await this.assertInvitationCurrent(evidence);
    let reservation;
    try {
      reservation = await this.services.reserve({ operationId: plan.reservationOperationId, uid: evidence.uid,
        kind: "googleSubject", value: evidence.subject });
    } catch {
      throw new GoogleBootstrapPreparationError("RESERVATION_CONFLICT");
    }
    if (reservation.uid !== evidence.uid || reservation.identifierHash !== plan.subjectHash) {
      throw new GoogleBootstrapPreparationError("RESERVATION_CONFLICT");
    }

    const verifiedProfile = await this.ensureVerifiedProfile(evidence, plan, principal);
    await this.assertInvitationCurrent(evidence);
    const authorization = employeeInvitationLinkAuthorizationSchema.parse({
      authorizationId: plan.authorizationId, operation: "google.identity_link", operationId: plan.linkOperationId,
      invitationId: evidence.invitationId, idempotencyKey: plan.linkIdempotencyKey, targetUid: evidence.uid,
      googleSubjectHash: plan.subjectHash, authorizedByUid: principal.uid, expectedRevision: plan.verifiedProfileRevision,
      reason: "Preparación de identidad Workspace verificada por invitación", issuedAt: plan.authorizationIssuedAt,
      expiresAt: plan.authorizationExpiresAt, state: "pending", stateChangedAt: null, version: 1
    });
    await this.ensureAuthorization(authorization, principal);

    await this.assertInvitationCurrent(evidence);
    let linkResult;
    try {
      linkResult = await this.services.linkVerifiedIdentity({ trustedTargetUid: evidence.uid,
        trustedAdministratorUid: principal.uid, request: { authorizationId: plan.authorizationId, operation: "google.identity_link",
          operationId: plan.linkOperationId, idempotencyKey: plan.linkIdempotencyKey, targetUid: evidence.uid,
          googleSubjectHash: plan.subjectHash, expectedRevision: plan.verifiedProfileRevision,
          requestedActivationStatus: "linked_pending_activation" },
        verifiedIdentity: { subject: evidence.subject, verifiedAt: evidence.verifiedAt,
          validUntil: evidence.validUntil, verificationId: evidence.verificationId } });
    } catch (error) {
      if (error instanceof GoogleBootstrapPreparationError) throw error;
      throw error;
    }
    await this.assertInvitationCurrent(evidence);

    const linkOperation = await this.db.collection("identityLinkOperations").doc(plan.linkIdempotencyKey).get();
    const linkedAt = Timestamp.fromMillis(Number(linkOperation.data()?.completedAt?.toMillis?.() ?? this.now().toMillis()));
    if (!linkOperation.exists || linkResult.uid !== evidence.uid || linkResult.revision < plan.verifiedProfileRevision + 1) {
      throw new GoogleBootstrapPreparationError("PROFILE_CONFLICT");
    }
    const document = this.createCoordinationDocument(plan, evidence, principal, linkResult.revision, linkedAt);
    await this.assertInvitationCurrent(evidence);
    let coordination;
    try { coordination = await this.services.createCoordination({ trustedAdministratorUid: principal.uid, document }); }
    catch { throw new GoogleBootstrapPreparationError("COORDINATION_CONFLICT"); }
    await this.markPrepared(evidence, plan, principal);
    return Object.freeze({ proofId: evidence.proofId, uid: evidence.uid, authorizationId: plan.authorizationId,
      operationId: plan.linkOperationId, coordinationOperationId: plan.coordinationOperationId,
      state: coordination.document.state, replayed: reservation.replayed || linkResult.replayed || coordination.replayed });
  }

  async prepareLatestForInvitation(invitationIdInput: unknown, principalInput: AdminPrincipal) {
    const invitationId = z.string().uuid().parse(invitationIdInput);
    const invitation = await this.db.collection("invitations").doc(invitationId).get();
    const parsed = invitationDocumentSchema.safeParse(invitation.data());
    if (!invitation.exists || !parsed.success || parsed.data.verificationMethod !== "googleWorkspace"
      || !parsed.data.uid || parsed.data.status !== "active") throw new GoogleBootstrapPreparationError("INVITATION_INVALID");
    const proofs = await this.db.collection("identityVerifiedGoogleProofs").where("invitationId", "==", invitationId).get();
    const latest = proofs.docs.flatMap((doc) => {
      const proof = identityVerifiedGoogleProofSchema.safeParse(doc.data());
      return proof.success && proof.data.state === "verified" && proof.data.nonceVerified ? [proof.data] : [];
    }).sort((a, b) => b.verifiedAt.toMillis() - a.verifiedAt.toMillis())[0];
    if (!latest) throw new GoogleBootstrapPreparationError("PROOF_NOT_FOUND");
    return this.prepare({ proofId: latest.proofId }, principalInput);
  }

  private async loadProof(proofId: string) {
    const snapshot = await this.db.collection("identityVerifiedGoogleProofs").doc(proofId).get();
    if (!snapshot.exists) throw new GoogleBootstrapPreparationError("PROOF_NOT_FOUND");
    const parsed = identityVerifiedGoogleProofSchema.safeParse(snapshot.data());
    if (!parsed.success || parsed.data.proofId !== proofId || parsed.data.proofId !== parsed.data.verificationId
      || parsed.data.state !== "verified" || parsed.data.nonceVerified !== true) throw new GoogleBootstrapPreparationError("PROOF_INVALID");
    if (parsed.data.validUntil.toMillis() <= this.now().toMillis()) throw new GoogleBootstrapPreparationError("PROOF_EXPIRED");
    return parsed.data;
  }

  private async resolveCurrent(evidence: Awaited<ReturnType<GoogleBootstrapPreparationService["loadProof"]>>) {
    const invitationSnapshot = await this.db.collection("invitations").doc(evidence.invitationId).get();
    const profileSnapshot = await this.db.collection("users").doc(evidence.uid).get();
    const invitation = invitationDocumentSchema.safeParse(invitationSnapshot.data());
    if (!invitationSnapshot.exists || !invitation.success || !this.validInvitation(invitation.data, evidence)) {
      throw new GoogleBootstrapPreparationError("INVITATION_INVALID");
    }
    const rawProfile = profileSnapshot.data();
    const legacyProfile = userV2DocumentSchema.safeParse(rawProfile);
    const workspaceProfile = googleWorkspaceUserV21DocumentSchema.safeParse(rawProfile);
    const normalizedEmail = legacyProfile.success ? legacyProfile.data.normalizedEmail : workspaceProfile.success ? workspaceProfile.data.normalizedEmail : null;
    const revision = legacyProfile.success ? legacyProfile.data.revision : workspaceProfile.success ? workspaceProfile.data.revision : null;
    if (!profileSnapshot.exists || normalizedEmail === null || !revision) throw new GoogleBootstrapPreparationError("CORPORATE_EMAIL_REQUIRED");
    if (normalizeIdentityEmail(normalizedEmail) !== evidence.normalizedEmail || invitation.data.normalizedEmail !== evidence.normalizedEmail) {
      throw new GoogleBootstrapPreparationError("PROFILE_INVALID");
    }
    if (legacyProfile.success && (legacyProfile.data.status !== "invited" || legacyProfile.data.authDisabled !== true
      || legacyProfile.data.email === null || legacyProfile.data.email === undefined
      || normalizeIdentityEmail(legacyProfile.data.email) !== evidence.normalizedEmail)) throw new GoogleBootstrapPreparationError("PROFILE_INVALID");
    let workspaceNeedsVerification = false;
    if (workspaceProfile.success) {
      const workspace = workspaceProfile.data.googleWorkspace;
      const declared = workspace.linkingStatus === "declared" && workspace.verificationStatus === "unverified" && workspace.subject === null;
      const verifiedOrLinked = workspace.verificationStatus === "verified" && workspace.subject === evidence.subject
        && (workspace.linkingStatus === "verified" || workspace.linkingStatus === "linked");
      const emailDomain = normalizeWorkspaceDomain(evidence.normalizedEmail.slice(evidence.normalizedEmail.lastIndexOf("@") + 1));
      if (workspaceProfile.data.uid !== evidence.uid || workspaceProfile.data.status !== "invited"
        || workspaceProfile.data.authDisabled !== true || workspaceProfile.data.email !== evidence.normalizedEmail
        || workspace.authorizedDomain !== emailDomain
        || (!declared && !verifiedOrLinked)) throw new GoogleBootstrapPreparationError("PROFILE_CONFLICT");
      workspaceNeedsVerification = declared;
    }
    return { profileRevision: revision, profileNeedsVerification: legacyProfile.success || workspaceNeedsVerification };
  }

  private async ensurePlan(evidence: Awaited<ReturnType<GoogleBootstrapPreparationService["loadProof"]>>,
    profileRevision: number, profileNeedsVerification: boolean, principal: AdminPrincipal) {
    const ref = this.db.collection("identityGoogleBootstrapPreparations").doc(evidence.proofId);
    const proofHash = hashIdentityVerifiedGoogleProof(evidence);
    return this.db.runTransaction(async (transaction) => {
      const [currentProof, invitationSnapshot, profileSnapshot, planSnapshot] = await Promise.all([
        transaction.get(this.db.collection("identityVerifiedGoogleProofs").doc(evidence.proofId)),
        transaction.get(this.db.collection("invitations").doc(evidence.invitationId)),
        transaction.get(this.db.collection("users").doc(evidence.uid)), transaction.get(ref)
      ]);
      const proof = identityVerifiedGoogleProofSchema.safeParse(currentProof.data());
      const invitation = invitationDocumentSchema.safeParse(invitationSnapshot.data());
      if (!currentProof.exists || !proof.success || hashIdentityVerifiedGoogleProof(proof.data) !== proofHash || !invitationSnapshot.exists || !invitation.success
        || !this.validInvitation(invitation.data, evidence)) throw new GoogleBootstrapPreparationError("INVITATION_INVALID");
      const legacyProfile = userV2DocumentSchema.safeParse(profileSnapshot.data());
      const workspaceProfile = googleWorkspaceUserV21DocumentSchema.safeParse(profileSnapshot.data());
      const currentEmail = legacyProfile.success ? legacyProfile.data.normalizedEmail
        : workspaceProfile.success ? workspaceProfile.data.normalizedEmail : null;
      if (!profileSnapshot.exists || currentEmail !== evidence.normalizedEmail) throw new GoogleBootstrapPreparationError("PROFILE_INVALID");
      if (planSnapshot.exists) {
        const plan = identityGoogleBootstrapPreparationPlanSchema.safeParse(planSnapshot.data());
        if (!plan.success || plan.data.proofHash !== proofHash || plan.data.uid !== evidence.uid
          || plan.data.invitationId !== evidence.invitationId || plan.data.subjectHash !== identifierKeyHash("googleSubject", evidence.subject, this.identifierPepper)
          || plan.data.normalizedEmail !== evidence.normalizedEmail) throw new GoogleBootstrapPreparationError("PLAN_CONFLICT");
        return plan.data;
      }
      const createdAt = this.now();
      const authExpiresAt = Timestamp.fromMillis(Math.min(createdAt.toMillis() + 15 * 60_000, evidence.validUntil.toMillis()));
      if (authExpiresAt.toMillis() <= createdAt.toMillis()) throw new GoogleBootstrapPreparationError("PROOF_EXPIRED");
      const plan = identityGoogleBootstrapPreparationPlanSchema.parse({ proofId: evidence.proofId, proofHash, invitationId: evidence.invitationId,
        uid: evidence.uid, subjectHash: identifierKeyHash("googleSubject", evidence.subject, this.identifierPepper),
        normalizedEmail: evidence.normalizedEmail, credentialGeneration: evidence.credentialGeneration,
        verifiedProfileRevision: profileRevision + (profileNeedsVerification ? 1 : 0),
        reservationOperationId: uuidFor(evidence.proofId, "reservation"), authorizationId: uuidFor(evidence.proofId, "authorization"),
        linkOperationId: uuidFor(evidence.proofId, "e4b2-operation"), linkIdempotencyKey: uuidFor(evidence.proofId, "e4b2-idempotency"),
        coordinationOperationId: uuidFor(evidence.proofId, "e5b2-operation"), coordinationIdempotencyKey: uuidFor(evidence.proofId, "e5b2-idempotency"),
        authorizationIssuedAt: createdAt, authorizationExpiresAt: authExpiresAt, createdAt, state: "preparing", preparedAt: null, version: 1 });
      transaction.create(ref, plan);
      return plan;
    });
  }

  private async ensureVerifiedProfile(evidence: Awaited<ReturnType<GoogleBootstrapPreparationService["loadProof"]>>,
    plan: z.infer<typeof identityGoogleBootstrapPreparationPlanSchema>, principal: AdminPrincipal) {
    const invitationRef = this.db.collection("invitations").doc(evidence.invitationId);
    const profileRef = this.db.collection("users").doc(evidence.uid);
    return this.db.runTransaction(async (transaction) => {
      const [invitationSnapshot, profileSnapshot] = await Promise.all([transaction.get(invitationRef), transaction.get(profileRef)]);
      const invitation = invitationDocumentSchema.safeParse(invitationSnapshot.data());
      if (!invitationSnapshot.exists || !invitation.success || !this.validInvitation(invitation.data, evidence)) {
        throw new GoogleBootstrapPreparationError("INVITATION_INVALID");
      }
      if (!profileSnapshot.exists) throw new GoogleBootstrapPreparationError("PROFILE_INVALID");
      const v2 = userV2DocumentSchema.safeParse(profileSnapshot.data());
      if (v2.success) {
        if (v2.data.status !== "invited" || !v2.data.authDisabled || !v2.data.email
          || normalizeIdentityEmail(v2.data.email) !== evidence.normalizedEmail || v2.data.revision + 1 !== plan.verifiedProfileRevision
          || v2.data.phoneE164 !== null || v2.data.normalizedPhone !== null) throw new GoogleBootstrapPreparationError("PROFILE_INVALID");
        const domain = normalizeWorkspaceDomain(evidence.normalizedEmail.slice(evidence.normalizedEmail.lastIndexOf("@") + 1));
        const verified = googleWorkspaceUserV21DocumentSchema.parse({
          uid: evidence.uid, displayName: v2.data.displayName, status: "invited", authDisabled: true,
          invitationStatus: v2.data.invitationStatus, authMethod: "googleWorkspace", phoneE164: null, normalizedPhone: null,
          email: evidence.normalizedEmail, normalizedEmail: evidence.normalizedEmail, phoneVerifiedAt: null,
          emailVerifiedAt: evidence.verifiedAt, googleWorkspace: { authorizedDomain: domain, subject: evidence.subject,
            linkingStatus: "verified", verificationStatus: "verified", verifiedAt: evidence.verifiedAt, linkedAt: null,
            verificationRevision: 1, operationId: null }, activationStatus: "recovery_required",
          credentialRevision: v2.data.credentialRevision + 1, authorizationRevision: v2.data.authorizationRevision,
          sessionValidAfter: v2.data.sessionValidAfter, createdAt: v2.data.createdAt, createdBy: v2.data.createdBy,
          updatedAt: this.now(), updatedBy: principal.uid, revision: plan.verifiedProfileRevision,
          pendingOperationId: null, identityContractVersion: "2.1", version: 2
        });
        transaction.set(profileRef, verified);
        transaction.create(this.db.collection("auditEvents").doc(`google-bootstrap-proof-${evidence.proofId}`), auditEventDocumentSchema.parse({
          occurredAt: this.now(), actorType: "admin", actorUid: principal.uid, actorEmail: principal.email, providerEventId: null,
          action: "identity.google_proof_recorded", resourceType: "user", resourceId: evidence.uid, targetUid: evidence.uid, appId: null,
          before: { revision: v2.data.revision, authDisabled: true }, after: { revision: plan.verifiedProfileRevision,
            verificationStatus: "verified", authDisabled: true, subjectHash: plan.subjectHash }, reason: "Invitación Google verificada",
          requestId: evidence.proofId, source: "admin-api", result: "success", version: 1
        }));
        return verified;
      }
      const existing = googleWorkspaceUserV21DocumentSchema.safeParse(profileSnapshot.data());
      if (existing.success && existing.data.googleWorkspace.linkingStatus === "declared"
        && existing.data.googleWorkspace.verificationStatus === "unverified" && existing.data.googleWorkspace.subject === null) {
        if (existing.data.uid !== evidence.uid || existing.data.status !== "invited" || !existing.data.authDisabled
          || existing.data.email !== evidence.normalizedEmail || existing.data.revision + 1 !== plan.verifiedProfileRevision) {
          throw new GoogleBootstrapPreparationError("PROFILE_CONFLICT");
        }
        const domain = normalizeWorkspaceDomain(evidence.normalizedEmail.slice(evidence.normalizedEmail.lastIndexOf("@") + 1));
        const verified = googleWorkspaceUserV21DocumentSchema.parse({
          ...existing.data, emailVerifiedAt: evidence.verifiedAt,
          googleWorkspace: { ...existing.data.googleWorkspace, authorizedDomain: domain, subject: evidence.subject,
            linkingStatus: "verified", verificationStatus: "verified", verifiedAt: evidence.verifiedAt,
            verificationRevision: existing.data.googleWorkspace.verificationRevision + 1, operationId: null },
          activationStatus: "recovery_required", credentialRevision: existing.data.credentialRevision + 1,
          updatedAt: this.now(), updatedBy: principal.uid, revision: plan.verifiedProfileRevision
        });
        transaction.set(profileRef, verified);
        transaction.create(this.db.collection("auditEvents").doc(`google-bootstrap-proof-${evidence.proofId}`), auditEventDocumentSchema.parse({
          occurredAt: this.now(), actorType: "admin", actorUid: principal.uid, actorEmail: principal.email, providerEventId: null,
          action: "identity.google_proof_recorded", resourceType: "user", resourceId: evidence.uid, targetUid: evidence.uid, appId: null,
          before: { revision: existing.data.revision, authDisabled: true }, after: { revision: plan.verifiedProfileRevision,
            verificationStatus: "verified", authDisabled: true, subjectHash: plan.subjectHash }, reason: "Invitación Google verificada",
          requestId: evidence.proofId, source: "admin-api", result: "success", version: 1
        }));
        return verified;
      }
      const verifiedUnlinked = existing.success && existing.data.googleWorkspace.linkingStatus === "verified"
        && existing.data.revision === plan.verifiedProfileRevision;
      const alreadyLinked = existing.success && existing.data.googleWorkspace.linkingStatus === "linked"
        && existing.data.activationStatus === "linked_pending_activation" && existing.data.revision === plan.verifiedProfileRevision;
      const linkedByThisPreparation = existing.success && existing.data.googleWorkspace.linkingStatus === "linked"
        && existing.data.activationStatus === "linked_pending_activation" && existing.data.revision === plan.verifiedProfileRevision + 1;
      if (!existing.success || existing.data.uid !== evidence.uid || existing.data.googleWorkspace.subject !== evidence.subject
        || existing.data.email !== evidence.normalizedEmail || existing.data.googleWorkspace.verificationStatus !== "verified"
        || (!verifiedUnlinked && !alreadyLinked && !linkedByThisPreparation)
        || existing.data.authDisabled !== true || existing.data.status !== "invited") throw new GoogleBootstrapPreparationError("PROFILE_CONFLICT");
      return existing.data;
    });
  }

  private async ensureAuthorization(authorization: z.infer<typeof employeeInvitationLinkAuthorizationSchema>, principal: AdminPrincipal) {
    const ref = this.db.collection("identityLinkAuthorizations").doc(authorization.authorizationId);
    const snapshot = await ref.get();
    if (snapshot.exists) {
      const existing = employeeInvitationLinkAuthorizationSchema.safeParse(snapshot.data());
      if (!existing.success || existing.data.authorizationId !== authorization.authorizationId
        || existing.data.operationId !== authorization.operationId || existing.data.idempotencyKey !== authorization.idempotencyKey
        || existing.data.invitationId !== authorization.invitationId || existing.data.targetUid !== authorization.targetUid
        || existing.data.googleSubjectHash !== authorization.googleSubjectHash || existing.data.expectedRevision !== authorization.expectedRevision
        || existing.data.authorizedByUid !== authorization.authorizedByUid || existing.data.expiresAt.toMillis() !== authorization.expiresAt.toMillis()
        || !["pending", "consumed"].includes(existing.data.state)) throw new GoogleBootstrapPreparationError("AUTHORIZATION_CONFLICT");
      return existing.data;
    }
    try { return await this.services.persistEmployeeInvitationAuthorization(authorization, principal); }
    catch { throw new GoogleBootstrapPreparationError("AUTHORIZATION_CONFLICT"); }
  }

  private createCoordinationDocument(plan: z.infer<typeof identityGoogleBootstrapPreparationPlanSchema>, evidence: Awaited<ReturnType<GoogleBootstrapPreparationService["loadProof"]>>,
    _principal: AdminPrincipal, profileRevision: number, linkedAt: Timestamp) {
    if (this.now().toMillis() >= plan.authorizationExpiresAt.toMillis()) throw new GoogleBootstrapPreparationError("PREPARATION_EXPIRED");
    return authCoordinationDocumentSchema.parse({ operationId: plan.coordinationOperationId, operation: "google.firebase_provider_link",
      expectedFirebaseUid: evidence.uid, expectedInternalUid: evidence.uid, googleSubjectHash: plan.subjectHash, state: "not_started",
      expectedProfileRevision: profileRevision, currentProfileRevision: profileRevision,
      idempotencyKey: plan.coordinationIdempotencyKey, authorizationId: plan.authorizationId, challengeId: null,
      evidence: { authorization: { authorizationId: plan.authorizationId, operation: "google.identity_link",
        validatedBy: "identity-link-authorization", validatedAt: plan.authorizationIssuedAt, validUntil: plan.authorizationExpiresAt },
        firestoreLink: { linkOperationId: plan.linkOperationId, observedBy: "identity-linking-service", linkedAt: linkedAt,
          profileRevision, activationStatus: "linked_pending_activation", authDisabled: true },
        challenge: null, googleVerification: null, firebaseSession: null, firebaseProvider: null, postflight: null },
      conflictReason: null, revision: 1, lastEvent: null, createdAt: plan.createdAt, updatedAt: plan.createdAt,
      expiresAt: plan.authorizationExpiresAt, localActivationStatus: "linked_pending_activation", localAuthDisabled: true, version: 1 });
  }

  private async markPrepared(evidence: Awaited<ReturnType<GoogleBootstrapPreparationService["loadProof"]>>,
    plan: z.infer<typeof identityGoogleBootstrapPreparationPlanSchema>, principal: AdminPrincipal) {
    const invitationRef = this.db.collection("invitations").doc(evidence.invitationId);
    const planRef = this.db.collection("identityGoogleBootstrapPreparations").doc(evidence.proofId);
    await this.db.runTransaction(async (transaction) => {
      const [invitationSnapshot, planSnapshot] = await Promise.all([transaction.get(invitationRef), transaction.get(planRef)]);
      const invitation = invitationDocumentSchema.safeParse(invitationSnapshot.data());
      const currentPlan = identityGoogleBootstrapPreparationPlanSchema.safeParse(planSnapshot.data());
      if (!invitationSnapshot.exists || !invitation.success || !this.validInvitation(invitation.data, evidence)
        || !planSnapshot.exists || !currentPlan.success || currentPlan.data.proofHash !== plan.proofHash) {
        throw new GoogleBootstrapPreparationError("INVITATION_INVALID");
      }
      if (currentPlan.data.state === "prepared") return;
      transaction.update(planRef, { state: "prepared", preparedAt: this.now() });
      transaction.create(this.db.collection("auditEvents").doc(`google-bootstrap-prepared-${evidence.proofId}`), auditEventDocumentSchema.parse({
        occurredAt: this.now(), actorType: "admin", actorUid: principal.uid, actorEmail: principal.email, providerEventId: null,
        action: "identity.google_bootstrap_prepared", resourceType: "user", resourceId: evidence.uid, targetUid: evidence.uid,
        appId: null, before: null, after: { authorizationId: plan.authorizationId, coordinationOperationId: plan.coordinationOperationId,
          authDisabled: true, activationStatus: "linked_pending_activation" }, reason: null, requestId: evidence.proofId,
        source: "admin-api", result: "success", version: 1
      }));
    });
  }

  private async assertInvitationCurrent(evidence: Awaited<ReturnType<GoogleBootstrapPreparationService["loadProof"]>>) {
    const snapshot = await this.db.collection("invitations").doc(evidence.invitationId).get();
    const invitation = invitationDocumentSchema.safeParse(snapshot.data());
    if (!snapshot.exists || !invitation.success || !this.validInvitation(invitation.data, evidence)) {
      throw new GoogleBootstrapPreparationError("INVITATION_INVALID");
    }
  }

  private assertPlan(plan: z.infer<typeof identityGoogleBootstrapPreparationPlanSchema>, evidence: Awaited<ReturnType<GoogleBootstrapPreparationService["loadProof"]>>) {
    if (plan.uid !== evidence.uid || plan.invitationId !== evidence.invitationId || plan.credentialGeneration !== evidence.credentialGeneration
      || plan.normalizedEmail !== evidence.normalizedEmail || plan.subjectHash !== identifierKeyHash("googleSubject", evidence.subject, this.identifierPepper)) {
      throw new GoogleBootstrapPreparationError("PLAN_CONFLICT");
    }
  }

  private assertNotExpired(plan: z.infer<typeof identityGoogleBootstrapPreparationPlanSchema>) {
    if (plan.authorizationExpiresAt.toMillis() <= this.now().toMillis()) throw new GoogleBootstrapPreparationError("PREPARATION_EXPIRED");
  }

  private validInvitation(invitation: z.infer<typeof invitationDocumentSchema>, evidence: Awaited<ReturnType<GoogleBootstrapPreparationService["loadProof"]>>) {
    const now = this.now().toMillis();
    return invitation.invitationId === evidence.invitationId && invitation.uid === evidence.uid
      && invitation.normalizedEmail === evidence.normalizedEmail && invitation.token !== null
      && invitation.token.generation === evidence.credentialGeneration
      && effectiveInvitationStatus(invitation, now) === "active" && invitation.token.expiresAt.toMillis() > now
      && invitation.expiresAt.toMillis() > now;
  }
}
