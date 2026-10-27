import { Buffer } from "node:buffer";
import { FieldPath, type DocumentSnapshot, type Firestore, type QueryDocumentSnapshot } from "firebase-admin/firestore";
import { z } from "zod";
import { ApiError } from "../http/errors.js";
import { userDocumentSchema, type UserDocument } from "../models/admin-collections.js";

export type DirectoryUser = {
  uid: string;
  email?: string | null;
  displayName?: string | null;
  emailVerified: boolean;
  disabled: boolean;
  customClaims?: Record<string, unknown>;
  metadata: { creationTime: string; lastSignInTime?: string };
};

export type UserDirectory = {
  listUsers(maxResults: number, pageToken?: string): Promise<{ users: DirectoryUser[]; pageToken?: string }>;
  getUser(uid: string): Promise<DirectoryUser>;
  getUserByEmail(email: string): Promise<DirectoryUser>;
  getUsers(identifiers: Array<{ uid: string }>): Promise<{ users: DirectoryUser[] }>;
  updateUser(uid: string, properties: { disabled?: boolean; password?: string; emailVerified?: boolean }): Promise<DirectoryUser>;
  revokeRefreshTokens(uid: string): Promise<void>;
  createUser(properties: { uid: string; email: string; displayName: string; emailVerified: false; disabled: true }): Promise<DirectoryUser>;
};

type Cursor = { authPageToken: string | null; profileAfter: string | null };
type Integrity = "linked" | "missing_profile" | "orphan_profile" | "profile_mismatch" | "invalid_profile";

const emailSchema = z.string().trim().email().max(254).transform((value) => value.toLowerCase());
const uidSchema = z.string().trim().min(1).max(128).refine((value) => !value.includes("/"));
const cursorSchema = z.object({
  authPageToken: z.string().min(1).max(2048).nullable(),
  profileAfter: uidSchema.nullable()
}).strict();

function authCode(error: unknown): string | undefined {
  return typeof error === "object" && error !== null && "code" in error ? String(error.code) : undefined;
}

function isUserNotFound(error: unknown): boolean {
  return authCode(error) === "auth/user-not-found";
}

function encodeCursor(cursor: Cursor): string | null {
  if (!cursor.authPageToken && !cursor.profileAfter) return null;
  return Buffer.from(JSON.stringify(cursor), "utf8").toString("base64url");
}

function decodeCursor(value: string | undefined): Cursor {
  if (!value) return { authPageToken: null, profileAfter: null };
  if (value.length > 4096) throw new ApiError(400, "VALIDATION_ERROR", "El cursor no es válido.");
  try {
    return cursorSchema.parse(JSON.parse(Buffer.from(value, "base64url").toString("utf8")));
  } catch {
    throw new ApiError(400, "VALIDATION_ERROR", "El cursor no es válido.");
  }
}

function iso(value: unknown): string | null {
  if (typeof value === "object" && value !== null && "toDate" in value && typeof value.toDate === "function") {
    return value.toDate().toISOString();
  }
  return null;
}

function safeProfile(snapshot: DocumentSnapshot | QueryDocumentSnapshot): { value: UserDocument | null; exists: boolean } {
  if (!snapshot.exists) return { value: null, exists: false };
  const parsed = userDocumentSchema.safeParse(snapshot.data());
  return { value: parsed.success ? parsed.data : null, exists: true };
}

function publicUser(auth: DirectoryUser | null, snapshot: DocumentSnapshot | QueryDocumentSnapshot | null) {
  const profile = snapshot ? safeProfile(snapshot) : { value: null, exists: false };
  const value = profile.value;
  let integrity: Integrity;
  if (!auth) integrity = value ? "orphan_profile" : "invalid_profile";
  else if (!profile.exists) integrity = "missing_profile";
  else if (!value) integrity = "invalid_profile";
  else if (value.normalizedEmail !== auth.email?.toLowerCase() || value.authDisabled !== auth.disabled) integrity = "profile_mismatch";
  else integrity = "linked";

  return {
    uid: auth?.uid ?? snapshot?.id ?? "unknown",
    email: auth?.email ?? value?.email ?? null,
    displayName: auth?.displayName ?? value?.displayName ?? null,
    emailVerified: auth?.emailVerified ?? null,
    disabled: auth?.disabled ?? null,
    authCreatedAt: auth?.metadata.creationTime ?? null,
    lastSignInAt: auth?.metadata.lastSignInTime ?? null,
    isProtected: auth?.customClaims?.super_admin === true,
    integrity,
    profile: value ? {
      status: value.status,
      authDisabled: value.authDisabled,
      invitationStatus: value.invitationStatus,
      createdAt: iso(value.createdAt),
      updatedAt: iso(value.updatedAt),
      revision: value.revision,
      version: value.version
    } : null
  };
}

export class UserQueryService {
  constructor(private readonly directory: UserDirectory, private readonly db: Firestore) {}

  async list(input: { pageSize?: string; pageToken?: string; email?: string }) {
    if (input.email !== undefined) {
      if (input.pageToken !== undefined || input.pageSize !== undefined) {
        throw new ApiError(400, "VALIDATION_ERROR", "La consulta por correo no admite paginación.");
      }
      return this.byEmail(input.email);
    }

    const pageSize = input.pageSize === undefined ? 50 : Number(input.pageSize);
    if (!Number.isInteger(pageSize) || pageSize < 1 || pageSize > 100) {
      throw new ApiError(400, "VALIDATION_ERROR", "El tamaño de página debe estar entre 1 y 100.");
    }
    const cursor = decodeCursor(input.pageToken);
    const authPage = cursor.authPageToken === null && input.pageToken ? { users: [] as DirectoryUser[] } :
      await this.directory.listUsers(pageSize, cursor.authPageToken ?? undefined).catch((error) => {
        if (authCode(error) === "auth/invalid-page-token") {
          throw new ApiError(400, "VALIDATION_ERROR", "El cursor no es válido.");
        }
        throw error;
      });

    const authRefs = authPage.users.map((user) => this.db.collection("users").doc(user.uid));
    const authProfiles = authRefs.length ? await this.db.getAll(...authRefs) : [];
    const users = authPage.users.map((user, index) => publicUser(user, authProfiles[index] ?? null));

    let nextProfileAfter: string | null = null;
    if (!(cursor.profileAfter === null && input.pageToken)) {
      let query = this.db.collection("users").orderBy(FieldPath.documentId()).limit(pageSize);
      if (cursor.profileAfter) query = query.startAfter(cursor.profileAfter);
      const profilePage = await query.get();
      const identifiers = profilePage.docs.map((doc) => ({ uid: doc.id }));
      if (identifiers.length) {
        const authMatches = await this.directory.getUsers(identifiers);
        const found = new Set(authMatches.users.map((user) => user.uid));
        for (const profile of profilePage.docs) {
          if (!found.has(profile.id)) users.push(publicUser(null, profile));
        }
      }
      if (profilePage.docs.length === pageSize) nextProfileAfter = profilePage.docs.at(-1)?.id ?? null;
    }

    return {
      users,
      nextPageToken: encodeCursor({ authPageToken: authPage.pageToken ?? null, profileAfter: nextProfileAfter })
    };
  }

  async get(uidInput: string) {
    const result = uidSchema.safeParse(uidInput);
    if (!result.success) throw new ApiError(400, "VALIDATION_ERROR", "El identificador de usuario no es válido.");
    const reference = this.db.collection("users").doc(result.data);
    const [auth, profile] = await Promise.all([
      this.directory.getUser(result.data).catch((error) => {
        if (isUserNotFound(error)) return null;
        throw error;
      }),
      reference.get()
    ]);
    if (!auth && !profile.exists) throw new ApiError(404, "NOT_FOUND", "El usuario no existe.");
    return publicUser(auth, profile);
  }

  private async byEmail(input: string) {
    const parsed = emailSchema.safeParse(input);
    if (!parsed.success) throw new ApiError(400, "VALIDATION_ERROR", "El correo electrónico no es válido.");
    const email = parsed.data;
    const auth = await this.directory.getUserByEmail(email).catch((error) => {
      if (isUserNotFound(error)) return null;
      throw error;
    });
    const profiles = await this.db.collection("users").where("normalizedEmail", "==", email).limit(20).get();
    const identifiers = profiles.docs.map((doc) => ({ uid: doc.id }));
    const matches = identifiers.length ? await this.directory.getUsers(identifiers) : { users: [] };
    const authByUid = new Map(matches.users.map((user) => [user.uid, user]));
    if (auth) authByUid.set(auth.uid, auth);
    const users = profiles.docs.map((profile) => publicUser(authByUid.get(profile.id) ?? null, profile));
    if (auth && !profiles.docs.some((profile) => profile.id === auth.uid)) {
      users.unshift(publicUser(auth, await this.db.collection("users").doc(auth.uid).get()));
    }
    return { users, nextPageToken: null };
  }
}
