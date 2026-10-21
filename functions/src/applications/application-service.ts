import { createHash, randomUUID } from "node:crypto";
import { Timestamp, type Firestore, type Transaction } from "firebase-admin/firestore";
import { z } from "zod";
import type { AdminPrincipal } from "../auth/require-super-admin.js";
import { ApiError } from "../http/errors.js";
import type { ApplicationDocument } from "../models/admin-collections.js";

const slugSchema = z.string().trim().min(2).max(80).regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/);
const text = (max: number) => z.string().trim().min(1).max(max);
const nullableIcon = z.union([z.string().trim().min(1).max(64), z.null()]);

export const createApplicationSchema = z.object({
  slug: slugSchema,
  name: text(120),
  description: z.string().trim().max(500),
  category: text(80),
  launchUrl: text(2048),
  accessLevel: z.enum(["public", "private"]),
  iconKey: nullableIcon.default(null),
  displayOrder: z.number().int().min(0).max(10000).default(0)
}).strict();

export const updateApplicationSchema = z.object({
  name: text(120).optional(),
  description: z.string().trim().max(500).optional(),
  category: text(80).optional(),
  launchUrl: text(2048).optional(),
  accessLevel: z.enum(["public", "private"]).optional(),
  iconKey: nullableIcon.optional(),
  displayOrder: z.number().int().min(0).max(10000).optional(),
  expectedRevision: z.number().int().positive()
}).strict();

export const actionSchema = z.object({
  expectedRevision: z.number().int().positive(),
  reason: z.string().trim().min(3).max(500).optional()
}).strict();

type CreateInput = z.infer<typeof createApplicationSchema>;
type UpdateInput = z.infer<typeof updateApplicationSchema>;
type Status = ApplicationDocument["status"];
type KeyKind = "slug" | "url" | "categoryName";

function fold(value: string): string {
  return value.normalize("NFKD").replace(/[\u0300-\u036f]/g, "").trim().replace(/\s+/g, " ").toLowerCase();
}

function normalizeUrl(value: string): string {
  let url: URL;
  try { url = new URL(value); } catch { throw new ApiError(400, "VALIDATION_ERROR", "La URL no es válida."); }
  if (url.protocol !== "https:" || url.username || url.password) {
    throw new ApiError(400, "VALIDATION_ERROR", "La URL debe usar HTTPS y no incluir credenciales.");
  }
  url.hash = "";
  url.hostname = url.hostname.toLowerCase();
  if (url.pathname !== "/") url.pathname = url.pathname.replace(/\/+$/, "");
  return url.toString();
}

function keysFor(app: Pick<ApplicationDocument, "slug" | "normalizedLaunchUrl" | "normalizedCategory" | "normalizedName">) {
  return [
    { kind: "slug" as const, value: app.slug },
    { kind: "url" as const, value: app.normalizedLaunchUrl },
    { kind: "categoryName" as const, value: `${app.normalizedCategory}\u0000${app.normalizedName}` }
  ];
}

function keyId(kind: KeyKind, value: string): string {
  return `${kind}_${createHash("sha256").update(value).digest("hex")}`;
}

function parsed<T>(schema: z.ZodType<T>, input: unknown): T {
  const result = schema.safeParse(input);
  if (!result.success) throw new ApiError(400, "VALIDATION_ERROR", result.error.issues[0]?.message ?? "Datos no válidos.");
  return result.data;
}

export class ApplicationService {
  constructor(private readonly db: Firestore, private readonly now = () => Timestamp.now()) {}

  async list(filters: { q?: string; status?: string; accessLevel?: string; category?: string; publicOnly?: boolean } = {}) {
    if (filters.q && filters.q.length > 160) throw new ApiError(400, "VALIDATION_ERROR", "La búsqueda es demasiado larga.");
    if (filters.status && !["draft", "active", "inactive", "archived"].includes(filters.status)) throw new ApiError(400, "VALIDATION_ERROR", "El estado no es válido.");
    if (filters.accessLevel && !["public", "private"].includes(filters.accessLevel)) throw new ApiError(400, "VALIDATION_ERROR", "El nivel de acceso no es válido.");
    if (filters.category && filters.category.length > 80) throw new ApiError(400, "VALIDATION_ERROR", "La categoría no es válida.");
    const snapshot = await this.db.collection("applications").orderBy("updatedAt", "desc").limit(500).get();
    const q = fold(filters.q ?? "");
    return snapshot.docs.map((doc) => doc.data() as ApplicationDocument).filter((app) => {
      if (filters.publicOnly && (app.status !== "active" || app.accessLevel !== "public")) return false;
      if (filters.status && app.status !== filters.status) return false;
      if (filters.accessLevel && app.accessLevel !== filters.accessLevel) return false;
      if (filters.category && app.normalizedCategory !== fold(filters.category)) return false;
      return !q || [app.appId, app.slug, app.normalizedName, app.normalizedCategory, app.normalizedLaunchUrl].some((v) => v.includes(q));
    });
  }

  async get(appId: string): Promise<ApplicationDocument> {
    const snapshot = await this.db.collection("applications").doc(appId).get();
    if (!snapshot.exists) throw new ApiError(404, "NOT_FOUND", "La aplicación no existe.");
    return snapshot.data() as ApplicationDocument;
  }

  async create(input: unknown, actor: AdminPrincipal, requestId: string): Promise<ApplicationDocument> {
    const value = parsed(createApplicationSchema, input);
    const timestamp = this.now();
    const appId = randomUUID();
    const app: ApplicationDocument = {
      appId, slug: value.slug, name: value.name, normalizedName: fold(value.name),
      description: value.description, category: value.category, normalizedCategory: fold(value.category),
      launchUrl: normalizeUrl(value.launchUrl), normalizedLaunchUrl: normalizeUrl(value.launchUrl),
      status: "draft", accessLevel: value.accessLevel, iconKey: value.iconKey,
      displayOrder: value.displayOrder, createdAt: timestamp, createdBy: actor.uid,
      updatedAt: timestamp, updatedBy: actor.uid, revision: 1, version: 1
    };
    await this.db.runTransaction(async (tx) => {
      await this.reserveKeys(tx, app, appId, timestamp);
      tx.create(this.db.collection("applications").doc(appId), app);
      this.audit(tx, "application.created", appId, actor, requestId, null, app);
    });
    return app;
  }

  async update(appId: string, input: unknown, actor: AdminPrincipal, requestId: string): Promise<ApplicationDocument> {
    const value = parsed(updateApplicationSchema, input);
    return this.db.runTransaction(async (tx) => {
      const ref = this.db.collection("applications").doc(appId);
      const snap = await tx.get(ref);
      if (!snap.exists) throw new ApiError(404, "NOT_FOUND", "La aplicación no existe.");
      const before = snap.data() as ApplicationDocument;
      if (before.status === "archived") throw new ApiError(409, "INVALID_STATE_TRANSITION", "Una aplicación archivada no se puede editar.");
      if (before.revision !== value.expectedRevision) throw new ApiError(409, "REVISION_CONFLICT", "La aplicación cambió. Recarga los datos.");
      const after: ApplicationDocument = {
        ...before,
        name: value.name ?? before.name,
        description: value.description ?? before.description,
        category: value.category ?? before.category,
        accessLevel: value.accessLevel ?? before.accessLevel,
        iconKey: value.iconKey === undefined ? before.iconKey : value.iconKey,
        displayOrder: value.displayOrder ?? before.displayOrder,
        normalizedName: value.name ? fold(value.name) : before.normalizedName,
        normalizedCategory: value.category ? fold(value.category) : before.normalizedCategory,
        launchUrl: value.launchUrl ? normalizeUrl(value.launchUrl) : before.launchUrl,
        normalizedLaunchUrl: value.launchUrl ? normalizeUrl(value.launchUrl) : before.normalizedLaunchUrl,
        updatedAt: this.now(), updatedBy: actor.uid, revision: before.revision + 1
      };
      await this.replaceKeys(tx, before, after, appId, after.updatedAt);
      tx.set(ref, after);
      this.audit(tx, "application.updated", appId, actor, requestId, before, after);
      return after;
    });
  }

  async changeStatus(appId: string, target: Status, input: unknown, actor: AdminPrincipal, requestId: string) {
    const value = parsed(actionSchema, input);
    return this.db.runTransaction(async (tx) => {
      const ref = this.db.collection("applications").doc(appId);
      const snap = await tx.get(ref);
      if (!snap.exists) throw new ApiError(404, "NOT_FOUND", "La aplicación no existe.");
      const before = snap.data() as ApplicationDocument;
      if (before.revision !== value.expectedRevision) throw new ApiError(409, "REVISION_CONFLICT", "La aplicación cambió. Recarga los datos.");
      const allowed: Record<Status, Status[]> = { draft: ["active", "inactive", "archived"], active: ["inactive", "archived"], inactive: ["active", "archived"], archived: [] };
      if (!allowed[before.status].includes(target)) throw new ApiError(409, "INVALID_STATE_TRANSITION", "El cambio de estado no está permitido.");
      if (target === "archived" && !value.reason) throw new ApiError(400, "VALIDATION_ERROR", "Indica el motivo del archivo.");
      const after = { ...before, status: target, updatedAt: this.now(), updatedBy: actor.uid, revision: before.revision + 1 };
      tx.set(ref, after);
      this.audit(tx, `application.${target === "inactive" ? "deactivated" : target}`, appId, actor, requestId, before, after, value.reason);
      return after;
    });
  }

  private async reserveKeys(tx: Transaction, app: ApplicationDocument, appId: string, timestamp: Timestamp) {
    const keys = keysFor(app);
    const refs = keys.map((key) => this.db.collection("applicationUniqueKeys").doc(keyId(key.kind, key.value)));
    const snapshots = await Promise.all(refs.map((ref) => tx.get(ref)));
    for (let index = 0; index < keys.length; index += 1) {
      const key = keys[index]!;
      const ref = refs[index]!;
      const existing = snapshots[index]!;
      if (existing.exists && existing.data()?.appId !== appId) throw new ApiError(409, "DUPLICATE_APPLICATION", "Ya existe una aplicación con esos datos.");
      tx.set(ref, { ...key, appId, createdAt: timestamp, version: 1 });
    }
  }

  private async replaceKeys(tx: Transaction, before: ApplicationDocument, after: ApplicationDocument, appId: string, timestamp: Timestamp) {
    const oldKeys = keysFor(before); const newKeys = keysFor(after);
    await this.reserveKeys(tx, after, appId, timestamp);
    for (const key of oldKeys) {
      if (!newKeys.some((next) => next.kind === key.kind && next.value === key.value)) {
        tx.delete(this.db.collection("applicationUniqueKeys").doc(keyId(key.kind, key.value)));
      }
    }
  }

  private audit(tx: Transaction, action: string, appId: string, actor: AdminPrincipal, requestId: string, before: ApplicationDocument | null, after: ApplicationDocument, reason?: string) {
    tx.create(this.db.collection("auditEvents").doc(randomUUID()), {
      occurredAt: after.updatedAt, actorUid: actor.uid, actorEmail: actor.email ?? "unknown@plcocina.invalid",
      action, resourceType: "application", resourceId: appId, targetUid: null, appId,
      before, after, reason: reason ?? null, requestId, source: "admin-api", result: "success", version: 1
    });
  }
}

export function publicApplication(app: ApplicationDocument) {
  const { appId, slug, name, description, category, launchUrl, iconKey, displayOrder } = app;
  return { appId, slug, name, description, category, launchUrl, iconKey, displayOrder };
}
