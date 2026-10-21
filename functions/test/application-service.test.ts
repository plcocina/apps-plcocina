import type { Firestore } from "firebase-admin/firestore";
import { Timestamp } from "firebase-admin/firestore";
import { describe, expect, it } from "vitest";
import type { AdminPrincipal } from "../src/auth/require-super-admin.js";
import { ApplicationService } from "../src/applications/application-service.js";

class FakeRef { constructor(readonly path: string) {} }

class FakeFirestore {
  readonly data = new Map<string, Record<string, unknown>>();
  collection(name: string) { return { doc: (id: string) => new FakeRef(`${name}/${id}`) }; }
  async runTransaction<T>(work: (tx: ReturnType<FakeFirestore["transaction"]>) => Promise<T>) { return work(this.transaction()); }
  transaction() {
    return {
      get: async (ref: FakeRef) => ({ exists: this.data.has(ref.path), data: () => this.data.get(ref.path) }),
      set: (ref: FakeRef, value: Record<string, unknown>) => { this.data.set(ref.path, structuredClone(value)); },
      create: (ref: FakeRef, value: Record<string, unknown>) => { if (this.data.has(ref.path)) throw new Error("already exists"); this.data.set(ref.path, structuredClone(value)); },
      delete: (ref: FakeRef) => { this.data.delete(ref.path); }
    };
  }
}

const actor: AdminPrincipal = { uid: "admin-uid", email: "admin@plcocina.com", authTime: 1, issuedAt: 1, superAdmin: true };
const now = Timestamp.fromDate(new Date("2026-10-21T18:00:00.000Z"));
const input = { slug: "reportes", name: "Reportes", description: "Indicadores", category: "Operación", launchUrl: "https://reports.example.com/", accessLevel: "private" as const, iconKey: null, displayOrder: 10 };

function setup() {
  const db = new FakeFirestore();
  return { db, service: new ApplicationService(db as unknown as Firestore, () => now) };
}

describe("application service transactions", () => {
  it("creates three unique reservations and an append-only audit event", async () => {
    const { db, service } = setup();
    const app = await service.create(input, actor, "018f4f63-79d2-7f31-a847-8b75fbd18a11");
    expect(app.status).toBe("draft");
    expect([...db.data.keys()].filter((key) => key.startsWith("applicationUniqueKeys/"))).toHaveLength(3);
    expect([...db.data.keys()].filter((key) => key.startsWith("auditEvents/"))).toHaveLength(1);
  });

  it("rejects a duplicate slug atomically", async () => {
    const { service } = setup();
    await service.create(input, actor, "018f4f63-79d2-7f31-a847-8b75fbd18a11");
    await expect(service.create({ ...input, name: "Otro", category: "Otra", launchUrl: "https://other.example.com" }, actor, "018f4f63-79d2-7f31-a847-8b75fbd18a12")).rejects.toMatchObject({ code: "DUPLICATE_APPLICATION" });
  });

  it("rotates name, category and URL reservations in one update", async () => {
    const { db, service } = setup();
    const app = await service.create(input, actor, "018f4f63-79d2-7f31-a847-8b75fbd18a11");
    const updated = await service.update(app.appId, { expectedRevision: 1, name: "Producción", category: "Planta", launchUrl: "https://production.example.com" }, actor, "018f4f63-79d2-7f31-a847-8b75fbd18a12");
    expect(updated.revision).toBe(2);
    expect([...db.data.keys()].filter((key) => key.startsWith("applicationUniqueKeys/"))).toHaveLength(3);
    expect([...db.data.values()].find((value) => value.kind === "url")?.value).toBe("https://production.example.com/");
  });

  it("keeps reservations when archiving", async () => {
    const { db, service } = setup();
    const app = await service.create(input, actor, "018f4f63-79d2-7f31-a847-8b75fbd18a11");
    const archived = await service.changeStatus(app.appId, "archived", { expectedRevision: 1, reason: "Aplicación retirada" }, actor, "018f4f63-79d2-7f31-a847-8b75fbd18a12");
    expect(archived.status).toBe("archived");
    expect([...db.data.keys()].filter((key) => key.startsWith("applicationUniqueKeys/"))).toHaveLength(3);
    expect([...db.data.keys()].filter((key) => key.startsWith("auditEvents/"))).toHaveLength(2);
  });
});
