import test from "node:test";
import assert from "node:assert/strict";
import { buildApplicationCard, isSafeHttpsUrl, loadCatalog, renderCatalog, validateCatalogPayload } from "../public/assets/landing.js";

class FakeElement {
  constructor(tagName) { this.tagName = tagName.toUpperCase(); this.children = []; this.attributes = {}; this.dataset = {}; this.textContent = ""; }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = nodes; }
  setAttribute(name, value) { this.attributes[name] = value; }
  addEventListener(name, handler) { this[`on${name}`] = handler; }
}

function fakeDocument() {
  const nodes = { "catalog-grid": new FakeElement("div"), "application-count": new FakeElement("span") };
  return { nodes, createElement: (tag) => new FakeElement(tag), getElementById: (id) => nodes[id] ?? null };
}

const burritos = { appId: "app-burritos", slug: "calculadora-burritos", name: "Calculadora de Burritos", description: "Calcula ingredientes.", category: "Producción", launchUrl: "https://calculadora-burritos.plcocina.com/", iconKey: "burrito", displayOrder: 20 };
const reports = { appId: "app-reportes", slug: "reportes-mensuales-2026", name: "Reportes Mensuales 2026", description: "Consulta indicadores.", category: "Reportes", launchUrl: "https://reportes-mensuales-2026.plcocina.com/", iconKey: "reports", displayOrder: 10 };

test("valida el contrato y respeta displayOrder", () => {
  const result = validateCatalogPayload({ ok: true, data: [burritos, reports] });
  assert.deepEqual(result.map((app) => app.name), ["Reportes Mensuales 2026", "Calculadora de Burritos"]);
});

test("rechaza respuestas incompletas y URLs no HTTPS", () => {
  assert.equal(isSafeHttpsUrl("https://apps.plcocina.com"), true);
  assert.equal(isSafeHttpsUrl("http://apps.plcocina.com"), false);
  assert.equal(isSafeHttpsUrl("https://user:pass@apps.plcocina.com"), false);
  assert.throws(() => validateCatalogPayload({ ok: true, data: [{ ...reports, launchUrl: "javascript:alert(1)" }] }));
  assert.throws(() => validateCatalogPayload({ ok: true, data: [{ ...reports, displayOrder: "10" }] }));
});

test("crea tarjetas con texto seguro y enlace externo protegido", () => {
  const card = buildApplicationCard(fakeDocument(), { ...reports, name: "<img src=x onerror=alert(1)>" });
  assert.equal(card.children[2].textContent, "<img src=x onerror=alert(1)>");
  const link = card.children.at(-1);
  assert.equal(link.href, reports.launchUrl);
  assert.equal(link.target, "_blank");
  assert.equal(link.rel, "noopener noreferrer");
});

test("usa iconos conocidos por slug cuando iconKey no está configurado", () => {
  const card = buildApplicationCard(fakeDocument(), { ...burritos, iconKey: null });
  assert.equal(card.children[0].children[0].textContent, "🌯");
});

test("renderiza ambas aplicaciones y actualiza el contador sin contar proyectos futuros", () => {
  const documentRef = fakeDocument();
  renderCatalog(documentRef, [reports, burritos]);
  assert.equal(documentRef.nodes["catalog-grid"].children.length, 2);
  assert.equal(documentRef.nodes["application-count"].textContent, "2 aplicaciones disponibles");
});

test("una lista válida vacía muestra estado vacío, no error", () => {
  const documentRef = fakeDocument();
  renderCatalog(documentRef, []);
  assert.match(documentRef.nodes["catalog-grid"].children[0].textContent, /No hay aplicaciones/);
  assert.equal(documentRef.nodes["application-count"].textContent, "0 aplicaciones disponibles");
});

test("un fallo muestra estado recuperable con reintento", async () => {
  const documentRef = fakeDocument();
  const result = await loadCatalog(documentRef, { fetchImpl: async () => { throw new Error("offline"); } });
  assert.equal(result, null);
  const state = documentRef.nodes["catalog-grid"].children[0];
  assert.equal(state.attributes.role, "alert");
  assert.equal(state.children[1].textContent, "Reintentar");
  assert.equal(typeof state.children[1].onclick, "function");
});
