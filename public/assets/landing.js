export const CATALOG_URL = "https://adminapi-nnra4xim6q-uc.a.run.app/api/catalog/applications";

const ICONS = Object.freeze({ burrito: "🌯", calculator: "🧮", calculadora: "🧮", "calculadora-burritos": "🌯", chart: "📊", reports: "📊", reportes: "📊", "reportes-mensuales-2026": "📊", production: "🏭", produccion: "🏭" });

function isPlainObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }

export function isSafeHttpsUrl(value) {
  if (typeof value !== "string" || value.length > 2048) return false;
  try {
    const url = new URL(value);
    return url.protocol === "https:" && !url.username && !url.password;
  } catch { return false; }
}

function validateApplication(value) {
  if (!isPlainObject(value)) return null;
  const valid = typeof value.appId === "string" && value.appId.length > 0 && value.appId.length <= 128
    && typeof value.slug === "string" && /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(value.slug)
    && typeof value.name === "string" && value.name.trim().length > 0 && value.name.length <= 120
    && typeof value.description === "string" && value.description.length <= 500
    && typeof value.category === "string" && value.category.trim().length > 0 && value.category.length <= 80
    && (value.iconKey === null || (typeof value.iconKey === "string" && value.iconKey.length > 0 && value.iconKey.length <= 64))
    && Number.isInteger(value.displayOrder) && value.displayOrder >= 0 && value.displayOrder <= 10000
    && isSafeHttpsUrl(value.launchUrl);
  if (!valid) return null;
  return { appId: value.appId, slug: value.slug, name: value.name.trim(), description: value.description.trim(), category: value.category.trim(), launchUrl: value.launchUrl, iconKey: value.iconKey, displayOrder: value.displayOrder };
}

export function validateCatalogPayload(payload) {
  if (!isPlainObject(payload) || payload.ok !== true || !Array.isArray(payload.data)) throw new Error("INVALID_CATALOG_RESPONSE");
  const applications = payload.data.map(validateApplication);
  if (applications.some((application) => application === null)) throw new Error("INVALID_CATALOG_RESPONSE");
  return applications.sort((a, b) => a.displayOrder - b.displayOrder || a.name.localeCompare(b.name, "es"));
}

function iconFor(application) {
  const key = application.iconKey?.trim();
  if (!key) return ICONS[application.slug] ?? application.name.slice(0, 1).toUpperCase();
  return ICONS[key.toLowerCase()] ?? key;
}

function element(documentRef, tag, className, text) {
  const node = documentRef.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

export function buildApplicationCard(documentRef, application) {
  const article = element(documentRef, "article", "app featured active");
  article.dataset.applicationId = application.appId;
  const cardTop = element(documentRef, "div", "card-top");
  const symbol = element(documentRef, "span", "symbol", iconFor(application));
  symbol.setAttribute("aria-hidden", "true");
  cardTop.append(symbol, element(documentRef, "span", "status", "Disponible"));
  article.append(cardTop);
  if (application.category) article.append(element(documentRef, "span", "category", application.category));
  article.append(element(documentRef, "h3", "", application.name));
  article.append(element(documentRef, "p", "", application.description));
  const link = element(documentRef, "a", "app-link", "Abrir aplicación ↗");
  link.href = application.launchUrl;
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  article.append(link);
  return article;
}

export function renderCatalog(documentRef, applications) {
  const grid = documentRef.getElementById("catalog-grid");
  const count = documentRef.getElementById("application-count");
  if (!grid || !count) return;
  grid.setAttribute("aria-busy", "false");
  const total = applications.length;
  count.textContent = `${total} ${total === 1 ? "aplicación disponible" : "aplicaciones disponibles"}`;
  if (total === 0) {
    grid.replaceChildren(element(documentRef, "div", "catalog-state", "No hay aplicaciones públicas disponibles por el momento."));
    return;
  }
  grid.replaceChildren(...applications.map((application) => buildApplicationCard(documentRef, application)));
}

export function renderCatalogError(documentRef, retry) {
  const grid = documentRef.getElementById("catalog-grid");
  const count = documentRef.getElementById("application-count");
  if (!grid || !count) return;
  grid.setAttribute("aria-busy", "false");
  count.textContent = "Catálogo no disponible";
  const state = element(documentRef, "div", "catalog-state catalog-error");
  state.setAttribute("role", "alert");
  state.append(element(documentRef, "p", "", "No fue posible consultar las aplicaciones. Puedes intentarlo nuevamente."));
  const button = element(documentRef, "button", "retry-button", "Reintentar");
  button.type = "button";
  button.addEventListener("click", retry);
  state.append(button);
  grid.replaceChildren(state);
}

export async function loadCatalog(documentRef, options = {}) {
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  const grid = documentRef.getElementById("catalog-grid");
  if (grid) grid.setAttribute("aria-busy", "true");
  try {
    const response = await fetchImpl(CATALOG_URL, { method: "GET", headers: { Accept: "application/json" }, cache: "no-store", credentials: "omit", referrerPolicy: "no-referrer", signal: options.signal });
    if (!response.ok) throw new Error("CATALOG_UNAVAILABLE");
    const applications = validateCatalogPayload(await response.json());
    renderCatalog(documentRef, applications);
    return applications;
  } catch (error) {
    if (error?.name === "AbortError") throw error;
    renderCatalogError(documentRef, () => loadCatalog(documentRef, { fetchImpl }));
    return null;
  }
}

if (typeof document !== "undefined") {
  const year = document.getElementById("year");
  if (year) year.textContent = new Date().getFullYear();
  loadCatalog(document);
}
