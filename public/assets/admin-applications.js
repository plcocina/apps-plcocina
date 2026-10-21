import { adminApiRequest, AdminApiError } from "/assets/admin-api-client.js";

const labels = { draft: "Borrador", active: "Activa", inactive: "Inactiva", archived: "Archivada", public: "Pública", private: "Privada" };
let currentUser;
let records = [];
let pendingAction = null;

const byId = (id) => document.getElementById(id);
const table = byId("applications-table");
const tbody = table.querySelector("tbody");
const message = byId("applications-message");
const count = byId("application-count");
const dialog = byId("application-dialog");
const form = byId("application-form");
const confirmDialog = byId("confirm-dialog");

function dateLabel(value) {
  const date = value?._seconds ? new Date(value._seconds * 1000) : new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : new Intl.DateTimeFormat("es-MX", { dateStyle: "medium" }).format(date);
}

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function visibleRecords() {
  const q = byId("application-search").value.trim().toLowerCase();
  const status = byId("status-filter").value;
  const access = byId("access-filter").value;
  const category = byId("category-filter").value.trim().toLowerCase();
  return records.filter((app) => {
    const haystack = [app.appId, app.slug, app.name, app.category, app.launchUrl].join(" ").toLowerCase();
    return (!q || haystack.includes(q)) && (!status || app.status === status) && (!access || app.accessLevel === access) && (!category || app.category.toLowerCase().includes(category));
  });
}

function actionButton(text, action, app) {
  const button = element("button", "", text);
  button.type = "button";
  button.dataset.action = action;
  button.dataset.appId = app.appId;
  return button;
}

function render() {
  tbody.replaceChildren();
  const apps = visibleRecords();
  count.textContent = `${apps.length} ${apps.length === 1 ? "aplicación" : "aplicaciones"}`;
  table.hidden = apps.length === 0;
  message.hidden = apps.length > 0;
  message.textContent = records.length === 0 ? "Aún no hay aplicaciones registradas." : "No hay resultados con estos filtros.";
  for (const app of apps) {
    const row = document.createElement("tr");
    const nameCell = document.createElement("td");
    const name = element("div", "app-name");
    name.append(element("strong", "", app.name), element("span", "", `${app.slug} · ${app.appId}`));
    const link = element("a", "", app.launchUrl); link.href = app.launchUrl; link.target = "_blank"; link.rel = "noopener noreferrer";
    name.append(link); nameCell.append(name);
    const category = element("td", "", app.category);
    const access = document.createElement("td"); access.append(element("span", `badge ${app.accessLevel}`, labels[app.accessLevel]));
    const status = document.createElement("td"); status.append(element("span", `badge ${app.status}`, labels[app.status]));
    const updated = element("td", "", dateLabel(app.updatedAt));
    const actions = document.createElement("td"); const wrap = element("div", "row-actions");
    if (app.status !== "archived") wrap.append(actionButton("Editar", "edit", app));
    if (app.status === "draft" || app.status === "inactive") wrap.append(actionButton("Activar", "activate", app));
    if (app.status === "active") wrap.append(actionButton("Desactivar", "deactivate", app));
    if (app.status !== "archived") wrap.append(actionButton("Archivar", "archive", app));
    actions.append(wrap); row.append(nameCell, category, access, status, updated, actions); tbody.append(row);
  }
}

async function load() {
  message.hidden = false; message.textContent = "Cargando aplicaciones…"; table.hidden = true; byId("retry-applications").hidden = true;
  try { records = await adminApiRequest(currentUser, "/api/admin/applications"); render(); }
  catch (error) { message.textContent = error instanceof AdminApiError ? error.message : "No fue posible cargar las aplicaciones."; byId("retry-applications").hidden = false; }
}

function openForm(app = null) {
  form.reset(); byId("form-error").hidden = true;
  byId("application-dialog-title").textContent = app ? "Editar aplicación" : "Nueva aplicación";
  byId("application-id").value = app?.appId ?? ""; byId("application-revision").value = app?.revision ?? "";
  byId("application-name").value = app?.name ?? ""; byId("application-slug").value = app?.slug ?? ""; byId("application-slug").disabled = Boolean(app);
  byId("application-description").value = app?.description ?? ""; byId("application-category").value = app?.category ?? "";
  byId("application-access").value = app?.accessLevel ?? "private"; byId("application-url").value = app?.launchUrl ?? "";
  byId("application-icon").value = app?.iconKey ?? ""; byId("application-order").value = app?.displayOrder ?? 0;
  dialog.showModal(); byId("application-name").focus();
}

async function save(event) {
  event.preventDefault(); if (!form.reportValidity()) return;
  const id = byId("application-id").value;
  const body = { name: byId("application-name").value.trim(), description: byId("application-description").value.trim(), category: byId("application-category").value.trim(), launchUrl: byId("application-url").value.trim(), accessLevel: byId("application-access").value, iconKey: byId("application-icon").value.trim() || null, displayOrder: Number(byId("application-order").value) };
  if (!id) body.slug = byId("application-slug").value.trim(); else body.expectedRevision = Number(byId("application-revision").value);
  byId("save-application").disabled = true; byId("form-error").hidden = true;
  try { await adminApiRequest(currentUser, id ? `/api/admin/applications/${id}` : "/api/admin/applications", { method: id ? "PATCH" : "POST", body }); dialog.close(); await load(); }
  catch (error) { byId("form-error").textContent = error instanceof AdminApiError ? error.message : "No fue posible guardar la aplicación."; byId("form-error").hidden = false; }
  finally { byId("save-application").disabled = false; }
}

function requestAction(action, app) {
  pendingAction = { action, app };
  const copy = action === "deactivate" ? `¿Desactivar “${app.name}”? Dejará de estar disponible en el catálogo.` : action === "archive" ? `¿Archivar “${app.name}”? La aplicación quedará en modo de solo lectura y sus claves seguirán reservadas.` : `¿Activar “${app.name}”?`;
  byId("confirm-title").textContent = action === "archive" ? "Archivar aplicación" : action === "deactivate" ? "Desactivar aplicación" : "Activar aplicación";
  byId("confirm-copy").textContent = copy; byId("confirm-reason-field").hidden = action !== "archive"; byId("confirm-reason").value = "";
  byId("accept-confirm").className = action === "activate" ? "primary-button inline-button" : "danger-button";
  confirmDialog.showModal();
}

async function acceptAction() {
  if (!pendingAction) return;
  const { action, app } = pendingAction; const reason = byId("confirm-reason").value.trim();
  if (action === "archive" && reason.length < 3) { byId("confirm-reason").focus(); return; }
  byId("accept-confirm").disabled = true;
  try { await adminApiRequest(currentUser, `/api/admin/applications/${app.appId}/${action}`, { method: "POST", body: { expectedRevision: app.revision, ...(reason ? { reason } : {}) } }); confirmDialog.close(); await load(); }
  catch (error) { byId("confirm-copy").textContent = error instanceof AdminApiError ? error.message : "No fue posible completar la acción."; }
  finally { byId("accept-confirm").disabled = false; pendingAction = null; }
}

export function initializeApplications(user) {
  currentUser = user;
  byId("new-application").onclick = () => openForm(); byId("close-application-dialog").onclick = () => dialog.close(); byId("cancel-application").onclick = () => dialog.close();
  byId("cancel-confirm").onclick = () => confirmDialog.close(); byId("accept-confirm").onclick = acceptAction; byId("retry-applications").onclick = load; form.onsubmit = save;
  for (const id of ["application-search", "status-filter", "access-filter", "category-filter"]) byId(id).addEventListener("input", render);
  byId("clear-filters").onclick = () => { for (const id of ["application-search", "status-filter", "access-filter", "category-filter"]) byId(id).value = ""; render(); };
  tbody.onclick = (event) => { const button = event.target.closest("button[data-action]"); if (!button) return; const app = records.find((item) => item.appId === button.dataset.appId); if (!app) return; if (button.dataset.action === "edit") openForm(app); else requestAction(button.dataset.action, app); };
  void load();
}
