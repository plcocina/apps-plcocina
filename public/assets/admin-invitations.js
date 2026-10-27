import { adminApiRequest, AdminApiError } from "./admin-api-client.js";

const PAGE_SIZE = 25;
const invitationLabels = {
  provisioning: "Preparando",
  pending_delivery: "Pendiente de envío",
  active: "Activa",
  accepting: "En aceptación",
  password_set: "Contraseña establecida",
  accepted: "Aceptada",
  expired: "Vencida",
  revoked: "Revocada",
  reconciliation_required: "Requiere conciliación"
};
const deliveryLabels = {
  pending: "Pendiente",
  accepted: "Aceptada por proveedor",
  delivered: "Entregada",
  delayed: "Demorada",
  bounced: "Rebotada",
  complained: "Marcada como spam",
  failed: "Fallida",
  unknown: "Sin confirmar"
};

function nullableIso(value) {
  if (value === null) return null;
  if (typeof value !== "string" || Number.isNaN(new Date(value).getTime())) return null;
  return value;
}

export function sanitizeInvitation(value) {
  if (!value || typeof value !== "object" || typeof value.invitationId !== "string") return null;
  if (!Object.hasOwn(invitationLabels, value.status) || !Object.hasOwn(deliveryLabels, value.deliveryStatus)) return null;
  const createdAt = nullableIso(value.createdAt);
  const expiresAt = nullableIso(value.expiresAt);
  if (!createdAt || !expiresAt || typeof value.email !== "string" || typeof value.displayName !== "string") return null;
  return {
    invitationId: value.invitationId,
    email: value.email.slice(0, 254),
    displayName: value.displayName.slice(0, 160),
    status: value.status,
    deliveryStatus: value.deliveryStatus,
    createdAt,
    expiresAt,
    acceptedAt: nullableIso(value.acceptedAt),
    revision: Number.isInteger(value.revision) && value.revision > 0 ? value.revision : null
  };
}

export function invitationsPath({ email = null, pageToken = null, pageSize = PAGE_SIZE } = {}) {
  const query = new URLSearchParams();
  if (email !== null) query.set("email", email.trim().toLowerCase());
  else {
    query.set("pageSize", String(pageSize));
    if (pageToken) query.set("pageToken", pageToken);
  }
  return `/api/admin/invitations?${query.toString()}`;
}

export function createInvitationsDataSource(user, request = adminApiRequest) {
  let cursors = [null];
  let pageIndex = 0;
  let nextPageToken = null;
  async function fetchPage(token = cursors[pageIndex]) {
    const data = await request(user, invitationsPath({ pageToken: token }));
    nextPageToken = typeof data?.nextPageToken === "string" && data.nextPageToken ? data.nextPageToken : null;
    return { invitations: Array.isArray(data?.invitations) ? data.invitations.map(sanitizeInvitation).filter(Boolean) : [], page: pageIndex + 1, nextPageToken };
  }
  return {
    first: async () => { cursors = [null]; pageIndex = 0; return fetchPage(); },
    next: async () => {
      if (!nextPageToken) return null;
      pageIndex += 1;
      cursors = cursors.slice(0, pageIndex);
      cursors[pageIndex] = nextPageToken;
      return fetchPage(nextPageToken);
    },
    previous: async () => {
      if (pageIndex === 0) return null;
      pageIndex -= 1;
      return fetchPage(cursors[pageIndex]);
    },
    search: async (email) => {
      const data = await request(user, invitationsPath({ email }));
      return { invitations: Array.isArray(data?.invitations) ? data.invitations.map(sanitizeInvitation).filter(Boolean) : [], page: 1, nextPageToken: null, search: true };
    }
  };
}

export function availableInvitationActions(invitation) {
  if (!invitation || invitation.revision === null) return [];
  const actions = [];
  if (["active", "pending_delivery", "expired", "reconciliation_required"].includes(invitation.status)) actions.push("resend");
  if (!["accepted", "revoked"].includes(invitation.status)) actions.push("revoke");
  return actions;
}

function validEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

export function createInvitationLogicalOperation(input, uuid = () => globalThis.crypto.randomUUID()) {
  const displayName = typeof input?.displayName === "string" ? input.displayName.trim() : "";
  const email = typeof input?.email === "string" ? input.email.trim().toLowerCase() : "";
  const expiresInHours = Number(input?.expiresInHours ?? 72);
  if (displayName.length < 1 || displayName.length > 160) throw new TypeError("El nombre no es válido.");
  if (email.length > 254 || !validEmail(email)) throw new TypeError("El correo electrónico no es válido.");
  if (!Number.isInteger(expiresInHours) || expiresInHours < 1 || expiresInHours > 168) throw new TypeError("La vigencia no es válida.");
  return Object.freeze({ scope: "create", action: "create", idempotencyKey: uuid(), body: { displayName, email, expiresInHours } });
}

export function createInvitationActionOperation(invitation, action, reason = "", uuid = () => globalThis.crypto.randomUUID()) {
  if (!availableInvitationActions(invitation).includes(action)) throw new TypeError("La operación no está permitida para esta invitación.");
  const trimmedReason = typeof reason === "string" ? reason.trim() : "";
  if (action === "revoke" && (trimmedReason.length < 3 || trimmedReason.length > 500)) throw new TypeError("Se requiere un motivo de entre 3 y 500 caracteres.");
  return Object.freeze({
    scope: invitation.invitationId,
    invitationId: invitation.invitationId,
    action,
    idempotencyKey: uuid(),
    body: {
      expectedRevision: invitation.revision,
      ...(action === "resend" ? { expiresInHours: 72 } : { reason: trimmedReason })
    }
  });
}

export function invitationOperationErrorKind(error) {
  if (!(error instanceof AdminApiError)) return "unknown";
  if (error.status === 401 || error.status === 403) return "session";
  if (error.status === 503 && error.code === "INTERNAL_ERROR") return "provider-disabled";
  if (["NETWORK_ERROR", "SERVICE_UNAVAILABLE", "INTERNAL_ERROR", "OPERATION_IN_PROGRESS"].includes(error.code) || (typeof error.status === "number" && error.status >= 500)) return "ambiguous";
  if (["REVISION_CONFLICT", "INVALID_STATE_TRANSITION", "PROFILE_REQUIRED", "PROFILE_INCONSISTENT", "PROTECTED_ACCOUNT", "DELIVERY_RETRY_WINDOW_EXPIRED"].includes(error.code)) return "stale";
  return "definitive";
}

export function createInvitationOperationExecutor(user, request = adminApiRequest) {
  const activeScopes = new Set();
  return {
    isActive: (scope) => activeScopes.has(scope),
    execute: async (operation) => {
      if (activeScopes.has(operation.scope)) throw new AdminApiError("OPERATION_IN_PROGRESS", "Ya hay una operación en curso.", 409);
      activeScopes.add(operation.scope);
      const path = operation.action === "create"
        ? "/api/admin/invitations"
        : `/api/admin/invitations/${encodeURIComponent(operation.invitationId)}/${operation.action}`;
      try {
        return await request(user, path, { method: "POST", idempotencyKey: operation.idempotencyKey, body: operation.body });
      } finally {
        activeScopes.delete(operation.scope);
      }
    }
  };
}

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function dateLabel(value, empty = "—") {
  if (!value) return empty;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "No disponible" : new Intl.DateTimeFormat("es-MX", { dateStyle: "medium", timeStyle: "short" }).format(date);
}

function badgeClass(value) {
  return value.replaceAll("_", "-");
}

export function initializeInvitations(user, options = {}) {
  const byId = (id) => document.getElementById(id);
  const table = byId("invitations-table");
  const tbody = table.querySelector("tbody");
  const message = byId("invitations-message");
  const pagination = byId("invitations-pagination");
  const source = createInvitationsDataSource(user, options.request);
  const operations = createInvitationOperationExecutor(user, options.request);
  const ambiguousOperations = new Map();
  const createDialog = byId("create-invitation-dialog");
  const createForm = byId("create-invitation-form");
  const actionDialog = byId("invitation-operation-dialog");
  const actionForm = byId("invitation-operation-form");
  const actionReason = byId("invitation-operation-reason");
  let loaded = false;
  let searching = false;
  let lastAction = () => source.first();
  let visibleInvitations = new Map();
  let pendingCreate = null;
  let pendingAction = null;

  function showState(text) {
    message.textContent = text;
    message.hidden = false;
    table.hidden = true;
    pagination.hidden = true;
  }

  function render(result) {
    tbody.replaceChildren();
    const records = result.invitations;
    visibleInvitations = new Map(records.map((item) => [item.invitationId, item]));
    byId("invitation-count").textContent = `${records.length} ${records.length === 1 ? "invitación" : "invitaciones"}`;
    byId("invitation-mode").textContent = searching ? "Resultado de búsqueda exacta" : `Página ${result.page}`;
    byId("invitations-page-label").textContent = `Página ${result.page}`;
    byId("previous-invitations").disabled = searching || result.page === 1;
    byId("next-invitations").disabled = searching || !result.nextPageToken;
    table.hidden = records.length === 0;
    message.hidden = records.length > 0;
    message.textContent = searching ? "No se encontró una invitación con ese correo." : "No hay invitaciones en esta página.";
    pagination.hidden = searching || records.length === 0;

    for (const invitation of records) {
      const row = document.createElement("tr");
      const recipient = document.createElement("td");
      const recipientWrap = element("div", "invitation-recipient");
      recipientWrap.append(element("strong", "", invitation.displayName), element("span", "", invitation.email));
      recipient.append(recipientWrap);
      const status = document.createElement("td"); status.append(element("span", `badge ${badgeClass(invitation.status)}`, invitationLabels[invitation.status]));
      const delivery = document.createElement("td"); delivery.append(element("span", `badge ${badgeClass(invitation.deliveryStatus)}`, deliveryLabels[invitation.deliveryStatus]));
      const created = element("td", "", dateLabel(invitation.createdAt));
      const validity = element("td", "", `${invitation.status === "expired" ? "Venció" : "Vence"}: ${dateLabel(invitation.expiresAt)}`);
      const acceptance = element("td", "", dateLabel(invitation.acceptedAt, "Pendiente"));
      const actions = document.createElement("td");
      const actionWrap = element("div", "invitation-actions");
      for (const action of availableInvitationActions(invitation)) {
        const button = element("button", action === "revoke" ? "danger-action" : "", action === "resend" ? "Reenviar" : "Revocar");
        button.type = "button";
        button.dataset.invitationAction = action;
        button.dataset.invitationId = invitation.invitationId;
        button.disabled = operations.isActive(invitation.invitationId);
        actionWrap.append(button);
      }
      if (!actionWrap.childElementCount) actionWrap.append(element("span", "summary-note", "Sin acciones disponibles"));
      actions.append(actionWrap);
      row.append(recipient, status, delivery, created, validity, acceptance, actions);
      tbody.append(row);
    }
  }

  function feedback(text, isError = false) {
    const node = byId("invitations-feedback");
    node.textContent = text;
    node.classList.toggle("error-state", isError);
    node.hidden = false;
  }

  async function handleOperationError(error, operation, errorNode, retryButton, closeDialog) {
    const kind = invitationOperationErrorKind(error);
    if (kind === "session") {
      closeDialog();
      await options.onSessionExpired?.(error.message);
      return;
    }
    if (kind === "provider-disabled") {
      ambiguousOperations.delete(operation.scope);
      closeDialog();
      feedback("El proveedor de invitaciones está deshabilitado. No se creó ni se representó ningún envío como completado.", true);
      return;
    }
    if (kind === "ambiguous") {
      ambiguousOperations.set(operation.scope, operation);
      errorNode.textContent = "No se pudo confirmar el resultado. Reintenta para consultar o completar exactamente la misma operación.";
      errorNode.hidden = false;
      retryButton.textContent = "Reintentar operación";
      return;
    }
    ambiguousOperations.delete(operation.scope);
    closeDialog();
    const stale = kind === "stale";
    feedback(stale ? "La invitación cambió o ya no admite esta operación. Se actualizará la consulta." : error instanceof AdminApiError ? error.message : "No fue posible completar la operación.", true);
    if (stale) await run(lastAction);
  }

  function openCreate() {
    pendingCreate = ambiguousOperations.get("create") ?? null;
    createForm.reset();
    byId("invitation-hours").value = "72";
    const locked = Boolean(pendingCreate);
    if (locked) {
      byId("invitation-name").value = pendingCreate.body.displayName;
      byId("invitation-email").value = pendingCreate.body.email;
      byId("invitation-hours").value = String(pendingCreate.body.expiresInHours);
    }
    for (const input of [byId("invitation-name"), byId("invitation-email"), byId("invitation-hours")]) input.disabled = locked;
    byId("create-invitation-error").hidden = true;
    byId("confirm-create-invitation").textContent = locked ? "Reintentar operación" : "Crear invitación";
    createDialog.showModal();
    (locked ? byId("confirm-create-invitation") : byId("invitation-name")).focus();
  }

  async function submitCreate(event) {
    event.preventDefault();
    if (!pendingCreate) {
      if (!createForm.reportValidity()) return;
      try {
        pendingCreate = createInvitationLogicalOperation({
          displayName: byId("invitation-name").value,
          email: byId("invitation-email").value,
          expiresInHours: byId("invitation-hours").value
        }, options.uuid);
      } catch (error) {
        byId("create-invitation-error").textContent = error.message;
        byId("create-invitation-error").hidden = false;
        return;
      }
    }
    const operation = pendingCreate;
    const confirm = byId("confirm-create-invitation");
    confirm.disabled = true;
    byId("cancel-create-invitation").disabled = true;
    byId("close-create-invitation").disabled = true;
    try {
      const result = await operations.execute(operation);
      ambiguousOperations.delete("create");
      pendingCreate = null;
      createDialog.close();
      feedback(`Invitación creada. Estado de entrega: ${deliveryLabels[result.deliveryStatus] ?? "Sin confirmar"}.`);
      await run(lastAction);
    } catch (error) {
      await handleOperationError(error, operation, byId("create-invitation-error"), confirm, () => createDialog.close());
    } finally {
      confirm.disabled = false;
      byId("cancel-create-invitation").disabled = false;
      byId("close-create-invitation").disabled = false;
    }
  }

  function openAction(invitation, action) {
    if (!availableInvitationActions(invitation).includes(action) || operations.isActive(invitation.invitationId)) return;
    const saved = ambiguousOperations.get(invitation.invitationId) ?? null;
    if (saved && saved.action !== action) return;
    pendingAction = { invitation, action, operation: saved };
    const revoke = action === "revoke";
    byId("invitation-operation-title").textContent = saved ? `Reintentar ${revoke ? "revocación" : "reenvío"}` : revoke ? "Revocar invitación" : "Reenviar invitación";
    byId("invitation-operation-copy").textContent = revoke
      ? "La invitación dejará de ser válida y la cuenta provisional quedará deshabilitada."
      : "Se generará un enlace nuevo con vigencia de 72 horas; el enlace anterior dejará de ser válido.";
    byId("invitation-operation-reason-field").hidden = !revoke;
    actionReason.value = saved?.body.reason ?? "";
    actionReason.disabled = Boolean(saved);
    byId("invitation-operation-error").hidden = true;
    const confirm = byId("confirm-invitation-operation");
    confirm.textContent = saved ? "Reintentar operación" : revoke ? "Revocar invitación" : "Reenviar invitación";
    confirm.className = revoke ? "danger-button" : "primary-button inline-button";
    actionDialog.showModal();
    (revoke && !saved ? actionReason : confirm).focus();
  }

  async function submitAction(event) {
    event.preventDefault();
    if (!pendingAction) return;
    const { invitation, action } = pendingAction;
    if (!pendingAction.operation) {
      const reason = actionReason.value.trim();
      if (action === "revoke" && (reason.length < 3 || reason.length > 500)) {
        actionReason.setCustomValidity("Escribe un motivo de entre 3 y 500 caracteres.");
        actionReason.reportValidity();
        return;
      }
      actionReason.setCustomValidity("");
      pendingAction.operation = createInvitationActionOperation(invitation, action, reason, options.uuid);
    }
    const operation = pendingAction.operation;
    const confirm = byId("confirm-invitation-operation");
    confirm.disabled = true;
    byId("cancel-invitation-operation").disabled = true;
    try {
      const result = await operations.execute(operation);
      ambiguousOperations.delete(invitation.invitationId);
      actionDialog.close();
      feedback(action === "revoke" ? "Invitación revocada correctamente." : `Reenvío confirmado. Estado de entrega: ${deliveryLabels[result.deliveryStatus] ?? "Sin confirmar"}.`);
      await run(lastAction);
    } catch (error) {
      await handleOperationError(error, operation, byId("invitation-operation-error"), confirm, () => actionDialog.close());
    } finally {
      confirm.disabled = false;
      byId("cancel-invitation-operation").disabled = false;
    }
  }

  async function run(action) {
    lastAction = action;
    showState("Cargando invitaciones…");
    byId("retry-invitations").hidden = true;
    try {
      const result = await action();
      if (result) render(result);
    } catch (error) {
      if (error instanceof AdminApiError && (error.status === 401 || error.status === 403)) {
        showState("La sesión administrativa venció. Inicia sesión nuevamente.");
        await options.onSessionExpired?.(error.message);
        return;
      }
      showState(error instanceof AdminApiError ? error.message : "No fue posible cargar las invitaciones.");
      byId("retry-invitations").hidden = false;
    }
  }

  function activate(view = location.hash.slice(1)) {
    if (view === "invitations" && !loaded) {
      loaded = true;
      searching = false;
      void run(() => source.first());
    }
  }

  byId("invitation-search-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const input = byId("invitation-search");
    if (!input.reportValidity()) return;
    const email = input.value.trim();
    if (!email) { input.setCustomValidity("Escribe un correo electrónico."); input.reportValidity(); input.setCustomValidity(""); return; }
    searching = true;
    void run(() => source.search(email));
  });
  byId("invitation-search").addEventListener("input", (event) => event.currentTarget.setCustomValidity(""));
  byId("clear-invitation-search").addEventListener("click", () => { byId("invitation-search").value = ""; searching = false; void run(() => source.first()); });
  byId("previous-invitations").addEventListener("click", () => void run(() => source.previous()));
  byId("next-invitations").addEventListener("click", () => void run(() => source.next()));
  byId("retry-invitations").addEventListener("click", () => void run(lastAction));
  byId("new-invitation").addEventListener("click", openCreate);
  createForm.addEventListener("submit", submitCreate);
  byId("cancel-create-invitation").addEventListener("click", () => createDialog.close());
  byId("close-create-invitation").addEventListener("click", () => createDialog.close());
  tbody.addEventListener("click", (event) => {
    const button = event.target.closest("button[data-invitation-action]");
    if (!button) return;
    const invitation = visibleInvitations.get(button.dataset.invitationId);
    if (invitation) openAction(invitation, button.dataset.invitationAction);
  });
  actionReason.addEventListener("input", () => actionReason.setCustomValidity(""));
  actionForm.addEventListener("submit", submitAction);
  byId("cancel-invitation-operation").addEventListener("click", () => actionDialog.close());
  window.addEventListener("admin:viewchange", (event) => activate(event.detail?.view));
  activate();
}
