import { adminApiRequest, AdminApiError } from "./admin-api-client.js";

const PAGE_SIZE = 25;
const integrityLabels = {
  linked: "Vinculada",
  missing_profile: "Sin perfil",
  orphan_profile: "Sin cuenta Auth",
  profile_mismatch: "Datos inconsistentes",
  invalid_profile: "Perfil inválido"
};

function nullableText(value, maximum = 254) {
  return typeof value === "string" && value.length <= maximum ? value : null;
}

export function sanitizeUser(value) {
  if (!value || typeof value !== "object" || typeof value.uid !== "string" || value.uid.length < 1 || value.uid.length > 128) return null;
  const integrity = Object.hasOwn(integrityLabels, value.integrity) ? value.integrity : "invalid_profile";
  const profileStatus = ["invited", "active", "disabled"].includes(value.profile?.status) ? value.profile.status : null;
  return {
    uid: value.uid,
    email: nullableText(value.email),
    displayName: nullableText(value.displayName, 160),
    disabled: typeof value.disabled === "boolean" ? value.disabled : null,
    lastSignInAt: nullableText(value.lastSignInAt),
    isProtected: value.isProtected === true,
    integrity,
    profileStatus,
    authDisabled: typeof value.profile?.authDisabled === "boolean" ? value.profile.authDisabled : null,
    profileRevision: Number.isInteger(value.profile?.revision) && value.profile.revision > 0 ? value.profile.revision : null
  };
}

export function availableUserActions(user, actorUid) {
  if (!user || user.uid === actorUid || user.isProtected || user.integrity !== "linked" || user.profileRevision === null) return [];
  if (user.profileStatus === "active" && user.disabled === false && user.authDisabled === false) return ["suspend", "revoke-sessions"];
  if (user.profileStatus === "disabled" && user.disabled === true && user.authDisabled === true) return ["reactivate"];
  return [];
}

export function createLogicalUserOperation(user, action, reason, uuid = () => globalThis.crypto.randomUUID()) {
  const trimmedReason = typeof reason === "string" ? reason.trim() : "";
  if (!Number.isInteger(user?.profileRevision) || user.profileRevision < 1) throw new TypeError("La revisión del perfil no es válida.");
  if ((action === "suspend" || action === "revoke-sessions") && (trimmedReason.length < 3 || trimmedReason.length > 500)) {
    throw new TypeError("Se requiere un motivo de entre 3 y 500 caracteres.");
  }
  if (!availableUserActions(user, null).includes(action)) throw new TypeError("La operación no está permitida para esta cuenta.");
  return Object.freeze({
    uid: user.uid,
    action,
    idempotencyKey: uuid(),
    body: { expectedRevision: user.profileRevision, ...(trimmedReason ? { reason: trimmedReason } : {}) }
  });
}

export function isAmbiguousOperationError(error) {
  return error instanceof AdminApiError && (
    error.code === "NETWORK_ERROR" ||
    error.code === "SERVICE_UNAVAILABLE" ||
    error.code === "INTERNAL_ERROR" ||
    error.code === "OPERATION_IN_PROGRESS" ||
    (typeof error.status === "number" && error.status >= 500)
  );
}

export function createUserOperationExecutor(user, request = adminApiRequest) {
  const activeUids = new Set();
  return {
    isActive: (uid) => activeUids.has(uid),
    execute: async (operation) => {
      if (activeUids.has(operation.uid)) throw new AdminApiError("OPERATION_IN_PROGRESS", "Ya hay una operación en curso para esta cuenta.", 409);
      activeUids.add(operation.uid);
      try {
        return await request(user, `/api/admin/users/${encodeURIComponent(operation.uid)}/${operation.action}`, {
          method: "POST",
          idempotencyKey: operation.idempotencyKey,
          body: operation.body
        });
      } finally {
        activeUids.delete(operation.uid);
      }
    }
  };
}

export function usersPath({ email = null, pageToken = null, pageSize = PAGE_SIZE } = {}) {
  const query = new URLSearchParams();
  if (email !== null) query.set("email", email.trim().toLowerCase());
  else {
    query.set("pageSize", String(pageSize));
    if (pageToken) query.set("pageToken", pageToken);
  }
  return `/api/admin/users?${query.toString()}`;
}

export function createUsersDataSource(user, request = adminApiRequest) {
  let cursors = [null];
  let pageIndex = 0;
  let nextPageToken = null;

  async function fetchPage(token = cursors[pageIndex]) {
    const data = await request(user, usersPath({ pageToken: token }));
    nextPageToken = typeof data?.nextPageToken === "string" && data.nextPageToken ? data.nextPageToken : null;
    return { users: Array.isArray(data?.users) ? data.users.map(sanitizeUser).filter(Boolean) : [], page: pageIndex + 1, nextPageToken };
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
      const data = await request(user, usersPath({ email }));
      return { users: Array.isArray(data?.users) ? data.users.map(sanitizeUser).filter(Boolean) : [], page: 1, nextPageToken: null, search: true };
    }
  };
}

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function dateLabel(value) {
  if (!value) return "Nunca";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "No disponible" : new Intl.DateTimeFormat("es-MX", { dateStyle: "medium", timeStyle: "short" }).format(date);
}

function accountState(user) {
  if (user.disabled === true || user.profileStatus === "disabled") return ["disabled", "Deshabilitada"];
  if (user.profileStatus === "invited") return ["invited", "Invitada"];
  if (user.disabled === false || user.profileStatus === "active") return ["active", "Activa"];
  return ["partial", "No disponible"];
}

export function initializeUsers(user, options = {}) {
  const byId = (id) => document.getElementById(id);
  const section = byId("users");
  const applications = byId("applications");
  const table = byId("users-table");
  const tbody = table.querySelector("tbody");
  const message = byId("users-message");
  const pagination = byId("users-pagination");
  const source = createUsersDataSource(user, options.request);
  const operations = createUserOperationExecutor(user, options.request);
  const ambiguousOperations = new Map();
  const operationDialog = byId("user-operation-dialog");
  const operationForm = byId("user-operation-form");
  const operationReason = byId("user-operation-reason");
  const operationError = byId("user-operation-error");
  let lastAction = () => source.first();
  let loaded = false;
  let searching = false;
  let visibleUsers = new Map();
  let pendingOperation = null;

  function showState(text) {
    message.textContent = text;
    message.hidden = false;
    table.hidden = true;
    pagination.hidden = true;
  }

  function render(result) {
    tbody.replaceChildren();
    const users = result.users;
    visibleUsers = new Map(users.map((item) => [item.uid, item]));
    byId("user-count").textContent = `${users.length} ${users.length === 1 ? "usuario" : "usuarios"}`;
    byId("user-mode").textContent = searching ? "Resultado de búsqueda exacta" : `Página ${result.page}`;
    byId("users-page-label").textContent = `Página ${result.page}`;
    byId("previous-users").disabled = searching || result.page === 1;
    byId("next-users").disabled = searching || !result.nextPageToken;
    table.hidden = users.length === 0;
    message.hidden = users.length > 0;
    message.textContent = searching ? "No se encontró una cuenta con ese correo." : "No hay usuarios en esta página.";
    pagination.hidden = searching || users.length === 0;

    for (const userRecord of users) {
      const row = document.createElement("tr");
      const identity = document.createElement("td");
      const identityWrap = element("div", "user-name");
      identityWrap.append(element("strong", "", userRecord.displayName ?? "Nombre no disponible"), element("span", "", userRecord.email ?? "Correo no disponible"));
      identity.append(identityWrap);
      const [stateClass, stateText] = accountState(userRecord);
      const status = document.createElement("td"); status.append(element("span", `badge ${stateClass}`, stateText));
      const lastAccess = element("td", "", dateLabel(userRecord.lastSignInAt));
      const integrity = document.createElement("td");
      const integrityClass = userRecord.integrity === "linked" ? "linked" : userRecord.integrity === "missing_profile" || userRecord.integrity === "orphan_profile" ? "partial" : "inconsistent";
      integrity.append(element("span", `badge ${integrityClass}`, integrityLabels[userRecord.integrity]));
      const protection = document.createElement("td"); protection.append(element("span", `badge ${userRecord.isProtected ? "protected" : "standard"}`, userRecord.isProtected ? "Protegida" : "Estándar"));
      const actions = document.createElement("td");
      const actionWrap = element("div", "user-actions");
      const allowed = availableUserActions(userRecord, user.uid);
      for (const action of allowed) {
        const label = action === "suspend" ? "Suspender" : action === "reactivate" ? "Reactivar" : "Revocar sesiones";
        const button = element("button", action === "suspend" ? "danger-action" : "", label);
        button.type = "button";
        button.dataset.userAction = action;
        button.dataset.uid = userRecord.uid;
        button.disabled = operations.isActive(userRecord.uid);
        actionWrap.append(button);
      }
      if (allowed.length === 0) actionWrap.append(element("span", "summary-note", "Sin acciones disponibles"));
      actions.append(actionWrap);
      row.append(identity, status, lastAccess, integrity, protection, actions);
      tbody.append(row);
    }
  }

  function feedback(text, isError = false) {
    const node = byId("users-feedback");
    node.textContent = text;
    node.classList.toggle("error-state", isError);
    node.hidden = false;
  }

  function operationKey(record, action) {
    return `${record.uid}:${action}`;
  }

  function openOperation(record, action) {
    if (!availableUserActions(record, user.uid).includes(action) || operations.isActive(record.uid)) return;
    const saved = ambiguousOperations.get(operationKey(record, action)) ?? null;
    pendingOperation = { record, action, logical: saved };
    const requiresReason = action === "suspend" || action === "revoke-sessions";
    const label = action === "suspend" ? "Suspender cuenta" : action === "reactivate" ? "Reactivar cuenta" : "Revocar sesiones";
    byId("user-operation-title").textContent = saved ? `Reintentar: ${label.toLowerCase()}` : label;
    byId("user-operation-copy").textContent = action === "suspend"
      ? "La cuenta perderá acceso y sus sesiones activas serán revocadas."
      : action === "reactivate" ? "La cuenta recuperará la posibilidad de iniciar sesión." : "Todas las sesiones actuales dejarán de ser válidas.";
    byId("user-operation-reason-field").hidden = !requiresReason;
    operationReason.value = saved?.body.reason ?? "";
    operationReason.disabled = Boolean(saved);
    operationError.hidden = true;
    const confirm = byId("confirm-user-operation");
    confirm.disabled = false;
    confirm.textContent = saved ? "Reintentar operación" : label;
    confirm.className = action === "reactivate" ? "primary-button inline-button" : "danger-button";
    operationDialog.showModal();
    if (requiresReason && !saved) operationReason.focus(); else confirm.focus();
  }

  async function submitOperation(event) {
    event.preventDefault();
    if (!pendingOperation) return;
    const { record, action } = pendingOperation;
    const requiresReason = action === "suspend" || action === "revoke-sessions";
    if (requiresReason && !pendingOperation.logical) {
      const reason = operationReason.value.trim();
      if (reason.length < 3 || reason.length > 500) {
        operationReason.setCustomValidity("Escribe un motivo de entre 3 y 500 caracteres.");
        operationReason.reportValidity();
        return;
      }
      operationReason.setCustomValidity("");
      pendingOperation.logical = createLogicalUserOperation(record, action, reason, options.uuid);
    } else if (!pendingOperation.logical) {
      pendingOperation.logical = createLogicalUserOperation(record, action, "", options.uuid);
    }

    const logical = pendingOperation.logical;
    const key = operationKey(record, action);
    const confirm = byId("confirm-user-operation");
    confirm.disabled = true;
    byId("cancel-user-operation").disabled = true;
    operationError.hidden = true;
    try {
      await operations.execute(logical);
      ambiguousOperations.delete(key);
      operationDialog.close();
      feedback(action === "suspend" ? "Cuenta suspendida correctamente." : action === "reactivate" ? "Cuenta reactivada correctamente." : "Sesiones revocadas correctamente.");
      await run(lastAction);
    } catch (error) {
      if (error instanceof AdminApiError && (error.status === 401 || error.status === 403)) {
        operationDialog.close();
        await options.onSessionExpired?.(error.message);
        return;
      }
      if (isAmbiguousOperationError(error)) {
        ambiguousOperations.set(key, logical);
        operationReason.disabled = true;
        operationError.textContent = error?.code === "OPERATION_IN_PROGRESS"
          ? "La operación sigue en curso. Espera un momento y reintenta con la misma solicitud."
          : "No se pudo confirmar el resultado. Reintenta para consultar o completar la misma operación de forma segura.";
        operationError.hidden = false;
        confirm.textContent = "Reintentar operación";
      } else {
        ambiguousOperations.delete(key);
        operationDialog.close();
        const stale = error instanceof AdminApiError && ["REVISION_CONFLICT", "PROFILE_REQUIRED", "PROFILE_INCONSISTENT", "PROTECTED_ACCOUNT", "INVALID_STATE_TRANSITION"].includes(error.code);
        feedback(stale ? "La cuenta cambió o ya no admite esta operación. Se actualizará la consulta." : error instanceof AdminApiError ? error.message : "No fue posible completar la operación.", true);
        if (stale) await run(lastAction);
      }
    } finally {
      confirm.disabled = false;
      byId("cancel-user-operation").disabled = false;
    }
  }

  async function run(action) {
    lastAction = action;
    showState("Cargando usuarios…");
    byId("retry-users").hidden = true;
    try {
      const result = await action();
      if (result) render(result);
    } catch (error) {
      if (error instanceof AdminApiError && (error.status === 401 || error.status === 403)) {
        showState("La sesión administrativa venció. Inicia sesión nuevamente.");
        await options.onSessionExpired?.(error.message);
        return;
      }
      showState(error instanceof AdminApiError ? error.message : "No fue posible cargar los usuarios.");
      byId("retry-users").hidden = false;
    }
  }

  function activateView() {
    const requested = location.hash.slice(1);
    const target = ["applications", "users", "invitations"].includes(requested) ? requested : "applications";
    for (const view of document.querySelectorAll("[data-admin-section]")) view.hidden = view.dataset.adminSection !== target;
    for (const link of document.querySelectorAll("[data-admin-view]")) {
      const selected = link.dataset.adminView === target;
      link.classList.toggle("selected", selected);
      if (selected) link.setAttribute("aria-current", "page"); else link.removeAttribute("aria-current");
    }
    if (target === "users" && !loaded) {
      loaded = true;
      searching = false;
      void run(() => source.first());
    }
    window.dispatchEvent(new CustomEvent("admin:viewchange", { detail: { view: target } }));
  }

  byId("user-search-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const input = byId("user-search");
    if (!input.reportValidity()) return;
    const email = input.value.trim();
    if (!email) { input.setCustomValidity("Escribe un correo electrónico."); input.reportValidity(); input.setCustomValidity(""); return; }
    searching = true;
    void run(() => source.search(email));
  });
  byId("user-search").addEventListener("input", (event) => event.currentTarget.setCustomValidity(""));
  byId("clear-user-search").addEventListener("click", () => { byId("user-search").value = ""; searching = false; void run(() => source.first()); });
  byId("previous-users").addEventListener("click", () => void run(() => source.previous()));
  byId("next-users").addEventListener("click", () => void run(() => source.next()));
  byId("retry-users").addEventListener("click", () => void run(lastAction));
  tbody.addEventListener("click", (event) => {
    const button = event.target.closest("button[data-user-action]");
    if (!button) return;
    const record = visibleUsers.get(button.dataset.uid);
    if (record) openOperation(record, button.dataset.userAction);
  });
  operationReason.addEventListener("input", () => operationReason.setCustomValidity(""));
  operationForm.addEventListener("submit", submitOperation);
  byId("cancel-user-operation").addEventListener("click", () => operationDialog.close());
  window.addEventListener("hashchange", activateView);
  activateView();
}
