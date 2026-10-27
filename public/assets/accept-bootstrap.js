(function bootstrapInvitationAcceptance() {
  "use strict";

  const parameters = new URLSearchParams(window.location.hash.slice(1));
  let invitationId = parameters.get("invitationId") ?? "";
  let token = parameters.get("token") ?? "";

  window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}`);

  function addLink(rel, href, options) {
    const link = document.createElement("link");
    link.rel = rel;
    link.href = href;
    if (options?.type) link.type = options.type;
    if (options?.crossOrigin) link.crossOrigin = options.crossOrigin;
    document.head.append(link);
  }

  addLink("icon", "/logo_PL-Cocina-icono.png", { type: "image/png" });
  addLink("preconnect", "https://fonts.googleapis.com");
  addLink("preconnect", "https://fonts.gstatic.com", { crossOrigin: "anonymous" });
  addLink("stylesheet", "https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap");
  addLink("stylesheet", "/assets/accept-invitation.css");

  window.addEventListener("DOMContentLoaded", function loadAcceptanceApplication() {
    const credentials = { invitationId, token };
    invitationId = "";
    token = "";
    import("/assets/accept-invitation.js")
      .then(function initialize(module) { return module.startAcceptance(credentials); })
      .catch(function showBootstrapFailure() {
        const status = document.getElementById("acceptance-status");
        if (status) status.textContent = "No fue posible iniciar el proceso. Recarga la página e intenta nuevamente.";
      });
  }, { once: true });
})();
