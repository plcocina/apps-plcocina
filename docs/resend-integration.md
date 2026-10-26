# Preparación de Resend para invitaciones

El adaptador `ResendInvitationEmailProvider` y `POST /api/webhooks/resend` están integrados técnicamente en el código local de `adminApi`. La activación permanece bloqueada por defecto mediante `RESEND_INVITATIONS_ENABLED=false`; las pruebas del adaptador utilizan una implementación `fetch` simulada y los emuladores nunca habilitan el proveedor externo.

Los parámetros `RESEND_API_KEY`, `RESEND_WEBHOOK_SIGNING_SECRET` e `INVITATION_TOKEN_KEY_V1` están declarados como secretos de Cloud Functions Gen 2, pero sus valores no están configurados. No existe un proveedor Resend habilitado, no se ha conectado ningún servicio externo y el Módulo 2 no se ha desplegado a producción. La activación real requiere aprobación y el procedimiento controlado de C7.

## Configuración futura

- Verificar el dominio `plcocina.com` en Resend y autorizar `invitaciones@plcocina.com` como remitente.
- Desactivar `open_tracking` y `click_tracking` para el dominio antes de habilitar envíos. El endpoint de envío no sustituye esa configuración de dominio.
- Guardar la API key de envío y el secreto de firma de webhooks como dos secretos independientes en Secret Manager. No deben ser variables planas, archivos del repositorio ni valores accesibles al navegador.
- Conceder a la cuenta runtime únicamente `roles/secretmanager.secretAccessor` sobre esas dos versiones de secreto, no sobre todo el proyecto.
- Inyectar `enabled: true` sólo en producción y únicamente cuando ambos requisitos operativos estén verificados. El valor predeterminado debe seguir siendo `false`.
- Mantener el enlace base exacto `https://apps.plcocina.com/accept-invitation/`; `invitationId` y token se incorporan sólo al fragmento y nunca se persiste el enlace completo.

## Idempotencia y recuperación

Cada solicitud usa `invitation/{invitationId}/generation/{generation}` como `Idempotency-Key`. `adminOperations` y `delivery.retryUntil` limitan reintentos automáticos a 23 horas, dejando una hora de margen frente a la retención de 24 horas de Resend. HTTP 409, timeout, fallo de red y respuesta exitosa inválida se consideran ambiguos y requieren recuperación segura; no se debe crear una clave nueva para la misma generación.

## Webhooks

La verificación opera sobre el cuerpo crudo y los encabezados `svix-id`, `svix-timestamp` y `svix-signature`, con comparación constante, tolerancia temporal y una reserva anti-repetición. `FirestoreWebhookReplayStore` implementa la reserva transaccional deny-by-default en Firestore y el servicio registra únicamente referencias controladas, sin conservar el cuerpo sensible del proveedor.

El endpoint local existe, pero responde de forma cerrada cuando la bandera está deshabilitada. No se han creado valores de secretos, permisos IAM para leerlos, configuración de proveedor externo ni recursos productivos del Módulo 2.
