# C7 — Preparación técnica para producción

Este documento es un checklist de preparación y activación gradual, no una autorización de despliegue. El Módulo 2 permanece únicamente en commits locales. Resend, las invitaciones reales y el webhook permanecen deshabilitados mientras `RESEND_INVITATIONS_ENABLED` conserve su valor predeterminado `false`.

## Estado implementado localmente

- Etapa A: consulta administrativa de Firebase Authentication y perfiles `users/{uid}`, con paginación, búsqueda exacta por correo, proyección limitada y detección de inconsistencias sin reparación automática.
- Etapa B: suspensión, reactivación y revocación de sesiones con revisión optimista, idempotencia, `adminOperations`, protección de Super Admin y auditoría append-only.
- C1–C3: creación recuperable de invitaciones, cuentas provisionales deshabilitadas, reserva única de correo, rotación de tokens, reenvío, revocación y expiración.
- C4: validación, establecimiento de contraseña y confirmación. Los tokens se comparan en tiempo constante, la contraseña no se persiste y los resultados inciertos fallan cerrados.
- C5: página `/accept-invitation`, limpieza inmediata del fragmento, persistencia de Authentication sólo en memoria, CSP compatible, `Cache-Control: no-store` y `Referrer-Policy: no-referrer`.
- C6: pruebas unitarias, reglas, Auth/Firestore Emulator y flujo E2E con Hosting, Functions, Auth y Firestore Emulator. El E2E integral pasó localmente usando Node 24 del host; producción y el runtime declarado requieren Node 22, por lo que la regresión final debe repetirse con Node 22.

Nada de A/B ni C1–C6 se ha publicado. No existe proveedor externo habilitado, invitación real enviada, secreto configurado ni cambio IAM aplicado para el Módulo 2.

## Controles preparados

- `adminApi` declara `RESEND_API_KEY`, `RESEND_WEBHOOK_SIGNING_SECRET` e `INVITATION_TOKEN_KEY_V1` como parámetros secretos de Cloud Functions Gen 2, sin valores en el repositorio.
- `RESEND_INVITATIONS_ENABLED=false` mantiene deshabilitados el adaptador y el receptor. Los emuladores fuerzan proveedor simulado y nunca habilitan Resend.
- `POST /api/webhooks/resend` usa `express.raw` antes de `express.json`, valida HMAC sobre los bytes recibidos y sólo después procesa el evento.
- `FirestoreWebhookReplayStore` reserva transaccionalmente el SHA-256 de `svix-id`; dos entregas concurrentes no pueden adquirir la misma reserva.
- La conciliación invalida primero el estado Firestore, nunca repite una actualización de contraseña y no modifica la propia cuenta del actor, `PROTECTED_SUPER_ADMIN_UID` ni cuentas con `super_admin === true`.
- No existe registro público general ni endpoint público para crear cuentas, conceder permisos o modificar Custom Claims.
- Las colecciones administrativas permanecen deny-by-default para clientes; sólo Firebase Admin SDK puede acceder a ellas.

## Pendientes obligatorios

### Resend

- Verificar `plcocina.com` o un subdominio dedicado y publicar exactamente los registros DKIM y SPF proporcionados; revisar DMARC antes de modificarlo.
- Autorizar `invitaciones@plcocina.com` como remitente.
- Desactivar tracking de aperturas y clics antes de cualquier envío.
- Crear una API key limitada a envío, documentar propietario, caducidad y rotación.
- Registrar el webhook HTTPS únicamente para `email.sent`, `email.delivered`, `email.delivery_delayed`, `email.bounced`, `email.complained` y `email.failed`.
- Confirmar TLS, región de procesamiento, límites, rebotes y quejas. Mantener Resend deshabilitado hasta completar todas las verificaciones.

### Secret Manager e IAM

- Crear versiones independientes para `RESEND_API_KEY`, `RESEND_WEBHOOK_SIGNING_SECRET` e `INVITATION_TOKEN_KEY_V1`; nunca copiarlas a `.env`, GitHub, logs o archivos del repositorio.
- Conceder `roles/secretmanager.secretAccessor` a `portal-admin-api@plcocina-apps.iam.gserviceaccount.com` sobre cada secreto individual, no sobre todo el proyecto.
- Añadir exclusivamente `firebaseauth.users.create` y `firebaseauth.users.update` al rol runtime aprobado. No conceder delete, `sendEmail` ni administración de claims.
- Configurar y verificar `PROTECTED_SUPER_ADMIN_UID` antes de habilitar cualquier mutación. Si falta o no es válido, el backend debe continuar fallando cerrado.
- Confirmar que `firebaseauth.users.get` y el acceso Firestore servidor existentes continúan efectivos.
- Renovar la sesión local de Firebase CLI antes de cualquier operación sobre Google Cloud. Las pruebas E2E mostraron credenciales locales caducadas al intentar consultar secretos declarados; esto no impidió el escenario emulado, pero sí bloquea operaciones reales.

### Expiración, conciliación, TTL e índices

- Definir frecuencia, tamaño de lote, reintentos, alertas y responsable operativo de `InvitationReconciliationService.reconcileOnce(limit)`.
- No programar Cloud Scheduler o Cloud Tasks hasta aprobar esa política y verificar que no amplíe los permisos del runtime.
- Aplicar y verificar TTL sólo para `invitationRateLimits.expiresAt` y `webhookReplayEvents.expiresAt` mediante un despliegue explícito de índices.
- Mantener sin TTL `auditEvents`, `adminOperations`, `invitations`, `invitationUniqueKeys`, `users` y `accessGrants`.
- Recordar que TTL es eventual y no transaccional: limpieza y seguridad no pueden depender de la eliminación puntual de documentos.

### Webhooks, monitoreo y registros

- Verificar deduplicación, tolerancia temporal, rotación con solapamiento del signing secret y tratamiento de eventos desconocidos.
- Crear métricas y alertas para 4xx/5xx, `reconciliation_required`, `AUTH_STATE_AMBIGUOUS`, respuestas ambiguas/409 del proveedor, latencia, replays, rebotes y quejas.
- Alertar cuando el endpoint o el proveedor estén deshabilitados inesperadamente.
- Definir retención y acceso a logs. Nunca registrar cuerpos HTTP sensibles, firmas, encabezados de autorización, tokens, contraseñas ni enlaces completos de invitación.

### Aplicaciones privadas

La visibilidad `private` en el catálogo sólo evita publicar una tarjeta; no protege la aplicación ni su dominio. Antes de presentar una aplicación privada a usuarios se debe verificar protección efectiva en su propio backend o perímetro: autenticación, autorización, revocación, sesión y control de acceso por aplicación. El Módulo 2 no debe crear `accessGrants` ni asumir que ocultar una URL concede o revoca acceso. Esta activación queda fuera de C7 y requiere una fase aprobada de permisos individuales.

## Procedimiento de despliegue gradual

Cada fase requiere aprobación independiente. No combinar IAM, Firestore, Functions y Hosting en un solo cambio.

### Fase 0 — congelación y regresión

1. Congelar los SHA autorizados y revisar que no existan archivos locales, secretos o duplicados incluidos.
2. Usar Node 22 y repetir build, pruebas unitarias, reglas, Auth/Firestore Emulator y E2E integral.
3. Confirmar `RESEND_INVITATIONS_ENABLED=false`, ausencia de registro público y Firestore deny-by-default.
4. Renovar Firebase CLI y ejecutar únicamente preflights de lectura.

Condición de paro: cualquier diferencia de SHA, prueba fallida, secreto en el artefacto, permiso inesperado o acceso a recursos reales desde emuladores.

### Fase 1 — IAM y secretos sin tráfico

1. Verificar el dominio y remitente en Resend sin habilitar envíos de la aplicación.
2. Crear los tres secretos y conceder acceso individual a la cuenta runtime.
3. Añadir sólo `firebaseauth.users.create` y `firebaseauth.users.update`.
4. Configurar `PROTECTED_SUPER_ADMIN_UID` y mantener `RESEND_INVITATIONS_ENABLED=false`.
5. Revisar permisos efectivos antes de continuar.

Rollback: retirar los permisos nuevos y deshabilitar o revocar las credenciales externas sólo después de confirmar que ninguna revisión activa las utiliza.

### Fase 2 — Firestore

1. Desplegar explícitamente las reglas deny-by-default, sin Functions ni Hosting.
2. Ejecutar pruebas negativas desde clientes anónimo, autenticado y Super Admin.
3. Desplegar por separado `firestore.indexes.json` para las dos políticas TTL.
4. Verificar en consola que no se creó TTL para colecciones permanentes.

Rollback: restaurar reglas previamente aprobadas si cambió su comportamiento. No borrar documentos ni auditorías; revertir TTL requiere una decisión operativa separada.

### Fase 3 — Functions sin envíos reales

1. Desplegar exclusivamente `functions:admin-api` con la bandera en `false`.
2. Validar health, autenticación, autorización, lectura de usuarios y respuesta fail-closed de invitaciones/webhook sin crear datos reales.
3. Habilitar webhook sólo en un entorno de validación y probar firmas, replay, auditoría y observabilidad.
4. Mantener el envío real deshabilitado hasta una aprobación adicional.

Rollback: desactivar la bandera, retirar tráfico de la revisión nueva o volver a desplegar el SHA anterior. Conservar `adminOperations`, invitaciones y auditoría para conciliación.

### Fase 4 — Hosting

1. Publicar `/accept-invitation` únicamente después de confirmar que Functions está operativa y segura.
2. Verificar que el landing, catálogo y dashboard existentes permanezcan intactos.
3. Confirmar CSP, `no-store`, `no-referrer`, limpieza del fragmento y ausencia de analítica o recursos nuevos.

Rollback: volver al release anterior de Hosting. No revertir automáticamente Functions, Firestore ni documentos.

### Fase 5 — activación controlada

1. Habilitar Resend primero para un destinatario interno autorizado.
2. Completar una invitación, reenvío idempotente, revocación, expiración, rebote controlado y conciliación.
3. Observar métricas, logs sanitizados, latencia, duplicados y quejas durante la ventana acordada.
4. Autorizar por separado el uso administrativo general.

Rollback inmediato: `RESEND_INVITATIONS_ENABLED=false`, deshabilitar el webhook en Resend y revocar la API key si existe riesgo de compromiso. No eliminar evidencia operativa.

## Verificaciones posteriores a cada despliegue

- Confirmar SHA, revisión activa, cuenta runtime y configuración no secreta.
- Verificar autenticación revocada, usuario común rechazado y Super Admin autorizado.
- Confirmar que no existe registro público general y que los endpoints no exponen claims, tokens, contraseñas ni datos del proveedor.
- Confirmar reglas deny-by-default y que Admin SDK conserva únicamente el acceso esperado.
- Revisar que invitaciones sigan deshabilitadas hasta la Fase 5.
- Confirmar que landing, catálogo, dashboard y aplicaciones independientes responden sin cambios.
- Revisar métricas, errores y auditoría append-only; comprobar ausencia de cuerpos o secretos en logs.

## Condiciones de detención

Detener la activación sin intentar reparaciones automáticas si ocurre cualquiera de estas condiciones:

- diferencia entre el SHA aprobado y el desplegado;
- fallo de build, pruebas, reglas, E2E o preflight;
- permisos IAM faltantes o más amplios que los aprobados;
- secreto ausente, expuesto o accesible fuera de la cuenta runtime;
- `PROTECTED_SUPER_ADMIN_UID` ausente o incorrecto;
- registro público, acceso cliente a colecciones administrativas o protección insuficiente de una cuenta privilegiada;
- envío duplicado, firma inválida aceptada, replay procesado o token/enlace sensible en logs;
- estado `AUTH_STATE_AMBIGUOUS` o `reconciliation_required` sin procedimiento operativo disponible;
- cambio inesperado en landing, catálogo, dashboard, aplicaciones independientes o dominios;
- intento de tratar la visibilidad privada del catálogo como control real de acceso.
