# Módulo 2 — Administración de usuarios

## Etapa A: consulta administrativa

La Etapa A es exclusivamente de lectura. `adminApi` combina Firebase Authentication con los perfiles `users/{uid}` sin crear, corregir ni eliminar registros.

### IAM efectivo verificado

Verificación manual de sólo lectura realizada el 22 de octubre de 2026 en Google Cloud IAM para `portal-admin-api@plcocina-apps.iam.gserviceaccount.com`:

- Rol personalizado `projects/plcocina-apps/roles/portalAdminAuthReader`, con exactamente `firebaseauth.users.get`.
- Rol predefinido `roles/datastore.user`.

Estos permisos cubren `getUser`, `getUserByEmail`, `getUsers`, `listUsers` y las lecturas Firestore de esta etapa. No se requiere ningún permiso IAM adicional. La cuenta runtime no tiene mediante estos roles permisos `firebaseauth.users.create`, `firebaseauth.users.update`, `firebaseauth.users.delete` ni `firebaseauth.users.sendEmail`.

### Endpoints

- `GET /api/admin/users?pageSize=50&pageToken=...`
- `GET /api/admin/users?email=usuario@plcocina.com`
- `GET /api/admin/users/:uid`

Todos exigen un Firebase ID token, verificación de revocación y el Custom Claim booleano `super_admin === true`. El correo es una búsqueda exacta normalizada; no existe búsqueda parcial ni descarga completa para buscar texto.

La paginación usa un cursor opaco que coordina una página de Authentication y una página de perfiles. Los perfiles de esa página se contrastan mediante `getUsers`; sólo los que no existen en Authentication se agregan como huérfanos. El servicio no repara inconsistencias.

Los estados de integridad son:

- `linked`
- `missing_profile`
- `orphan_profile`
- `profile_mismatch`
- `invalid_profile`

La respuesta expone únicamente UID, correo, nombre, verificación de correo, estado disabled, fechas Auth autorizadas, indicador protegido, estado de integridad y una proyección limitada del perfil. No expone Custom Claims, proveedores, hashes, salts, tokens ni campos de auditoría del perfil. `isProtected` es verdadero para cualquier cuenta cuyo claim `super_admin` sea exactamente el booleano `true`.

## Etapa B: `adminOperations`

La Etapa B usa esta colección para coordinar operaciones entre Authentication y Firestore:

```text
adminOperations/{operationId}
  operationId: UUID del Idempotency-Key
  type: operación administrativa permitida
  targetUid: UID o null
  actorUid: UID Super Admin
  inputHash: SHA-256 de la entrada canónica, sin secretos
  status: pending | auth_applied | completed | reconciliation_required
  requestId / leaseOwner: UUID de transporte
  expectedRevision: revisión del perfil solicitada
  attempts: entero positivo
  createdAt / updatedAt / completedAt
  failureCode: código controlado o null
  version: 1
```

Reglas previstas:

1. El mismo `operationId` con el mismo `inputHash` devuelve o continúa el resultado existente.
2. La misma clave con otra entrada devuelve conflicto.
3. Antes de mutar Authentication se registra `pending` en una transacción Firestore.
4. Después de mutar Auth se registra `auth_applied`.
5. Perfil y auditoría se finalizan transaccionalmente como `completed`.
6. Una operación que quede entre sistemas se marca `reconciliation_required`; conserva la reserva del perfil y sólo la misma clave idempotente puede recuperarla.
7. Los eventos de auditoría no contienen contraseñas, tokens, códigos OOB ni enlaces de correo.
8. `users/{uid}.pendingOperationId` serializa mutaciones sobre una misma cuenta; no se modifica durante consultas.
9. Las cuentas sin perfil o con perfil inválido/inconsistente se rechazan y no se reparan automáticamente.

Etapa B requiere el permiso runtime `firebaseauth.users.update`, actualmente ausente. No se aplicó ningún cambio IAM.

## Preparación: invitaciones sin proveedor externo

Firebase Authentication diferencia dos operaciones:

- `generatePasswordResetLink`: genera y devuelve al backend un enlace OOB; no envía el correo. Para entregarlo se necesita un proveedor de correo propio.
- `sendPasswordResetEmail` / Identity Toolkit `GetOobCode` sin retorno de enlace: Firebase genera y envía el correo mediante su plantilla configurada. Esta es la alternativa a investigar para evitar proveedor externo y requiere `firebaseauth.users.sendEmail`.

La opción Firebase-managed reduce secretos e infraestructura, pero tiene personalización y observabilidad de entrega más limitadas. Antes de Etapa B debe probarse en un proyecto/emulador controlado qué plantilla, remitente, dominio autorizado, `continueUrl` y handler se usarán. La Etapa A no solicita `firebaseauth.users.sendEmail` y no envía correos.

## Protección de Super Admin

Las mutaciones bloquean cualquier objetivo cuyo `customClaims.super_admin === true`, la propia cuenta del actor y `PROTECTED_SUPER_ADMIN_UID`. La UI futura podrá ocultar acciones, pero el control autoritativo permanece en el backend después de volver a consultar el usuario de Authentication.

## Etapas C1/C2: invitaciones y provisionamiento

`POST /api/admin/invitations` exige Super Admin, token no revocado e `Idempotency-Key` UUID. Admite nombre, correo válido de cualquier dominio y vigencia entre 1 y 168 horas; usa 72 horas por omisión.

La clave idempotente también identifica la invitación. El UID provisional se deriva determinísticamente de ella, lo que permite recuperar una creación exitosa de Authentication aunque falle la escritura posterior. La cuenta se crea sin contraseña, deshabilitada, con correo no verificado y sin claims administrativos. El perfil queda `invited` y no se crea ningún `accessGrant`.

El token se deriva con HMAC-SHA-256 usando una clave versionada de al menos 256 bits, el ID, la generación y una sal aleatoria. Firestore conserva exclusivamente SHA-256 del token, sal, versión, generación y vigencia. Mantener versiones anteriores en el keyring permite reconstruir reintentos; retirarlas invalida las invitaciones que dependan de ellas.

`invitationUniqueKeys/{sha256(normalizedEmail)}` reserva el correo transaccionalmente. `adminOperations` registra los checkpoints `reserved`, `auth_created`, `profile_created`, `email_requested`, `email_accepted`, `password_applied` y `completed`.

El proveedor `SimulatedInvitationEmailProvider` sólo existe para pruebas y conserva idempotencia en memoria. El runtime usa un proveedor deshabilitado y responde 503 antes de crear datos mientras no se aprueben C3 y sus secretos.

## Etapa C3: ciclo de invitaciones

`POST /api/admin/invitations/:invitationId/resend` exige `expectedRevision` e `Idempotency-Key` UUID. La reserva transaccional incrementa la generación y crea una sal nueva antes de entregar: el hash anterior deja de coincidir de inmediato y sólo puede existir una generación activa. Se admiten reenvíos explícitos desde `active`, `pending_delivery`, `expired` o `reconciliation_required`; no desde invitaciones aceptadas, revocadas o durante aceptación.

`POST /api/admin/invitations/:invitationId/revoke` exige motivo, revisión e idempotencia. La transacción cambia primero a `revoked` y elimina el token; después deshabilita la cuenta provisional y revoca refresh tokens. Si Authentication falla, la invitación permanece revocada y sin token mientras `adminOperations` queda en `reconciliation_required`. La misma clave retoma los efectos pendientes. La propia cuenta, el UID protegido y cualquier cuenta con `super_admin === true` se rechazan antes de modificar Firestore.

La expiración efectiva se calcula con el reloj del servidor: al alcanzar `expiresAt` se considera vencida aunque el documento siga diciendo `active`. `InvitationService.reconcileExpired()` materializa posteriormente `expired`, elimina el token, deshabilita la cuenta provisional, revoca sesiones, actualiza el perfil y registra auditoría. No hay todavía scheduler ni cambios de infraestructura.

El proveedor simulado reproduce aceptación, rechazo, timeout, fallo de red y respuesta perdida. Los reintentos de la misma operación reutilizan la clave de entrega por generación. Una respuesta perdida se recupera sin una segunda entrega. `firstAttemptAt` y `retryUntil` limitan la recuperación automática a 23 horas; después se libera la operación pendiente y se requiere un reenvío explícito con una nueva clave administrativa, que vuelve a rotar el token.

Firestore y auditoría conservan únicamente hash, sal, generación, versión de clave y códigos controlados. El token claro vive sólo en memoria durante la llamada al proveedor simulado y nunca se incluye en errores, operaciones o eventos.

## Etapa C4: aceptación y contraseña

`POST /api/invitations/validate` valida ID y token sin consumirlo. La respuesta sólo confirma vigencia y fecha de expiración; invitaciones inexistentes, inválidas, vencidas, revocadas o de generaciones anteriores comparten el código genérico `INVITATION_INVALID`. La comparación del hash usa tiempo constante.

`POST /api/invitations/establish-password` aplica la política de 12–128 caracteres sin normalizar la contraseña. Una transacción vuelve a validar el token, cambia la invitación a `accepting`, elimina el token y reserva `consumeOperationId` antes de llamar a Authentication. La contraseña sólo se entrega a `updateUser` en memoria. Authentication habilita temporalmente la cuenta para permitir la confirmación, mientras `users/{uid}` continúa `invited` y no existe ningún `accessGrant`.

Tras el efecto Auth se registra `password_applied` y la invitación pasa a `password_set` con una ventana de confirmación de diez minutos. Si la llamada Auth o una escritura posterior produce un resultado incierto, el backend intenta deshabilitar la cuenta y revocar sesiones, conserva el token consumido y deja la invitación en `reconciliation_required`. Nunca repite automáticamente `updateUser(password)`. La recuperación segura consiste en comprobar que la cuenta está deshabilitada y ejecutar un reenvío administrativo explícito, que rota token y generación. Si la compensación también falla (`AUTH_STATE_AMBIGUOUS`), primero debe deshabilitarse y revocarse la cuenta mediante un procedimiento administrativo.

`POST /api/invitations/:invitationId/confirm` exige un ID token no revocado. UID y correo deben coincidir con Authentication y la invitación; las cuentas protegidas o administrativas se rechazan. La transacción cambia invitación a `accepted` y perfil a `active`, conserva la ausencia de privilegios y registra auditoría append-only.

Los intentos de validación y contraseña se limitan mediante contadores Firestore transaccionales por invitación y un hash efímero del origen. Los documentos sólo contienen hashes, ventana, contador y expiración prevista; los clientes no pueden acceder a `invitationRateLimits`. Antes de producción debe habilitarse una política TTL sobre `expiresAt` mediante el proceso de infraestructura aprobado; TTL sólo limpia datos y no es un control de seguridad.

## Etapa C5: página de aceptación

`/accept-invitation` implementa los tres pasos de verificación, contraseña y confirmación con la UI APPS PL COCINA. Un script bloqueante, servido desde el mismo origen antes de CSS, fuentes o Firebase, lee `invitationId` y `token` del fragmento y ejecuta inmediatamente `history.replaceState`. Después entrega ambos valores al módulo principal mediante un cierre en memoria.

El token no entra al DOM, URL de API, almacenamiento web, cookies ni registros. La contraseña se limpia de ambos campos después de cada intento. Firebase Authentication se inicializa exclusivamente con `inMemoryPersistence`; cualquier sesión presente en esa instancia se cierra antes de autenticar y la sesión usada para confirmar se cierra al terminar o fallar.

El usuario escribe el correo que recibió la invitación porque el backend no lo revela. Si Authentication falla después de establecer la contraseña, el formulario permite corregir correo y volver a introducir la misma contraseña sin reenviar la operación de establecimiento. Una pérdida de red durante el establecimiento se trata como resultado incierto y no ofrece repetición automática.

Hosting aplica `Cache-Control: no-store, max-age=0` y `Referrer-Policy: no-referrer` a la ruta. La CSP existente permite únicamente los módulos Firebase oficiales ya autorizados y las conexiones explícitas a Firebase y `adminApi`; la página no incluye analítica, píxeles ni scripts adicionales.
