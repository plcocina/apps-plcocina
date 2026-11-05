# Módulo 3C-E5A — arquitectura de integración Firebase Auth y Google Workspace

## 1. Alcance y decisión

Este documento diseña una integración futura. No habilita Google, no modifica Firebase Authentication, no crea usuarios, no vincula proveedores, no emite Custom Tokens y no activa perfiles.

La decisión provisional es una **estrategia híbrida controlada**:

1. El backend conserva la autoridad sobre UID objetivo, prueba Google reciente, nonce, reserva `googleSubject`, autorización administrativa, coordinación e idempotencia.
2. La operación real de proveedor usa, cuando sea viable, `linkWithCredential()` sobre un usuario Firebase ya autenticado y existente, porque el vínculo queda asociado al mismo Firebase UID.
3. El backend confirma después la postcondición mediante `getUser(uid)` y `providerData`, sin confiar en el resultado declarado por el cliente.
4. La activación es una operación administrativa posterior y separada. Ni el vínculo Firestore E4B2 ni el provider linking habilitan acceso.
5. Custom Tokens no son la ruta primaria: autentican un UID, no prueban que `google.com` quedó vinculado, y Firebase documenta que el primer inicio puede crear el registro si no existía.

Esta estrategia aún **no es viable para producción**. En particular, una cuenta Firebase realmente deshabilitada no puede establecer la sesión previa que exige el vínculo de cliente. No se aprueba habilitarla temporalmente hasta demostrar en un proyecto aislado que todos los recursos permanecen fail-closed mientras Firestore sigue bloqueado.

## 2. Cuatro decisiones separadas

| Decisión | Autoridad | Resultado | No concede |
|---|---|---|---|
| A. Vínculo de identidad Firestore | E4B2 | `sub` reservado queda asociado al UID; `linked_pending_activation`; `authDisabled=true` | Provider Firebase, sesión o acceso |
| B. Vínculo de proveedor Firebase | Firebase Auth | `providerData` del mismo UID contiene `google.com` y el provider UID esperado | Estado local activo, grants o rol |
| C. Sesión Firebase | Firebase Auth + backend | ID Token Firebase vigente, UID exacto y no revocado | Perfil válido o acceso a una aplicación |
| D. Autorización efectiva | Perfil local + estado + Access Grants | Acceso a una aplicación concreta | Privilegios globales o `super_admin` |

Completar A no completa B, C ni D. Un Google ID Token nunca sustituye al Firebase ID Token del backend administrativo.

## 3. Comparación de estrategias

| Criterio | A. Provider linking | B. Backend + Custom Token | C. Híbrida recomendada |
|---|---|---|---|
| Conservación de UID | Firebase declara que los proveedores vinculados identifican al mismo Firebase UID | El token lleva el UID elegido, pero puede crear el usuario si no existe | Preflight estricto + vínculo sobre usuario existente + postflight |
| Prerrequisito | Usuario Firebase actualmente autenticado; credencial Google válida | Backend capaz de verificar Google y firmar Custom Tokens; cliente canjea el token | Sesión Firebase reciente del UID, prueba Google reciente y autorización E4B2 |
| Provider `google.com` real | Sí | No; es autenticación delegada, no provider linking | Sí, mediante A bajo coordinación de backend |
| Cuenta deshabilitada | Bloqueo esperado; requiere validación aislada | No debe usarse como bypass del bloqueo | Flujo bloqueado hasta diseñar/validar ventana segura |
| Conflictos | `credential-already-in-use`, provider ya vinculado, email en uso, credencial inválida | Emisión al UID equivocado o creación accidental | Detecta antes; confirma después; nunca fusiona automáticamente |
| Privilegio backend | Moderado; verifica y coordina | Alto: permiso para firmar tokens y endpoint crítico | Mínimo necesario; Custom Tokens fuera de la ruta primaria |
| Recuperación | Reintento condicionado a postcondición real | Revocación y conciliación; no prueba provider | Saga idempotente y conciliación manual fail-closed |
| Estado provisional | Candidato sólo en cuenta existente con sesión reciente | Rechazada como estrategia principal | Seleccionada para pruebas aisladas, no para producción |

Firebase documenta que `linkWithCredential()` vincula una credencial al usuario autenticado y que los proveedores vinculados conservan el mismo UID. También advierte de un problema conocido en algunos proyectos y de conflictos de credenciales; por ello la viabilidad debe probarse con las versiones exactas y configuración elegidas: [Account linking](https://firebase.google.com/docs/auth/web/account-linking), [API JS `linkWithCredential`](https://firebase.google.com/docs/reference/js/auth).

Firebase documenta que `signInWithCustomToken()` autentica el UID incluido y crea un registro si no existía. Esa semántica impide usarlo sin `getUser(uid)` previo y postcondición, y no lo convierte en provider linking: [Custom Tokens](https://firebase.google.com/docs/auth/admin/create-custom-tokens).

## 4. Invariantes absolutas de UID

Antes de cualquier operación real deben cumplirse simultáneamente:

- `getUser(targetUid)` existe; `authUser.uid === targetUid`.
- `users/{targetUid}.uid === targetUid`; no se acepta selección por email.
- el perfil Google v2.1 está `linked` y `activationStatus=linked_pending_activation`;
- `authDisabled=true` local permanece hasta activación administrativa;
- el `sub` procede del verificador E3B con prueba reciente y nonce consumible;
- `authIdentifierKeys/{HMAC(sub)}` pertenece al mismo UID;
- la autorización administrativa liga UID, hash de `sub`, operación y revisión;
- ningún otro `UserRecord.providerData` conocido posee `google.com/sub`;
- el usuario objetivo no es `super_admin`, no está suspendido ni en conciliación;
- correo y provider no presentan conflicto, pero el correo nunca decide el UID.

Después de provider linking se exige:

- `result.user.uid === targetUid` en cliente;
- un Firebase ID Token nuevo cuyo `uid === targetUid`;
- `getUser(targetUid).providerData` contiene exactamente `providerId=google.com` y provider UID coherente con el `sub` verificado;
- no apareció un UID nuevo ni cambió el propietario de la reserva.

Cualquier diferencia produce `reconciliation_required`. Se prohíben merge, import, delete/recreate, cambio de UID o creación silenciosa como recuperación.

## 5. Prueba reciente, nonce, state y CSRF

### Emisión

1. Un backend futuro autentica la sesión Firebase actual, comprueba revocación, UID, estado local y autorización.
2. Genera con CSPRNG un `nonce` OIDC y un `state` independientes, ambos de un solo uso.
3. Sólo persiste hashes con pepper en `identityProviderChallenges/{challengeId}`: UID, operation ID, authorization ID, hash de `sub` esperado si ya existe, hash de nonce, hash de state, sesión/canal, emisión, expiración breve, estado `pending`, intentos y versión.
4. Entrega al cliente el valor opaco necesario para iniciar OAuth; el cliente no elige UID, audiencia, dominio, operación ni autorización.

### Validación y consumo

- `state` se compara con el valor ligado a la misma sesión/navegador para impedir CSRF y correlacionar solicitud/respuesta.
- `nonce` se valida contra el claim firmado del ID Token para impedir replay del token.
- E3B valida firma, `iss`, `aud`, `azp`, tiempos, `sub`, email verificado y `hd`; `hd` se valida como claim, no como autorización.
- El consumo del challenge se realiza en una transacción Firestore junto con la creación de la evidencia verificada/operación de coordinación.
- Dos consumos concurrentes producen un ganador; el segundo recibe `NONCE_REPLAYED`.
- Challenge vencido, revocado, usado o ligado a otra sesión/UID/operación falla sin emitir credencial ni avanzar estado.

Google describe `state` como protección anti-forgery/correlación y `nonce` como protección de replay; `hd` sólo optimiza/restringe la experiencia y debe validarse en el token: [Google OpenID Connect](https://developers.google.com/identity/openid-connect/openid-connect).

Una firma válida no demuestra frescura si el nonce no fue emitido, ligado y consumido por el servidor.

## 6. Estados separados

### Identidad local existente

`declared -> verified -> linked -> linked_pending_activation`; cualquier ambigüedad lleva a `reconciliation_required`.

### Coordinación propuesta

`not_started -> challenge_issued -> google_proof_verified -> provider_link_pending -> provider_link_confirmed -> activation_pending -> active`

Estados de bloqueo: `provider_conflict`, `auth_state_unknown`, `revocation_pending`, `reconciliation_required`, `cancelled`.

| Transición | Precondición | Efecto externo permitido | Acceso |
|---|---|---|---|
| `not_started -> challenge_issued` | E4B2 completo, autorización vigente, UID existente | Ninguno | Denegado |
| `challenge_issued -> google_proof_verified` | state/nonce válidos y consumo único | Ninguno | Denegado |
| `google_proof_verified -> provider_link_pending` | sesión Firebase reciente del mismo UID; cuenta no suspendida | Intentar `linkWithCredential` una vez | Denegado |
| `provider_link_pending -> provider_link_confirmed` | postflight Admin confirma `google.com/sub` en mismo UID | Registrar resultado y auditoría | Denegado |
| `provider_link_confirmed -> activation_pending` | autorización de activación independiente | Preparar saga de activación | Denegado |
| `activation_pending -> active` | Auth y perfil reconciliados, sesiones revocadas, controles aprobados | Habilitación coordinada | Sólo según Access Grants |

`authDisabled` es una bandera local contractual. `UserRecord.disabled` es estado Firebase Auth. No se sincronizan por sí solos y deben registrarse por separado en la operación.

## 7. Coordinación sin transacción distribuida

Firebase Auth y Firestore no comparten una transacción ACID. Se adopta una saga fail-closed con `operationId`, `idempotencyKey`, revisión esperada, leases acotados y postcondiciones observables.

### Provider linking

1. Reservar operación Firestore en `provider_link_pending`; mantener acceso local denegado.
2. Ejecutar una vez la llamada Firebase desde el cliente autenticado.
3. Consultar `getUser(uid)` desde backend y clasificar la realidad:
   - provider correcto en UID correcto: confirmar;
   - provider ausente: reintento seguro si autorización/challenge siguen vigentes;
   - provider en otro UID o resultado ambiguo: conciliación;
   - proveedor correcto pero Firestore no confirmó: reintento sólo de confirmación, no nuevo link.
4. Nunca deshacer mediante `unlink`, borrar usuario o mover proveedor automáticamente.

### Activación

El orden provisional más seguro es mantener el perfil local denegado durante toda la saga, habilitar Firebase sólo cuando exista autorización de activación y finalizar el perfil después de verificar Auth. Si Firebase queda habilitado y Firestore no finaliza, el backend y las reglas deben continuar denegando por estado local; se revocan sesiones y se pasa a conciliación. Esta premisa debe auditarse contra **todos** los recursos Firebase antes de aprobarla.

| Falla parcial | Estado seguro y recuperación |
|---|---|
| Firestore E4B2 vinculado; provider Firebase falla | `linked_pending_activation`, acceso denegado; reintento condicionado o conciliación |
| Provider Firebase confirma; Firestore pendiente | Bloqueo local; postflight idempotente confirma sin volver a vincular |
| Revocación administrativa durante operación | Challenge/autorización revocados; no iniciar nueva llamada; postflight y conciliación si ya ocurrió |
| Autorización caduca tras llamada | No activar; registrar realidad Firebase y conciliar |
| Caída de red/resultado desconocido | Consultar `getUser(uid).providerData`; no repetir a ciegas |
| Conflicto de provider/email | No iniciar sesión con la credencial conflictiva ni fusionar; conciliación manual |
| Revocación de sesiones falla | `revocation_pending`, acceso local denegado; reintento acotado |

## 8. Sesiones, claims y autorización efectiva

Cada solicitud protegida futura debe validar:

1. Firebase ID Token del proyecto, firma, audiencia, expiración y UID.
2. Revocación cuando corresponda mediante `verifyIdToken(idToken, true)`.
3. `UserRecord.disabled === false` y provider esperado cuando la política lo exija.
4. Perfil local existente, UID idéntico, método asignado, no suspendido, no conciliado y activación completa.
5. Access Grant activo para la aplicación concreta.
6. `super_admin` sólo en la cuenta password protegida; Google nunca lo crea ni hereda.

Firebase ID Tokens duran aproximadamente una hora; revocar refresh tokens impide renovaciones, pero los ID Tokens existentes requieren comprobación de revocación o expiran naturalmente: [Manage sessions](https://firebase.google.com/docs/auth/admin/manage-sessions), [Verify ID Tokens](https://firebase.google.com/docs/auth/admin/verify-id-tokens).

No se copian grupos Workspace a custom claims ni Access Grants. No se añaden claims al Custom Token. Suspensión, cambio de método o revocación administrativa exigen: bloqueo local inmediato, deshabilitar Auth cuando corresponda, revocar refresh tokens, verificación con `checkRevoked` y auditoría de cada resultado.

## 9. Niveles de validación

### Nivel A — Emulator local

Auth + Firestore Emulator permite probar estados, idempotencia, Custom Tokens simulados, cuenta deshabilitada y ausencia de permisos. Sus límites son bloqueantes: no reproduce IAM; no valida firma ni expiración de Custom Tokens; no reproduce rate limiting/anti-abuse; acepta credenciales OIDC reales pero eso no valida configuración productiva; y existen diferencias en blocking functions. Fuente: [Authentication Emulator](https://firebase.google.com/docs/emulator-suite/connect_auth).

### Nivel B — proyecto Firebase aislado real

Debe ser un proyecto nuevo y desechable, sin usuarios/datos PL COCINA, con usuarios sintéticos, dominio Workspace de prueba, Client IDs separados, IAM mínimo, budgets/alertas, logs redactados, inventario de servicios/costos, credenciales no reutilizadas y plan de eliminación verificable.

Pruebas mínimas: conservación real del UID, providerData, cuenta disabled, conflictos, sesión reciente, nonce/state, revocación, token confusion, fallos parciales, Custom Token sin creación accidental, eventos reales y rollback manual. No se habilita producción hasta cerrar todas.

## 10. Secuencia E5B+

| Módulo | Límite y entrega | Criterio de aceptación | Reversión |
|---|---|---|---|
| E5B1 | Contratos de coordinación y postcondiciones; sin Auth real | Máquina de estados e idempotencia probadas localmente | Retirar contratos no expuestos |
| E5B2 | Challenge, hash de nonce/state y consumo atómico | Un ganador concurrente; replay/CSRF rechazados | Revocar challenges; preservar auditoría |
| E5C1 | Adaptador Firebase Auth inyectable y Emulator | UID preservado; provider/disabled/conflictos clasificados | Deshabilitar adaptador; no borrar cuentas |
| E5C2 | Saga de provider linking aislada | Fallos parciales convergen a bloqueo o confirmación | Detener orquestador; conciliación manual |
| E5D | Reconciliación y recuperación sin unlink automático | Diagnóstico y reintentos idempotentes | Mantener bloqueo |
| E5E | Activación administrativa independiente | Auth/perfil/sesiones coherentes; grants intactos | Bloqueo local + revocación |
| E5F | Proyecto real aislado | Matriz Nivel B completa y evidencia aprobada | Eliminar proyecto/credenciales de prueba |
| E5G | Preparación de despliegue | IAM, observabilidad, runbook y aprobación | Feature flag cerrada/rollback de revisión |

## 11. Bloqueos de producción

- proveedor Google aún no habilitado ni configurado;
- sesión previa y reautenticación reciente no demostradas para cuentas deshabilitadas;
- problema conocido de account linking no evaluado con versiones exactas;
- nonce/state no persistidos ni consumidos;
- saga Auth/Firestore y postflight no implementados;
- no existe reconciliación operativa ni activación administrativa;
- cobertura integral de reglas/servicios durante una posible ventana Auth habilitada no auditada;
- Custom Token signing/IAM no aprobados y no necesarios en la ruta primaria;
- proyecto aislado real no creado ni probado.

Ninguna de estas capacidades se presenta como existente.
