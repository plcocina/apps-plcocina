# Módulo 3C-E5B2 — persistencia transaccional de coordinación Firebase Auth

## Alcance

E5B2 persiste de forma aislada la máquina de estados definida por E5B1. No ejecuta OAuth, `linkWithCredential()`, Firebase Auth Admin, activación, creación de usuarios, Access Grants, custom claims, endpoints ni triggers.

El servicio interno crea y recupera operaciones, aplica exclusivamente `evaluateAuthCoordinationTransition` y persiste el documento resultante dentro de transacciones Firestore. E5B1 permanece como fuente de verdad de estados, evidencias, orden, revisiones y bloqueos.

## Modelo persistente

- `identityAuthCoordinations/{operationId}`: documento E5B1 completo.
- `identityAuthCoordinationLocks/{kind-hash}`: lock determinístico para UID o hash de `googleSubject`.
- `identityAuthCoordinationIdempotency/{idempotencyKey}`: hash canónico, operación, clase de acción y revisión resultante.
- `auditEvents/auth-coordination-{operationId}-{revision}`: auditoría append-only determinística.

Los identificadores de locks se derivan sin queries. Dos operaciones incompatibles sobre el mismo UID o subject compiten por el mismo documento; la transacción permite un solo ganador. Los locks no se liberan, reasignan ni compensan automáticamente cuando una operación queda bloqueada.

## Transacciones, revisión e idempotencia

La creación lee operación, clave idempotente y ambos locks antes de crear cualquiera de ellos. Un reintento idéntico devuelve replay; reutilizar operation ID o idempotency key con parámetros distintos falla sin escrituras.

Cada transición exige `operationId`, revisión esperada, evento E5B1 confiable y actor interno protegido. La transacción lee el documento, la clave idempotente y ambos locks; luego ejecuta la función pura E5B1. Una transición efectiva incrementa exactamente una revisión, actualiza ambos locks y crea una auditoría. Un replay no modifica revisión, locks ni auditoría.

La clave idempotente conserva el hash de cada transición, incluso después de eventos posteriores. Por ello una reutilización tardía incompatible no puede confundirse con un evento nuevo.

## Fallos parciales y conciliación

Los estados `provider_conflict`, `auth_state_unknown`, `revocation_pending`, `reconciliation_required` y `cancelled` se persisten como bloqueos fail-closed. E5B2 no afirma que Firebase Auth haya sido reparado ni intenta unlink, merge, eliminación, cambio de UID o reasignación de subject.

La creación determinística de auditoría forma parte de la misma transacción. Si colisiona o falla cualquier escritura final, operación, revisión, idempotencia y locks permanecen sin cambios.

## Seguridad y privacidad

- Sólo se persisten hashes de subject y evidencias tipadas E5B1.
- No se almacenan ID Tokens, access tokens, refresh tokens, credenciales, nonce o state en claro.
- UID Firebase e interno permanecen idénticos.
- `linked_pending_activation` y `localAuthDisabled=true` permanecen invariantes.
- El Super Admin protegido queda fuera del flujo Google.
- No se crean perfiles activos, grants, claims, sesiones o privilegios.

## Pruebas focales

Las pruebas con Firestore Emulator cubren creación y recuperación, concurrencia equivalente, conflictos por UID y subject, reuse de operation/idempotency, transición válida, replay concurrente, transiciones incompatibles concurrentes, revisión obsoleta, estado externo desconocido, conservación de locks, rollback ante colisión de auditoría, ausencia de efectos de autorización y protección del Super Admin.

## Límites pendientes

E5B2 no implementa challenge persistente, consumo de nonce/state, adaptador Firebase Auth, provider linking real, postflight real, reconciliación operativa ni activación. Tampoco demuestra semántica Gen2 o comportamiento en un proyecto Firebase real; esas validaciones permanecen para módulos posteriores y no se presentan como garantías actuales.

## Reversión

Mientras no exista exposición operativa, la reversión consiste en retirar el servicio, su prueba Emulator, esta documentación y la entrada focalizada del manifiesto de Vitest. Los datos de auditoría y operaciones de entornos de prueba se preservan; no se liberan locks automáticamente.
