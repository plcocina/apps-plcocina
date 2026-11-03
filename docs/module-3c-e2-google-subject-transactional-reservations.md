# Módulo 3C-E2 — reservas transaccionales de Google Subject

3C-E2 valida la unicidad concurrente de `googleSubject` en Firestore Emulator. No habilita Google OAuth, validación de tokens, `hd`, account linking, perfiles activos, endpoints ni triggers.

## Modelo de unicidad

`IdentityReservationService` normaliza el `sub` con `normalizeGoogleSubject` y calcula un HMAC que identifica el documento `authIdentifierKeys/{identifierHash}`. El valor claro no se persiste. El prefijo de entrada al HMAC incluye el tipo `googleSubject`, por lo que las reservas de email, teléfono y Google permanecen separadas.

La reserva y su operación confirmada se crean dentro de una sola transacción Firestore:

- `authIdentifierKeys/{identifierHash}` contiene tipo, UID propietario, estado `reserved` y operación propietaria.
- `identityOperations/{operationId}` registra el input hash y resultado de la reserva.
- No se escriben perfiles, Access Grants, auditoría, Firebase Auth ni claims.

## Semántica transaccional

1. Si no existen clave ni operación, la transacción crea ambas.
2. Si la misma operación ya existe con el mismo UID, tipo y hash, devuelve replay sin escrituras.
3. Si la clave está `reserved` por el mismo UID con otra operación equivalente, devuelve como replay la operación propietaria existente y no crea otra operación.
4. Si la clave pertenece a otro UID, rechaza `IDENTIFIER_COLLISION` sin escribir la operación perdedora.
5. Si una operación confirmada se reutiliza con otro UID, tipo o identificador, rechaza `IDEMPOTENCY_CONFLICT` sin crear una segunda clave.
6. Una clave `released` conserva la regla existente de poder reservarse nuevamente; 3C-E2 no añade transiciones de liberación o reasignación.

Firestore reintenta la función transaccional cuando cambia un documento leído. Por ello, dos solicitudes concurrentes sobre el mismo hash convergen: una crea la clave; la otra reevalúa contra el propietario confirmado y se convierte en replay del mismo UID o conflicto para otro UID.

## Casos comprobados con Firestore Emulator

- Dos UID concurrentes para el mismo `googleSubject`: exactamente un ganador.
- El perdedor no sobrescribe la clave ni crea operación parcial.
- Dos solicitudes concurrentes equivalentes del mismo UID: ambas convergen a una operación.
- Reintento con misma operación y reintento equivalente con nueva operación: no-op sin cambios de timestamps, revisiones ni auditoría.
- Conflicto secuencial: propietario preservado.
- Reutilización de operación con otro subject: atomicidad, sin segunda clave.
- Subject inválido: rechazo antes de cualquier escritura.
- Reserva Google aislada: no crea usuario, activación, vínculo, grant, claim ni auditoría.
- Reservas SMS y Email Link conservan tipos y hashes independientes.

Las pruebas se ejecutan con Admin SDK apuntando obligatoriamente a `FIRESTORE_EMULATOR_HOST` y project ID `demo-plcocina-apps`. No utilizan mocks para las garantías concurrentes.

## Limitaciones pendientes

- Firestore Emulator demuestra el comportamiento transaccional esperado, pero no sustituye la validación posterior en el proyecto Firebase aislado aprobado.
- No se ha probado todavía OAuth, firma de token, `hd`, account linking, conservación real del UID ni eventos Gen2.
- No existe todavía un flujo operativo que active o vincule el perfil a partir de la reserva.
- Las reglas de cliente permanecen deny-by-default; el servicio usa Admin SDK/IAM y la autorización administrativa será responsabilidad de una fase posterior.

## Reversión

El cambio funcional es acotado: retirar la rama de replay por mismo propietario restaura la semántica anterior de colisión para operaciones distintas. No deben borrarse reservas para revertir código. Las reservas existentes siguen siendo válidas y no contienen datos Google en claro.

Ante una inconsistencia, se debe detener el consumidor futuro, preservar la clave y operación, y llevar el caso a conciliación. 3C-E2 no autoriza liberar, reasignar ni sobrescribir un `googleSubject`.
