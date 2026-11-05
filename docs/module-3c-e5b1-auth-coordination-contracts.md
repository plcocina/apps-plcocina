# Módulo 3C-E5B1 — contratos de coordinación Firebase Auth/Firestore

## 1. Alcance implementado

E5B1 incorpora únicamente contratos estrictos y una máquina de estados pura para coordinar una futura vinculación de proveedor Google. No persiste operaciones, no accede a Firebase Auth o Firestore, no ejecuta OAuth, no consume nonce, no vincula proveedores y no activa usuarios.

Los estados de coordinación no sustituyen los estados del perfil Google v2.1. En particular, `linked_pending_activation` continúa siendo el estado local E4B2 del perfil; no es un estado de coordinación. Todos los documentos E5B1 mantienen `localActivationStatus=linked_pending_activation` y `localAuthDisabled=true`.

## 2. Contratos incorporados

`identity-auth-coordination-contracts.ts` define:

- `authCoordinationDocumentSchema`: operación, UID Firebase e interno, hash de `googleSubject`, estado, revisiones, idempotencia, autorización, challenge, evidencias, expiración y conflicto.
- Evidencia tipificada de autorización validada, vínculo Firestore E4B2, challenge, verificación Google, sesión Firebase, observación de provider y postflight.
- `authCoordinationEventSchema`: eventos estrictos y discriminados.
- `createTrustedAuthCoordinationEvent()`: frontera en memoria que marca eventos producidos por componentes confiables; un objeto cliente que sólo imita la forma del evento es rechazado por la máquina.

Los esquemas usan `.strict()` y no admiten tokens Google/Firebase, credenciales OAuth, secretos o campos desconocidos. Las evidencias contienen referencias UUID, hashes, resultados mínimos, fuente tipificada y timestamps.

La marca de confianza es una protección de composición interna para E5B1, no autenticación persistente. E5B2 deberá construir eventos exclusivamente después de validar y consumir evidencia en backend.

## 3. Estados de coordinación

Estados de progreso documentados por E5A:

- `not_started`
- `challenge_issued`
- `google_proof_verified`
- `provider_link_pending`
- `provider_link_confirmed`
- `activation_pending`

`active` existe en el vocabulario futuro de E5A, pero `authCoordinationDocumentSchema` y la transición `activation_completed` lo rechazan en E5B1 porque la activación está fuera de alcance.

Estados bloqueados:

- `provider_conflict`
- `auth_state_unknown`
- `revocation_pending`
- `reconciliation_required`
- `cancelled`

Las situaciones ejemplificadas como `authorization_validated` y `firestore_linked` se representan mediante evidencias obligatorias. La observación Firebase y el postflight también son evidencias; sólo cuando ambas coinciden se alcanza `provider_link_confirmed`.

## 4. Tabla de transiciones

| Evento | Origen | Destino | Evidencia requerida |
|---|---|---|---|
| `challenge_issued` | `not_started` | `challenge_issued` | Challenge servidor vigente |
| `google_proof_verified` | `challenge_issued` | `google_proof_verified` | Challenge vigente; verificación E3B; nonce verificado; hash de subject coincidente |
| `provider_link_requested` | `google_proof_verified` | `provider_link_pending` | Prueba Google vigente y sesión Firebase verificada del mismo UID |
| `postflight_verified` | `provider_link_pending` | `provider_link_confirmed` | Observación `google.com` y postflight Admin con UID/hash coincidentes |
| `activation_prepared` | `provider_link_confirmed` | `activation_pending` | Sólo prepara una fase futura; conserva bloqueo local |
| `activation_completed` | cualquiera | rechazo | `ACTIVATION_OUT_OF_SCOPE` |

Eventos de fallo:

| Evento | Estado bloqueado | Motivo |
|---|---|---|
| `authorization_revoked` | `cancelled` | `AUTHORIZATION_REVOKED` |
| `user_suspended` | `revocation_pending` | `USER_SUSPENDED` |
| `challenge_expired` | `cancelled` | `CHALLENGE_EXPIRED` |
| `provider_credential_conflict` | `provider_conflict` | `PROVIDER_CREDENTIAL_IN_USE` |
| `provider_result_unknown` | `auth_state_unknown` | `PROVIDER_RESULT_UNKNOWN` |
| `firestore_inconsistent` | `reconciliation_required` | `FIRESTORE_INCONSISTENT` |
| `postflight_failed` | `reconciliation_required` | `POSTFLIGHT_FAILED` |

No hay transición normal desde estados bloqueados. E5B1 no implementa unlink, merge, eliminación, reasignación ni compensación destructiva.

## 5. Invariantes

- UID Firebase esperado y UID interno esperado son idénticos.
- Toda evidencia Firebase pertenece a ese mismo UID.
- Hash de verificación Google, provider y postflight coincide con `googleSubjectHash`.
- Revisión actual, revisión esperada y revisión E4B2 coinciden.
- Autorización y operación continúan vigentes.
- Challenge y evidencia Google no están vencidos.
- El Super Admin protegido nunca entra al flujo Google.
- Firestore E4B2 permanece en `linked_pending_activation` con `authDisabled=true`.
- No se omiten challenge, prueba Google, sesión Firebase, provider observation o postflight.
- Ninguna transición concede Access Grants, claims, roles, sesión o activación.

## 6. Revisiones e idempotencia

Cada evento incluye revisión de coordinación y perfil. Una transición nueva válida incrementa únicamente la revisión del documento resultante en memoria.

El hash canónico del evento incluye parámetros y evidencias. Si el último evento tiene la misma idempotency key y hash, la evaluación devuelve `replay` con el documento intacto. La misma clave con cualquier diferencia produce `IDEMPOTENCY_CONFLICT`. Una revisión obsoleta produce `REVISION_CONFLICT`; un evento fuera de orden produce `EVENT_OUT_OF_ORDER`.

Esta semántica es pura. La unicidad concurrente y persistencia transaccional de idempotencia quedan para E5B2 o un módulo posterior.

## 7. Fallos parciales

- Firestore vinculado pero provider pendiente: `provider_link_pending`, acceso local bloqueado.
- Provider observado con Firestore inconsistente: `reconciliation_required`.
- Resultado Firebase desconocido tras interrupción: `auth_state_unknown`.
- Credencial Google en otro UID: `provider_conflict`.
- Suspensión durante el proceso: `revocation_pending`.
- Autorización revocada o challenge vencido: `cancelled`.
- Postflight incorrecto: `reconciliation_required`.

Los estados describen la inconsistencia; no afirman haber reparado sistemas externos.

## 8. Compatibilidad

E5B1 no modifica los contratos Google E1, reservas E2, verificador E3B, contratos E4B1, servicio E4B2, `userProfileDocumentSchema`, perfiles v2, SMS, Email Link, password v1, Access Grants, auditoría, handlers 3C-C, endpoints, triggers, UI, Hosting o Firestore Rules.

La prueba de compatibilidad reutiliza el request E4B1 y confirma que la evidencia E4B2 conserva `linked_pending_activation` y `authDisabled=true`.

## 9. Validación ejecutada

- Suite focalizada E5B1: 23/23 aprobadas.
- Contratos E4B1 directamente relacionados: 13/13 aprobadas.
- Total focalizado/relacionado: 36/36 aprobadas.
- Build TypeScript estricto con Node 22: aprobado.
- Firestore/Auth Emulator: no ejecutado; las funciones son puras y no lo requieren.

Las pruebas cubren contrato inicial, UID/hash/estado inválidos, orden y saltos, replay, conflicto idempotente, revisión, revocación, expiración, estados parciales, provider conflict, postflight, conciliación, activación prohibida, Super Admin, compatibilidad y ausencia de mutación.

## 10. Dependencias pendientes

- E5B2: almacenamiento, hashing y consumo atómico de challenge/nonce/state.
- Persistencia transaccional de operaciones, revisión e idempotencia.
- Adaptador Firebase Auth aislado, provider linking y postflight real.
- Reconciliación operativa de estados parciales.
- Activación administrativa independiente.
- Proyecto Firebase real aislado y validación de UID/provider/session.

Ninguna dependencia pendiente se presenta como implementada.

## 11. Reversión

Al no existir persistencia ni exposición operativa, el rollback consiste en retirar los dos módulos de contratos/transiciones, la prueba focalizada y este documento. No requiere migrar datos ni revertir Firebase. No deben modificarse o eliminarse contratos E1–E4B2.
