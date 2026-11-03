# Módulo 3C-E1 — contratos de identidad v2.1 para Google Workspace

3C-E1 amplía únicamente modelos, contratos, validadores y pruebas internas. No habilita OAuth, account linking, Identity Platform, proveedores, endpoints, triggers ni escrituras en Firebase/Google Cloud.

## Alcance implementado

- `authMethodV21Schema` representa `sms`, `email` y `googleWorkspace`. El `authMethodSchema` operativo permanece en `sms|email` para no alterar 3C-B/3C-C.
- `googleWorkspaceUserV21DocumentSchema` representa un perfil Google aislado con UID permanente, correo normalizado, dominio autorizado, `sub` nullable, revisiones, operación pendiente y estados separados de vinculación/verificación.
- `userV21DocumentSchema` permite validar perfiles v2 actuales y el nuevo perfil Google. No se añadió a `userProfileDocumentSchema`, por lo que los handlers actuales no pueden tratar Google como Email Link por accidente.
- `identityIdentifierKindSchema` incorpora `googleSubject`. `IdentityReservationService` normaliza y reserva su hash HMAC con la transacción e idempotencia ya existentes.
- Los contratos internos de creación aceptan una declaración Google con correo y dominio, pero no aceptan `sub`: éste sólo puede aparecer como resultado de una verificación futura.
- El contrato HTTP de preprovisión no cambió; no existe todavía una ruta capaz de crear una identidad Google.

## Estados diferenciados

| Estado de vínculo | Estado de verificación | `sub` | Significado |
|---|---|---|---|
| `declared` | `unverified` | `null` | Admin declaró correo y dominio; no hay prueba Google |
| `verified` | `verified` | requerido | Token/proveedor fue verificado, pero el UID todavía no está vinculado |
| `linked` | `verified` | requerido | La credencial verificada quedó asociada al UID esperado |
| `reconciliation_required` | `reconciliation_required` | opcional | Resultado ambiguo; operación conservada y acceso bloqueado |

Una identidad `pending` debe estar declarada, invitada y con Auth deshabilitado. Una identidad `active` exige estado `linked`, verificación, `sub`, sellos de verificación/vinculación, correo verificado, perfil activo y Auth habilitado. El sufijo del correo nunca cambia `verificationStatus`.

## Normalización e invariantes

- Correo: NFKC, trim y lowercase mediante `normalizeIdentityEmail`.
- Dominio: NFKC, trim, lowercase y sintaxis DNS mediante `normalizeWorkspaceDomain`; no incluye `@`.
- Google `sub`: NFKC y trim, conservando mayúsculas/minúsculas; se valida como identificador opaco y no se deriva del correo.
- UID: campo explícito e inmutable en el contrato; los contratos de actualización son strict y no aceptan `uid`.
- No se aceptan teléfono, campos desconocidos ni `super_admin` en un perfil Google.
- Revisiones de credencial, autorización, documento y verificación deben ser enteros positivos.
- Una conciliación exige coherencia entre perfil y bloque Google y conserva un `operationId`.
- No se crean Access Grants ni custom/session claims; ningún archivo de esos subsistemas fue modificado.

## Unicidad de `sub`

La validación local sólo comprueba forma y coherencia dentro de un documento. La unicidad entre UID se representa con una reserva `googleSubject` cuyo ID es HMAC del `sub`. La implementación existente de reservas usa una transacción Firestore y rechaza una clave no liberada; las pruebas focales con almacenamiento falso cubren colisión e idempotencia.

Esto no se presenta como garantía global todavía: debe validarse con concurrencia real en Firestore Emulator y después en el proyecto aislado 3C-E, incluyendo reglas IAM, reintentos y fallos ambiguos. No se realizó ninguna escritura externa en 3C-E1.

## Compatibilidad

- Los perfiles v2 SMS/Email Link continúan usando el esquema operativo sin campos nuevos obligatorios.
- Los perfiles v1 password y la protección del Super Admin no cambiaron.
- Las transiciones de activación actuales no cambiaron.
- `identity-admin-http-contracts.ts`, preprovisión, blocking services/functions, `index.ts`, `app.ts`, UI, Access Grants y Firestore Rules no fueron modificados.

## Pruebas focales

Las pruebas cubren declaración pendiente sin `sub`, activación sólo verificada/vinculada, correo/dominio/identificadores inconsistentes, campos administrativos prohibidos, conciliación, revisiones, normalización, combinaciones de método inválidas, UID no actualizable, compatibilidad SMS/Email Link/password v1, reserva HMAC, replay idempotente y colisión del mismo `sub` entre UID.

## Riesgos pendientes

- Verificación criptográfica del ID token, `hd`, `iss`, `aud`, `exp` y `email_verified`.
- Account linking y conservación real del UID.
- Valores reales de eventos/credenciales Gen2 y comportamiento de Admin SDK.
- Política de alias y cambio de correo principal.
- Concurrencia/rollback de reservas en Firestore real.
- Integración futura con blocking functions sin superar siete segundos.

Estos puntos requieren fases posteriores y el entorno aislado aprobado; no son hechos comprobados por las validaciones locales de 3C-E1.
