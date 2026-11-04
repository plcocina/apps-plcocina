# Módulo 3C-E4B2 — vinculación transaccional aislada de Google Workspace

## 1. Alcance

E4B2 implementa un servicio interno, sin endpoint ni trigger, que vincula una identidad Google previamente verificada con un UID existente. Reutiliza el contrato Google v2.1 de E1, la reserva HMAC transaccional de E2 y los contratos de autorización de E4B1. No implementa OAuth, Firebase Auth account linking, activación, migración, sesiones, Access Grants ni custom claims.

La implementación no se importa desde `index.ts`, `app.ts` ni los handlers 3C-C. Por tanto, no está disponible en producción y sólo se invoca directamente en pruebas aisladas.

## 2. Servicio y contratos reutilizados

`GoogleIdentityLinkingService` recibe el UID objetivo y el administrador desde contexto interno confiable. El `googleSubject` procede de `VerifiedGoogleIdentityEvidence`, se normaliza y se convierte al mismo HMAC usado por `IdentityReservationService`; nunca se acepta el hash como sustituto de la evidencia verificada.

El servicio reutiliza:

- `googleWorkspaceUserV21DocumentSchema` y su estado exclusivo `linked_pending_activation`;
- `identityLinkAuthorizationSchema` y `linkGoogleIdentityRequestSchema`;
- `identityIdentifierKeyDocumentSchema` y `identifierKeyHash`;
- `auditEventDocumentSchema` para auditoría append-only.

La persistencia mínima de autorizaciones es una capacidad interna. Sólo acepta como `authorizedByUid` el Super Admin protegido configurado. La autenticación, revocación de sesión, doble control y emisión operativa siguen pendientes; no existe endpoint para crearlas o revocarlas.

## 3. Modelo transaccional

La vinculación ejecuta una única transacción Firestore y lee antes de escribir:

1. `users/{uid}`: perfil Google v2.1 existente y verificado.
2. `authIdentifierKeys/{googleSubjectHash}`: reserva E2, `kind=googleSubject`, estado `reserved` y mismo UID.
3. `identityLinkAuthorizations/{authorizationId}`: autorización pendiente, vigente y ligada a UID, hash, operación, idempotencia y revisión.
4. `identityLinkOperations/{idempotencyKey}`: resultado determinista para replay o detección de reutilización conflictiva.

Sólo después de validar todas las precondiciones, la misma transacción:

- conserva el UID y el `subject` verificado;
- cambia `linkingStatus` de `verified` a `linked`;
- establece `activationStatus=linked_pending_activation` y mantiene `status=invited` y `authDisabled=true`;
- incrementa `revision` y `credentialRevision` exactamente una vez;
- consume la autorización;
- crea el resultado idempotente completado;
- crea `auditEvents/google-link-{operationId}` mediante ID determinista.

Las colecciones específicas `identityLinkAuthorizations` e `identityLinkOperations` son necesarias para separar autorizaciones de un solo uso y resultados de vinculación de las operaciones de reserva E2, cuyos documentos tienen otro contrato. Ambas permanecen inaccesibles a clientes bajo las reglas deny-by-default existentes; las reglas no fueron modificadas.

## 4. Autorización, concurrencia e idempotencia

La autorización fija la operación `google.identity_link`, UID, HMAC del subject, revisión, administrador, vigencia, operation ID e idempotency key. Una autorización expirada, revocada, consumida o no coincidente aborta sin escrituras.

La clave de idempotencia identifica el documento de operación. Un replay exactamente equivalente devuelve el resultado previo con `replayed=true`, sin subir revisión, volver a consumir autorización ni crear otra auditoría. La misma clave con parámetros distintos produce `IDEMPOTENCY_CONFLICT`.

Firestore serializa las transacciones concurrentes. Dos solicitudes equivalentes producen un solo commit; dos subjects incompatibles sobre un UID no pueden confirmar la misma revisión; y dos UID no pueden usar la misma reserva `googleSubject`. No se libera, reasigna ni crea una reserva implícitamente.

## 5. Invariantes demostradas

- El UID objetivo existe y se conserva exactamente.
- El subject verificado, el perfil, la reserva y la autorización coinciden.
- Un subject reservado por otro UID aborta sin modificar propietario ni destino.
- Usuarios suspendidos, estados no verificados, conciliaciones y el Super Admin protegido se rechazan.
- La vinculación nunca activa el perfil ni Authentication.
- No se crean usuarios, sesiones, Access Grants, roles ni custom claims.
- SMS y Email Link permanecen fuera del esquema Google y son rechazados por este servicio sin modificación.
- Un fallo en cualquiera de las escrituras finales revierte perfil, autorización, operación y auditoría.

## 6. Pruebas ejecutadas

Con el proyecto local `demo-plcocina-apps` y Firestore Emulator:

- E4B2 transaccional: 22/22 aprobadas.
- Contratos E4B1: 13/13 aprobadas.
- Reservas E2: 11/11 aprobadas.
- Total focalizado: 46/46 aprobadas.
- Build TypeScript estricto con Node 22: aprobado.

Las pruebas verifican documentos persistidos, consumo único, auditoría única, ausencia de efectos parciales, concurrencia equivalente y conflictiva, expiración, revocación, revisión obsoleta, reserva ausente o ajena, suspensión, Super Admin, transiciones inválidas y ausencia de Access Grants/custom claims. No representan validación contra Firebase real.

## 7. Riesgos y dependencias pendientes

Permanecen fuera de E4B2: OAuth, validación operativa de frescura y nonce, account linking oficial, conservación real del UID en Firebase Auth, aliases, sesiones, eventos Gen2, emisión/revocación administrativa desplegada, doble control, activación y validación en un proyecto Firebase aislado real. La unicidad demostrada corresponde al Firestore Emulator y al modelo transaccional actual.

## 8. Rollback

Como el servicio no está expuesto, el rollback de código consiste en retirar el servicio, su suite y esta documentación, además de eliminar su inclusión en la configuración Emulator. No deben borrarse reservas, operaciones, autorizaciones consumidas ni auditorías ya confirmadas; cualquier dato persistido requiere conciliación administrativa futura, no reversión automática.
