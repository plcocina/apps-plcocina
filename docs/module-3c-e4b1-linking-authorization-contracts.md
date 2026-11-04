# Módulo 3C-E4B1 — contratos de autorización y vinculación

3C-E4B1 implementa exclusivamente contratos y evaluación pura. No crea, consume o revoca autorizaciones persistentes; no escribe perfiles, reservas, operaciones o auditoría; no integra OAuth, Firebase Auth, endpoints, triggers ni account linking.

## Estado Google-only

`googleWorkspaceActivationStatusSchema` añade `linked_pending_activation` sólo al documento Google Workspace v2.1. `activationStatusSchema`, `userV2DocumentSchema` y `userProfileDocumentSchema` no cambian, por lo que SMS, Email Link y handlers 3C-C no reconocen el estado nuevo.

Un documento válido en este estado exige:

- UID existente conservado;
- `linkingStatus: linked` y `verificationStatus: verified`;
- `sub`, `verifiedAt`, `linkedAt` y sello de correo presentes;
- `status: invited` y `authDisabled: true`;
- ninguna transición implícita a `active`.

Los estados Google `linked` sólo son válidos con `active` o `linked_pending_activation`; no se reutiliza `recovery_required` como estado intermedio.

## Contratos añadidos

`identityLinkAuthorizationSchema` representa una autorización interna con:

- UUID de autorización, operación e idempotencia;
- operación literal `google.identity_link`;
- UID objetivo y UID administrador canónicos;
- hash HMAC `googleSubject` de 64 caracteres hexadecimales;
- `expectedRevision` no negativa;
- emisión, expiración, razón, estado y versión.

La vigencia máxima contractual es 15 minutos. El esquema distingue `pending`, `consumed`, `revoked` y `expired`; sólo `pending` carece de `stateChangedAt`. La evaluación recibe un `Timestamp` confiable proporcionado por el servicio, no por el cliente.

`linkGoogleIdentityRequestSchema` liga exactamente la solicitud a autorización, operación, idempotency key, UID, hash, revisión y `linked_pending_activation`. Es strict y no acepta `active`, `super_admin`, UID alternativo ni campos desconocidos.

## Evaluación pura

`evaluateIdentityLinkAuthorization` rechaza estados caducado, revocado o consumido y también una autorización pendiente cuyo `expiresAt` ya se alcanzó.

`evaluateGoogleIdentityLink` no realiza I/O. Evalúa:

- destino distinto al UID protegido Super Admin;
- UID y revisión del perfil;
- estado Google `verified`, no activo y deshabilitado;
- coincidencia del hash verificado, autorización y solicitud;
- vigencia y estado de autorización;
- idempotencia de una operación completada;
- propietario de reserva suministrado por una futura dependencia transaccional.

El resultado puro puede ser:

- `link`: propone `linked` + `linked_pending_activation`, `authDisabled: true` y revisión siguiente;
- `replay`: devuelve la revisión confirmada sin cambios;
- `reconciliation_required`: reserva ausente o perteneciente a otro UID.

No muta el objeto de perfil ni afirma que una transacción o auditoría fueron persistidas.

## Separación de validaciones

Los esquemas validan forma, límites, coherencia temporal y binding de valores. Quedan para E4B2, dentro de una transacción Firestore:

- existencia y revisión real del perfil;
- propiedad real de la reserva;
- autorización almacenada y consumo atómico;
- operación/idempotency key persistidas;
- sesión Firebase del administrador, revocación y claim protegido;
- auditoría append-only y ausencia de escrituras parciales.

No se simulan estas garantías mediante validación local.

## Pruebas focalizadas

`identity-linking-contracts.test.ts` cubre estado Google vinculado no activo, evidencia y `sub`, `authDisabled`, contratos SMS/Email, autorización válida/caducada/revocada/consumida, revisión, UID, hash, idempotencia, activación prohibida, Super Admin, campos desconocidos, replay y conciliación por reserva.

Resultados focalizados de E4B1:

- pruebas nuevas y compatibilidad directa E1: 23/23 aprobadas;
- build TypeScript estricto de Functions: aprobado;
- `git diff --check`: aprobado;
- manifiesto Functions: únicamente `adminApi`.

No se ejecutó regresión integral.

## Compatibilidad

- E1 conserva documentos declarados y activos existentes.
- E2 conserva reservas y su HMAC sin cambios.
- E3B conserva su salida verificada y no se conecta automáticamente.
- SMS, Email Link, password v1, Super Admin, 3C-C, Access Grants, reglas, UI y Hosting no se modifican.

## Dependencias pendientes para E4B2

- repositorio transaccional de perfil/reserva/autorización/operación/auditoría;
- emisión y revalidación administrativa real;
- consumo de autorización e idempotencia persistentes;
- evidencia E3B vigente ligada a operación;
- pruebas de concurrencia con Firestore Emulator;
- account linking, UID real, nonce y OAuth continúan bloqueados para fases posteriores.

## Rollback

Retirar el módulo de contratos, su prueba y la extensión Google-only restaura E4B1. No existe dato persistido que migrar o revertir y no se deben limpiar reservas E2.
