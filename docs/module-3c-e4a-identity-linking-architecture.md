# Módulo 3C-E4A — arquitectura de conciliación y vinculación de identidad

Este documento especifica 3C-E4B. No implementa account linking, OAuth, endpoints, triggers, usuarios, perfiles, reservas, permisos ni operaciones externas.

## 1. Decisiones cerradas

1. El UID interno preexistente es la identidad estable de PL Cocina y nunca se sustituye, deriva ni reasigna durante una vinculación.
2. El identificador estable de Google es el `sub` verificado por E3B. Correo, dominio, nombre y teléfono son atributos auxiliares y no autorizan vínculos.
3. Un `googleSubject` pertenece como máximo a un UID mediante la reserva transaccional de E2.
4. Un UID no adquiere proveedores o identidades mediante coincidencias implícitas.
5. Vincular exige simultáneamente: prueba Google reciente y confiable, autorización administrativa vigente ligada al UID y `sub`, reserva perteneciente al mismo UID, revisión esperada y estado local compatible.
6. Verificación criptográfica, autorización administrativa, vinculación y autorización de aplicaciones son decisiones distintas.
7. `linked` no significa perfil `active`, sesión habilitada ni acceso efectivo.
8. Ninguna operación de E4B crea o modifica Access Grants, roles, custom claims o `super_admin`.
9. No se diseñan desvinculación, liberación o reasignación de `sub`; cualquier necesidad se bloquea y pasa a decisión futura.
10. Toda evidencia ausente, ambigua, caducada o inconsistente produce rechazo fail-closed o `reconciliation_required`, nunca reparación automática.

## 2. Actores y límites de confianza

| Actor/componente | Autoridad permitida | Autoridad prohibida |
|---|---|---|
| Administrador autenticado | Solicitar una autorización de vínculo para un UID y `sub` concretos | Aportar claims Google, elegir un UID por correo o conceder permisos implícitos |
| Autenticación administrativa existente | Probar Firebase ID Token vigente, revocación, UID administrador y `super_admin === true` | Sustituirse por Google ID Token |
| Verificador E3B | Producir `VerifiedGoogleIdentity` con `sub`, correo, dominio y tiempos verificados | Elegir UID, reservar, vincular o autorizar aplicaciones |
| Servicio de autorización de vínculo | Emitir/validar autorización de un solo uso ligada al contexto exacto | Verificar criptografía Google o crear Access Grants |
| Servicio de conciliación E4B | Aplicar transacción de estado, reserva, operación y auditoría | Activar Auth, crear proveedor real o modificar permisos |
| Capa de autorización | Resolver acceso posterior por UID, perfil y Access Grants | Inferir acceso por token Google, `hd` o vínculo |

Un Google ID Token jamás es credencial administrativa de PL Cocina. La sesión del administrador debe verificarse con el mecanismo Firebase existente, incluyendo revocación y claim booleano protegido. La identidad Google prueba posesión del `sub`; no prueba autoridad para vincularlo.

## 3. Estados y significado

- `declared`: una operación administrativa creó la intención de método Google; `sub` aún es `null`, sin prueba.
- `verified`: E3B verificó recientemente un `sub`; existe evidencia sanitizada, pero no vínculo.
- `linked`: una autorización administrativa válida y una transacción confirmaron la correspondencia entre reserva, `sub` y UID.
- `reconciliation_required`: un conflicto o resultado ambiguo bloquea activación y conserva correlación para revisión manual.

La persistencia futura debe seguir `googleWorkspaceIdentitySchema` y `googleWorkspaceUserV21DocumentSchema`. Estos continúan aislados de `userProfileDocumentSchema` y de 3C-C. E4B no debe incorporar Google al esquema operativo ni cambiar `authMethodSchema`.

### Decisión de representación no activa

El contrato E1 actual permite expresar `linkingStatus: linked`, pero no dispone de un `activationStatus` semánticamente correcto para “vinculada, aún no activa”: `pending` exige `declared`, `auth_enabled_pending_proof` prohíbe `linked`, `active` habilitaría demasiado y `recovery_required` no debe reutilizarse como comodín.

E4B debe añadir exclusivamente al contrato Google v2.1 aislado el estado de activación `linked_pending_activation`. No se añade al `activationStatusSchema` operativo usado por SMS/Email Link ni a `userProfileDocumentSchema`. La transición de vínculo termina en `linkingStatus: linked` + `activationStatus: linked_pending_activation`, con `status` no activo y `authDisabled: true`. Un módulo posterior, con account linking real ya validado, será responsable de cualquier activación. Hasta que esta extensión aislada exista y sea probada, E4B no puede persistir `linked` de forma correcta.

## 4. Tabla de transiciones

| Origen | Evento autorizado | Solicitante | Evidencia y verificaciones | Resultado | Rechazos | Efectos permitidos y auditoría |
|---|---|---|---|---|---|---|
| `declared` | `google.identity_verified` | Orquestador interno dentro de flujo administrativo | Resultado E3B íntegro y reciente; UID objetivo ya seleccionado administrativamente; correo/dominio coherentes; revisión vigente; perfil no suspendido | `verified` | Token inválido/caducado, `sub` ausente, revisión obsoleta, perfil incompatible | Guardar evidencia sanitizada, `sub`, `verifiedAt`, subir revisión; auditoría append-only. No vincular ni activar |
| `verified` | `google.identity_link_authorized` | Administrador `super_admin` autenticado por Firebase | Sesión no revocada; autorización ligada a UID, hash de `sub`, revisión y operación; justificación; expiración corta | Sigue `verified` hasta consumo | Actor no autorizado, sesión caducada/revocada, identidad suspendida, datos distintos | Crear autorización pendiente de un solo uso y auditoría de emisión; ningún cambio de identidad |
| `verified` | `google.identity_linked` | Servicio E4B consumiendo autorización | Prueba E3B vigente; autorización vigente/no usada; reserva `googleSubject` del mismo UID; `expectedRevision`; idempotency key; estado coherente | `linked` | Reserva ausente/ajena, autorización inválida, prueba distinta/caducada, revisión obsoleta, `super_admin`, perfil suspendido | Transacción actualiza vínculo y revisiones, consume autorización, confirma operación y crea una auditoría determinista. No activar, conceder ni llamar Auth |
| `linked` | Repetición exacta de operación confirmada | Servicio E4B | Mismo operation ID, UID, hash de `sub`, autorización e input hash | `linked` sin cambios | Cualquier diferencia | Devuelve resultado previo; no sube revisión ni duplica auditoría |
| Cualquiera excepto conflicto irreversible | `google.identity_reconciliation_required` | Servicio E4B | Resultado ambiguo o inconsistencia comprobada con operation ID | `reconciliation_required` | Solicitud cliente sin evidencia interna | Bloqueo local, correlación y auditoría; nunca reasignar o liberar reserva |
| `reconciliation_required` | Revisión manual futura | Operador autorizado bajo procedimiento aún no diseñado | Evidencia forense, doble control y operación específica futura | Sin transición en E4B | Todo intento automático | Sólo lectura/diagnóstico en E4B; resolución queda bloqueada para fase posterior |

No se permite `declared -> linked` como atajo persistente. Un orquestador podrá encadenar verificación y vinculación, pero cada decisión debe tener evidencia, revisión y operación distinguibles; un fallo entre ellas deja estado seguro, no activo.

## 5. Contratos internos propuestos para E4B

```ts
type VerifiedIdentityEvidence = {
  verificationId: string;
  identity: VerifiedGoogleIdentity; // salida E3B, no payload cliente
  verifiedAt: Date;
  validUntil: Date;
  verifierRevision: string;
};

type IdentityLinkAuthorization = {
  authorizationId: string;
  targetUid: string;
  googleSubjectHash: string;
  expectedRevision: number;
  issuedByUid: string;
  issuedAt: Date;
  expiresAt: Date;
  reason: string;
  state: "pending" | "consumed" | "revoked" | "expired";
  operationId: string;
};

type LinkGoogleIdentityInput = {
  operationId: string;
  idempotencyKey: string;
  targetUid: string;             // contexto servidor autorizado
  expectedRevision: number;
  authorizationId: string;
  verifiedEvidence: VerifiedIdentityEvidence;
};

type LinkGoogleIdentityResult = {
  operationId: string;
  uid: string;
  subjectHash: string;
  previousState: "verified";
  state: "linked";
  revision: number;
  replayed: boolean;
};

interface IdentityLinkAuthorizationVerifier {
  verify(input: {
    authorizationId: string;
    targetUid: string;
    subjectHash: string;
    expectedRevision: number;
    operationId: string;
    now: Date;
  }): Promise<IdentityLinkAuthorization>;
}

interface GoogleIdentityReconciliationService {
  recordVerifiedIdentity(input: RecordVerifiedIdentityInput): Promise<VerifiedIdentityResult>;
  linkVerifiedIdentity(input: LinkGoogleIdentityInput): Promise<LinkGoogleIdentityResult>;
}
```

No se acepta `sub`, correo, dominio, actor, rol, UID objetivo o autorización como campos libres provenientes de un navegador. `targetUid` procede de la operación administrativa autenticada; `sub` procede del objeto E3B en memoria o de evidencia servidor íntegra.

## 6. Autorización administrativa

### Emisión

Sólo el Super Admin protegido actual puede autorizar en la primera implementación. Debe autenticarse con Firebase ID Token del proyecto, verificado con revocación; UID exacto y claim booleano `super_admin` deben satisfacer la política vigente. Google ID Token no puede autenticar esta acción.

La autorización se emite después de conocer el `sub` verificado y se liga criptográficamente o mediante documento servidor protegido a:

- `authorizationId` y `operationId` únicos;
- UID objetivo exacto;
- HMAC del `sub`, nunca correo;
- `expectedRevision` del perfil;
- UID administrador, revisión de su sesión y `auth_time`/momento verificado;
- motivo obligatorio, emisión, expiración corta y estado;
- revisión de credencial/configuración relevante.

No es un bearer token reutilizable por el cliente. El documento queda inaccesible a clientes mediante reglas actuales deny-by-default y sólo se consume en transacción servidor.

### Vigencia e invalidación

La autorización falla si está vencida, revocada, consumida, ligada a otra operación, cambia UID/`sub`/revisión, el administrador pierde privilegio o su sesión fue revocada, cambia el perfil/reserva, o la evidencia Google deja de estar vigente. La duración exacta requiere aprobación en E4B; debe ser breve y nunca superior a la vigencia de la prueba Google.

Un cambio de correo observado no cambia el `sub`, pero exige coherencia con `hd` y política antes de vincular. Un cambio de dominio no autorizado invalida la prueba y autorización. Una suspensión o `reconciliation_required` bloquea consumo.

### Separación de permisos

- Autorización administrativa: permite intentar una única transición de vínculo.
- Prueba Google: demuestra control reciente del `sub` bajo política E3B.
- Access Grant: autoriza una aplicación después de existir un UID válido; no se toca aquí.

## 7. Transacción de vinculación

E4B debe ejecutar una única transacción Firestore que lea antes de escribir:

1. Perfil Google v2.1 del UID objetivo y su revisión.
2. Reserva `authIdentifierKeys/{HMAC(googleSubject)}`.
3. Autorización administrativa.
4. Operación idempotente `identityOperations/{operationId}` o colección específica versionada.
5. Cualquier evidencia de verificación persistida necesaria.

La transacción valida:

- perfil existente, UID idéntico, método `googleWorkspace`, estado `verified`, no activo por inferencia, no suspendido y no `super_admin`;
- revisión igual a `expectedRevision`;
- `sub` del perfil/evidencia y hash de reserva idénticos;
- reserva `reserved` o estado futuro permitido, tipo `googleSubject` y propietaria del mismo UID;
- autorización `pending`, vigente y ligada exactamente a UID/hash/revisión/operación;
- evidencia E3B vigente y no sustituida por claims cliente;
- idempotency key no usada con otro input.

En el commit atómico:

- cambia `linkingStatus` de `verified` a `linked` y fija `linkedAt`;
- establece el estado Google-only `linked_pending_activation`, manteniendo perfil no activo y Auth deshabilitado;
- conserva UID, correo declarado, Access Grants y autorización de aplicaciones;
- incrementa `revision` y `credentialRevision` exactamente una vez;
- consume la autorización;
- confirma la operación con input hash y resultado;
- crea un evento append-only con ID determinista derivado de la operación.

No habilita Firebase Auth, no cambia `status` a `active`, no modifica `activationStatus` a `active`, no emite claims y no revoca/crea sesiones. La activación real y account linking permanecen fuera de E4B.

Si cualquier escritura falla, ninguna se confirma. No se permite actualizar perfil y dejar autorización/auditoría pendientes, ni consumir autorización sin vínculo.

## 8. Idempotencia, concurrencia y conflictos

- El input hash incluye operation ID, idempotency key, UID, hash del `sub`, autorización, revisión y versión del contrato.
- Repetición exacta de una operación confirmada devuelve el resultado almacenado sin escrituras.
- Misma clave u operation ID con cualquier campo diferente produce `IDEMPOTENCY_CONFLICT`.
- Dos UID para el mismo `sub`: la reserva E2 permite un solo propietario; el otro falla sin cambios parciales.
- Dos operaciones para el mismo UID/revisión: la primera confirmada incrementa revisión y consume autorización; la segunda reintenta sobre revisión/estado nuevos y falla o hace replay exacto.
- Reserva del mismo UID: es requisito válido, no autorización suficiente.
- Reserva de otro UID: conflicto bloqueante; no se reasigna ni se libera.
- Reserva inexistente: rechazo `RESERVATION_REQUIRED`; E4B no la crea implícitamente.
- Autorización caducada/revocada: rechazo sin transición ni renovación automática.
- Estado `reconciliation_required`: sólo diagnóstico/manual; ninguna vinculación automática.

## 9. Auditoría

Cada emisión, revocación, consumo, rechazo relevante y conciliación requiere evento append-only con:

- event ID/operation ID, tipo y versión;
- actor UID y mecanismo de autenticación administrativa;
- UID objetivo y hash del `sub`;
- authorization ID, revisión esperada/obtenida y resultado;
- timestamps servidor y motivo redactado;
- before/after sanitizados de estado y revisiones;
- código de rechazo sin token, correo completo, `sub`, nonce o secretos.

El replay exacto no crea un segundo evento. Los intentos fallidos pueden usar telemetría separada si no pueden formar parte de la transacción, sin revelar existencia de cuentas al consumidor.

## 10. Compatibilidad

E4B no modifica SMS, Email Link, password v1, UID, perfiles v2 existentes, Access Grants, revocación de sesiones, Super Admin, handlers 3C-C, reglas Firestore, catálogo ni UI. `googleWorkspace` sigue siendo un contrato aislado y opcional; no se asume que todos los empleados lo poseen.

La extensión `linked_pending_activation` pertenece sólo al esquema Google v2.1 aislado. No cambia transiciones ni parsers operativos de SMS/Email Link y no autoriza incorporar perfiles Google a 3C-C.

## 11. Rollback y decisiones bloqueantes

Rollback de código: retirar servicio, contratos y pruebas E4B. Como no habrá endpoint/trigger, ninguna ruta operativa lo invocará. Una operación ya confirmada no se revierte borrando auditoría o reserva; se bloquea el perfil y se lleva a conciliación.

Bloqueos para activación real:

- flujo OAuth y prueba real de frescura;
- consumo atómico de nonce/replay;
- account linking oficial y conservación real de UID;
- política de autorización, expiración, doble control y revocación;
- esquema definitivo de evidencia/operación/auditoría y migración compatible;
- extensión Google-only `linked_pending_activation` y sus invariantes, sin alterar el esquema operativo;
- comportamiento de aliases, cambios de correo/dominio y suspensión Workspace;
- validación en proyecto aislado de Firebase Auth, eventos Gen2 y sesiones.

E4B sólo puede demostrar transacciones y políticas locales; no debe presentar estos bloqueos como resueltos.
