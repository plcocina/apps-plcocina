# Módulo 3C-D — arquitectura mixta de identidad

Este documento es diseño, no implementación. No autoriza cambiar código, registrar triggers, habilitar proveedores, crear usuarios ni modificar recursos externos.

## 1. Decisiones aprobadas

- Los métodos asignables por administrador son `googleWorkspace`, `phone` y `emailLink`. `password` queda sólo para compatibilidad v1 y el Super Admin protegido.
- Autenticarse no crea perfil, Access Grants ni autorización. El acceso exige un `users/{uid}` válido, estado habilitado, método asignado, identificador coherente y ausencia de conciliación.
- No hay autorregistro público. `beforeCreate` continúa deny-by-default y `beforeSignIn` fail-closed.
- Un correo `@plcocina.com` no demuestra pertenencia a Workspace. Para Google se exige proveedor `google.com`, token de Google validado, `email_verified=true`, `hd` autorizado y vinculación explícita al UID preprovisionado.
- El UID de PL Cocina es la clave estable de autorización. El `sub` de Google es el identificador inmutable del proveedor; el correo es mutable y no se usa como clave primaria.
- No se añadirán `customClaims` ni `sessionClaims`. Los permisos siguen dependiendo de Access Grants por UID.
- Todo cambio de método es administrativo, auditable, revoca sesiones y conserva UID/Access Grants sólo cuando la identidad nueva queda probada sin ambigüedad.

## 2. Estado comprobado y alcance

La revisión se hizo en `codex/module-3a-access-grants`, commit `deb7e3d526c9e81c4bb7e08de42271ec154f4404`.

- 3C-A define perfiles v2 con `sms|email`, estados `pending`, `auth_enabled_pending_proof`, `active`, `recovery_required` y `reconciliation_required`, revisiones, reservas HMAC e identificadores canónicos.
- 3C-B preprovisiona una cuenta Auth deshabilitada con UID determinista, mantiene checkpoints idempotentes y deriva a conciliación ante resultados ambiguos.
- 3C-C implementa política aislada para `beforeCreate`/`beforeSignIn`, compatibilidad v1, Super Admin protegido, errores genéricos y fallo cerrado. Los handlers no están exportados por `index.ts`.
- Las invitaciones v1 usan email/password y UID determinista. Access Grants están vinculados al UID y no al correo o proveedor.
- Firestore está deny-by-default para clientes; Admin SDK depende de IAM. Emuladores Auth/Functions/Firestore están configurados, pero no reproducen de forma concluyente el despacho real de blocking functions.

## 3. Contrato propuesto de identidad v2.1

El cambio futuro debe ser aditivo y migrable; no se modifica todavía el esquema vigente.

| Campo conceptual | Regla propuesta |
|---|---|
| `authMethod` | `googleWorkspace | phone | emailLink`; `password` sólo en perfil v1/protegido, no asignable a empleados nuevos |
| `uid` | UID Firebase/PL Cocina estable, generado por preprovisión y nunca derivado de correo, teléfono o `sub` |
| `identifier.kind` | `googleSubject | phone | email` |
| `identifier.normalized` | `sub` exacto para Google; E.164 para Phone; NFKC+trim+lowercase para Email Link |
| `firebaseProviderId` | `google.com`, `phone` o `password` (Email Link y password comparten proveedor Firebase, se distinguen por método del evento) |
| `google.subject` | `sub` validado; inmutable, reservado de forma única, nullable fuera de Google |
| `google.hostedDomain` | `hd` validado contra allowlist exacta; nunca inferido del sufijo del correo |
| `google.primaryEmail` | correo verificado observado; mutable, sólo atributo y evidencia |
| `activationStatus` | conservar estados 3C-A; añadir evidencia de prueba sin crear un estado paralelo |
| `verification` | tipo, fecha, revisión de credencial, emisor/audiencia y hash de evidencia sanitizada; nunca almacenar token |
| `credentialRevision` | aumenta ante cambio de método/identificador/proveedor; obliga revocación |
| `authorizationRevision` | cambia sólo por autorización, separado de credenciales |
| `sessionValidAfter` | sello servidor posterior a revocación/cambio; rechaza sesiones anteriores |
| `pendingOperationId` | una sola operación administrativa propietaria; replay con misma clave y mismo input |
| `audit` | actor, motivo, before/after sanitizado, UID, revisión, resultado y correlación; sin PII/token en claro |

Reservas futuras: `authIdentifierKeys` debe admitir `googleSubject`. La reserva de email continúa siendo necesaria para preautorizar y detectar colisiones, pero no sustituye la reserva de `sub`. Hasta conocer el `sub`, la identidad Google queda `pending` o `auth_enabled_pending_proof`; sólo pasa a `active` después de validar y reservar `sub`, vincularlo al UID esperado y confirmar integridad Auth/Firestore.

### Invariantes

1. Un `sub` sólo puede pertenecer a un UID y un UID Google sólo puede tener un `sub` activo.
2. Ninguna coincidencia de correo/teléfono cambia método ni vincula credenciales automáticamente.
3. Un UID en `recovery_required` o `reconciliation_required` no inicia sesión.
4. Un perfil v2 con claim `super_admin=true` es inválido; el Super Admin sigue una rama protegida independiente.
5. Crear o vincular proveedor nunca crea Access Grants.
6. Cambiar método conserva UID sólo tras prueba fuerte del método nuevo; si existe colisión, se bloquea y concilia.

## 4. Matriz de métodos y proveedores

| Método PL Cocina | Proveedor Firebase | Método esperado del evento | Identificador de negocio | Prueba mínima |
|---|---|---|---|---|
| `googleWorkspace` | `google.com` | sufijo de `eventType` y valores reales de `credential` por confirmar en 3C-E | `sub` de Google + `hd` autorizado | ID token firmado, `iss`, `aud`, `exp`, `sub`, `hd`, `email_verified`; UID vinculado |
| `phone` | `phone` | `phone` | teléfono E.164 | SMS exitoso + coincidencia con perfil/reserva |
| `emailLink` | `password` | valor real esperado `emailLink`, por confirmar | correo normalizado | enlace válido de un solo uso + correo verificado/coherente |
| `password` v1 | `password` | `password` | correo normalizado | perfil v1 válido; o UID exacto del Super Admin, correo verificado y claim booleano |

No se debe comparar indistintamente `providerId`, `signInMethod` y `eventType`. La referencia oficial muestra que `eventType` incluye evento y método (por ejemplo `...beforeSignIn:password`); `credential.providerId` representa el proveedor OAuth y `credential.signInMethod` pertenece al tipo Gen2 usado actualmente. Sus valores reales deben capturarse de forma sanitizada en 3C-E.

## 5. Preprovisión y primera vinculación de Google

### Opción A — precrear Auth y vincular después

El Admin SDK crea previamente un usuario deshabilitado con UID determinista y correo no verificado, más perfil/reserva/operación. Ventajas: conserva UID, replica 3C-B, facilita rollback y evita crear permisos durante OAuth. Riesgo crítico: precrear por email no adjunta por sí solo `google.com`; la política de account linking puede producir error, vinculación automática o reemplazo de credenciales según proveedor y configuración. La documentación oficial advierte que proveedores confiables pueden auto-vincular y que un correo no verificado puede ser sobrescrito.

Compatibilidad: `beforeSignIn` vuelve a ejecutarse al vincular un proveedor OAuth; el comportamiento de `beforeCreate` para `Admin SDK createUser` debe verificarse experimentalmente. Para v1, no vincular Google automáticamente. Rollback: deshabilitar cuenta, revocar tokens, retirar proveedor vinculado sólo mediante operación aprobada y restaurar estado previo; nunca cambiar UID.

### Opción B — primer inicio controlado

Se permite que Google llegue a `beforeCreate`, pero sólo si existe una preautorización exacta y de un solo uso. El handler valida token/Workspace y fuerza correspondencia con la operación. Problema: en `beforeCreate` el UID candidato puede no ser el UID preprovisionado; rechazar después no resuelve el enlace al UID deseado. Además, cualquier hueco convierte el flujo en autorregistro. Es útil como experimento para conocer eventos, no como ruta preferida sin una garantía oficial de UID.

### Opción C — broker/control administrativo de credencial

Un componente servidor obtiene/verifica la credencial Google, resuelve la preautorización y completa una vinculación explícita con autenticación reciente o un flujo de recuperación administrado. Puede usar APIs oficiales de Identity Platform/SDK cliente, pero no debe almacenar ID/access/refresh tokens. Ventaja: separación clara de prueba y activación. Costes: mayor complejidad, riesgo de diseñar un broker propio y necesidad de documentar exactamente qué API oficial conserva UID. Custom tokens no sirven como prueba de Google y no disparan blocking functions.

### Recomendación

Usar A como base de preprovisión y un flujo explícito de vinculación controlada inspirado en C. Antes de implementarlo, 3C-E debe determinar con configuración real de “una cuenta por correo” cuál de estas variantes conserva el UID sin auto-vinculación insegura. No aprobar un flujo que dependa sólo del correo. Si no puede demostrarse una vinculación oficial, atómica y recuperable, mantener Google bloqueado y resolver mediante conciliación manual.

## 6. Verificación de Google Workspace

Para la primera vinculación se requiere el ID token OAuth disponible en `event.credential` cuando el reenvío de credenciales esté habilitado. Validar con librería oficial:

- firma contra claves de Google y algoritmo permitido;
- `iss` igual a `accounts.google.com` o `https://accounts.google.com`;
- `aud` dentro de los client IDs aprobados del proyecto aislado;
- `exp`/`iat` y, si aplica, nonce/flujo anti-replay;
- `sub` no vacío y único;
- `email_verified=true` y correo coherente con la preautorización, como atributo mutable;
- `hd` exactamente en la allowlist de Workspace; la ausencia indica que no se probó dominio alojado.

El perfil crudo de `additionalUserInfo` es auxiliar, no sustituto del token firmado. `credential.claims` está documentado para SAML/OIDC genérico y puede estar vacío para Google; no asumir `hd` allí. La tabla oficial indica que Google puede entregar ID token, access token y, bajo condiciones, refresh token; para PL Cocina no se debe solicitar ni persistir refresh token.

`hd` prueba que Google asocia la cuenta a un dominio alojado en ese instante, pero no refleja por sí solo el estado interno autorizado por PL Cocina ni garantiza detección inmediata de suspensión/eliminación. Para suspensión corporativa se requiere combinar: perfil local habilitado, revocación local inmediata y, si se aprueba en el futuro, verificación administrativa con Google Workspace Directory API mediante un componente separado y privilegios mínimos. Esa consulta no debe añadirse al camino crítico de 7 segundos sin caché/timeout/fail-closed diseñados.

Cambios de correo o alias no cambian `sub`. Actualizar correo observado exige operación auditada; si `sub` coincide y `hd` sigue autorizado, puede conservarse UID tras revisión. Si cambia `sub`, falta `hd`, aparece otro UID o hay más de una cuenta candidata: `reconciliation_required`.

## 7. Flujo administrativo

| Operación | Secuencia segura | Revocación/conciliación |
|---|---|---|
| Crear empleado | Admin elige método; normaliza/reserva; crea UID/perfil/Auth deshabilitado; audita | Cuenta queda `pending`; cero grants automáticos |
| Activar | Habilita ventana de prueba; prueba credencial; valida integridad; activa | Revocar al inicio y al cerrar ventana fallida |
| Suspender | Perfil `disabled`, Auth disabled, `sessionValidAfter=now`, revocar refresh tokens | Idempotente; fallo parcial => conciliación |
| Reactivar | Verificar método/identificador y estado externo; habilitar ventana de prueba | No restaurar por coincidencia de correo |
| Cambiar método | Reservar nuevo identificador, subir revisión, revocar, probar, activar y liberar reserva anterior | Conservar UID/grants; colisión/resultado ambiguo => conciliación |
| Reemplazar teléfono | Nueva reserva E.164 + SMS; no liberar anterior antes del commit | Fallo parcial conserva cuenta bloqueada |
| Cambiar correo | Reserva nueva; verificar enlace o Google `sub`; tratar alias/cambio primario explícitamente | Nunca auto-vincular |
| Revocar sesiones | `revokeRefreshTokens` + actualizar `sessionValidAfter` | Confirmar tokens previos rechazados |
| Consultar auditoría | Vista por UID/operación/revisión con datos redactados | Acceso sólo administrativo |

## 8. Ajustes futuros de blocking functions

`beforeCreate` debe seguir rechazando por defecto. Para Google sólo considerará una excepción estrecha si: existe operación preautorizada vigente, UID/credencial pueden vincularse con seguridad, token Google completo se valida y no hay colisión. Si cualquiera falta, rechazo genérico. No se implementa hasta resolver la conservación de UID.

`beforeSignIn` debe:

1. Proteger primero al Super Admin: UID exacto, password, correo verificado y claim booleano.
2. Rechazar claims administrativos en empleados.
3. Leer perfil/operación con deadline interno inferior a siete segundos; error o timeout => fail-closed.
4. Determinar método a partir de campos reales capturados; exigir coherencia entre `eventType`, proveedor y método sin asumir equivalencia.
5. Para Google, verificar token y comparar `sub`/`hd`/correo observado con perfil y reserva.
6. Comprobar estado, `authDisabled`, revisión, ventana de activación y conciliación.
7. No emitir claims; devolver éxito vacío.

## 9. Mapa de cambios futuros

| Archivo | Cambio previsto | Impacto/dependencias |
|---|---|---|
| `functions/src/identities/identity-models.ts` | métodos/`googleSubject`, evidencia y reservas | Alto; migración compatible y todos los parsers |
| `functions/src/identities/identity-contracts.ts` | create/update y reglas por método | Medio; API administrativa futura |
| `functions/src/identities/identity-admin-http-contracts.ts` | request/response Google | Medio; clientes administrativos, sin tocar ahora UI |
| `functions/src/identities/identity-transitions.ts` | validar transiciones de cambio/vinculación | Medio; estados actuales e idempotencia |
| `functions/src/identities/identity-reservation-service.ts` | reserva única de `googleSubject` | Alto; HMAC, concurrencia, migración |
| `functions/src/identities/identity-preprovision-service.ts` | precrear Google, vincular/conciliar, revocar | Alto; Admin Auth, auditoría y rollback |
| `functions/src/identities/identity-blocking-service.ts` | política Workspace y método | Alto; token verifier, Firestore y 7 s |
| `functions/src/identities/identity-blocking-functions.ts` | adaptar campos reales Gen2 y credencial OAuth | Alto; pruebas reales obligatorias |
| `functions/src/models/admin-collections.ts` | operaciones/auditoría v2.1 | Alto; compatibilidad de lectura |
| `functions/src/users/user-control-service.ts` | cambio de método/correo/teléfono y revocación | Alto; Super Admin y conciliación |
| `functions/src/users/user-query-service.ts` | integridad/proveedor sin exponer secretos | Bajo/medio |
| `functions/test/identity-*.test.ts` | contratos, políticas, idempotencia y colisiones | Alto; unitarias/emulador |
| `docs/module-3c-c-identity-blocking.md` | runbook y valores verificados | Bajo, posterior a 3C-E |
| `functions/src/index.ts`, `functions/src/app.ts` | sólo en una fase de registro/endpoints aprobada | Bloqueado en 3C-D; revisión separada |
| `public/**`, `firestore.rules`, Access Grants | ningún cambio requerido por el contrato base | Fuera de alcance salvo decisión posterior explícita |

## 10. Hipótesis pendientes de verificación

- Valores reales de `event.credential.providerId`, `signInMethod`, `eventType`, ID token y `additionalUserInfo` en Google, Phone, Email Link y password con Functions Gen2.
- Si `Admin SDK createUser` omite `beforeCreate` en la configuración real; la documentación revisada no da una garantía inequívoca.
- Comportamiento exacto de account linking para Google Workspace con usuario precreado, correo no verificado/verificado y cada ajuste de “una cuenta por correo”.
- Si el UID precreado se conserva en todas las variantes aceptables y cómo deshacer una vinculación sin perder proveedores v1.
- Latencia de validación de token + Firestore dentro del margen interno p99 menor de 4 s.
- Tiempo/efecto de suspensión o eliminación en Workspace y necesidad real de Directory API.

## 11. Riesgos bloqueantes y decisiones requeridas

1. Aprobar el flujo de vinculación sólo después de demostrar conservación de UID y ausencia de auto-vinculación por correo.
2. Aprobar si `hd` + token válido basta para cada login o si se exige comprobación Directory API con sus costes/IAM/latencia.
3. Elegir configuración de account linking del proyecto aislado y política para cuentas v1 con correo coincidente.
4. Aprobar ID/región/facturación/propietarios del entorno aislado, límite de SMS y dos operadores IAM de recuperación.
5. Definir política de alias y cambio de correo primario manteniendo `sub`.
6. Prohibir producción mientras cualquier hipótesis anterior siga abierta.

## Referencias oficiales

- [Identity Platform: blocking functions](https://cloud.google.com/identity-platform/docs/blocking-functions)
- [Referencia de credenciales en blocking functions](https://cloud.google.com/identity-platform/docs/reference/gcip-cloud-functions)
- [Identity Platform: vinculación de cuentas](https://cloud.google.com/identity-platform/docs/link-accounts)
- [Firebase: usuarios y vinculación automática](https://firebase.google.com/docs/auth/users)
- [Firebase Admin SDK: administrar usuarios](https://firebase.google.com/docs/auth/admin/manage-users)
- [Google OpenID Connect](https://developers.google.com/identity/openid-connect/openid-connect)
