# Módulo 3C-E4A — modelo de amenazas de conciliación y vinculación

Este documento define amenazas y controles obligatorios para E4B. Los controles no se consideran implementados ni probados por E4A.

## 1. Activos

- UID interno estable y su historial.
- `sub` Google verificado y reserva HMAC `googleSubject`.
- Autorizaciones administrativas, revisiones e idempotency keys.
- Estados `declared`, `verified`, `linked` y `reconciliation_required`.
- Evidencia de verificación, operaciones y auditoría append-only.
- Access Grants, roles, custom claims y sesión protegida del Super Admin.

## 2. Amenazas, controles y riesgos residuales

| Amenaza | Escenario | Impacto | Control obligatorio | Pendiente/bloqueo |
|---|---|---|---|---|
| Apropiación de UID | Atacante usa correo coincidente para vincular su `sub` a un UID con permisos | Toma de cuenta y grants heredados | UID de contexto administrativo + `sub` E3B + reserva del mismo UID + autorización exacta | Account linking real por validar |
| Vinculación por email | Correo, alias, nombre, dominio o teléfono selecciona automáticamente UID | Asociación errónea | Prohibición explícita; correo sólo coherencia/atributo; `sub` es clave | Política de alias pendiente |
| Replay de autorización | Autorización válida se reutiliza para segunda vinculación | Vínculo duplicado o alterado | Estado de un solo uso, expiración, consumo transaccional y binding completo | Duración/almacenamiento por definir |
| Idempotency key maliciosa | Misma clave con UID o `sub` distinto | Confusión de operación | Input hash completo y conflicto fail-closed | Esquema definitivo E4B |
| Carrera de reserva | Dos UID reclaman el mismo `sub` | Dos propietarios | Reserva transaccional E2 y lectura en la transacción de vínculo | Integración Emulator E4B |
| Doble vínculo concurrente | Dos operaciones consumen misma autorización/revisión | Auditoría o estado duplicados | Lectura/consumo atómico, expectedRevision y evento determinista | Pruebas Emulator |
| Revisión obsoleta | Admin autoriza sobre un perfil que cambió | Sobrescritura de estado nuevo | Binding a `expectedRevision`; no merge automático | Ninguno si se aplica atómicamente |
| Operación parcial | Perfil queda linked sin auditoría o autorización consumida | Estado no trazable | Una transacción para perfil, autorización, operación y auditoría | Límites de transacción por validar |
| Transición inválida | `declared` o conciliación pasa a `linked` por atajo | Salto de prueba/control | Máquina de estados cerrada; ninguna reparación implícita | Contratos E4B |
| Perfil suspendido | Se vincula identidad a usuario deshabilitado | Preparación de acceso indebido | Rechazo por estado y revisión; fail-closed | Semántica exacta de suspensión |
| Elevación de privilegios | Vínculo crea grants, claims o `super_admin` | Acceso administrativo | E4B sin dependencias/escrituras de autorización; Super Admin password-only | Regresión obligatoria |
| Reconciliación automática | Conflicto se “resuelve” por correo o último escritor | Apropiación o pérdida de evidencia | `reconciliation_required`; sólo procedimiento manual futuro | Procedimiento aún no diseñado |
| Prueba Google caducada | Token/evidencia antigua se usa después de perder control | Vínculo sin posesión actual | `validUntil`, reloj servidor y autorización no más larga que prueba | Frescura real/nonce bloqueantes |
| Replay de token/nonce | Misma prueba Google alimenta varios intentos | Múltiples vínculos | Binding a operación y consumo nonce futuro | E3B no consume nonce todavía |
| Token confusion | Google ID Token autentica admin o Firebase token prueba `sub` | Cruce de autoridades | Verificadores y contratos separados; tipo único por contexto | Validación aislada posterior |
| Administrador revocado | Autorización emitida se consume después de revocar sesión/rol | Acción ya no autorizada | Revalidar revocación/rol al emitir y, según política, al consumir | Diseño de snapshot/revalidación |
| Cambio de correo | Correo cambia entre verificación y vínculo | Inconsistencia o falsa selección | No cambia `sub`; revisión/coherencia obligatoria; invalidar si política falla | Alias/primary email pendientes |
| Cambio de dominio | Cuenta deja dominio permitido | Vinculación corporativa indebida | `hd` reciente permitido y coherencia; autorización expira | Señal de suspensión Workspace pendiente |
| Auditoría duplicada/borrable | Reintentos crean eventos múltiples o actor altera historial | Trazabilidad falsa | ID determinista, append-only, IAM servidor y replay no-op | Reglas/IAM reales por validar |
| Fuga de identidad | Logs guardan token, `sub`, correo o autorización bearer | Privacidad/replay | Hash/HMAC, redacción y códigos genéricos | Revisión de logging E4B |

## 3. Condiciones fail-closed

La operación se rechaza sin efectos cuando falta o no coincide cualquiera de:

- UID objetivo obtenido del contexto administrativo;
- administrador Firebase vigente y autorizado;
- autorización pendiente ligada a UID, hash de `sub`, revisión y operación;
- resultado E3B íntegro, reciente y coherente;
- reserva `googleSubject` del mismo UID;
- perfil Google v2.1 en estado `verified` y revisión esperada;
- idempotency key/operation ID no conflictivos;
- capacidad de confirmar atómicamente vínculo, consumo, operación y auditoría.

También se rechazan perfiles suspendidos, UID Super Admin, reservas ajenas/ausentes, estado de conciliación, `sub` distinto, dominio no permitido, autorización vencida/revocada y token de tipo incorrecto.

## 4. Escenarios concurrentes

### Dos UID, mismo `sub`

E2 permite una sola reserva. E4B lee esa reserva dentro de la transacción: sólo el UID propietario puede continuar. El perdedor no cambia perfil, autorización, operación ni auditoría.

### Mismo UID, dos operaciones

Ambas leen la misma revisión/autorización. La primera confirmada consume autorización e incrementa revisión. Firestore reintenta la segunda, que observa estado nuevo: sólo un replay con input idéntico obtiene el resultado; cualquier diferencia falla.

### Timeout después del commit

El cliente reintenta con el mismo operation ID/idempotency key. La operación confirmada devuelve resultado almacenado y no repite revisión ni auditoría. No se infiere fallo por ausencia de respuesta.

### Fallo antes del commit

La transacción no publica cambios. La autorización continúa conforme a su estado previo y puede reintentarse si sigue vigente. No se escriben marcadores parciales fuera de transacción para aparentar éxito.

## 5. Separación de autorización

- **Administrador:** Firebase ID Token vigente y Super Admin password-only autoriza el vínculo exacto.
- **Google:** E3B demuestra control reciente del `sub`; no autoriza administración.
- **Aplicación:** Access Grants deciden acceso después de UID/perfil válidos; no cambian con el vínculo.

Mezclar cualquiera de estas capas es una vulnerabilidad de elevación o token confusion.

## 6. Riesgos no resueltos

- E3B compara nonce confiable pero no lo consume atómicamente; replay completo sigue bloqueando activación real.
- No está demostrado el account linking oficial ni la conservación del UID en Firebase Auth real.
- No existe aún contrato operativo aprobado para emitir/revocar autorizaciones ni doble control.
- No se definió desvinculación, reasignación o liberación segura de `sub`.
- Cambios de correo, alias, dominio y suspensión Workspace necesitan política y validación real.
- IAM, auditoría append-only, latencia y recuperación ante eventos Gen2 requieren proyecto aislado.

Mientras estos puntos permanezcan abiertos, E4B debe seguir aislado y no puede activar OAuth, Auth, sesiones o acceso.
