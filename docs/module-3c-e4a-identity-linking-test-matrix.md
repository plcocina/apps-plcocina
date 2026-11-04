# Módulo 3C-E4A — matriz futura de pruebas de vinculación

Esta matriz especifica pruebas para 3C-E4B y validaciones posteriores. No registra resultados ejecutados en E4A.

## 1. Niveles

- **Unitaria:** validadores, contratos, decisiones de estado, autorización e idempotencia con dependencias inyectadas.
- **Firestore Emulator:** atomicidad, concurrencia, revisiones, reserva, autorización, operación y auditoría con datos sintéticos.
- **Proyecto Firebase aislado:** OAuth, Firebase Auth/account linking, UID real, sesiones, eventos Gen2 y tokens reales. Fuera de E4B local salvo autorización posterior.

## 2. Contratos, estados y autorización

| ID | Caso | Resultado esperado | Nivel |
|---|---|---|---|
| C-01 | Identidad `declared` con resultado E3B válido y reciente | Pasa a `verified`, conserva UID y no vincula/activa | Unitaria + Emulator |
| C-02 | Intento directo `declared -> linked` sin evidencia separada | Rechazo de transición | Unitaria |
| C-03 | Vínculo autorizado de UID y `sub` coincidentes | `linked`, UID intacto, revisión incrementada una vez | Emulator |
| C-03A | Persistencia posterior al vínculo | `activationStatus=linked_pending_activation`, perfil no activo y Auth deshabilitado | Unitaria + Emulator |
| C-04 | Ausencia de autorización administrativa | Rechazo fail-closed, sin escrituras | Unitaria + Emulator |
| C-05 | Autorización caducada | Rechazo; no renovación automática | Unitaria + Emulator |
| C-06 | Autorización revocada o consumida | Rechazo salvo replay exacto ya confirmado | Emulator |
| C-07 | Autorización ligada a otro UID, `sub`, revisión u operación | Rechazo `AUTHORIZATION_MISMATCH` | Unitaria + Emulator |
| C-08 | Sesión del administrador revocada o sin `super_admin === true` | No emitir autorización | Unitaria; proyecto aislado para sesión real |
| C-09 | Google ID Token usado como credencial administrativa | Rechazo por tipo de token | Unitaria; aislado posterior |
| C-10 | `sub` verificado distinto al autorizado | Rechazo, autorización pendiente/no consumida según política segura | Emulator |
| C-11 | Prueba Google caducada o revisión de verificador incompatible | Rechazo sin vínculo | Unitaria + Emulator |
| C-12 | Estado `reconciliation_required` intenta vincular | Rechazo; requiere intervención manual | Unitaria + Emulator |
| C-13 | Perfil suspendido/deshabilitado | Rechazo sin transición | Unitaria + Emulator |
| C-14 | Intento de vincular el UID protegido `super_admin` | Rechazo explícito | Unitaria + Emulator |

## 3. Reserva, concurrencia e idempotencia

| ID | Caso | Resultado esperado | Nivel |
|---|---|---|---|
| T-01 | Reserva `googleSubject` del mismo UID | Puede vincular sólo si todas las demás evidencias son válidas | Emulator |
| T-02 | Reserva inexistente | `RESERVATION_REQUIRED`; no se crea implícitamente | Emulator |
| T-03 | Reserva del mismo `sub` perteneciente a otro UID | Conflicto; propietario preservado, cero escrituras parciales | Emulator |
| T-04 | Dos UID reclaman concurrentemente el mismo `sub` | Exactamente un propietario de reserva; como máximo un vínculo | Emulator |
| T-05 | Dos vínculos concurrentes sobre misma revisión | Uno confirma; otro falla por revisión/consumo o replay exacto | Emulator |
| T-06 | Reintento exacto de operación confirmada | Mismo resultado, `replayed=true`, sin revisión/auditoría adicional | Unitaria + Emulator |
| T-07 | Idempotency key reutilizada con otro UID/`sub`/autorización | `IDEMPOTENCY_CONFLICT`, estado intacto | Unitaria + Emulator |
| T-08 | Operation ID reutilizado con input distinto | `IDEMPOTENCY_CONFLICT` | Unitaria + Emulator |
| T-09 | `expectedRevision` obsoleta | Rechazo de concurrencia sin consumo parcial | Emulator |
| T-10 | Falla después de lecturas y antes del commit | Ninguna escritura visible | Emulator |
| T-11 | Conflicto transaccional/reintento Firestore | Convergencia al resultado válido, sin doble auditoría | Emulator |
| T-12 | Auditoría determinista ya existente pero operación inconsistente | Rechazo/conciliación; no sobrescritura | Emulator |

## 4. Identidad, compatibilidad y privilegios

| ID | Caso | Resultado esperado | Nivel |
|---|---|---|---|
| I-01 | Comparar UID antes/después del vínculo | Exactamente el mismo UID | Unitaria + Emulator; aislado para Auth real |
| I-02 | Cambio de correo con el mismo `sub` y `hd` permitido | No cambia UID/`sub`; exige política y revisión, no vínculo por correo | Unitaria + Emulator |
| I-03 | Mismo correo con `sub` diferente | Rechazo/conciliación, nunca reasignación | Emulator |
| I-04 | Cambio a dominio no autorizado | Prueba/autorización inválidas; no vínculo | Unitaria |
| I-05 | Vínculo exitoso | Usa sólo `linked_pending_activation`; no cambia a `active` ni habilita Auth | Emulator |
| I-06 | Vínculo exitoso | Access Grants exactamente iguales antes/después | Emulator |
| I-07 | Vínculo exitoso | No crea ni modifica custom claims o roles | Unitaria; aislado posterior para Auth real |
| I-08 | Intento de elevar a `super_admin` en input/evidencia | Campo rechazado; ninguna escritura | Unitaria + Emulator |
| I-09 | Perfiles SMS y Email Link pasan por validadores/servicios existentes | Comportamiento idéntico, servicio E4B los rechaza como método incorrecto | Unitaria |
| I-10 | Password v1 y Super Admin protegido | Compatibilidad y rama password preservadas | Unitaria existente/regresión posterior |
| I-11 | Handlers 3C-C reciben perfil Google aislado | No lo interpretan como Email Link; fail-closed | Unitaria existente/regresión posterior |
| I-12 | Repetición exacta | No duplica evento append-only | Emulator |
| I-13 | Perfil SMS/Email intenta usar `linked_pending_activation` | Rechazo; el estado existe sólo en contrato Google aislado | Unitaria |

## 5. Conciliación, revocación y casos bloqueados

| ID | Caso | Resultado esperado | Nivel |
|---|---|---|---|
| R-01 | Resultado ambiguo tras operación | `reconciliation_required`, correlación preservada, sin activación | Emulator |
| R-02 | Estado de conciliación recibe reintento automático | Rechazo | Unitaria + Emulator |
| R-03 | Autorización revocada antes del consumo | No vincula | Emulator |
| R-04 | Solicitud de desvincular, liberar o reasignar `sub` | Operación no disponible/rechazada en E4B | Unitaria |
| R-05 | Suspensión administrativa posterior a vínculo | Flujo existente bloquea acceso; E4B no cambia grants ni libera `sub` | Regresión; aislado posterior para sesiones |

## 6. Validación posterior en proyecto aislado

Requieren OAuth/Firebase real y no deben simularse como aprobadas localmente:

- account linking conservando el UID precreado;
- prueba Google reciente y consumo real de nonce;
- invalidación por revocación de sesión administrativa;
- efectos de cambio de correo, alias, suspensión o eliminación Workspace;
- ausencia de custom claims y proveedores inesperados después del vínculo real;
- eventos Gen2, latencia, fallos ambiguos y recuperación;
- revocación de sesiones y activación posterior bajo un módulo separado.

## 7. Criterio futuro de aprobación local

E4B sólo estará listo para regresión si todos los casos unitarios y Emulator implementables pasan, las transacciones son atómicas e idempotentes, el UID se conserva, la auditoría no se duplica y no existe integración con endpoints, Auth real, grants, claims o activación. Esa aprobación no autoriza account linking ni producción.
