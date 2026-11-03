# Módulo 3C-D — matriz de pruebas reales para 3C-E

Todos los sujetos, teléfonos, correos, UIDs y documentos serán sintéticos. Cada ejecución debe registrar: SHA, project ID/number, región, versión de Function, configuración de trigger, hora UTC, correlación sanitizada, latencia, resultado Auth, estado Firestore y operador. Nunca incluir tokens, enlaces completos, correo o teléfono en claro.

## Criterios transversales

- Cada blocking function debe completar en menos de 7 segundos; objetivo interno p95 ≤ 2 s y p99 ≤ 4 s. Un solo timeout de 7 s bloquea avance hasta identificar la causa.
- Los rechazos deben usar un error genérico indistinguible para usuario inexistente, suspendido, método incorrecto o identificador inconsistente.
- Después de cada prueba: confirmar que no aparecieron cuentas huérfanas, claims nuevos, Access Grants, perfiles automáticos o PII en logs.
- `beforeCreate` y `beforeSignIn` se evalúan por separado y juntos; al crear desde cliente se espera que se ejecuten ambos en el orden documentado.

## Matriz

| ID | Escenario y precondiciones | Procedimiento | Resultado esperado | Evidencia requerida | Aprobación |
|---|---|---|---|---|---|
| C01 | Admin SDK con UID explícito; reserva y operación válidas | Preprovisionar SMS y Email Link con SDK servidor | Confirmar experimentalmente si Admin SDK omite `beforeCreate`; mismo UID en Auth/Firestore, cuenta deshabilitada | Eventos de trigger, Auth sanitizado, documentos y auditoría | Pasa sólo si no nace otro UID y el comportamiento coincide en 3 intentos |
| C02 | Cliente web aislado, correo no autorizado | Intentar crear email/password y Email Link sin preprovisión | `beforeCreate` rechaza; ninguna cuenta ni perfil | Error genérico, búsqueda Auth y Firestore vacía | Cero cuentas huérfanas |
| C03 | Cliente Phone, número mexicano ficticio no reservado | Solicitar/confirmar código | País o formato no concede acceso; creación rechazada | Eventos y ausencia de Auth/profile | Cero excepción por teléfono |
| C04 | Dominio de correo aparente de PL Cocina, sin reserva | Intentar autorregistro | Dominio no concede acceso | Error genérico y ausencia de registros | Cero excepción por dominio |
| C05 | Auth sintético existente sin `users/{uid}` | Iniciar sesión por su método | Rechazo fail-closed | `beforeSignIn`, lectura `not found`, sin token | Ningún ID token emitido |
| C06 | Perfil v2 SMS activo, teléfono reservado/verificado | Iniciar con Phone | Acceso permitido; UID estable, sin claims de handler | `signInMethod`, UID, perfil y token decodificado sanitizado | `phone`, UID idéntico, sin claims nuevos |
| C07 | Perfil v2 Email activo, correo verificado | Iniciar con Email Link HTTPS | Acceso permitido y `emailVerified` real documentado | Contexto, Auth antes/después y token sanitizado | Método/estado coinciden; no contraseña creada |
| C08 | Perfil v1 activo/aceptado | Iniciar con email/password | Compatibilidad preservada | Contexto real y acceso posterior | Método `password`, sin cambio de perfil |
| C09 | Perfil SMS; intentar Email Link, y viceversa | Autenticar con método no asignado | Rechazo genérico | Método real y resultado | Cero token/sesión |
| C10 | Perfil y Auth con identificadores distintos | Iniciar con credencial válida de Auth | Rechazo genérico | Hashes/últimos dígitos sólo en evidencia protegida | Sin filtrar cuál dato difiere |
| C11 | Perfil/registro suspendido | Intentar iniciar sesión | Rechazo | Auth disabled, perfil y error | Sin sesión nueva |
| C12 | `adminOperations` en `reconciliation_required` | Intentar iniciar sesión | Rechazo fail-closed | Operación y consulta Firestore | Sin token hasta conciliación |
| C13 | Cuenta Auth deshabilitada y perfil válido | Intentar ambos métodos | Auth rechaza; handler no debe conceder acceso | Resultado Auth y, si existe, evento | Sin sesión |
| C14 | `auth_enabled_pending_proof`; `sessionValidAfter` actual | Probar en minuto 0, 14:59 y 15:01 | Permitir dentro; rechazar fuera | Timestamps servidor y latencia | Frontera reproducible sin reloj cliente |
| C15 | Email Link nuevo | Capturar `credential.signInMethod`, providerId y `emailVerified` | Documentar valores reales sin asumir `emailLink` | Evento sanitizado y comparación SDK | Código actual coincide o se detiene 3C-E |
| C16 | Phone nuevo y v1 password | Capturar métodos reales | Documentar `phone` y `password` efectivos | Eventos sanitizados | Coinciden con allowlist del código |
| A01 | Super Admin sintético exacto, correo verificado, claim verdadero | Iniciar email/password | Acceso permitido y middleware administrativo válido | UID, método, claim y health admin | Únicamente UID protegido |
| A02 | UID protegido con password incorrecto, email no verificado o claim ausente | Probar cada variante | Rechazo sin degradar política | Tres resultados y logs genéricos | 3/3 rechazados |
| A03 | Empleado v2 con `super_admin=true` | Iniciar con método correcto e invocar API admin | Blocking function rechaza; middleware también rechaza si se alcanza | Auth y respuesta API | Ningún acceso administrativo |
| A04 | Empleado suspendido con token previo | Suspender, revocar tokens, intentar API y refresh | Token previo revocado y nuevo sign-in rechazado | `auth_time`, revocación y 401/403 | Sin sesión válida residual |
| A05 | Sesión de Super Admin activa; vía IAM independiente preparada | Desregistrar/re-registrar trigger en ventana | Acceso Firebase y recuperación IAM demostrados | Capturas de configuración y auditoría | Dos operadores pueden recuperar |
| R01 | Firestore inaccesible para runtime | Retirar temporalmente permiso en entorno aislado o usar fault injection aprobado | `beforeSignIn` rechaza en menos de 7 s | Error genérico, latencia y logs | Sin token; rollback restaura acceso |
| R02 | Firestore responde error transitorio | Inyectar UNAVAILABLE/DEADLINE_EXCEEDED | Rechazo; cliente puede reintentar sin duplicar estado | Dos intentos correlacionados | Cero writes/claims/grants |
| R03 | Lectura lenta | Añadir latencia controlada de 1, 4, 6.5 y >7 s | Medir margen; >7 s falla por plataforma | Histograma p50/p95/p99 | p99 normal <4 s; no continuar si se acerca a 7 s |
| R04 | Reintento idéntico después de error ambiguo | Repetir creación/preprovisión con misma idempotency key | Mismo UID y una sola reserva/cuenta | Operaciones, Auth y hashes | Cero UID adicional |
| R05 | Handler lanza error interno inesperado | Fault injection antes/después de lectura | Cliente recibe error genérico sin PII | Respuesta y búsqueda de logs | Cero correo/teléfono/token en salida |
| R06 | Handlers exitosos | Decodificar token y leer Auth tras login | No se emiten `customClaims` ni `sessionClaims`; claims previos no se elevan | Diff de claims antes/después | Diff vacío salvo claims estándar |
| R07 | 100 inicios sintéticos dentro de cuota | Ejecutar carga baja controlada | Sin carreras; medir invocaciones y coste | Métricas, errores, coste estimado | 100 % decisión correcta; sin abuso de SMS |
| R08 | `beforeCreate` y `beforeSignIn` registrados | Crear cliente autorizado/no autorizado | Confirmar orden y que rechazo temprano no deja usuario | IDs de evento correlacionados | Orden documentado y cero huérfanos |

## Google Workspace

| ID | Escenario y precondiciones | Resultado esperado | Evidencia requerida | Criterio de aprobación |
|---|---|---|---|---|
| G01 | Empleado preautorizado, UID precreado, Google Workspace válido | `sub`, `hd`, audiencia, emisor, expiración y correo verificado pasan; se conserva UID y activa sólo después de la prueba | Auth antes/después, claims del ID token redactados, reserva de `sub`, eventos y auditoría | Un UID, un `sub`, cero grants/claims nuevos |
| G02 | Cuenta corporativa real no registrada en PL Cocina | Rechazo genérico en `beforeCreate`; sin perfil ni cuenta persistida | Evento, búsqueda Auth/Firestore y conteos | Cero autorregistro y cero rastro salvo auditoría sanitizada |
| G03 | Cuenta Google personal | Rechazo porque falta `hd`, aunque el correo sea verificado | Verificación de token redactada y ausencia de cuenta | 100 % rechazada en popup y redirect |
| G04 | Cuenta de otro Workspace | Rechazo por `hd` fuera de allowlist | `hd` redactado/clasificado y evento | Sin sesión ni perfil |
| G05 | Correo termina en `@plcocina.com`, pero token no prueba Workspace | Rechazo; el sufijo nunca sustituye `hd` | Token de laboratorio/fault injection y decisión | Sin bypass por dominio aparente |
| G06 | Perfil local o cuenta Workspace suspendida | Perfil local suspendido siempre rechaza; suspensión Workspace debe producir el resultado definido por la comprobación aprobada | Estado local, estado Directory si se usa, revocación y token | Sin sesión nueva; sesiones previas revocadas |
| G07 | Mismo `sub`, correo primario modificado | Bloquear hasta operación administrativa o aceptar sólo según política aprobada; UID no cambia | `sub` antes/después, correo observado, revisión y auditoría | Ningún segundo UID; cambio explícito y trazable |
| G08 | Alias corporativo del mismo usuario | No crear identidad por alias; resolver por `sub` y política de correo | Token, `sub`, correo primario/alias y reserva | Un UID; resultado coincide con política aprobada |
| G09 | Vinculación a UID preexistente | Proveedor Google queda en el UID preprovisionado | `providerData`, UID antes/después, eventos y configuración de linking | UID idéntico en tres repeticiones |
| G10 | Correo coincide con UID A pero `sub` está reservado por UID B | Rechazo y `reconciliation_required`; no auto-vincular ni sobrescribir | Dos reservas, Auth antes/después y operación | Cero mutación irreversible y cero token |
| G11 | Cambio `phone`/`emailLink` a Google | UID/Access Grants se conservan; sesiones revocadas; método anterior queda según política explícita | grants antes/después, revisiones, proveedores y revocación | Diff de grants vacío, revisión incrementada, un método activo |
| G12 | Revocación de sesiones Google | Refresh previo deja de renovar; inicio nuevo revalida método/estado/Workspace | `tokensValidAfterTime`, `auth_time`, rechazo/aceptación | Cero sesión residual fuera de ventana documentada |
| G13 | ID token con firma, `aud`, `iss` o `exp` inválido | Rechazo antes de reservar o activar | Resultado del verificador por variante, sin token en logs | 4/4 variantes rechazadas |
| G14 | Valores reales del evento Google Gen2 | Capturar `providerId`, `signInMethod`, sufijo `eventType`, presencia de ID token y `additionalUserInfo` sin asumir equivalencia | Esquema sanitizado de `beforeCreate`, `beforeSignIn` y linking | Allowlist futura basada en observación reproducida |
| G15 | Cuenta precreada con correo no verificado/verificado bajo cada ajuste de account linking | Determinar error, auto-vinculación, sobrescritura y UID final; cualquier pérdida de UID bloquea diseño | Config exacta, Auth antes/después, proveedor y eventos | Se aprueba una sola variante segura o se declara bloqueante |

## SMS

| ID | Escenario | Resultado esperado | Evidencia requerida | Criterio de aprobación |
|---|---|---|---|---|
| S01 | Teléfono reservado, cuenta habilitada y código correcto | Inicio permitido en mismo UID | Evento, UID, perfil y reserva | Método real `phone`, sin claims/grants nuevos |
| S02 | Teléfono no registrado y código correcto/ficticio | `beforeCreate` rechaza y no persiste cuenta | Auth/Firestore antes/después | Cero cuenta huérfana |
| S03 | Código inválido o vencido | Auth rechaza antes de autorización | Código de error sanitizado y ausencia de evento/token | Cero sesión y cero cambio de estado |
| S04 | Cuenta suspendida | Rechazo; refresh previo revocado | estado Auth/perfil, revocación y evento | Sin sesión residual |
| S05 | Cambio de teléfono | Nuevo E.164 se prueba y reserva; UID/grants permanecen; anterior se libera al final | reservas, revisiones, Auth y grants | Sin ventana con dos números activos ni pérdida de UID |
| S06 | Reintentos de SMS y operación | Límites/cooldown; misma idempotency key no duplica UID/reserva | conteos, costes, operación y errores | Dentro del límite aprobado y un solo resultado |

## Email Link

| ID | Escenario | Resultado esperado | Evidencia requerida | Criterio de aprobación |
|---|---|---|---|---|
| E01 | Correo autorizado y enlace válido | Inicio permitido en UID reservado; método observado documentado | evento, UID, verificación y enlace redactado | Un uso, un UID, sin password creado |
| E02 | Enlace vencido | Auth rechaza sin cambiar perfil | error, timestamps y estado | Cero sesión/mutación |
| E03 | Enlace reutilizado | Segundo uso rechazado | dos resultados correlacionados | Exactamente un éxito |
| E04 | Correo introducido no coincide con el enlace/perfil | Rechazo genérico | valores hash/redactados y evento | Sin revelar cuál correo existe |
| E05 | Cambio de correo | Nueva reserva/enlace; UID/grants conservados; anterior se libera al commit | reservas, revisión, Auth y grants | Un correo activo, un UID |
| E06 | Correo no autorizado solicita enlace | Respuesta anti-enumeración y ningún usuario/perfil | respuesta cliente y búsquedas | Sin filtración ni creación |

## Compatibilidad, rollback y criterios de plataforma

| ID | Escenario | Resultado esperado | Evidencia requerida | Criterio de aprobación |
|---|---|---|---|---|
| K01 | Invitación v1 completa | Email/password sigue funcionando sin conversión automática | invitación, UID, perfil v1 y evento | Comportamiento previo intacto |
| K02 | Admin SDK `createUser` con triggers registrados | Determinar empíricamente si dispara `beforeCreate`/`beforeSignIn` | invocaciones por event ID y Auth | Resultado repetido y documentado; no se infiere |
| K03 | Rollback de revisión | Desregistrar trigger, comprobar auth base y restaurar revisión conocida | config antes/después, login sintético y logs | Recuperación en ventana aprobada, sin trigger huérfano |
| K04 | Operación ambigua repetida | Misma clave converge; clave distinta no secuestra reserva | operaciones, reserva y cuenta | Un UID/una reserva; ambigüedad bloqueada |
| K05 | Duplicidad de UID/proveedor | Bloqueo y conciliación, sin borrar cuentas | Auth/proveedores, operaciones y auditoría | Cero merge/borrado automático |

## Evidencia de cierre de 3C-E

El paquete de evidencia debe incluir resultados de cada ID, matriz firmada por dos revisores, configuración antes/después de triggers, listado de exports desplegados, IAM efectivo, presupuesto/alertas, métricas de latencia, conteo Auth/Firestore y revisión de logs. Debe excluir PII, secretos, tokens, códigos SMS, enlaces Email Link y credenciales.

## Condiciones de detención

Detener inmediatamente si Admin SDK dispara inesperadamente `beforeCreate` sin un flujo seguro, un método real no coincide con la allowlist, `emailVerified` difiere del supuesto, p99 supera 4 s, un timeout alcanza 7 s, nace una cuenta huérfana, aparece un claim administrativo, se filtra un identificador, falla la vía IAM de recuperación o cualquier solicitud apunta a `plcocina-apps`.
