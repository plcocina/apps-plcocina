# Módulo 3C-E3A — modelo de amenazas para Google ID Tokens

Este modelo identifica amenazas y controles de diseño para una implementación futura. Los controles no se consideran implementados ni probados en 3C-E3A.

## 1. Activos y límites

Activos protegidos:

- UID estable de PL Cocina y su vínculo con `googleSubject`.
- Reserva única de `googleSubject` y operaciones idempotentes.
- Estado de identidad (`declared`, `verified`, `linked`, `reconciliation_required`).
- Perfiles, Access Grants, rol `super_admin` y sesiones.
- Client IDs, allowlists, claves públicas, nonce y configuración.
- Tokens y datos personales en tránsito, memoria y logs.

Límites de confianza:

- Navegador/cliente: no confiable; tokens y campos separados son entrada hostil.
- Google OIDC: autoridad criptográfica sólo después de validar firma, emisor, audiencia y política.
- Verificador: transforma un token no confiable en claims mínimos verificados; no autoriza.
- Conciliación: relaciona claims con reservas/UID; no concede permisos.
- Autorización: usa estado local y Access Grants; no confía en correo o dominio como rol.

## 2. Amenazas y mitigaciones requeridas

| Amenaza | Escenario | Impacto | Mitigación de diseño | Riesgo/validación pendiente |
|---|---|---|---|---|
| Suplantación | Token falso, firma inválida o clave controlada por atacante | Apropiación de identidad | Algoritmos cerrados, claves oficiales por HTTPS, firma obligatoria, `kid` y emisor exactos | Selección de biblioteca y pruebas de rotación |
| Claims manipulados | Cliente modifica `sub`, `email`, `hd` o `email_verified` | Identidad o dominio falsos | Ignorar campos del cliente; usar sólo payload firmado tras todas las políticas | Pruebas negativas E3B |
| Replay | Reutilización de token/nonce válido | Repetición de una vinculación o sesión | Token de vida corta, operación idempotente y nonce servidor de un solo uso cuando aplique | Flujo OAuth/nonce aún no elegido |
| Token confusion | Google ID Token usado donde se espera Firebase, o token para otro Client ID | Acceso en consumidor equivocado | Verificadores separados, audiencia/emisor exactos y un tipo de credencial por endpoint | Validación aislada posterior |
| Apropiación de UID | Coincidencia de correo vincula `sub` atacante a UID existente | Toma de cuenta y grants heredados | `sub` + reserva única + operación explícita; prohibir vínculo/reasignación por correo | Account linking y UID real pendientes |
| Carrera de reserva | Dos UID reclaman el mismo `sub` | Doble propietario | Transacción de 3C-E2, exactamente un ganador, perdedor sin efectos | Ya cubierto localmente por E2; integrar sin debilitarlo |
| Cambio de correo | Correo primario/alias cambia o se reutiliza | Vínculo erróneo o bloqueo | `sub` como clave; correo sólo atributo observado; conciliación auditada | Política de alias pendiente |
| Dominio no autorizado | `hd` ausente, engañoso o no permitido; sufijo de correo simulado | Acceso corporativo indebido | `hd` firmado, normalizado, igualdad exacta con allowlist y coherencia de correo | Alcance real de `hd` y señal de suspensión pendientes |
| Elevación de privilegios | Token incluye roles o correo privilegiado | `super_admin`, grants o claims indebidos | Ignorar roles externos; autorización local por UID/grants; Google nunca crea `super_admin` | Pruebas de autorización futuras |
| Activación automática | Token válido convierte reserva pendiente en perfil activo | Autorregistro o salto de aprobación | Verificación sólo produce `verified`; vinculación y activación son operaciones separadas | Diseñar workflow futuro |
| Configuración ausente/permisiva | Allowlist vacía interpretada como “permitir todo” | Aceptación global | Fallo de arranque/verificación, configuración tipada y no vacía | Gestión segura de configuración pendiente |
| Audiencia/presentador incorrectos | `aud` o `azp` de otro cliente autorizado por Google | Token legítimo en contexto incorrecto | Listas explícitas y coherencia `aud`/`azp`; sin comodines | Inventario de Client IDs pendiente |
| Claves obsoletas o envenenadas | Caché eterna, JWKS malformado o URL manipulada | Aceptar firma retirada/atacante | Endpoint fijo de biblioteca, TTL acotado, validación de conjunto, refresco único | Parámetros de caché pendientes |
| Indisponibilidad de claves | Google no responde durante verificación | Denegación o bypass tentador | Caché válida acotada; sin clave válida, fail-closed; reintentos limitados | Objetivos de disponibilidad pendientes |
| Reloj manipulado | `exp`/`iat` eludidos por desvío o tolerancia grande | Tokens vencidos o futuros aceptados | Reloj confiable inyectable, tolerancia mínima con máximo fijo | Fijar tolerancia E3B |
| Fuga de secretos/PII | Token, nonce, correo o `sub` aparece en logs | Reutilización, privacidad, enumeración | Redacción estructural; nunca registrar token/payload/nonce/PII completa | Auditoría de logging E3B |
| Enumeración | Errores revelan reserva, UID o cuenta | Reconocimiento para ataques | Mensaje externo genérico; códigos detallados sólo internos y redactados | Diseñar contrato externo futuro |
| Confused deputy | Verificador accede a Firestore o ejecuta vínculo | Efectos con autoridad excesiva | Componente puro respecto a negocio; dependencias mínimas y sin Admin SDK/Firestore | Revisar imports y permisos E3B |
| Reintento no idempotente | Timeout repite conciliación y crea estados parciales | Vínculos/grants inconsistentes | Operación/revisión, transacciones y no-op; nunca escribir desde verificador | Servicio de conciliación futuro |

## 3. Abusos que deben fallar cerrados

- Token sin firma válida aunque el correo termine en un dominio permitido.
- Token válido de Google emitido para un Client ID no autorizado.
- `hd` aportado como parámetro del cliente o inferido sólo del correo.
- Correo verificado con `sub` ausente o inconsistente.
- Token válido sin reserva, con reserva de otro UID o con perfil en conciliación.
- Identidad sólo `declared` o `verified` tratada como `linked`/`active`.
- Token Google usado como credencial del backend administrativo actual.
- Identidad Google usada para crear Access Grants, custom claims o `super_admin`.
- Error de red, claves, configuración o reloj tratado como éxito.

## 4. Propiedades de seguridad esperadas

1. **Autenticidad:** sólo una firma Google válida bajo trust roots aprobados permite producir claims verificados.
2. **Contexto:** emisor, audiencia y presentador ligan el token al consumidor correcto.
3. **Frescura:** expiración, emisión y nonce —cuando exista— limitan reutilización.
4. **Identidad estable:** `sub`, no correo, relaciona la cuenta Google con una reserva.
5. **Unicidad:** un `googleSubject` no puede quedar asociado a dos UID.
6. **Separación:** verificación no implica vinculación; vinculación no implica autorización.
7. **Mínimo privilegio:** el verificador no escribe estado ni posee autoridad para grants/claims.
8. **Fallo seguro:** cualquier ambigüedad o dependencia no disponible rechaza la operación.
9. **Privacidad:** tokens y claims sensibles no se persisten ni registran.

Estas propiedades son objetivos de diseño y deberán convertirse en pruebas y controles verificables en módulos posteriores.

## 5. Riesgos residuales y decisiones pendientes

- Un token válido y `hd` autorizado no demuestra por sí solo que PL Cocina deba autorizar al usuario.
- La revocación, suspensión o eliminación en Workspace puede no reflejarse inmediatamente en un ID token ya emitido.
- Account linking puede tener comportamientos dependientes de configuración; no se presume conservación de UID.
- El correo puede cambiar, ser alias o reutilizarse; la política operativa debe definirse sin degradar el uso de `sub`.
- La protección de replay depende del flujo OAuth y del contrato de nonce aún no aprobados.
- Los parámetros de caché, timeout, reloj y reintentos necesitan límites operativos medidos.
- Debe aprobarse el inventario de Client IDs, dominios, presentadores y responsables de rotación/configuración.
- Eventos Gen2, tokens reales, aliases y UID requieren validación posterior en un proyecto aislado.

Mientras estos riesgos sigan abiertos, no se autoriza OAuth, vinculación, activación ni despliegue.
