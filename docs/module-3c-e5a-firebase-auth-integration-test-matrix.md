# Módulo 3C-E5A — matriz de pruebas Firebase Auth y Google Workspace

Esta matriz es diseño futuro. E5A no ejecutó pruebas ni habilitó Firebase Auth.

## 1. Niveles y criterios

- **U — unitaria:** contratos, reloj, hashing, transiciones, errores y adaptadores inyectados.
- **E — Auth + Firestore Emulator:** concurrencia, persistencia, disabled, sesiones simuladas e idempotencia con `demo-plcocina-apps`.
- **R — proyecto real aislado:** semántica real de Google OAuth, provider linking, UID, conflictos, revocación, IAM y eventos.

Un caso E no sustituye R cuando depende de seguridad del proveedor, firma de Custom Tokens, IAM, anti-abuse o comportamiento productivo. La documentación oficial señala que Auth Emulator no valida firma/expiración de Custom Tokens ni reproduce IAM o rate limiting: [Auth Emulator](https://firebase.google.com/docs/emulator-suite/connect_auth).

## 2. Precondiciones y UID

| ID | Caso | Resultado exigido | Nivel |
|---|---|---|---|
| U-01 | UID existe en Auth y perfil Firestore con mismo valor | Continúa; UID registrado como invariante | U/E/R |
| U-02 | UID Auth ausente | Bloqueo; no `createUser`, Custom Token ni recuperación silenciosa | U/E/R |
| U-03 | UID del Firebase ID Token difiere del objetivo | Rechazo antes de OAuth/linking | U/E/R |
| U-04 | Perfil pertenece a otro UID | Rechazo y conciliación | U/E |
| U-05 | Email coincide pero UID/sub no | No selección, merge ni reasignación | U/E/R |
| U-06 | UID protegido Super Admin | Rechazo; password permanece único mecanismo | U/E/R |
| U-07 | Cuenta suspendida o perfil conciliado | Sin challenge ni vínculo | U/E/R |
| U-08 | E4B2 no está `linked_pending_activation` | Sin provider linking | U/E |
| U-09 | Reserva `googleSubject` ausente/ajena | Rechazo; propietario intacto | U/E |

## 3. Challenge, state, nonce y token

| ID | Caso | Resultado exigido | Nivel |
|---|---|---|---|
| N-01 | Emisión válida | Nonce/state CSPRNG, hashes persistidos, TTL breve, ligados a UID/operación/sesión | U/E |
| N-02 | State distinto o de otra sesión | CSRF rechazado sin consumir nonce válido | U/E/R |
| N-03 | Nonce ausente o distinto en token | Rechazo E3B | U/E/R |
| N-04 | Challenge vencido/revocado | Rechazo sin avance | U/E |
| N-05 | Primer consumo válido | Estado `consumed` dentro de transacción | E |
| N-06 | Replay secuencial | `NONCE_REPLAYED`; cero efectos | E/R |
| N-07 | Dos consumos concurrentes | Exactamente un ganador | E/R |
| N-08 | Cliente cambia UID/aud/hd/operación | Parámetros ignorados/rechazados; autoridad servidor | U/E/R |
| N-09 | Firma/iss/aud/azp/exp/iat/sub/email_verified/hd inválidos | Rechazo fail-closed | U; R para configuración real |
| N-10 | Google token presentado como Firebase token | Rechazo por emisor/audiencia | U/R |
| N-11 | Firebase token presentado como Google token | Rechazo E3B | U/R |

## 4. Provider linking y conflictos

| ID | Caso | Resultado exigido | Nivel |
|---|---|---|---|
| L-01 | Sesión Firebase reciente del UID + credencial Google válida | Provider `google.com` aparece en el mismo UID | E si soportado; R obligatorio |
| L-02 | Resultado client-side declara otro UID | Rechazo y conciliación | U/E/R |
| L-03 | Postflight providerData coincide con `sub` | Confirmación idempotente | E/R |
| L-04 | Provider ya vinculado al mismo UID/sub | Replay/no-op confirmado por postflight | E/R |
| L-05 | Otro Google ya vinculado al UID | `provider_conflict`; no reemplazo | E/R |
| L-06 | Credencial en otro UID | Conflicto; no iniciar sesión con ella ni fusionar | E/R |
| L-07 | Email en uso por otra cuenta | Bloqueo/conciliación; email no decide UID | E/R |
| L-08 | Credencial expirada/inválida | Operación queda reintentable sólo con prueba nueva | E/R |
| L-09 | Provider deshabilitado/configuración incorrecta | Fail-closed; sin cambio Firestore | E/R |
| L-10 | Cuenta Firebase disabled | No vínculo; validar ventana segura sólo en R | E/R |
| L-11 | Reautenticación no reciente | Exigir nueva autenticación aprobada | E/R |
| L-12 | Problema conocido SDK/proyecto | Detectado en canary aislado; producción bloqueada | R |

Firebase enumera conflictos como provider ya vinculado y credencial ya usada por otra cuenta; no se aplicarán sus recuperaciones genéricas de “iniciar sesión en la otra cuenta” porque violarían el UID elegido administrativamente: [Account linking](https://firebase.google.com/docs/auth/web/account-linking), [Auth JS API](https://firebase.google.com/docs/reference/js/auth).

## 5. Custom Tokens — evaluación, no ruta primaria

| ID | Caso | Resultado exigido | Nivel |
|---|---|---|---|
| C-01 | UID preexistente y permitido | Token sin claims administrativos; canje mantiene UID | E/R |
| C-02 | UID inexistente | Backend rechaza antes de emitir; verificar que no se crea usuario | U/E/R |
| C-03 | UID suspendido/disabled | No emisión | U/E/R |
| C-04 | Token replay/expirado | Producción rechaza; Emulator no es evidencia suficiente | R |
| C-05 | IAM de firmado ausente | Fail-closed y sin fallback a claves largas | R |
| C-06 | Token válido | No se considera `google.com` vinculado sin providerData | E/R |
| C-07 | Claims adicionales solicitados | Rechazo; no roles, grants ni `super_admin` | U/E/R |

Firebase indica que el canje crea el registro si no existe; C-02 es bloqueo absoluto: [Custom Tokens](https://firebase.google.com/docs/auth/admin/create-custom-tokens).

## 6. Saga, concurrencia y fallos parciales

| ID | Caso | Resultado exigido | Nivel |
|---|---|---|---|
| S-01 | Dos solicitudes equivalentes | Una llamada efectiva; mismo resultado; una auditoría | U/E/R |
| S-02 | Misma clave con parámetros distintos | `IDEMPOTENCY_CONFLICT` | U/E |
| S-03 | Dos providers/subjects para un UID | Máximo uno; el otro conciliado | E/R |
| S-04 | Mismo subject para dos UID | Reserva E2 conserva un propietario | E/R |
| S-05 | Firestore confirma A; Auth falla B | `linked_pending_activation`, acceso denegado | E/R |
| S-06 | Auth confirma B; Firestore falla coordinación | Postflight detecta provider; no relink; conciliación | E/R |
| S-07 | Red cae con resultado desconocido | Consultar postcondición, nunca repetir a ciegas | U/E/R |
| S-08 | Autorización expira/revoca durante llamada | No activar; registrar realidad y conciliar | E/R |
| S-09 | Auditoría/operación falla | Estado local no afirma confirmación; recuperación por postflight | E/R |
| S-10 | Reintento tras interrupción | Converge a confirmado o bloqueado sin duplicados | E/R |
| S-11 | Intento de rollback automático con unlink/delete | Prohibido por contrato | U |

## 7. Activación, sesiones y autorización

| ID | Caso | Resultado exigido | Nivel |
|---|---|---|---|
| A-01 | Provider confirmado sin autorización de activación | Sigue `linked_pending_activation`; acceso denegado | U/E/R |
| A-02 | Coincidencia de email | Nunca activa | U/E/R |
| A-03 | Auth habilitado mientras perfil bloqueado | Backend/reglas deniegan todo acceso protegido | E/R |
| A-04 | Perfil activo mientras Auth disabled | Inicio/uso bloqueado; conciliación | E/R |
| A-05 | Activación válida | UID/provider/perfil/sesión coherentes; grants intactos | E/R |
| A-06 | Sin Access Grant | Autenticación posible, aplicación denegada | U/E/R |
| A-07 | Grant activo para app A, no B | Sólo A autorizada | U/E/R |
| A-08 | Suspensión | Bloqueo local inmediato, Auth disabled, refresh tokens revocados | E/R |
| A-09 | ID Token anterior tras revocación | `verifyIdToken(..., true)` rechaza; sin check puede vivir hasta expirar | E/R |
| A-10 | Revocación falla | `revocation_pending`, acceso local denegado | U/E/R |
| A-11 | Intento de custom claims/roles | Ningún cambio | U/E/R |
| A-12 | Google intenta `super_admin` | Rechazo; password-only | U/E/R |

Fuente de semántica de revocación y tokens: [Manage sessions](https://firebase.google.com/docs/auth/admin/manage-sessions), [Verify ID Tokens](https://firebase.google.com/docs/auth/admin/verify-id-tokens).

## 8. Criterios del proyecto aislado real

Antes de Nivel R deben aprobarse: proyecto desechable separado, usuarios sintéticos, dominio/Client IDs de prueba, IAM mínimo, secrets separados, budget/alertas, inventario de APIs/costos, logging redactado, responsables, ventana y plan de eliminación.

La salida requiere evidencia de UID antes/después, providerData, tokens redactados, estados Firestore, auditoría, conflictos, revocación y eliminación final de recursos. Ningún dato o secreto de producción puede entrar al proyecto.

## 9. Gate de producción

Producción permanece bloqueada si falla cualquier caso R de UID, provider conflict, disabled, nonce/state, token confusion, revocación, falla parcial o autorización. También queda bloqueada si alguna superficie permite acceso con Auth habilitado y perfil local denegado.
