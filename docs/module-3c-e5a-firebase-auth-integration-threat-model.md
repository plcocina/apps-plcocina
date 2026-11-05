# Módulo 3C-E5A — modelo de amenazas Firebase Auth y Google Workspace

## 1. Activos y límites de confianza

Activos: UID Firebase/interno, reserva `googleSubject`, autorización administrativa, challenges nonce/state, credenciales Google, Firebase ID/refresh tokens, estado de perfil, Access Grants, claim `super_admin`, operaciones y auditoría.

Límites: navegador, Google OIDC, Firebase Auth, backend administrativo, Firestore y aplicaciones consumidoras. Cada tipo de token tiene un verificador y audiencia únicos. Ningún correo, dominio, claim Google o resultado client-side cruza un límite como autorización local.

Escala: **Crítico** = apropiación/privilegio o acceso sistémico; **Alto** = acceso indebido o inconsistencia explotable; **Medio** = degradación/filtración limitada; **Bajo** = impacto operacional acotado.

## 2. Amenazas, mitigaciones y gates

| ID | Amenaza | Riesgo | Mitigaciones obligatorias | Prueba/gate |
|---|---|---:|---|---|
| T-01 | Account takeover por vincular Google ajeno | Crítico | UID por contexto servidor; E3B; nonce/state; reserva; autorización; sesión Firebase reciente; postflight providerData | U-03, N-02..07, L-01..07; R obligatorio |
| T-02 | Confusión Google ID Token/Firebase ID Token | Crítico | Entradas separadas, issuer/audience/verificador dedicados; nunca Google como credencial admin | N-10/N-11 en R |
| T-03 | Replay de Google token | Alto | Nonce CSPRNG, hash, TTL, ligadura y consumo atómico | N-03..07 |
| T-04 | CSRF OAuth | Alto | State independiente ligado a sesión/operación, redirect URI exacta, cookie segura | N-02 en navegador real |
| T-05 | Nonce reutilizado o controlado por cliente | Alto | Sólo backend genera; comparación con claim firmado; un ganador transaccional | N-05..08 |
| T-06 | Apropiación de UID por email | Crítico | Prohibir lookup/merge por email; UID y sub exactos | U-03..05, L-07 |
| T-07 | Provider ya pertenece a otro UID | Crítico | Preflight, manejo `credential-already-in-use`, no sign-in con credencial conflictiva, conciliación | L-05/L-06 en R |
| T-08 | Creación accidental de usuario | Crítico | `getUser(uid)` previo; Custom Token fuera de ruta primaria; no federated sign-in directo | U-02, C-02 |
| T-09 | Firebase Auth habilitado mientras Firestore bloquea | Alto | Todas las superficies consultan estado local; activación saga; revocar y conciliar | A-03; inventario completo R |
| T-10 | Firestore vinculado sin provider real | Alto | `linked_pending_activation`; acceso denegado; providerData postflight | S-05, A-01 |
| T-11 | Revocación incompleta | Alto | Bloqueo local primero; disable Auth; revoke refresh; checkRevoked; estado `revocation_pending` | A-08..10 |
| T-12 | ID Token anterior sigue activo | Alto | Comprobar revocación; TTL conocido; autorización local por solicitud | A-09 |
| T-13 | Elevación mediante claims/grupos Workspace | Crítico | No mapear grupos/hd a claims/grants; `super_admin` password-only | A-11/A-12 |
| T-14 | Custom Token emitido indebidamente | Crítico | IAM mínimo, no endpoint genérico, precondiciones, audiencia/TTL, sin claims, auditoría | C-01..07; security review |
| T-15 | Compromiso de cuenta Workspace | Alto | Autorización administrativa separada, sesión reciente, revocación/suspensión y conciliación | R con cuenta revocada/suspendida |
| T-16 | OAuth mal configurado | Alto | Client IDs/redirect URIs/hd/azp allowlist, secretos separados, proyecto aislado | N-09, L-09 en R |
| T-17 | Falla parcial Auth/Firestore | Alto | Saga idempotente, postflight, fail-closed, no compensación destructiva | S-05..11 |
| T-18 | Cliente falsifica éxito de linking | Alto | Backend consulta `getUser(uid).providerData`; compara provider UID/sub | L-02/L-03 |
| T-19 | Cuenta suspendida se reactiva | Crítico | Estado local y Auth disabled; no challenge; activación separada | U-07, L-10, A-08 |
| T-20 | Filtración de token/sub/nonce | Alto | No logs de tokens; hashes con pepper; respuestas genéricas; retención mínima | Revisión logs R |
| T-21 | Race entre revocación y vínculo | Alto | Revisiones, autorización vigente dentro de cada checkpoint, postflight y conciliación | S-08 concurrente |
| T-22 | Auditoría duplicada o mutable | Medio | ID determinista, create-only, replay no-op, reglas deny-by-default | S-01/S-09 |
| T-23 | Emulator genera falsa confianza | Alto | Etiquetar límites; R obligatorio para seguridad real | Gate Nivel R |
| T-24 | Problema conocido del SDK de linking | Alto | Versión fijada, canary aislado, matriz de errores, feature flag cerrada | L-12 |

## 3. Abusos por estrategia

### Provider linking

El atacante intenta aportar una credencial ya usada, aprovechar una sesión antigua o hacer que la aplicación cambie al UID de la credencial. La recuperación genérica sugerida por Firebase —iniciar sesión con la cuenta propietaria y luego vincular— no es aceptable aquí: el UID objetivo ya fue elegido administrativamente. Todo conflicto se bloquea.

Firebase confirma que las credenciales pueden producir `provider-already-linked`, `credential-already-in-use` y errores de email/proveedor; el proyecto también debe evaluar el problema conocido documentado: [Account linking](https://firebase.google.com/docs/auth/web/account-linking), [Auth API](https://firebase.google.com/docs/reference/js/auth).

### Custom Tokens

Un backend comprometido con permiso de firmado podría autenticar cualquier UID. Además, el canje puede crear el usuario ausente. Por eso no existe endpoint genérico, no se incluyen privilegios, se exige existencia previa, y la estrategia no prueba provider linking: [Custom Tokens](https://firebase.google.com/docs/auth/admin/create-custom-tokens).

### Híbrida

Reduce la autoridad del cliente, pero añade estados parciales. Su seguridad depende de que todas las superficies denieguen acceso mientras el perfil no esté activo y de que la realidad Firebase se confirme por lectura Admin. Sin ese inventario, no se habilita una ventana temporal.

## 4. Sesiones y bloqueo

Deshabilitar una cuenta y revocar refresh tokens no elimina instantáneamente todo ID Token ya emitido. Los backends sensibles deben verificar revocación y el estado local. Firebase documenta el chequeo `verifyIdToken(idToken, true)` y la vida aproximada de una hora del ID Token: [Manage sessions](https://firebase.google.com/docs/auth/admin/manage-sessions).

Orden ante incidente:

1. Bloquear perfil local y Access Grant evaluation.
2. Marcar coordinación `revocation_pending`.
3. Deshabilitar Firebase Auth.
4. Revocar refresh tokens.
5. Confirmar `tokensValidAfterTime`/estado y aplicar checkRevoked.
6. Finalizar o mantener conciliación; nunca reactivar automáticamente.

## 5. Nonce, state y redirección

`state` protege la correlación/CSRF del navegador; `nonce` liga el ID Token a la solicitud y protege replay. No son intercambiables. Ambos se generan en servidor, tienen TTL, se ligan al UID/operación/sesión y se consumen una vez. `hd` no reemplaza ninguno ni autoriza internamente: [Google OIDC](https://developers.google.com/identity/openid-connect/openid-connect).

Ataques que deben probarse: fijación de state, callback cruzado entre sesiones, nonce de otra operación, doble callback concurrente, callback tardío, redirect URI engañosa, token válido con `hd` no permitido y sustitución de `sub`/email.

## 6. Fallos parciales y respuesta

| Realidad observada | Clasificación | Acción permitida |
|---|---|---|
| Firestore linked; Auth sin provider | Seguro pero incompleto | Mantener bloqueo; reintentar con nueva prueba/autorización o conciliar |
| Auth con provider; Firestore pendiente | Inconsistente | Bloquear; confirmar postcondición; no volver a linkear |
| Auth enabled; perfil bloqueado | Riesgo alto | Denegar localmente, revocar sesiones, conciliar |
| Perfil activo; Auth disabled | Indisponibilidad segura | Bloquear y conciliar |
| Provider en otro UID | Posible apropiación | Congelar operación; preservar evidencia; revisión manual |
| Resultado externo desconocido | Ambiguo | Read-after-write Admin; no compensación automática |

Está prohibido usar `deleteUser`, recreación, `unlink`, cambio de email o merge automático como rollback. Una auditoría confirmada no se borra.

## 7. Riesgo residual y bloqueos

Permanecen críticos hasta Nivel R: comportamiento real de linking, cuenta disabled, reautenticación, conflictos de provider/email, revocación, sesiones existentes, configuración OAuth, IAM de firmado y diferencias Emulator/producción.

Auth Emulator es útil para coordinación, pero no reproduce IAM, firma/expiración de Custom Tokens ni anti-abuse, y presenta diferencias de eventos: [Auth Emulator](https://firebase.google.com/docs/emulator-suite/connect_auth). Ningún resultado local autoriza producción.

## 8. Condiciones de aprobación

No se habilita Google hasta que:

- todos los casos críticos Nivel R estén aprobados;
- UID antes/después y providerData estén demostrados;
- nonce/state y revocación funcionen bajo concurrencia;
- todas las superficies denieguen acceso en estados parciales;
- exista reconciliación manual, runbook de incidente y observabilidad redactada;
- IAM, Client IDs, dominios, redirect URIs, costos y eliminación del proyecto de prueba estén aprobados;
- el mecanismo siga sin crear Access Grants, claims o `super_admin`.
