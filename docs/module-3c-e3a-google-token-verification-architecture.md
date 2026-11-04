# Módulo 3C-E3A — arquitectura de verificación de Google ID Tokens

Este documento define el diseño para 3C-E3B. No implementa un verificador, no habilita OAuth, no vincula cuentas y no autoriza cambios en Firebase, Google Cloud, usuarios, perfiles, Access Grants ni custom claims.

## 1. Decisiones y alcance

- El identificador estable de Google es `sub`; el correo es un atributo mutable y nunca la clave principal.
- Un Google ID Token sólo aporta evidencia de identidad después de validar criptografía y política. No demuestra por sí mismo vinculación con un UID ni autorización para una aplicación.
- La verificación produce una identidad `verified`, no una identidad `linked`. La vinculación requiere conciliación separada contra la reserva `googleSubject` y el UID esperado.
- Una reserva `googleSubject` de 3C-E2 prueba exclusividad local del identificador, no autenticidad del token ni permiso de acceso.
- La autorización continúa basada en el UID vinculado, el perfil local válido y los Access Grants existentes. Nunca se concede por correo, dominio o token válido.
- El backend administrativo actual continúa aceptando exclusivamente Firebase ID Tokens donde ya corresponda. Un Google ID Token no es sustituto de un Firebase ID Token.
- Todo fallo de configuración, claves, red, reloj o claims se resuelve en rechazo fail-closed.

## 2. Flujo conceptual

1. Un futuro flujo OAuth obtiene un Google ID Token y lo entrega al componente de verificación como cadena opaca.
2. `GoogleIdentityTokenVerifier` valida firma, claves, emisor, audiencia, tiempo y claims obligatorios.
3. Si todo es válido, devuelve claims mínimos, tipados y normalizados. Nunca devuelve el token ni claims no aprobados como autoridad.
4. `IdentityReconciliationService` compara el `sub` verificado con la reserva `googleSubject`, el UID esperado y el estado local.
5. Si no existe una correspondencia inequívoca, conserva o establece `reconciliation_required`; no reasigna por correo.
6. Sólo un flujo futuro, explícito y auditable puede convertir `verified` en `linked`.
7. `AuthorizationLayer` evalúa el UID ya vinculado contra perfil, estado y Access Grants. La validez del token Google no crea permisos.

## 3. Componentes y responsabilidades

### A. Google Identity Token Verifier

Responsabilidad única: recibir un token opaco y configuración explícita, verificarlo y devolver claims confiables o un rechazo tipificado.

No accede a Firestore, Firebase Auth, Access Grants, perfiles ni auditoría de negocio; no crea, activa o vincula usuarios. Tampoco decide qué UID corresponde a la identidad.

Validaciones obligatorias:

1. El token tiene estructura JWT válida, algoritmo permitido y firma legítima de Google.
2. La clave procede del conjunto público oficial de Google, obtenido por HTTPS con rotación y caché seguras.
3. `iss` es exactamente `accounts.google.com` o `https://accounts.google.com`.
4. `aud` coincide exactamente con uno de los Client IDs configurados; no se aceptan comodines ni audiencias aportadas por el cliente.
5. `exp` existe, es numérico y no ha vencido, con tolerancia de reloj mínima y explícita.
6. `iat` existe, es coherente con `exp` y no está en el futuro más allá de la tolerancia aprobada. Propuesta para E3B: tolerancia máxima de 60 segundos, configurable con un límite superior fijo.
7. `sub` es obligatorio, canónico y válido conforme al contrato `normalizeGoogleSubject`; no se transforma a correo ni UID.
8. `email_verified` es el booleano literal `true`.
9. `hd` existe, está normalizado y pertenece por igualdad exacta a la allowlist administrativa.
10. El correo tiene formato válido, su dominio es coherente con `hd` y con la política administrativa, pero continúa siendo un atributo mutable.
11. `azp`, si está presente o si la forma de `aud` lo exige, debe pertenecer a una lista explícita de presentadores autorizados y ser coherente con la audiencia. Ausencia o ambigüedad se rechaza cuando la política lo requiera.
12. Cuando el flujo OAuth use `nonce`, debe coincidir mediante comparación segura con un desafío servidor de un solo uso, ligado a sesión/operación, con expiración y consumo atómico. Sin un flujo definido, el verificador no debe fingir protección de replay.

Ningún `sub`, `email`, `email_verified`, `hd`, `aud`, `azp`, `nonce` o rol enviado como campos separados por el cliente tiene autoridad. Sólo se consideran los claims del token cuya firma y política completa fueron aprobadas.

### B. Identity Reconciliation Service

Responsabilidad futura: relacionar el `sub` verificado con una reserva `googleSubject` y un UID local sin alterar automáticamente la identidad.

Debe preservar la progresión explícita:

- `declared`: existe intención administrativa, sin prueba criptográfica.
- `verified`: existe prueba criptográfica vigente, pero todavía no vínculo.
- `linked`: una operación autorizada confirmó la correspondencia entre `sub`, reserva y UID.
- `reconciliation_required`: existe conflicto, ausencia o ambigüedad que bloquea activación.

Reglas:

- Verificar no equivale a vincular.
- Una coincidencia de correo, alias o dominio nunca reasigna ni selecciona automáticamente un UID.
- Una reserva inexistente, perteneciente a otro UID o incompatible produce conciliación o rechazo; no se sobrescribe.
- El UID permanece estable. Cualquier duda de conservación real del UID queda para validación aislada posterior.
- Cambios de correo no cambian `sub`; cambios de `sub` no se tratan como cambios de correo.

### C. Authorization Layer

Responsabilidad: determinar acceso de un UID ya vinculado mediante el modelo vigente de perfiles y Access Grants.

- Un token Google válido no crea perfiles, grants, claims ni roles.
- El dominio Workspace no concede privilegios.
- `super_admin` continúa limitado al mecanismo password protegido existente; una identidad `googleWorkspace` no puede adquirirlo.
- Perfiles pendientes, sólo verificados, deshabilitados o en conciliación fallan cerrados.

## 4. Límites de confianza y tipos de token

| Artefacto | Verificador | Finalidad | No demuestra |
|---|---|---|---|
| Google ID Token | `GoogleIdentityTokenVerifier` futuro | Identidad Google y claims OIDC bajo política local | UID Firebase vinculado, perfil activo, Access Grant o rol |
| Firebase ID Token | Firebase Admin SDK en la capa existente | Sesión Firebase del usuario para el proyecto y backend correspondiente | Que el proveedor Google fue validado conforme a E3B si esa evidencia no forma parte del flujo aprobado |

La aceptación de un tipo de token en el punto de entrada del otro constituye token confusion. Cada endpoint futuro debe declarar un único tipo de credencial, emisor y audiencia, usar un verificador dedicado y rechazar el resto antes de procesar identidad.

Después de una verificación Google completa pueden confiarse únicamente: `iss`, `aud`, `sub`, tiempos validados, `email`, `email_verified`, `hd`, `azp` y `nonce` cuando hayan pasado sus políticas. El correo sigue requiriendo conciliación como atributo mutable. UID, estado local, reserva, vínculo, grants y rol siempre provienen de sistemas locales autorizados.

Jamás se acepta del cliente como autoridad: UID objetivo, rol, estado de vinculación, dominio permitido, Client ID permitido, resultado de verificación, reserva, Access Grant, claims administrativos o una versión decodificada del payload.

## 5. Contrato documental para 3C-E3B

```ts
type VerifyGoogleIdTokenInput = {
  idToken: string;
  expectedNonce?: string;
  correlationId: string;
};

type VerifiedGoogleIdentity = {
  issuer: "accounts.google.com" | "https://accounts.google.com";
  audience: string;
  authorizedParty: string | null;
  subject: string;
  email: string;
  emailVerified: true;
  hostedDomain: string;
  issuedAt: Date;
  expiresAt: Date;
  nonceVerified: boolean;
};

interface GoogleIdentityTokenVerifier {
  verify(input: VerifyGoogleIdTokenInput): Promise<VerifiedGoogleIdentity>;
}
```

La implementación debe recibir por inyección:

- `allowedIssuers`: conjunto cerrado con los dos emisores Google OIDC admitidos.
- `allowedAudiences`: Client IDs explícitos, no vacíos.
- `allowedAuthorizedParties`: presentadores explícitos para política `azp`.
- `allowedWorkspaceDomains`: dominios canónicos exactos.
- `clock`, tolerancia acotada y límites de vigencia.
- proveedor de claves/JWKS, caché y transporte HTTP.
- verificador/consumidor de nonce cuando el flujo lo requiera.
- logger estructurado con redacción.

La configuración ausente, vacía, inválida o contradictoria debe impedir construir/iniciar el verificador o causar un error seguro; nunca habilitar valores por defecto permisivos.

### Resultado y errores tipificados

El éxito contiene sólo los campos mínimos anteriores. Los errores internos previstos son:

- `TOKEN_MISSING`, `TOKEN_MALFORMED`, `TOKEN_TOO_LARGE`.
- `SIGNATURE_INVALID`, `ALGORITHM_NOT_ALLOWED`, `KEY_ID_UNKNOWN`.
- `KEY_FETCH_FAILED`, `KEY_SET_INVALID`, `KEY_ROTATION_UNAVAILABLE`.
- `ISSUER_NOT_ALLOWED`, `AUDIENCE_NOT_ALLOWED`, `AUTHORIZED_PARTY_NOT_ALLOWED`.
- `TOKEN_EXPIRED`, `TOKEN_NOT_YET_VALID`, `ISSUED_AT_INVALID`.
- `SUBJECT_INVALID`, `EMAIL_INVALID`, `EMAIL_NOT_VERIFIED`.
- `HOSTED_DOMAIN_MISSING`, `HOSTED_DOMAIN_NOT_ALLOWED`, `IDENTITY_CLAIMS_INCONSISTENT`.
- `NONCE_REQUIRED`, `NONCE_INVALID`, `NONCE_REPLAYED`.
- `VERIFIER_MISCONFIGURED`, `VERIFICATION_UNAVAILABLE`.

Los consumidores externos reciben un rechazo genérico; el código detallado queda sólo en telemetría interna redactada y no debe revelar si existe una cuenta o reserva.

## 6. Dependencias, claves y reloj

Para Node 22 se recomienda evaluar primero `google-auth-library`, mantenida por Google, usando su verificación de ID tokens y complementando de forma explícita las políticas que no cubra. `jose` es una alternativa consolidada para JWT/JWKS si se justifica una capa más explícita. E3B debe elegir una sola ruta tras revisar su API vigente; no se implementará criptografía propia ni se instalarán dependencias en E3A.

La caché de claves debe:

- respetar `Cache-Control`/expiración de la respuesta oficial, con límite local máximo;
- indexar por `kid` y algoritmo permitido;
- refrescar una vez ante `kid` desconocido para soportar rotación, evitando bucles y tormentas;
- deduplicar solicitudes concurrentes;
- conservar claves previas sólo dentro de una ventana acotada y válida;
- fallar cerrada si no existe una clave válida en caché y Google no está disponible;
- no aceptar claves, JWKS URL o certificados suministrados por el cliente.

El reloj se inyecta en pruebas. La tolerancia se aplica únicamente a desviaciones pequeñas; no prolonga arbitrariamente `exp` ni permite `iat` futuro. Los límites exactos y la vigencia máxima aceptable deben fijarse en E3B.

## 7. Logging y datos sensibles

Nunca registrar tokens, encabezados JWT completos, payloads, certificados, nonce, correo completo, `sub` en claro, refresh/access tokens ni secretos de configuración. La telemetría permitida incluye código de error, fase, latencia, `kid` sanitizado, audiencia clasificada por alias interno, hash no reversible/correlacionable con pepper cuando esté aprobado y `correlationId` validado.

Los logs no afirman que una identidad está vinculada o autorizada cuando sólo fue verificada. Las respuestas al cliente son genéricas para evitar enumeración.

## 8. Riesgos y decisiones pendientes

- Seleccionar la biblioteca y confirmar exactamente qué claims/políticas valida su API vigente.
- Aprobar Client IDs, presentadores `azp`, dominios y propietarios de configuración.
- Definir el flujo OAuth, generación/almacenamiento/consumo de nonce y política anti-replay.
- Definir cómo se entrega la evidencia verificada al servicio de conciliación sin introducir un endpoint inseguro.
- Validar en entorno aislado account linking, conservación de UID, aliases, cambios de correo y eventos Gen2.
- Definir límites de caché, timeouts, reintentos y tolerancia de reloj con objetivos operativos.
- Determinar si se requiere señal administrativa adicional de Workspace; `hd` no concede autorización interna.

Ningún punto pendiente se considera resuelto por este diseño.
