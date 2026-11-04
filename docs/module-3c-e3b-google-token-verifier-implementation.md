# Módulo 3C-E3B — implementación aislada del verificador Google ID Token

3C-E3B implementa verificación criptográfica y de política para Google ID Tokens como componente interno aislado. No está conectado a `index.ts`, `app.ts`, handlers 3C-C, OAuth, Firebase Auth, Firestore, perfiles, reservas, Access Grants ni custom claims.

## Biblioteca y dependencias

Se usa `google-auth-library` 11.3.1 como dependencia directa. Es la biblioteca oficial de Google ya presente transitivamente en el árbol de Firebase Admin y permite verificar firmas RSA con certificados confiables. Se descartó añadir `jose` porque no aporta una ventaja necesaria para este alcance y duplicaría dependencias.

No se implementó criptografía propia. Las pruebas generan un par RSA efímero controlado y firman fixtures locales; el código productivo delega la verificación a `verifySignedJwtWithCertsAsync`.

## Contrato y separación

`GoogleIdentityTokenVerifier.verify` recibe:

- `idToken`: cadena opaca, con tamaño máximo.
- `nonceContext`: opcional y sólo construible mediante `createTrustedNonceContext`; no acepta un nonce esperado como parámetro libre del cliente.

El resultado `VerifiedGoogleIdentity` contiene exclusivamente emisor, audiencia, `azp`, `sub`, correo normalizado, `emailVerified: true`, dominio Workspace, tiempos validados y si se comprobó nonce. No contiene UID, vínculo, estado activo, rol, grant ni claims administrativos.

La fuente de certificados, el verificador criptográfico y el reloj son interfaces inyectables. Esto permite pruebas aisladas sin red ni credenciales reales y mantiene separado el trust root de los parámetros del cliente.

## Política de validación

- Sólo algoritmo `RS256`.
- `kid` obligatorio y presente en certificados confiables; ante desconocido se permite un único refresco.
- Emisor dentro de la lista servidor, limitada a los dos emisores Google OIDC.
- Audiencia exacta dentro de Client IDs servidor.
- `iat`/`exp` enteros, ordenados, dentro de vigencia y duración máxima.
- Tolerancia de reloj configurable entre 0 y 60 segundos; valor predeterminado 60.
- `sub` obligatorio y canónico mediante el contrato E1.
- Correo canónico y `email_verified === true`.
- `hd` canónico, en allowlist y exactamente coherente con el dominio del correo.
- `azp`, cuando aparece, debe estar autorizado; puede exigirse por configuración.
- Nonce sólo se exige/compara cuando existe contexto confiable. El consumo atómico anti-replay queda para el flujo OAuth futuro.
- Configuración vacía, duplicada, no canónica o permisiva falla al construir el verificador.

Los errores tienen códigos internos tipificados y mensaje público uniforme. El componente no registra tokens ni claims.

## Claves y caché

`GoogleAuthLibraryCertificateSource` usa la obtención/caché de certificados federados de `google-auth-library`. Un `kid` desconocido causa como máximo un refresco con cliente nuevo; si sigue ausente se rechaza. Fallos de obtención, conjuntos vacíos o formatos inesperados fallan cerrados.

Las pruebas inyectan una fuente estática con clave pública efímera, por lo que no realizan consultas a Google. La rotación real, TTL/headers y disponibilidad de Google quedan para validación posterior autorizada.

## Pruebas focalizadas

`functions/test/google-token-verifier.test.ts` cubre firma RSA válida, firma alterada, clave desconocida/refresco único, expiración, `iat` futuro, emisor, audiencia, subject, correo verificado, `hd`, coherencia email/dominio, `azp`, nonce, token malformado, algoritmo no permitido, configuración incompleta, fallo de claves, token confusion Firebase/Google y ausencia de campos de autorización o vinculación en el resultado.

Las pruebas no usan mocks que declaren una firma válida: la aceptación criptográfica siempre pasa por `google-auth-library` contra la clave pública correspondiente.

Resultados focalizados de 3C-E3B:

- Prueba unitaria/criptográfica del verificador: 17/17 aprobadas.
- Build TypeScript estricto de Functions: aprobado.
- `git diff --check`: aprobado.
- Manifiesto Functions: únicamente `adminApi`; el verificador no añade endpoint ni trigger.

No se ejecutó la regresión integral en este módulo.

## Límites de confianza y riesgos pendientes

- Verificar no vincula ni autoriza.
- El correo no identifica al usuario; `sub` es el identificador estable futuro.
- La implementación no consume nonce de forma persistente ni promete prevención completa de replay.
- No se ha validado con tokens Google reales, rotación real, OAuth, aliases, account linking, conservación de UID o eventos Gen2.
- La lista real de Client IDs, `azp` y dominios debe provenir de configuración servidor aprobada en una fase posterior.
- La indisponibilidad real y objetivos de latencia requieren el proyecto aislado aprobado.

## Reversión

Eliminar el módulo, su prueba, este documento y la dependencia directa restaura el estado anterior. Como el componente no se exporta desde Functions ni escribe datos, la reversión no requiere migración, limpieza de usuarios, reservas o permisos.
