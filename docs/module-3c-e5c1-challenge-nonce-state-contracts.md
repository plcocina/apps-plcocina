# Módulo 3C-E5C1 — contratos Challenge, Nonce y State

## Alcance

E5C1 incorpora contratos estrictos y utilidades criptográficas puras para preparar un futuro flujo Google Workspace OAuth/OIDC. No persiste challenges, no consume nonce o state, no ejecuta OAuth, no valida callbacks, no modifica Firebase Auth y no avanza operaciones E5B1.

Los tres conceptos permanecen separados:

- **Challenge:** registro conceptual que liga una solicitud reciente con UID, operación interna, autorización y sesión confiable.
- **Nonce OIDC:** secreto aleatorio que el verificador E3B compara con el claim firmado `nonce` del Google ID Token.
- **State OAuth:** secreto aleatorio que un callback futuro deberá comparar para correlacionar solicitud y respuesta y mitigar CSRF o confusión de sesión.

Ninguno concede por sí mismo autenticación, autorización administrativa, activación ni acceso.

## Generación criptográfica

`generateAuthChallengeSecrets()` usa exclusivamente primitivas de Node.js:

- `crypto.randomUUID()` para el identificador opaco compatible con el UUID exigido por E5B1;
- dos invocaciones independientes de `crypto.randomBytes(32)` para nonce y state;
- base64url canónico sin padding, con 43 caracteres y 256 bits de entropía por secreto bearer;
- SHA-256 hexadecimal para representar el hash persistible futuro;
- `timingSafeEqual` sobre buffers SHA-256 de longitud fija para comparación.

Las funciones rechazan padding, alfabeto no base64url, longitudes distintas de 32 bytes, codificaciones no canónicas y hashes que no sean exactamente 64 caracteres hexadecimales minúsculos. No se usan `Math.random`, timestamps, contadores ni algoritmos criptográficos propios.

El `challengeId` es un localizador no secreto y no sustituye nonce o state. Nonce y state no deben registrarse en logs, auditorías o documentos persistentes.

## Contrato del challenge

`authChallengeDocumentSchema` contiene únicamente:

- `challengeId`;
- UID interno y Firebase esperados, obligatoriamente iguales;
- `coordinationOperationId` E5B1;
- `authorizationId` E4B1;
- hash canónico opcional de `googleSubject`;
- identificador opaco de sesión confiable;
- `nonceHash` y `stateHash`;
- emisión, expiración acotada a quince minutos, estado, sello de transición y revisión;
- versión contractual.

El esquema es estricto y rechaza propiedades adicionales. No admite Google ID Tokens, Firebase ID Tokens, access tokens, refresh tokens, credenciales OAuth, claims administrativos ni material secreto bearer.

## Estados

- `issued`: emitido y potencialmente validable; no tiene sello de transición.
- `consumed`: reservado para consumo atómico futuro; una nueva validación se clasifica como replay.
- `expired`: fuera de vigencia.
- `revoked`: invalidado administrativamente.

Este modelo corresponde al challenge conceptual de E5A. No cambia los estados de coordinación E5B1. Validar en memoria un challenge `issued` devuelve `consumed: false` y nunca cambia su estado.

## Contexto confiable y validación pura

`createTrustedAuthChallengeContext()` crea el contexto interno tipado que liga UID, operación, autorización, sesión, revisión, nonce, state y, cuando ya existe un subject esperado, el resultado E3B con `nonceVerified=true` y el hash de subject calculado por backend.

`evaluateAuthChallenge()` falla de forma cerrada ante:

- contexto sin marca interna de confianza;
- challenge expirado, revocado o consumido;
- UID, operación, autorización, sesión o revisión diferentes;
- nonce o state incorrectos;
- ausencia o conflicto del binding Google verificado cuando existe subject preasignado.

La función no acepta un hash de subject derivado de claims arbitrarios del cliente. El hash esperado procede del challenge creado por backend y el binding Google debe proceder del resultado criptográficamente verificado por E3B.

## Compatibilidad E3B, E4B1 y E5B1

- El nonce generado satisface el contrato `TrustedNonceContext` de E3B. E3B sigue siendo responsable de firma, issuer, audience, tiempos, subject, correo, dominio y claim nonce.
- `authorizationId` referencia la autorización E4B1; E5C1 no la crea, consume ni revoca.
- `coordinationOperationId`, UID y `challengeId` son compatibles con E5B1; E5C1 no persiste eventos ni transiciones.
- La identidad verificada sólo aporta `subject`, `nonceVerified=true` y el hash de subject calculado en contexto confiable.

## Replay y CSRF: diseño frente a protección efectiva

El diseño permite detectar en memoria un challenge ya `consumed`, nonce incorrecto, state incorrecto y binding de sesión distinto. Esa validación por sí sola **no** garantiza unicidad global, consumo único, protección efectiva contra replay ni protección efectiva contra CSRF.

La protección efectiva requiere E5C2: persistencia del challenge, comparación dentro del callback autorizado, transición transaccional `issued -> consumed`, revisión optimista, idempotencia y un único ganador concurrente. Hasta entonces no existe consumo operativo.

## Pruebas

La suite focal contiene 25 pruebas sintéticas: generación, independencia, 256 bits, canonicalidad, repetición, SHA-256, comparación correcta e incorrecta, entradas malformadas, compatibilidad E3B, contrato estricto, vigencia, expiración, revocación, consumo/replay, bindings UID/operación/autorización/sesión, nonce, state, revisión, subject y ausencia de efectos secundarios.

La ausencia de colisiones en una muestra repetida comprueba el comportamiento básico del generador, pero no demuestra matemáticamente ausencia absoluta de colisiones.

## Riesgos y dependencias pendientes

- Persistencia transaccional y consumo único E5C2.
- Hashing con estrategia de pepper/versionado si el modelo persistente futuro lo exige.
- Emisión y almacenamiento seguro de la referencia de sesión.
- Callback OAuth y correlación real de navegador/sesión.
- Integración con E3B y E5B1 en un orquestador interno.
- Pruebas de concurrencia en Firestore Emulator y validación posterior en proyecto aislado.

## Reversión

Como no existen persistencia ni exposición operativa, la reversión consiste en retirar los dos módulos aislados, la prueba focal y este documento. No requiere migración, despliegue, limpieza de datos ni cambios en Firebase.
