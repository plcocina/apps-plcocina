# Módulo 3C-E5C2 — persistencia Challenge, Nonce y State

## Alcance

E5C2 agrega un servicio interno aislado para crear, consultar, consumir, revocar y materializar la expiración de challenges en Firestore. No agrega endpoints, triggers, OAuth, callback de navegador, sesiones, usuarios, provider linking, Access Grants, custom claims ni activación.

Todavía no existe transporte OAuth operativo ni integración con una sesión de navegador. Consumir un challenge tampoco consume un Google ID Token ni avanza por sí mismo la coordinación E5B1.

## Contratos reutilizados

El servicio reutiliza sin modificaciones `authChallengeDocumentSchema`, `createTrustedAuthChallengeContext()` y `evaluateAuthChallenge()` de E5C1. La generación usa `generateAuthChallengeSecrets()`; nonce y state se generan independientemente y sólo se persisten sus hashes SHA-256 canónicos mediante `hashAuthChallengeSecret()`.

El reloj y el generador se inyectan en el servicio. Esto permite pruebas deterministas sin sustituir las primitivas criptográficas productivas.

## Colección y modelo persistente

La única colección nueva es:

`identityAuthChallenges/{challengeId}`

Cada documento contiene exclusivamente el contrato E5C1: identificador, UID interno/Firebase, operación de coordinación, autorización, referencia opaca de sesión, hash opcional de subject Google, hashes de nonce/state, timestamps, estado, revisión y versión. El esquema estricto rechaza propiedades adicionales y documentos malformados.

Nonce y state en claro se entregan una sola vez en `oneTimeSecrets`, separado del documento persistido. Las consultas posteriores devuelven únicamente el documento sin secretos. No se persisten tokens, códigos OAuth, credenciales, secretos, respuestas arbitrarias del cliente ni evidencia adicional.

## Operaciones

- `create`: valida contexto interno, UID, protección de Super Admin y vigencia máxima de quince minutos; genera los tres valores criptográficos y crea el documento con revisión 1 dentro de una transacción. Una colisión de `challengeId` se rechaza sin sobrescribir.
- `get`: exige operador interno y coincidencia completa de UID, operación, autorización, sesión y subject esperado. Es sólo lectura y nunca reautoriza consumo.
- `consume`: relee y valida el documento dentro de una transacción, ejecuta todas las comprobaciones E5C1 y realiza exactamente una transición `issued -> consumed` con incremento único de revisión.
- `revoke`: sólo permite a contexto interno autorizado transicionar un challenge vigente `issued -> revoked`; no revierte consumo ni acepta revisión obsoleta.
- `expire`: materializa `issued -> expired` únicamente cuando el reloj confiable alcanzó `expiresAt`. La seguridad del consumo no depende de TTL ni de esta materialización.

## Consumo único, replay y concurrencia

Firestore Transaction proporciona exclusión optimista sobre el documento. Dos consumos simultáneos releen tras conflicto: uno confirma `consumed` y el otro observa el estado terminal y falla como replay. El perdedor no incrementa revisión, no escribe auditoría y no recibe nueva prueba de posesión.

La consulta repetida permanece permitida bajo el contexto completo. Cambios de UID, operación, autorización, sesión, subject, nonce, state o revisión se rechazan sin escritura. No existe una ruta idempotente que vuelva a autorizar un challenge consumido.

Consumo y revocación concurrentes producen un único estado terminal con revisión 2. En la frontera de expiración, el consumo falla cerrado y la materialización de expiración puede ganar la transacción. Un challenge vencido no se consume aunque todavía conserve materialmente el estado `issued`.

## Revisión, revocación y expiración

La revisión inicial es 1 y cada transición material válida la incrementa una vez. Consumo y revocación requieren revisión esperada mediante el contexto E5C1 o la entrada interna. Expiración también exige revisión para su primera materialización. Los estados `consumed`, `revoked` y `expired` no liberan secretos ni eliminan el documento, por lo que el mismo identificador no puede reutilizarse.

## Validación demostrada en Emulator

La suite `identity-auth-challenge.emulator.test.ts` usa Firestore Emulator real con el proyecto demo `demo-plcocina-apps` y confirma creación, colisión, ausencia de secretos persistidos, lectura contextual, consumo único concurrente, replay, conflictos, revisión obsoleta, inexistencia, documento malformado, subject opcional, revocación, expiración, carreras y ausencia de escrituras colaterales.

Los resultados concretos de las ejecuciones focalizadas se registran en el reporte de entrega. Estas pruebas demuestran semántica transaccional en Emulator; no constituyen validación en Firebase/Google Cloud real y no se realizó ninguna operación externa.

## Limitaciones y dependencias posteriores

- Falta un orquestador interno futuro que conecte E3B, E4B1, E5B1/E5B2 y este servicio.
- Falta el transporte seguro de los secretos de una sola entrega y la referencia real de sesión/navegador.
- Faltan callback OAuth, correlación de state, verificación completa del Google ID Token y provider linking; están deliberadamente fuera de alcance.
- La autorización interna actual sigue el patrón del Super Admin protegido usado por E5B2. Una política futura puede introducir un principal de servicio más específico sin debilitar las validaciones del challenge.
- No se configuró TTL; si se agrega para limpieza operativa, nunca deberá considerarse control de seguridad.

## Reversión

Antes de cualquier integración o despliegue, la reversión consiste en retirar el servicio, su suite, esta documentación y la entrada de la configuración Vitest. No requiere migrar, borrar ni reutilizar documentos. Si existieran documentos en un entorno futuro, deben conservarse como estados terminales o archivarse mediante un procedimiento explícito; no deben borrarse para habilitar replay.
