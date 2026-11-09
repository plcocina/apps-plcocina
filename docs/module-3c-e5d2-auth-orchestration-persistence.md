# Módulo 3C-E5D2 — orquestación persistente de identidad

## Alcance y decisión de atomicidad

E5D2 implementa un servicio interno aislado para verificar evidencia Google fuera de Firestore y coordinar dentro de una única transacción el consumo E5C2 y la transición E5B2 `challenge_issued -> google_proof_verified`.

La revisión arquitectónica confirmó que la atomicidad es viable sin alterar contratos públicos. E5C2 y E5B2 ahora exponen primitivas internas de preparación transaccional: realizan lecturas y validaciones, devuelven las escrituras diferidas y permiten que E5D2 aplique ambos conjuntos sólo después de validar E4B2 y E5D1. Sus métodos públicos existentes conservan firma y semántica y siguen ejecutando sus propias transacciones cuando se usan aisladamente.

No hay transacciones anidadas, llamadas externas dentro del callback ni verificación criptográfica dentro de Firestore. No se implementan OAuth, callback, Firebase Auth Provider Linking, activación, usuarios, sesiones, Access Grants, claims, endpoints o triggers.

## Servicios reutilizados

- E3B mediante `InternalGoogleIdentityVerifier`, cuya implementación productiva debe ser `GoogleIdentityTokenVerifier`.
- E4B2 mediante documentos reales `users/{uid}`, `authIdentifierKeys/{subjectHash}` e `identityLinkAuthorizations/{authorizationId}`.
- E5B1 mediante `createTrustedAuthCoordinationEvent()` y `evaluateAuthCoordinationTransition()` invocado por E5B2.
- E5B2 mediante `prepareAuthCoordinationTransition()`.
- E5C1 mediante `createTrustedAuthChallengeContext()` y validación criptográfica nonce/state.
- E5C2 mediante `prepareAuthChallengeConsumption()`.
- E5D1 mediante evidencias creadas desde documentos leídos y `evaluateAuthOrchestration()`.

Los dobles del verificador E3B sólo existen en pruebas. La implementación no acepta objetos de evidencia Google proporcionados por el cliente.

## Modelo transaccional

Antes de la transacción:

1. Validar actor interno protegido e identificadores estrictos.
2. Leer el contexto de coordinación para fijar UID, subject, challenge y autorización desde Firestore.
3. Verificar criptográficamente el Google ID Token con E3B y nonce confiable.
4. Derivar el hash de subject con el mismo pepper y función E4B2.
5. Crear el evento E5B1 determinista. La evidencia temporal usa `iat`/`exp` firmados para que un reintento equivalente produzca el mismo hash.

Dentro de una única transacción Firestore:

1. Leer operación, idempotencia y locks E5B2.
2. Si existe un replay equivalente, validar que el challenge durable esté consumido y ligado al mismo UID implícito, operación, autorización, sesión y subject; devolver el resultado sin escribir.
3. Leer perfil, reserva de subject y autorización E4B2.
4. Exigir perfil `linked`, `linked_pending_activation`, `authDisabled=true`, revisión exacta y usuario no suspendido.
5. Exigir reserva `googleSubject` perteneciente al mismo UID.
6. Exigir autorización E4B2 consumida por la operación de vínculo exacta, emitida por el administrador protegido y todavía vigente.
7. Leer y validar el challenge E5C2, incluida revisión, sesión, nonce, state y subject Google verificado.
8. Construir evidencias E5D1 desde los documentos comprobados y exigir `atomic_consume_and_record`.
9. Escribir challenge consumido, coordinación, locks, idempotencia y auditoría determinista.

Todas las lecturas ocurren antes de cualquier escritura. Una excepción en cualquier paso aborta el conjunto completo.

## Idempotencia, replay y concurrencia

La idempotencia durable sigue siendo `identityAuthCoordinationIdempotency/{idempotencyKey}` con el hash canónico del evento E5B1. El evento contiene identificadores, UID, subject, revisiones y evidencia Google estable.

- Primer intento: challenge `issued -> consumed` y coordinación revisión 2→3.
- Replay equivalente: devuelve la coordinación durable y revisión del challenge; `challengeConsumedAgain=false`; no escribe ni audita.
- Reutilización conflictiva: E5B2 rechaza el hash diferente antes de cualquier escritura.
- Dos intentos equivalentes simultáneos: uno confirma y el reintento transaccional del otro observa idempotencia durable.
- Dos intentos conflictivos: exactamente uno puede confirmar.
- Otra ruta que consume primero el challenge no autoriza la transición E5D2.

El resultado no contiene token, nonce, state ni una nueva evidencia utilizable para provider linking.

## Auditoría y fallos parciales

La auditoría reutiliza `auditEvents/auth-coordination-{operationId}-{revision}` de E5B2 y se crea en la misma transacción. No se introduce una segunda auditoría E5D2. Una colisión del documento de auditoría aborta challenge, coordinación, locks e idempotencia.

Una respuesta ambigua después del commit se resuelve repitiendo exactamente la misma clave y evento; el documento idempotente demuestra el resultado. Si no existe, Firestore no confirmó la unidad. No hay estado intermedio `challenge_consumed_coordination_pending` producido por E5D2.

Resultados externos desconocidos, coordinación bloqueada, reserva conflictiva, autorización revocada, perfil suspendido o vínculo E4B2 incompleto fallan cerrados. No se realizan unlink, merge, borrado, recreación ni reasignación automática.

## Seguridad preservada

- UID Firebase e interno permanecen idénticos.
- El subject se deriva de E3B y se compara con coordinación, perfil, reserva, autorización y challenge.
- El correo nunca decide UID.
- `linked_pending_activation` y `authDisabled=true` permanecen invariantes.
- Super Admin sólo actúa como contexto administrativo y nunca es UID objetivo.
- No se crean usuarios Firebase, sesiones, grants, claims ni privilegios.
- SMS, Email Link, Password v1, handlers, UI, Hosting y reglas Firestore no cambian.

## Pruebas Emulator

`identity-auth-orchestration.emulator.test.ts` usa exclusivamente `demo-plcocina-apps` y Firestore Emulator real. Cubre primer intento, concurrencia equivalente/conflictiva, doble consumo, revisión, replay durable, challenge consumido/expirado/revocado, autorización revocada, suspensión, reserva ajena, E4B2 incompleto, coordinación bloqueada, resultado desconocido, fallo de auditoría, reintento después de aborto, subject conflictivo, auditoría única y ausencia de activación/privilegios.

Estas pruebas demuestran semántica transaccional en Emulator. No validan IAM, Firebase Auth real, provider linking ni comportamiento de un proyecto Firebase real.

## Limitaciones y dependencias posteriores

- No existe transporte OAuth ni callback que invoque el servicio.
- La interfaz E3B debe inyectarse sólo desde composición interna confiable futura.
- La vigencia administrativa se revalida en la transacción; un replay sólo consulta un resultado ya durable.
- Provider linking y postflight siguen bloqueados hasta un módulo posterior con saga observable.
- Firebase Auth nunca participa en la transacción Firestore.

## Reversión

Retirar el servicio E5D2, su suite, esta documentación y la entrada Vitest. Revertir las dos extracciones transaccionales restablece la implementación inline previa sin migrar datos ni modificar contratos. Los documentos de auditoría y operaciones de entornos de prueba deben preservarse; no se liberan locks ni se borran challenges para habilitar replay.
