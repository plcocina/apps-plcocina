# Módulo 3C-E5D1 — contratos de orquestación de identidad

## Alcance

E5D1 define exclusivamente contratos internos y política pura para coordinar evidencia de E3B, E4B1/E4B2, E5B2 y E5C2. No llama servicios, no persiste, no consume challenges, no ejecuta OAuth, no vincula providers, no crea usuarios y no activa identidades.

Una decisión `proceed` significa que las precondiciones lógicas están satisfechas; no demuestra que una escritura o efecto externo haya ocurrido. Las garantías transaccionales corresponden a E5D2.

## Contratos incorporados

`AuthOrchestrationInput` liga estrictamente:

- operación e idempotency key;
- UID Firebase e interno idénticos;
- hash canónico del Google subject;
- challenge, autorización y sesión opaca;
- estado y revisión esperados de coordinación;
- acción solicitada y hora del contexto;
- evidencias Google, Challenge, administrativa y de coordinación;
- fallo parcial observado, cuando existe;
- `activationRequested=false` como invariante contractual.

Los esquemas son estrictos y no admiten permisos, UID, subject ni campos arbitrarios del cliente. No contienen Google/Firebase ID Tokens, nonce, state, refresh tokens, códigos OAuth ni secretos.

## Evidencias y reglas de confianza

| Evidencia | Fuente obligatoria futura | Acredita |
|---|---|---|
| Google | E3B `google-token-verifier` | firma, issuer, audience, vigencia, subject, Workspace y nonce |
| Challenge | E5C2 `identity-auth-challenge-service` | ligadura UID/operación/autorización/sesión, vigencia y estado `validated` o `consumed` |
| Administrativa | E4B1/E4B2 | UID/subject autorizado, revisión, vigencia, estado local bloqueado y `linked_pending_activation` |
| Coordinación | E5B2 | operación, estado, revisión, idempotencia y ausencia de conflicto bloqueante |

Las fábricas internas añaden marcas no serializables para impedir que un objeto estructural común sea aceptado accidentalmente. Esa marca TypeScript/JavaScript no es una frontera de seguridad: en E5D2 cada adaptador debe leer o comprobar nuevamente la evidencia desde su servicio confiable, dentro del backend. Ningún cuerpo del cliente puede llamar una fábrica y convertirse por ello en evidencia.

## Flujo lógico seguro

El orden compatible con las dependencias reales es:

1. Autenticar y recuperar el contexto interno autorizado; fijar UID, operación y sesión desde servidor.
2. Confirmar que E4B2 ya dejó la identidad Firestore en `linked_pending_activation`, `authDisabled=true`, con reserva subject→UID correcta. El correo nunca elige UID.
3. Recuperar E5B2 y E5C2; comprobar operación, UID, autorización, sesión, estado y revisiones sin consumir.
4. Verificar criptográficamente el Google ID Token mediante E3B y el nonce emitido por E5C2.
5. Comparar el subject verificado con challenge, autorización, reserva y coordinación.
6. Revalidar autorización administrativa, suspensión y vigencia inmediatamente antes de escribir.
7. Consumir el challenge y persistir `google_proof_verified` como una sola unidad Firestore.
8. Sólo después, preparar la futura llamada de provider Firebase; mantener acceso y activación denegados.
9. Observar postflight desde Firebase Admin antes de confirmar el provider en coordinación.
10. Dejar cualquier activación para un módulo y autorización administrativa independientes.

La propuesta conceptual original situaba E4B2 al final. Los contratos E5A/E5B existentes demuestran que el vínculo Firestore y su reserva son precondiciones de `not_started -> challenge_issued`; por ello E5D1 conserva ese orden real y no vuelve a ejecutar E4B2.

## Decisiones puras

| Decisión | Significado | Reintento |
|---|---|---|
| `proceed` | Precondiciones lógicas satisfechas | Sólo mediante el paso señalado y su límite transaccional |
| `replay` | Mismo idempotency key y mismo request hash ya observado | Consultar resultado; nunca consumir de nuevo |
| `pending` | Firestore, Firebase Auth o postflight aún no confirmado | Observar realidad antes de continuar |
| `blocked` | Suspensión, revocación o estado bloqueado | Intervención administrativa |
| `reconciliation_required` | Efectos contradictorios o externos desconocidos | Prohibido reintentar hasta observar y conciliar |
| `reject` | Contrato, evidencia o precondición inválida | Corregir contexto; sin efecto |

La política valida UID, subject, challenge, sesión, autorización, vigencia, estado, revisión, idempotencia, confianza y prohibición de activación. Es determinista y no muta entradas.

## Estados, fallos parciales y recuperación

- `challenge_consumed_coordination_pending`: permite persistir solamente el resultado ya consumido; `consumeChallengeAgain=false`.
- `coordination_updated_challenge_pending`: contradicción insegura; requiere conciliación y no permite reintento ciego.
- `authorization_revoked_during_operation`: bloqueado para intervención.
- `reservation_owned_by_other_uid`: conciliación; nunca merge, unlink ni cambio de UID automático.
- `firestore_link_pending`: observar la operación Firestore existente.
- `firestore_linked_firebase_auth_pending`: mantener acceso denegado y observar Firebase Auth.
- `external_result_unknown`: conciliación antes de repetir efectos externos.
- `postflight_pending`: consultar postcondición, no repetir provider linking.

Una consulta de resultado anterior no constituye una autorización nueva. Sólo un replay con la misma clave y el mismo hash puede recuperar el resultado registrado. Reutilizar la clave con otro hash se rechaza como `IDEMPOTENCY_CONFLICT`.

No se declara recuperable un paso cuando sus efectos no pueden demostrarse. No existen compensaciones destructivas: unlink, merge, borrado/recreación y transferencia de reserva están prohibidos.

## Bloqueos obligatorios para E5D2

1. E5D2 no puede implementar consumo E5C2 y transición E5B2 como dos transacciones independientes. Debe agrupar ambas escrituras en una única transacción Firestore o crear previamente una operación durable que bloquee de forma fail-closed y permita confirmar el challenge ya consumido sin volver a consumirlo.
2. La llamada Firebase Auth nunca puede compartir ACID con Firestore. Debe ejecutarse como saga bloqueada, seguida de observación Admin y postflight idempotente.
3. No se puede avanzar cuando la autorización fue revocada/caducó, el usuario está suspendido, la reserva pertenece a otro UID o existe estado bloqueado/conciliación.
4. `linked_pending_activation` no concede acceso. E5D2 no puede producir `active`, Access Grants, custom claims ni privilegios.

## Pruebas focalizadas

La suite `identity-auth-orchestration.test.ts` usa datos sintéticos y cubre contrato estricto, UID/subject/challenge/sesión, evidencias ausentes/no confiables/caducadas, consumo previo, revisión/estado, suspensión, bloqueos, replay equivalente/conflictivo, fallos parciales, conciliación, transiciones de provider, Super Admin, activación prohibida y ausencia de efectos secundarios.

Las pruebas son puras. No simulan persistencia ni presentan una integración como implementada.

## Limitaciones

- No existe orquestador persistente E5D2.
- No existe callback OAuth ni transporte de navegador.
- No existe atomicidad distribuida Firebase Auth/Firestore.
- Las marcas internas requieren adaptadores backend correctamente encapsulados.
- No se ha ejecutado provider linking ni validación en proyecto Firebase real.

## Reversión

La reversión consiste en retirar los dos módulos puros, su prueba y este documento. No requiere migración, limpieza Firestore, cambios de Auth ni despliegue porque E5D1 no expone handlers ni ejecuta efectos.
