# Módulo 3C-E3A — matriz futura de pruebas de Google ID Tokens

Esta matriz describe pruebas previstas para 3C-E3B y fases posteriores. No registra resultados: ninguna de estas pruebas fue ejecutada por 3C-E3A.

## 1. Niveles de prueba

- **Local unitaria:** reloj, configuración, proveedor de claves y nonce inyectados; tokens/firmas de prueba controlados.
- **Local integración:** servidor JWKS/HTTP local, rotación y concurrencia sin servicios reales.
- **Firestore Emulator:** conciliación y reservas contra datos sintéticos; no prueba autenticidad de Google ni Firebase real.
- **Proyecto aislado posterior:** OAuth, tokens reales, account linking, UID, configuración de Client IDs y eventos Gen2. Requiere autorización expresa y queda fuera de E3A/E3B local.

## 2. Verificación criptográfica y claims

| ID | Caso | Resultado esperado | Nivel previsto |
|---|---|---|---|
| V-01 | Token correctamente firmado con todos los claims y políticas válidas | Devuelve identidad mínima `verified`, nunca `linked` | Local unitaria; confirmación aislada posterior |
| V-02 | Firma inválida o payload manipulado | `SIGNATURE_INVALID`, sin identidad parcial | Local unitaria |
| V-03 | Algoritmo no permitido o intento `none` | `ALGORITHM_NOT_ALLOWED` | Local unitaria |
| V-04 | Token vencido | `TOKEN_EXPIRED` aun con claims restantes correctos | Local unitaria |
| V-05 | `iss` distinto de los dos valores Google OIDC permitidos | `ISSUER_NOT_ALLOWED` | Local unitaria |
| V-06 | `aud` no incluida en la allowlist | `AUDIENCE_NOT_ALLOWED` | Local unitaria |
| V-07 | Token para Client ID Firebase/Google distinto al consumidor | Rechazo por audiencia; evita token confusion | Local unitaria; aislada posterior |
| V-08 | `iat` futuro dentro de tolerancia aprobada | Resultado conforme a política documentada | Local unitaria |
| V-09 | `iat` futuro fuera de tolerancia, ausente o incoherente con `exp` | `ISSUED_AT_INVALID` | Local unitaria |
| V-10 | `sub` ausente, vacío, demasiado largo o no canónico | `SUBJECT_INVALID` | Local unitaria |
| V-11 | `email_verified` ausente, falso o no booleano | `EMAIL_NOT_VERIFIED` | Local unitaria |
| V-12 | `email` ausente o inválido | `EMAIL_INVALID` | Local unitaria |
| V-13 | `hd` ausente | `HOSTED_DOMAIN_MISSING` | Local unitaria |
| V-14 | `hd` no autorizado, subdominio engañoso, caso/Unicode inválido | `HOSTED_DOMAIN_NOT_ALLOWED` | Local unitaria |
| V-15 | Correo, `hd` y política administrativa inconsistentes | `IDENTITY_CLAIMS_INCONSISTENT` | Local unitaria |
| V-16 | `azp` autorizado cuando aplica | Aceptación sólo si también cumple audiencia | Local unitaria |
| V-17 | `azp` ausente cuando es obligatorio o no autorizado | `AUTHORIZED_PARTY_NOT_ALLOWED` | Local unitaria |
| V-18 | Payload decodificado enviado por cliente sin token firmado | Rechazo antes de conciliación | Local unitaria/API futura |
| V-19 | Firebase ID Token presentado como Google ID Token | Rechazo por firma/emisor/audiencia | Local unitaria; aislada posterior |
| V-20 | Google ID Token presentado al backend que exige Firebase ID Token | Rechazo por el verificador Firebase existente | Proyecto aislado posterior |

## 3. Claves, caché, disponibilidad y configuración

| ID | Caso | Resultado esperado | Nivel previsto |
|---|---|---|---|
| K-01 | `kid` presente en caché vigente | Verificación sin consulta adicional | Local unitaria |
| K-02 | `kid` desconocido tras rotación | Un refresco controlado y nueva verificación | Local integración |
| K-03 | Dos verificaciones concurrentes requieren refresco | Una obtención deduplicada; resultados coherentes | Local integración |
| K-04 | Google/JWKS no disponible con clave válida en caché | Uso sólo dentro de vigencia y límites aprobados | Local integración |
| K-05 | Google/JWKS no disponible sin clave válida | `VERIFICATION_UNAVAILABLE`, fail-closed | Local integración |
| K-06 | Respuesta de claves malformada, algoritmo inesperado o URL no autorizada | Rechazo; no sustituir trust root | Local integración |
| K-07 | Fallo transitorio de claves | Reintentos acotados, sin bucle ni tormenta | Local integración |
| K-08 | Configuración sin emisores, audiencias, dominios o presentadores requeridos | `VERIFIER_MISCONFIGURED`, sin modo permisivo | Local unitaria |
| K-09 | Reloj inyectado en límites exactos de `iat`/`exp` | Comportamiento determinista en cada frontera | Local unitaria |

## 4. Nonce y replay

| ID | Caso | Resultado esperado | Nivel previsto |
|---|---|---|---|
| N-01 | Flujo exige nonce y el token no lo contiene | `NONCE_REQUIRED` | Local unitaria |
| N-02 | Nonce distinto, vencido o ligado a otra operación/sesión | `NONCE_INVALID` | Local unitaria/Firestore Emulator futuro |
| N-03 | Primer consumo válido de nonce | Aceptación y consumo atómico | Local integración/Firestore Emulator futuro |
| N-04 | Segundo consumo del mismo nonce | `NONCE_REPLAYED`, sin efectos parciales | Firestore Emulator futuro |
| N-05 | Dos consumos concurrentes | Exactamente un ganador si el diseño seleccionado usa consumo servidor | Firestore Emulator futuro |

Estas pruebas sólo aplican cuando el flujo OAuth y el contrato de nonce estén aprobados. E3A no afirma que exista hoy protección de replay.

## 5. Conciliación, vinculación y autorización

| ID | Caso | Resultado esperado | Nivel previsto |
|---|---|---|---|
| R-01 | Identidad Google válida sin reserva previa | Permanece sin vincular; rechazo o `reconciliation_required` | Firestore Emulator futuro |
| R-02 | Reserva `googleSubject` pertenece al UID esperado | Puede avanzar a revisión de vínculo, no enlaza sólo por verificar | Firestore Emulator futuro |
| R-03 | Reserva pertenece a otro UID | Conflicto, propietario intacto, sin escrituras parciales | Firestore Emulator futuro |
| R-04 | Correo coincide con otro UID pero `sub` no coincide | No apropiación ni reasignación por correo | Firestore Emulator futuro |
| R-05 | Cambio de correo/alias con mismo `sub` | Mantiene identidad del proveedor, exige política de actualización; no cambia UID automáticamente | Local/aislada posterior |
| R-06 | Mismo correo y dominio, `sub` diferente | Conciliación obligatoria | Firestore Emulator futuro |
| R-07 | Perfil `declared` recibe identidad verificada | Resultado máximo `verified`; no `linked` ni `active` | Firestore Emulator futuro |
| R-08 | Perfil pendiente o en conciliación intenta autorización | Fail-closed | Local/Firestore Emulator futuro |
| R-09 | Token válido sin Access Grant | Acceso denegado; no se crea grant | Local/Firestore Emulator futuro |
| R-10 | Intento de crear custom claims o perfil activo durante verificación | Ninguna escritura/efecto permitido | Local/Firestore Emulator futuro |
| R-11 | Identidad Google intenta adquirir `super_admin` | Rechazo; `super_admin` permanece password-only | Local/Firestore Emulator futuro |
| R-12 | Reintento equivalente de conciliación | Idempotente conforme a operación/revisión | Firestore Emulator futuro |

## 6. Proyecto aislado posterior

Requieren infraestructura y autorización fuera de 3C-E3A:

- Token Google real válido para cada Client ID aprobado.
- Comportamiento de `azp`, `nonce`, `hd`, alias y cambio de correo en el flujo elegido.
- Confusión real entre tokens Google y Firebase del proyecto.
- Account linking y conservación del UID precreado.
- Eventos Gen2 y credenciales observadas de forma sanitizada.
- Rotación real de claves, latencia y tolerancia a indisponibilidad.
- Suspensión/eliminación Workspace y cualquier señal administrativa adicional.

Estas validaciones no deben usar usuarios productivos ni afirmar resultados antes de ejecutarse en el proyecto aislado aprobado.

## 7. Criterios futuros de aprobación

3C-E3B sólo podrá considerarse localmente aprobado si todos los casos locales implementados pasan, los fallos son fail-closed, no existen logs sensibles, no hay escrituras de negocio desde el verificador y siguen separados verificación, conciliación y autorización. La aprobación local no autoriza OAuth, despliegue, account linking ni producción.
