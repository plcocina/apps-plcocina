# Módulo 3C-D — plan del entorno aislado de validación

Este documento diseña el entorno de 3C-E. No autoriza crear proyectos, habilitar APIs, asociar facturación, cambiar IAM, configurar proveedores ni desplegar recursos.

## 1. Estado comprobado en el repositorio

- Rama y base revisadas: `codex/module-3a-access-grants` en `deb7e3d526c9e81c4bb7e08de42271ec154f4404`.
- El proyecto operativo configurado es `plcocina-apps`; Hosting usa el target `portal` y Functions el codebase `admin-api` en `us-central1`, runtime Node 22.
- Los emuladores locales usan el proyecto ficticio `demo-plcocina-apps` y puertos dedicados para Auth, Functions, Firestore y Hosting.
- `functions/src/index.ts` sólo exporta `adminApi`. Los handlers 3C-C no están registrados ni aparecen como triggers en el manifiesto actual.
- Firestore aplica denegación total a clientes. Admin SDK accede mediante IAM.
- 3C-A aporta perfiles v2, normalización, reservas HMAC y transiciones; 3C-B aporta UID determinista, preprovisión deshabilitada y conciliación; 3C-C aporta políticas `beforeCreate` y `beforeSignIn` aisladas.
- Los perfiles v1, invitaciones email/password, Super Admin y Access Grants continúan siendo dependencias de compatibilidad. Los permisos permanecen basados en UID y no se conceden durante autenticación.
- No hay evidencia local suficiente para afirmar que Identity Platform, Phone, Email Link, facturación, triggers o permisos correspondientes estén habilitados en ningún proyecto remoto. Todo ello queda pendiente de verificación autorizada.

## 2. Proyecto aislado propuesto

| Elemento | Propuesta para 3C-E |
|---|---|
| Nombre visible | `PL Cocina Identity Validation` |
| ID candidato | `plcocina-identity-validation` |
| Alternativa | `plcocina-idval-<sufijo-aprobado>`; nunca inferir disponibilidad ni reutilizar `plcocina-apps` |
| Organización/carpeta | Carpeta no productiva con políticas y propietarios separados |
| Región Functions | `us-central1`, igual al código actual, sujeto a confirmar disponibilidad de blocking functions |
| Runtime | Node 22 |
| Datos | Sólo identidades sintéticas; prohibido exportar o copiar usuarios de producción |
| Dominio | Dominio/subdominio de prueba separado; no autorizar `apps.plcocina.com` ni `auth.plcocina.com` |
| Duración | Proyecto temporal con propietario, fecha de revisión y procedimiento explícito de retiro |

Identity Platform es requisito: las blocking functions no están disponibles en Firebase Authentication sin la actualización. Cada handler debe responder en menos de siete segundos; exceder ese límite hace fallar la operación cliente. `beforeCreate` se ejecuta antes de persistir una cuenta y `beforeSignIn` después de verificar credenciales pero antes de emitir el ID token. Crear una cuenta desde cliente provoca ambos eventos. Referencia: [Identity Platform — blocking functions](https://cloud.google.com/identity-platform/docs/blocking-functions).

## 3. Recursos mínimos futuros

1. Proyecto Google Cloud/Firebase independiente y vinculado a una cuenta de facturación aprobada.
2. Firebase Authentication with Identity Platform.
3. Proveedores:
   - Phone, limitado inicialmente a números ficticios configurados para prueba.
   - Email/Password, necesario también para Email Link.
   - Email Link habilitado con `handleCodeInApp=true` y un dominio autorizado exclusivamente de prueba.
4. Firestore en Native mode y región aprobada, con reglas deny-by-default equivalentes a las actuales.
5. Colecciones mínimas: `users`, `adminOperations`, `identityOperations`, `authIdentifierKeys`, `invitations`, `invitationUniqueKeys`, `auditEvents` y `accessGrants`. No copiar documentos operativos.
6. Dos Functions Gen2 aisladas: una para `beforeCreate` y otra para `beforeSignIn`; no mezclar con `adminApi`.
7. Una cuenta runtime exclusiva de validación, una identidad de despliegue y una identidad humana/IAM de recuperación independientes.
8. Logging, métricas y alertas con redacción de correo, teléfono, tokens, enlaces y credenciales.

Email Link requiere habilitar Email/Password y Email Link, y el dominio de retorno debe estar autorizado. No debe incluirse el correo en parámetros de retorno; el enlace debe usar HTTPS. Referencia: [Firebase Email Link](https://firebase.google.com/docs/auth/web/email-link-auth).

## 4. Configuración y secretos

| Dato | Tratamiento |
|---|---|
| `PROTECTED_SUPER_ADMIN_UID` | Configuración obligatoria, exacta y validada antes de registrar `beforeSignIn`; no usar el UID operativo |
| Pepper HMAC de reservas | Secret Manager del proyecto aislado, versión independiente, mínimo 32 bytes, acceso sólo runtime de preprovisión |
| Config Firebase web | Valores exclusivos del proyecto aislado; no son secretos, pero deben pasar la allowlist de project ID |
| Credenciales de despliegue | Workload Identity Federation o sesión humana temporal; prohibidas claves JSON persistentes |
| Teléfonos/correos | Ficticios o buzones controlados de prueba; nunca datos de empleados |
| Tokens y enlaces | Sólo memoria/artefacto protegido de ejecución; nunca logs, URL de reporte ni Git |

El código de validación futuro debe abortar si `projectId` no coincide exactamente con el ID aislado aprobado, si encuentra `plcocina-apps`, si ADC pertenece a una cuenta productiva o si faltan etiquetas `environment=identity-validation` y `data-classification=synthetic`.

## 5. IAM mínimo por función

No se aplicará IAM en 3C-D. En 3C-E se debe validar cada permiso efectivo y preferir roles personalizados:

| Principal | Permisos mínimos previstos | Exclusiones |
|---|---|---|
| Runtime blocking | Lectura servidor de `users`, `adminOperations` e `invitations`; logging básico | Sin create/update/delete de Auth, IAM, Billing, Hosting ni Secret Manager |
| Runtime preprovisión | `firebaseauth.users.get`, `firebaseauth.users.create`, `firebaseauth.users.update`; lectura/escritura acotada de Firestore; acceso sólo al pepper | Sin delete, configuración Auth, claims administrativos ni acceso a secretos ajenos |
| Despliegue Functions | Desplegar exclusivamente las dos Functions, `iam.serviceAccounts.actAs` sólo sobre su runtime y consumo de servicios | Sin administración de Auth, Billing, IAM o producción |
| Configuración Identity Platform | Acceso temporal para `firebaseauth.configs.get/update`; separar de despliegue | No mantener `roles/identityplatform.admin` permanentemente: incluye `firebaseauth.*`, delete y lectura de secretos |
| Recuperación | Dos operadores humanos IAM con MFA, fuera de Firebase Auth, capaces de leer configuración, desregistrar triggers y gestionar Functions | No depender de un inicio de sesión bloqueado por los propios triggers |
| Auditoría | `roles/identityplatform.viewer`, lectura de Functions/Logging y Firestore según necesidad | Sin permisos de mutación |

Los roles predefinidos de Identity Platform son amplios; `roles/identityplatform.admin` concede acceso total. Antes de usarlo temporalmente, documentar por qué un rol personalizado no cubre la operación y retirar el grant al finalizar. Referencias: [roles de Identity Platform](https://cloud.google.com/iam/docs/roles-permissions/identityplatform), [control de acceso](https://cloud.google.com/identity-platform/docs/access-control) y [permisos Firebase IAM](https://firebase.google.com/docs/projects/iam/permissions).

## 6. Facturación, cuotas y límites

- El proyecto debe estar asociado a facturación antes de Identity Platform y Phone. El precio de SMS depende del destino; confirmar la tarifa vigente antes de 3C-E: [precios Identity Platform](https://cloud.google.com/identity-platform/pricing).
- Configurar presupuesto exclusivo del proyecto, alertas de gasto real y previsto en umbrales 25 %, 50 %, 75 %, 90 % y 100 %, responsables nominales y revisión diaria durante pruebas.
- Un presupuesto de alertas no es un límite duro. Definir además límite operativo: cantidad máxima de identidades, SMS, Email Links y ejecuciones por jornada; detener manualmente al alcanzarlo. Referencia: [presupuestos y alertas](https://cloud.google.com/billing/docs/how-to/budgets).
- Usar números ficticios para la mayoría de Phone tests. Los SMS reales requieren aprobación individual y un máximo previo; existen límites por proyecto, IP y número. Las blocking functions tienen una cuota documentada de 4,000 invocaciones/minuto. Referencias: [cuotas Identity Platform](https://cloud.google.com/identity-platform/quotas) y [límites Firebase Auth](https://firebase.google.com/docs/auth/limits).
- Alertas mínimas: coste, SMS enviados, errores/latencia de blocking functions, 5xx, timeout, `reconciliation_required`, fallos del Super Admin y cambios de configuración Auth.

## 7. Barreras contra producción

1. No añadir el proyecto aislado como `default` en `.firebaserc` del repositorio operativo.
2. Usar un checkout/CI environment separado y comandos con `--project <ID-aislado>` literal; nunca alias ambiguos.
3. Verificar project number, project ID, cuenta runtime, región y etiquetas antes de cada mutación.
4. Denegar en CI cualquier valor `plcocina-apps`, dominio operativo, UID protegido operativo o cuenta `portal-admin-api@plcocina-apps.iam.gserviceaccount.com`.
5. No reutilizar secretos, cuentas de servicio, Workload Identity pools, buckets, Hosting targets ni dominios de producción.
6. Mantener Firestore vacío salvo fixtures sintéticos versionados sin PII.
7. Capturar antes/después de configuración con comandos de sólo lectura; una segunda persona aprueba registro y desregistro de triggers.

## 8. Secuencia autorizable para 3C-E

1. Aprobar ID, propietario, facturación máxima, región, IAM y vía de recuperación.
2. Crear proyecto y asociar Firebase mediante un cambio administrativo separado.
3. Aplicar etiquetas, presupuesto y alertas antes de habilitar Phone.
4. Configurar cuentas IAM separadas y verificar permisos efectivos.
5. Crear Firestore deny-by-default y cargar sólo fixtures sintéticos.
6. Actualizar a Identity Platform; configurar proveedores de prueba y dominio aislado.
7. Desplegar Functions sin registrar triggers; probar health directo y latencia.
8. Crear y verificar Super Admin sintético y dos operadores IAM de recuperación.
9. Registrar primero `beforeSignIn`, ejecutar la matriz y probar rollback.
10. Registrar `beforeCreate`, repetir creación, resiliencia y rollback.
11. Exportar evidencia sanitizada, desregistrar triggers si concluye la ventana y decidir continuar o retirar el entorno.

## 9. Criterios para no iniciar 3C-E

No continuar si falta cualquiera de estos elementos: ID aislado confirmado, facturación y presupuesto aprobados, números/buzones sintéticos, dos operadores IAM de recuperación, `PROTECTED_SUPER_ADMIN_UID` de prueba, permisos efectivos revisados, rollback ensayable, métricas de latencia, límite de SMS, separación comprobable de producción o aprobación explícita para registrar triggers.

## 10. Clasificación de decisiones

### Decisiones aprobadas

- Separación total de `plcocina-apps`, datos exclusivamente sintéticos, `us-central1` como región candidata coherente con el repositorio y ninguna credencial/UID/dominio productivo.
- Identity Platform es condición técnica para blocking functions; los triggers se prueban y registran por separado, con recuperación IAM independiente.
- Firestore continúa deny-by-default para clientes y los handlers no crean grants ni claims.

### Recomendaciones sujetas a aprobación

- ID `plcocina-identity-validation` o variante disponible; presupuesto por proyecto y límites operativos de SMS/identidades.
- Roles personalizados mínimos, dos operadores con MFA y Workload Identity Federation en lugar de claves persistentes.
- Registrar `beforeSignIn` antes de `beforeCreate`, con captura de configuración y rollback entre pasos.

### Hipótesis que 3C-E debe verificar

- Disponibilidad/región efectiva de los triggers Gen2, valores reales de eventos, bypass o no de Admin SDK, latencia, costes/cuotas vigentes y comportamiento de account linking.
- Configuración OAuth exacta, dominios autorizados y efecto de suspensión Workspace.

### Bloqueantes

- Falta de vía IAM independiente, facturación/límite aprobados, proyecto inequívocamente aislado, política de account linking, datos sintéticos o demostración de rollback.
- Cualquier comando/configuración que apunte a `plcocina-apps` o cualquier necesidad de copiar usuarios/secretos de producción.

## Referencias oficiales

- [Blocking functions](https://cloud.google.com/identity-platform/docs/blocking-functions)
- [Identity Platform pricing](https://cloud.google.com/identity-platform/pricing)
- [Identity Platform quotas](https://cloud.google.com/identity-platform/quotas)
- [Firebase Email Link](https://firebase.google.com/docs/auth/web/email-link-auth)
- [Firebase Authentication limits](https://firebase.google.com/docs/auth/limits)
- [Identity Platform IAM roles](https://cloud.google.com/iam/docs/roles-permissions/identityplatform)
- [Cloud Billing budgets](https://cloud.google.com/billing/docs/how-to/budgets)
