# IAM mínimo del backend administrativo

Este documento prepara la Fase 2B. No autoriza ni ejecuta cambios IAM.

## Separación de identidades

Se usarán tres identidades distintas:

1. Runtime: `portal-admin-api@plcocina-apps.iam.gserviceaccount.com`.
2. Despliegue: una cuenta de servicio distinta, federada desde GitHub.
3. Hosting: `github-firebase-deploy@plcocina-apps.iam.gserviceaccount.com`, sin permisos nuevos para Functions.

No se crearán claves privadas JSON. `adminApi` declara explícitamente la cuenta de runtime mediante la opción `serviceAccount` de Functions 2nd gen.

## Runtime: permisos actuales

Verificado en Google Cloud IAM el 22 de octubre de 2026. La cuenta runtime tiene asignados directamente:

- El rol personalizado `projects/plcocina-apps/roles/portalAdminAuthReader`, que contiene exclusivamente `firebaseauth.users.get`.
- `roles/datastore.user` para el acceso servidor a Firestore utilizado por aplicaciones y perfiles administrativos.

`firebaseauth.users.get` permite obtener y listar usuarios, además de la comprobación de revocación del Admin SDK. La Etapa A de usuarios no necesita crear, actualizar o eliminar usuarios ni enviar correo, por lo que no requiere cambios IAM.

## Etapas B–C7: permisos faltantes, pendientes de aprobación

La cuenta runtime **no tiene** `firebaseauth.users.update`. Este permiso es necesario para ejecutar `updateUser` durante suspensión, reactivación, establecimiento de contraseña y cierre seguro de estados ambiguos, además de `revokeRefreshTokens(uid)`.

No se modificó IAM. Antes de publicar Etapa B, un administrador deberá agregar exclusivamente `firebaseauth.users.update` al rol personalizado `portalAdminAuthReader` (o a un rol runtime igualmente acotado) y volver a verificar sus permisos efectivos. No se requieren `firebaseauth.users.create`, `firebaseauth.users.delete`, `firebaseauth.users.sendEmail` ni permisos para modificar Custom Claims.

El provisionamiento de cuentas provisionales mediante `createUser` requiere adicionalmente `firebaseauth.users.create`. La implementación local usa exclusivamente Auth Emulator y no modifica IAM.

El proveedor candidato es Resend, por lo que no se necesita `firebaseauth.users.sendEmail`. El adaptador externo permanece deshabilitado. C7 declara tres parámetros Gen 2 sin crear sus valores: `RESEND_API_KEY`, `RESEND_WEBHOOK_SIGNING_SECRET` e `INVITATION_TOKEN_KEY_V1`.

Cuando se autorice la activación, la cuenta runtime deberá recibir `roles/secretmanager.secretAccessor` por separado y únicamente sobre cada uno de esos tres secretos. No se concederá el rol sobre el proyecto completo. La cuenta de despliegue necesitará capacidad para asociar las versiones aprobadas a la función, pero no para leer sus valores.

## Runtime: permisos previstos para las siguientes etapas

Agregar únicamente cuando existan endpoints que los usen:

- `firebaseauth.users.create` (Etapa C2; identificado como faltante y pendiente de aprobación)
- `firebaseauth.users.update` (Etapa B; identificado como faltante y pendiente de aprobación)
- `firebaseauth.users.sendEmail` no se requiere para la arquitectura aprobada con proveedor transaccional
- acceso de lectura/escritura a documentos Firestore; inicialmente puede evaluarse `roles/datastore.user`, aunque se prefiere un rol personalizado después de medir las operaciones reales
- `roles/secretmanager.secretAccessor` sólo sobre el secreto concreto del proveedor de correo

No otorgar al runtime:

- `firebaseauth.users.delete`
- `firebaseauth.configs.getHashConfig`
- roles de Owner, Editor o Firebase Admin
- administración de IAM, Hosting, Functions, reglas o índices

## Identidad de despliegue dedicada

El workflow exige la variable de repositorio `FUNCTIONS_DEPLOY_SERVICE_ACCOUNT` y falla si coincide con la identidad de Hosting o de runtime. También exige `GCP_WORKLOAD_IDENTITY_PROVIDER`. La federación debe limitarse al repositorio `plcocina/apps-plcocina` y, de ser posible, al environment `admin-api-production` y la rama `main`.

La combinación de roles predefinidos soportada por Firebase para desplegar una función HTTPS es:

- `roles/cloudfunctions.admin` sobre el proyecto `plcocina-apps`.
- `roles/iam.serviceAccountUser` **sólo** sobre `portal-admin-api@plcocina-apps.iam.gserviceaccount.com`, para `iam.serviceAccounts.actAs`.
- `roles/iam.workloadIdentityUser` sobre la cuenta de despliegue, concedido exclusivamente al principal federado de GitHub autorizado.

Si las comprobaciones del Firebase CLI no están cubiertas por la política existente, añadir `roles/serviceusage.serviceUsageConsumer` sobre el proyecto. No conceder `roles/serviceusage.serviceUsageAdmin`: la identidad de despliegue no debe habilitar APIs.

`roles/cloudfunctions.admin` es el mínimo conjunto de roles predefinidos documentado por Firebase para funciones HTTPS; sigue siendo amplio. Después del primer despliegue controlado se deben revisar los permisos realmente utilizados y sustituirlo por un rol personalizado si la organización lo admite. No agregar de forma preventiva `roles/run.admin`, `roles/artifactregistry.admin`, `roles/editor` ni `roles/owner`.

La cuenta de despliegue no necesita permisos de administración de Firebase Authentication, Firestore, Hosting, reglas, índices o IAM. Este workflow despliega únicamente el codebase `functions:admin-api`.

## Identidades administradas de compilación

Functions 2nd gen usa Cloud Build, Artifact Registry y agentes de servicio administrados por Google. Sus permisos son independientes de la identidad de GitHub. Antes del primer despliegue, un administrador debe comprobar qué cuenta de compilación selecciona el proyecto y que conserva los roles de servicio requeridos. No se deben copiar esos permisos a la cuenta de despliegue ni a la cuenta de runtime.

## Invocación

La API recibe solicitudes HTTPS y aplica Firebase Authentication en la propia aplicación. La decisión de invocación pública de la función, ingress y eventual rewrite de Hosting se revisará antes del despliegue. CORS no sustituye la verificación del ID token.

## Condiciones previas

Antes de activar el workflow:

1. Crear o seleccionar una cuenta de servicio de despliegue dedicada, sin claves.
2. Configurar Workload Identity Federation y sus condiciones de repositorio/environment.
3. Aplicar únicamente los roles anteriores y verificar los agentes de servicio administrados.
4. Confirmar que las APIs necesarias ya están habilitadas mediante un proceso administrativo separado.
5. Configurar aprobación obligatoria para el environment de GitHub `admin-api-production`.

Ningún comando IAM ni despliegue forma parte de este cambio de repositorio.

## Referencias oficiales

- [IAM de proyectos Firebase](https://firebase.google.com/docs/projects/iam/permissions)
- [Identidad de ejecución de Functions](https://firebase.google.com/docs/functions/manage-functions#set_a_service_account)
- [Organización y despliegue por codebase](https://firebase.google.com/docs/functions/organize-functions?gen=2nd)
- [Workload Identity Federation para GitHub](https://github.com/google-github-actions/auth#readme)
