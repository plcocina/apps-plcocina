# IAM mínimo del backend administrativo

Este documento prepara la Fase 2B. No autoriza ni ejecuta cambios IAM.

## Separación de identidades

Se usarán tres identidades distintas:

1. Runtime: `portal-admin-api@plcocina-apps.iam.gserviceaccount.com`.
2. Despliegue: una cuenta de servicio distinta, federada desde GitHub.
3. Hosting: `github-firebase-deploy@plcocina-apps.iam.gserviceaccount.com`, sin permisos nuevos para Functions.

No se crearán claves privadas JSON. `adminApi` declara explícitamente la cuenta de runtime mediante la opción `serviceAccount` de Functions 2nd gen.

## Runtime: permisos actuales

Los endpoints de Fase 2A sólo verifican tokens y revocación. La cuenta de runtime necesita:

- `firebaseauth.users.get`: requerido por la comprobación de usuario y revocación del Admin SDK.
- `logging.logEntries.create`, normalmente mediante `roles/logging.logWriter`.

No necesita todavía crear, listar, actualizar o eliminar usuarios, ni leer o escribir Firestore.

## Runtime: permisos previstos para las siguientes etapas

Agregar únicamente cuando existan endpoints que los usen:

- `firebaseauth.users.list`
- `firebaseauth.users.create`
- `firebaseauth.users.update`
- `firebaseauth.users.sendEmail`, si el flujo de invitación elegido lo requiere
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
