# Desarrollo y operación del backend administrativo

## Alcance actual — Aplicaciones y control de usuarios

La función `adminApi` conserva:

- `GET /api/admin/health`
- `GET /api/admin/me`

También expone endpoints CRUD y acciones de estado bajo `/api/admin/applications`. Todos requieren un ID token no revocado y el Custom Claim booleano `super_admin === true`. Las aplicaciones, sus reservas de unicidad y sus eventos de auditoría se escriben con Firebase Admin SDK dentro de transacciones.

La Etapa A del Módulo 2 añade consultas de sólo lectura bajo `/api/admin/users`. Combinan Firebase Authentication y `users/{uid}`, admiten paginación y correo exacto, detectan perfiles faltantes o huérfanos y nunca reparan datos automáticamente.

La Etapa B añade `POST /api/admin/users/:uid/suspend`, `reactivate` y `revoke-sessions`. Exigen `expectedRevision`; suspensión y revocación exigen motivo; todas exigen `Idempotency-Key` UUID. Las operaciones se coordinan en `adminOperations`, serializan cada perfil mediante `pendingOperationId` y registran eventos append-only. No existen endpoints de eliminación, cambio de claims ni permisos por aplicación.

Las Etapas C1/C2 añaden el provisionamiento recuperable de cuentas provisionales. C3 añade reenvío, revocación y conciliación de expiraciones. C4 añade `POST /api/invitations/validate`, `POST /api/invitations/establish-password` y `POST /api/invitations/:invitationId/confirm`. Validación y contraseña usan tokens propios, límites transaccionales y respuestas sin datos administrativos; confirmación exige ID token no revocado y coincidencia de UID y correo. La página local `/accept-invitation` implementa el flujo visual de aceptación sin persistir el token ni la contraseña.

El adaptador de Resend y `POST /api/webhooks/resend` están integrados técnicamente en el código local. Ambos permanecen cerrados mientras `RESEND_INVITATIONS_ENABLED` conserve su valor predeterminado `false`. Los parámetros secretos están declarados para una activación futura, pero sus valores no están configurados, no existe un proveedor externo habilitado y ninguna parte del Módulo 2 se ha desplegado a producción.

`GET /api/catalog/applications` devuelve únicamente aplicaciones activas y públicas y es consumido por la portada dinámica.

## Requisitos locales

- Node.js 22
- Java compatible con Firebase Emulator Suite
- Firebase CLI

No usar credenciales de producción para las pruebas. Los scripts de emuladores fijan el proyecto ficticio `demo-plcocina-apps`, que no puede acceder a recursos reales.

## Instalación y pruebas unitarias

```bash
npm --prefix functions ci
npm run functions:build
npm run functions:test
```

Las pruebas unitarias inyectan un verificador de tokens controlado. Cubren token ausente, inválido, expirado, revocado, usuario deshabilitado y claim incorrecto, sin llamar a Firebase Authentication.

## Pruebas de reglas con Emulator Suite

```bash
npm run functions:test:emulator
```

La prueba inicia únicamente el emulador de Firestore bajo `demo-plcocina-apps` y comprueba que clientes anónimos, usuarios autenticados e incluso clientes con `super_admin` no puedan leer o escribir directamente las colecciones administrativas.

Para inspección manual completa, sin conexión a producción:

```bash
firebase emulators:start --project demo-plcocina-apps --only auth,functions,firestore
```

## Configuración preparada

- Runtime Node.js 22 en `us-central1`.
- Cuenta de runtime fijada a `portal-admin-api@plcocina-apps.iam.gserviceaccount.com`.
- UID protegido configurado mediante `PROTECTED_SUPER_ADMIN_UID`; si falta o es inválido, los endpoints mutables responden 503 sin tocar datos.
- Claves de invitación inyectables y versionadas; los valores reales de Secret Manager no están configurados y los endpoints públicos fallan cerrados si no hay keyring.
- Proveedor simulado únicamente en emuladores y pruebas. El runtime tiene integrado el adaptador Resend, pero permanece deshabilitado por defecto mediante `RESEND_INVITATIONS_ENABLED=false`.
- Codebase `admin-api`, sin rewrites de Hosting.
- Workflow independiente `.github/workflows/firebase-functions-deploy.yml`.
- Disparo exclusivamente manual, confirmación literal `DEPLOY` y environment `admin-api-production`.
- Pruebas unitarias, estáticas y de reglas antes de autenticar o desplegar.
- Validación de las credenciales ADC federadas mediante Google Cloud SDK antes de invocar Firebase CLI.
- Despliegue limitado a `firebase deploy --only functions:admin-api`.

El archivo temporal `gha-creds-*.json` creado por la acción oficial de autenticación contiene configuración federada de corta duración, no una clave privada de cuenta de servicio; está ignorado por Git y la acción lo elimina al finalizar.

Firebase CLI detecta ADC mediante `GOOGLE_APPLICATION_CREDENTIALS`; no requiere `firebase login`, `FIREBASE_TOKEN` ni un archivo de clave privada. Después de `auth@v3`, el workflow configura `setup-gcloud@v3` y comprueba tanto la existencia del archivo temporal como el intercambio por un access token, redirigiendo el token a `/dev/null`. A continuación ejecuta `firebase functions:list` como preflight de sólo lectura para verificar que Firebase CLI también puede consumir ADC. Si alguna comprobación falla, el despliegue no comienza.

## Configuración administrativa pendiente

Antes del primer despliegue se debe:

1. Crear o elegir una cuenta de despliegue distinta de las cuentas de Hosting y runtime.
2. Configurar Workload Identity Federation y los permisos descritos en `docs/backend-iam.md`.
3. Crear las variables GitHub `FUNCTIONS_DEPLOY_SERVICE_ACCOUNT` y `GCP_WORKLOAD_IDENTITY_PROVIDER`.
4. Proteger el environment `admin-api-production` con revisores obligatorios y limitarlo a `main`.
5. Confirmar que las APIs de Cloud Functions, Cloud Run, Cloud Build y Artifact Registry ya estén habilitadas; el workflow no las habilita.
6. Verificar la cuenta de servicio de compilación elegida por Cloud Build y sus permisos administrados.
7. Confirmar la política de invocación HTTPS antes del primer despliegue. CORS y la autenticación de aplicación no reemplazan IAM de invocación.
8. Revisar las reglas Firestore existentes. Este workflow no despliega reglas ni índices.
9. Desplegar primero la función y sólo después considerar un rewrite de Hosting en otra fase.
10. Obtener aprobación y agregar únicamente `firebaseauth.users.update` al runtime antes de publicar Etapa B.

## Primer despliegue futuro

Después de completar IAM, ejecutar manualmente el workflow **Deploy adminApi Function** desde el commit aprobado en `main` e introducir `DEPLOY`. Un push no ejecuta este workflow.

Secuencia equivalente de validación local:

```bash
npm --prefix functions ci
npm run functions:build
npm run functions:test
npm run functions:test:emulator
firebase deploy --only functions:admin-api --project plcocina-apps
```

El selector `functions:admin-api` corresponde al campo `codebase` de `firebase.json`; despliega únicamente ese codebase. Las reglas, índices y Hosting no están incluidos.

## Reversión futura

1. Identificar una revisión estable anterior de la función.
2. Redirigir tráfico a esa revisión o volver a desplegar el commit aprobado anterior.
3. No revertir automáticamente documentos de Firestore.
4. No eliminar auditorías.
5. Si la función se considera comprometida, retirar temporalmente su invocación, revocar las sesiones afectadas y rotar secretos administrados.
6. Confirmar que Hosting continúa sirviendo la portada pública incluso si el backend está retirado.

## Seguridad operativa

- Nunca registrar el header `Authorization` ni ID tokens.
- No habilitar trazas con cuerpos administrativos completos.
- Mantener respuestas `no-store`.
- CORS sólo permite `https://apps.plcocina.com` en producción.
- Cada operación futura debe volver a verificar token, revocación, rol y estado de acceso.
