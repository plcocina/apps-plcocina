# Desarrollo y operación del backend administrativo

## Alcance de Fase 3 — Administración de aplicaciones

La función `adminApi` conserva:

- `GET /api/admin/health`
- `GET /api/admin/me`

También expone endpoints CRUD y acciones de estado bajo `/api/admin/applications`. Todos requieren un ID token no revocado y el Custom Claim booleano `super_admin === true`. Las aplicaciones, sus reservas de unicidad y sus eventos de auditoría se escriben con Firebase Admin SDK dentro de transacciones. No existen endpoints para administrar usuarios, invitaciones o permisos.

`GET /api/catalog/applications` queda preparado para devolver únicamente aplicaciones activas y públicas. La portada no lo consume todavía.

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
