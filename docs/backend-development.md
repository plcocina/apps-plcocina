# Desarrollo y operación del backend administrativo

## Alcance de Fase 2A

La función `adminApi` contiene únicamente:

- `GET /api/admin/health`
- `GET /api/admin/me`

Ambos endpoints requieren un ID token no revocado y el Custom Claim booleano `super_admin === true`. No existen endpoints para crear usuarios, aplicaciones o permisos.

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

## Configuración de producción pendiente

Antes del primer despliegue se debe:

1. Crear una cuenta de servicio de runtime sin claves.
2. Asignar sólo los permisos revisados en `docs/backend-iam.md`.
3. Declarar esa cuenta en la configuración de `adminApi`.
4. Confirmar región `us-central1`, límites, concurrencia, ingress y política de invocación.
5. Revisar las reglas Firestore existentes del proyecto. Desplegar este archivo sin integrar reglas preexistentes podría bloquear otras cargas.
6. Crear Firestore e índices únicamente después de aprobar el entorno y la ubicación de datos.
7. Crear un workflow de backend separado. El workflow existente de Hosting debe conservar `--only hosting:portal`.
8. Desplegar primero la función y sólo después considerar un rewrite de Hosting.

## Despliegue futuro

Los comandos siguientes son referencia y no deben ejecutarse durante Fase 2A:

```bash
npm --prefix functions ci
npm run functions:build
npm run functions:test
npm run functions:test:emulator
firebase deploy --only functions:admin-api --project plcocina-apps
```

El selector definitivo de despliegue deberá verificarse contra el codebase antes de crear el workflow. Las reglas e índices se desplegarán en una operación separada y con revisión explícita.

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
