# APPS PL COCINA
Portal institucional de aplicaciones operativas.

- Proyecto Firebase: plcocina-apps
- Sitio Hosting adicional previsto: plcocina-portal
- Dominio personalizado previsto: apps.plcocina.com
- Aplicación actual: https://calculadora-burritos.plcocina.com/

## Estructura

- `public/`: único contenido publicado por Firebase Hosting.
- `public/admin/`: acceso privado para Super Admin; no contiene módulos administrativos.
- `scripts/`: utilidades locales con Firebase Admin SDK. Nunca se publican en Hosting.
- `docs/`: procedimientos operativos y de seguridad.

## Validación local

```bash
npm ci
npm run check
```

El inicio de sesión de `/admin` usa Firebase Authentication con correo y contraseña. El navegador sólo muestra el estado privado cuando el ID token contiene el Custom Claim booleano `super_admin === true`. Toda operación administrativa futura deberá volver a verificar el ID token y el rol en un backend autorizado.

Antes de habilitar despliegue automático, crear el sitio Hosting adicional y autorizar el repositorio en Workload Identity Federation. Usar únicamente `firebase deploy --only hosting:portal --project plcocina-apps` para evitar modificar el sitio por defecto.

## Administración y permisos

La portada de `apps.plcocina.com` permanece pública. `/admin` implementa únicamente autenticación y comprobación del Custom Claim `super_admin`; todavía no contiene módulos ni operaciones administrativas.

La comprobación del navegador evita mostrar el estado privado a usuarios no autorizados, pero no sustituye la autorización de servidor. Cada operación futura deberá enviar el ID token por HTTPS a un backend que ejecute `verifyIdToken(token, true)` y exija `super_admin === true` antes de procesarla.

El procedimiento controlado para establecer, revocar o recuperar el primer Super Admin se encuentra en `docs/super-admin-bootstrap.md`.
