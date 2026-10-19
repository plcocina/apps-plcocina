# Operación del primer Super Admin

Este procedimiento corresponde exclusivamente al proyecto Firebase `plcocina-apps` y a la cuenta inicial `hector@plcocina.com`. No crea usuarios, no cambia contraseñas y no modifica IAM ni Identity Platform.

## Controles previos

1. Copiar el UID de la cuenta inicial desde Firebase Console.
2. Validarlo por un segundo canal o una segunda persona autorizada.
3. Usar Cloud Shell o una estación administrativa controlada con MFA.
4. Autenticarse con Application Default Credentials o impersonación sin claves JSON.
5. Confirmar que la identidad ejecutora sólo tenga temporalmente estos permisos mínimos:
   - `firebaseauth.users.get`, para resolver la cuenta por UID y por correo.
   - `firebaseauth.users.list`, para comprobar que ninguna otra cuenta tenga `super_admin: true`.
   - `firebaseauth.users.update`, para asignar el Custom Claim únicamente en modo `--apply`.
6. No guardar el UID en archivos, historial compartido, CI ni GitHub Actions.

El script identifica la cuenta mediante las operaciones documentadas `getUser(uid)` y `getUserByEmail(email)` y exige que ambas búsquedas produzcan el mismo UID. No depende de `providerData` y no solicita `firebaseauth.configs.getHashConfig` ni acceso a hashes de contraseñas.

## Inspección sin cambios

Instalar exactamente las dependencias bloqueadas y ejecutar el modo predeterminado:

```bash
npm ci
read -r -p 'UID validado: ' EXPECTED_SUPER_ADMIN_UID
export EXPECTED_SUPER_ADMIN_UID
npm run super-admin:check
unset EXPECTED_SUPER_ADMIN_UID
```

La inspección falla de forma segura si el UID y `hector@plcocina.com` no resuelven a la misma cuenta, la cuenta está deshabilitada o existe otro usuario con `super_admin: true`.

## Asignación explícita

Ejecutar solamente después de revisar la salida de inspección:

```bash
read -r -p 'UID validado: ' EXPECTED_SUPER_ADMIN_UID
export EXPECTED_SUPER_ADMIN_UID
export CONFIRM_SUPER_ADMIN='assign:hector@plcocina.com'
npm run super-admin:apply
unset EXPECTED_SUPER_ADMIN_UID CONFIRM_SUPER_ADMIN
```

El script conserva otros Custom Claims, añade `super_admin: true` y vuelve a leer la cuenta para verificarlo. Después, retirar los permisos temporales o terminar la sesión de impersonación. El usuario debe cerrar sesión y volver a iniciarla para recibir un ID token actualizado.

## Revocación

Ante baja, cambio de funciones o sospecha de compromiso:

1. Deshabilitar temporalmente la cuenta si existe riesgo activo.
2. Desde un entorno administrativo autorizado, leer los claims actuales mediante Firebase Admin SDK.
3. Escribir nuevamente los claims existentes omitiendo `super_admin`; no usar `null` como valor de autorización.
4. Ejecutar `revokeRefreshTokens(uid)` para invalidar sesiones renovables.
5. Verificar que el usuario ya no tenga `super_admin === true`.
6. Registrar quién autorizó la revocación, cuándo se realizó y el UID afectado en el sistema administrativo externo; no guardar el UID en este repositorio.

Los backends futuros deben usar `verifyIdToken(token, true)` en cada solicitud para detectar tokens revocados y volver a comprobar que `super_admin === true`.

## Recuperación

Si se pierde acceso a la única cuenta Super Admin:

1. Recuperar primero la cuenta existente mediante un administrador autorizado de Firebase Authentication.
2. Si la cuenta fue comprometida, deshabilitarla, revocar sus refresh tokens y retirar su claim antes de promover otra cuenta.
3. Crear una cuenta sustituta sólo desde Firebase Console o Admin SDK en un entorno administrativo; nunca desde el portal Web.
4. Adaptar temporalmente el correo esperado del script mediante un cambio revisado y auditable, ejecutar inspección, obtener aprobación y aplicar contra el UID validado.
5. Restaurar el script a la identidad institucional aprobada o eliminar la variante temporal después del incidente.

No se debe habilitar registro público como mecanismo de recuperación.

## Consideraciones del frontend

La validación del claim en `/admin` evita mostrar el estado privado, pero no sustituye autorización de backend. El código HTML y JavaScript estático siempre es público. Ninguna operación privilegiada futura debe confiar únicamente en el navegador.
