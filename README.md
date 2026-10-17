# APPS PL COCINA
Portal institucional de aplicaciones operativas.

- Proyecto Firebase: plcocina-apps
- Sitio Hosting adicional previsto: plcocina-portal
- Dominio personalizado previsto: apps.plcocina.com
- Aplicación actual: https://calculadora-burritos.plcocina.com/

Antes de habilitar despliegue automático, crear el sitio Hosting adicional y autorizar el repositorio en Workload Identity Federation. Usar únicamente `firebase deploy --only hosting:portal --project plcocina-apps` para evitar modificar el sitio por defecto.

## Administración y permisos

La portada en `apps.plcocina.com` debe permanecer pública. El enlace `Admin` reserva la ruta `/admin`, pero el repositorio no publica todavía contenido en esa ruta: Firebase Hosting estático no puede autenticar ni autorizar por sí solo. Hasta completar el backend, `/admin` debe responder con el 404 normal del Hosting y no debe contener una pantalla administrativa, credenciales de prueba ni bypasses de desarrollo.

### Arquitectura prevista

1. Usar Firebase Authentication únicamente para iniciar sesión. Habilitar proveedores de correo que no restrinjan el dominio del usuario (por ejemplo, enlace por correo o Google más el flujo que se decida), con creación pública de cuentas bloqueada en la capa de aplicación y del backend.
2. Mantener una lista de usuarios autorizados en Cloud Firestore, creada y modificada exclusivamente por un Super Admin mediante endpoints protegidos. Una identidad autenticada que no esté autorizada no obtiene acceso a ninguna aplicación.
3. Asignar el rol global `super_admin` mediante Firebase custom claims desde un entorno privilegiado. El cliente puede usar el claim para navegación, pero nunca como control de acceso definitivo.
4. Colocar `/admin` detrás de un backend (Cloud Run o Cloud Functions) que verifique en cada solicitud la cookie de sesión o el ID token con Firebase Admin SDK y exija el custom claim `super_admin`. Responder `401` sin sesión y `403` sin el rol. Solo después de desplegar y probar este control se debe publicar la interfaz administrativa.
5. Modelar permisos individuales por aplicación en Firestore (por ejemplo, `users/{uid}` con un mapa o subcolección de permisos). Toda API de una aplicación debe verificar en el servidor el permiso correspondiente; ocultar enlaces en el portal es solo una mejora de experiencia.
6. Proteger Firestore con reglas de denegación por defecto. Las escrituras administrativas deben pasar por el backend; los clientes no deben poder otorgarse roles ni permisos.
7. Mantener el target de Hosting `portal` y el workflow actual. Cuando exista el backend, agregar su despliegue como un job separado y configurar una rewrite exacta para `/admin` y sus recursos, sin convertir la portada ni las aplicaciones existentes en contenido privado.

### Condiciones para habilitar `/admin`

- Firebase Authentication configurado sin registro público utilizable.
- Sesiones verificadas por el backend, incluyendo revocación.
- Custom claim `super_admin` emitido solo desde un entorno privilegiado.
- Respuestas `401` y `403` comprobadas con pruebas automatizadas.
- Firestore con reglas de denegación por defecto y permisos por aplicación probados en el servidor.
- Auditoría de altas, bajas y cambios de permisos.
- Confirmación de que el despliegue de `hosting:portal` y las aplicaciones enlazadas no cambian.
