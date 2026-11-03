# Módulo 3C-C — operación futura de blocking functions

## Dependencias

- Firebase Authentication debe actualizarse a Firebase Authentication with Identity Platform.
- Los proveedores Phone y Email Link deben configurarse únicamente después de validar el proyecto aislado.
- Las blocking functions requieren facturación, permisos de despliegue y configuración explícita en Identity Platform.
- `PROTECTED_SUPER_ADMIN_UID` debe estar disponible y validado antes de construir los triggers.

## Registro seguro futuro

1. Crear un proyecto Firebase aislado, sin usuarios ni credenciales productivas.
2. Configurar el UID protegido de prueba y verificar email/password, correo verificado y claim `super_admin === true`.
3. Construir `IdentityBlockingService` con `FirestoreIdentityBlockingStore`.
4. Envolver los handlers mediante `beforeUserCreated` y `beforeUserSignedIn` solamente en un módulo de despliegue revisado.
5. Registrar primero `beforeSignIn`, probar el Super Admin y empleados de prueba, y registrar después `beforeCreate`.
6. Confirmar métricas, latencia, errores genéricos y ausencia de identificadores en logs antes de autorizar producción.

El Auth Emulator no ejecuta de forma equivalente el registro administrado de blocking functions de Identity Platform. Las pruebas locales validan la política y las lecturas Firestore, pero el despacho real, los métodos reportados en `credential` y el bypass de Admin SDK deben confirmarse en un proyecto real aislado.

## Rollback

1. Mantener abierta y verificada una sesión administrativa de emergencia antes del cambio.
2. Si `beforeSignIn` bloquea al UID protegido, desregistrar o deshabilitar primero ese trigger desde una cuenta de emergencia autorizada.
3. Revertir la configuración de triggers a la revisión anterior; no relajar la política para dominios, teléfonos o claims.
4. Revocar sesiones emitidas durante la incidencia y conciliar operaciones incompletas.
5. No eliminar perfiles, reservas ni cuentas Auth durante el rollback.

El riesgo principal es bloquear al Super Admin por UID, claim, correo verificado o método incorrectos. No debe registrarse ningún trigger hasta completar una prueba real de acceso y recuperación. Las reservas en conciliación permanecen fail-closed y requieren el procedimiento administrativo de conciliación de un módulo posterior.
