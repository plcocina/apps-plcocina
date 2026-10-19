# IAM mínimo del backend administrativo

Este documento es un diseño para la Fase 2A. No autoriza ni ejecuta cambios IAM.

## Separación de identidades

Se usarán dos identidades distintas:

1. Una cuenta de servicio de runtime dedicada a `adminApi`.
2. Una identidad de despliegue federada desde GitHub, separada del runtime.

No se crearán claves JSON. La función deberá declarar explícitamente su cuenta de servicio antes del primer despliegue.

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

## Identidad de despliegue

La identidad de despliegue necesitará, con alcance limitado al proyecto y recursos previstos:

- crear y actualizar la función 2nd gen
- actuar como la cuenta de runtime (`iam.serviceAccounts.actAs`)
- escribir la imagen de compilación en Artifact Registry
- usar el servicio de build requerido por Functions 2nd gen
- desplegar reglas e índices sólo en un job independiente y aprobado

No debe tener permisos para administrar usuarios de Firebase Authentication en runtime.

## Invocación

La API recibe solicitudes HTTPS y aplica Firebase Authentication en la propia aplicación. La decisión de invocación pública de la función, ingress y eventual rewrite de Hosting se revisará antes del despliegue. CORS no sustituye la verificación del ID token.

## Condición previa

Antes de asignar roles se generará una matriz de permisos observados en un proyecto de prueba y se creará el rol personalizado más pequeño posible. Ningún comando IAM forma parte de esta fase.
