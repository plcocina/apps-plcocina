# Módulo 3C-D — rollback del entorno aislado

Este runbook es para el proyecto aislado futuro. No debe ejecutarse contra `plcocina-apps`. Borrar una Cloud Function no desregistra automáticamente su trigger: Identity Platform puede seguir intentando invocarla y bloquear todos los accesos. Referencia oficial: [blocking functions](https://cloud.google.com/identity-platform/docs/blocking-functions).

## 1. Preparación obligatoria antes de registrar triggers

1. Registrar project ID y number aislados, región, nombres de Functions, revisiones, URLs internas y configuración de triggers.
2. Designar dos operadores humanos con MFA y acceso IAM independiente de Firebase Authentication.
3. Verificar que ambos pueden leer configuración Identity Platform, desregistrar triggers y administrar exclusivamente las Functions aisladas.
4. Mantener una revisión anterior desplegada pero no registrada y el artefacto/SHA aprobado.
5. Mantener una sesión del Super Admin sintético como evidencia adicional, nunca como única vía de recuperación.
6. Capturar estado previo de proveedores, triggers, IAM, Firestore y Auth; guardar evidencia sin secretos.
7. Definir canal de incidente, responsable de decisión y ventana máxima de 15 minutos para iniciar rollback.

## 2. Orden universal de recuperación

1. **Congelar pruebas:** detener clientes, SMS, Email Links y automatizaciones; conservar logs y documentos.
2. **Confirmar aislamiento:** verificar dos veces que el project ID no sea `plcocina-apps`.
3. **Desregistrar el trigger afectado en Identity Platform.** Esta es la acción que retira la dependencia del flujo Auth.
4. **Verificar la configuración:** lectura independiente debe mostrar que el evento ya no referencia la Function.
5. **Probar autenticación base:** Super Admin sintético y un usuario v1 de prueba, sin trigger.
6. **Sólo después**, detener tráfico o eliminar/revertir la Cloud Function defectuosa.
7. Restaurar permisos/proveedor únicamente desde la captura aprobada y repetir pruebas negativas.
8. Preservar `adminOperations`, reservas, auditoría y logs; no borrar cuentas como forma de rollback.

## 3. Escenarios

### Todos los usuarios bloqueados

- Indicador: aumento inmediato de errores Auth, timeout o Function no disponible.
- Acción: operador IAM desregistra primero `beforeSignIn`; valida ausencia de referencia; prueba login base; después revierte la Function.
- Éxito: autenticación base funciona, no queda trigger colgante y no se emitieron tokens durante el incidente.

### Super Admin bloqueado

- No modificar el UID, claim o perfil para “hacerlo pasar”.
- Usar la identidad IAM independiente para desregistrar `beforeSignIn`.
- Confirmar correo verificado, método password, UID y claim en Auth antes de reintentar.
- Si la cuenta fue deshabilitada o sus sesiones revocadas, repararla sólo mediante una operación administrativa auditada del proyecto aislado.
- Éxito: Super Admin recuperado sin relajar la política para empleados.

### Fallo o timeout del handler

- Desregistrar sólo el evento afectado (`beforeCreate` o `beforeSignIn`).
- Comparar latencia con el límite de siete segundos y revisar dependencias Firestore.
- Revertir a la revisión conocida; probarla directamente antes de volver a registrar.
- No reintentar despliegues repetidamente mientras el trigger siga apuntando a una Function fallida.

### Firestore inaccesible

- Mantener fail-closed; no cambiar temporalmente el handler a allow-open.
- Desregistrar `beforeSignIn` si se necesita recuperar autenticación base.
- Restaurar el permiso mínimo del runtime o la disponibilidad de Firestore desde la captura previa.
- Validar reglas deny-by-default y acceso Admin SDK; volver a registrar sólo tras pruebas de lectura y latencia.

### Proveedor mal configurado

- Deshabilitar el proveedor afectado en el proyecto aislado y detener envíos.
- No deshabilitar Email/Password si todavía es la vía del Super Admin hasta que `beforeSignIn` esté desregistrado y exista recuperación IAM.
- Restaurar dominios, plantillas y configuración desde el estado aprobado; confirmar que no se autorizó un dominio operativo.
- Para Phone, detener SMS reales y conservar sólo números ficticios.

### Error durante registro del trigger

- Leer la configuración efectiva; no inferir éxito por la respuesta de CLI/Console.
- Si el trigger no aparece, no borrar la Function: corregir primero permisos o configuración.
- Si aparece parcialmente o apunta a revisión equivocada, desregistrarlo y verificar la ausencia antes de reintentar.

### Error durante eliminación

- Diferenciar:
  - **Desregistrar:** quitar la asociación del evento en Identity Platform.
  - **Eliminar Function:** borrar el recurso ejecutable de Cloud Functions/Cloud Run.
- Siempre desregistrar y verificar primero. Si se borró la Function antes, usar IAM de emergencia para quitar inmediatamente el trigger huérfano.

### Bloqueo exclusivo de usuarios Google

- Deshabilitar el proveedor Google o detener su cliente sólo en el proyecto aislado; no relajar `beforeSignIn` para el resto.
- Si la causa es verificación de token/`hd`, desregistrar temporalmente el trigger únicamente cuando la vía base v1 y el riesgo de autorregistro hayan sido evaluados; preferir volver a la revisión conocida.
- Mantener perfiles Google deshabilitados y revocar sus sesiones mientras no exista verificación fiable.
- Éxito: Phone, Email Link y v1 tienen el comportamiento aprobado; ninguna cuenta Google nueva se crea y las existentes quedan contenidas.

### Vinculación incorrecta o proveedor en UID equivocado

- Deshabilitar inmediatamente ambos UIDs implicados, revocar sesiones y marcar perfiles/operación `reconciliation_required`.
- No fusionar, borrar, copiar Access Grants ni cambiar correos como corrección rápida.
- Capturar `providerData`, reservas de correo/`sub`, revisiones y auditoría. Determinar cuál UID era el preautorizado.
- Sólo un procedimiento administrativo aprobado puede desvincular/revincular la credencial después de probar control de la cuenta. Si no es reversible con API oficial y evidencia suficiente, mantener bloqueado y escalar.
- Éxito: un solo UID autorizado conserva grants originales, el `sub` queda reservado una vez y el UID incorrecto no puede autenticarse.

### Duplicidad de UID o `sub`

- Congelar ambos registros y toda operación con las reservas afectadas.
- No elegir ganador por coincidencia de correo. Usar operación original, reserva, actor, `sub` verificado y auditoría.
- Conservar Access Grants sin moverlos hasta aprobar la conciliación. Toda baja de cuenta requiere respaldo/evidencia y revisión dual.
- Éxito: invariantes uno-a-uno restauradas, sesiones revocadas y decisión trazable.

### Suspensión del proveedor Google o error OAuth

- Deshabilitar temporalmente Google en el proyecto aislado y detener el botón/flujo de prueba; no cambiar los métodos asignados automáticamente.
- Restaurar client ID, secreto/configuración y dominios desde la captura aprobada; rotar secreto si hubo exposición.
- Probar cuenta personal, otro Workspace y usuario autorizado antes de reabrir.
- Éxito: sólo el client ID y redirect URIs aislados están activos; producción no aparece en la configuración.

### Registro equivocado de triggers

- Si el project ID, región, evento o revisión no coincide, desregistrar en Identity Platform inmediatamente y confirmar mediante lectura de configuración.
- Si el trigger fue registrado accidentalmente en producción, activar el procedimiento de incidente de producción; este runbook no autoriza mutarlo sin aprobación y operadores designados.
- No borrar primero la Function. Desregistrar elimina la asociación; eliminar sólo retira el ejecutable.

## 4. Verificación posterior

- Configuración muestra cero triggers o exactamente la revisión restaurada.
- Super Admin y v1 sintéticos autentican según el estado esperado.
- Autorregistro continúa rechazado cuando `beforeCreate` vuelve a registrarse.
- No hay cuentas huérfanas, claims nuevos, Access Grants, cambios de UID ni sesiones inesperadas.
- Firestore conserva reservas, operaciones y auditoría.
- Logs no contienen correo, teléfono, token, código SMS ni enlace Email Link.
- IAM temporal se retira; presupuesto, límites y alertas siguen activos.

## 5. Criterio para volver a registrar

Requiere causa raíz escrita, revisión de código/SHA, pruebas directas, p99 menor de 4 segundos, matriz relevante aprobada, dos operadores disponibles, captura de configuración y aprobación explícita. Un rollback exitoso no autoriza por sí mismo continuar pruebas.

## 6. Cierre o retiro del proyecto

Al finalizar 3C-E: desregistrar triggers, verificar configuración, deshabilitar proveedores y envíos, revocar sesiones, retirar IAM temporal y secretos, exportar sólo evidencia sanitizada y aplicar la política aprobada de retención/eliminación del proyecto. No eliminarlo mientras existan incidentes, conciliaciones o evidencia pendiente.
