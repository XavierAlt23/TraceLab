# TraceLab v1.0 — Arquitectura

## Alcance

Este documento fija la arquitectura inicial y los límites de seguridad de TraceLab. La raíz del proyecto todavía no contiene aplicación, manifiestos de dependencias ni repositorio Git. La implementación se realizará por fases autorizadas; este documento no adelanta las fases de usuarios, registros, auditoría, criptografía ni despliegue.

## Arquitectura objetivo

- **Interfaz:** React, Vite y TypeScript; diseño adaptable para teléfono y escritorio.
- **Aplicación y API:** un Cloudflare Worker escrito en TypeScript, que sirve los recursos compilados de Vite y atiende las rutas `/api/*`.
- **Persistencia:** Cloudflare D1 (SQLite), accesible desde el Worker mediante un binding. Las consultas usarán sentencias preparadas.
- **Recursos estáticos:** publicar la compilación frontend junto al Worker. Así la interfaz y la API comparten origen y la autorización de las API queda en el servidor.
- **Despliegue:** Cloudflare Workers y D1. Confirmar límites y disponibilidad del plan gratuito al llegar a la fase de despliegue.

Cloudflare documenta la publicación conjunta de Worker y recursos estáticos y el enrutamiento de API mediante el Worker. D1 ofrece un binding desde Workers y `batch()` ejecuta una secuencia de sentencias como una transacción; estas capacidades permiten diseñar cambios de negocio y evidencia para confirmarse juntos. La implementación deberá validar el comportamiento en pruebas de integración.

## Límites de confianza

1. El navegador es una interfaz no confiable: no decide roles, permisos, actor auditado ni validez de integridad.
2. El Worker valida sesiones y permisos en cada endpoint, valida entradas y realiza cambios de negocio y auditoría.
3. D1 guarda registros, sesiones, logs y metalogs. Las rutas públicas no ofrecen actualización ni eliminación de evidencias.
4. Los secretos criptográficos y credenciales especiales viven en secretos del entorno del Worker, nunca en el bundle web, D1, respuestas API ni logs.
5. La IP registrada será la observada por el servidor mediante metadatos de Cloudflare cuando esté disponible. No se afirmará que el navegador proporciona su dirección MAC.

La separación de funciones será lógica y aplicada en el backend. Worker y D1 comparten proveedor y cuenta; esto no constituye separación física ni almacenamiento WORM certificado.

## Roles y responsabilidades

| Rol | Capacidades previstas | Restricciones principales |
| --- | --- | --- |
| USER | Ingresar con nombre, consultar y editar registros propios, cerrar sesión | El nombre no verifica identidad real; sin contraseña ni correo |
| ADMIN | Consultar y editar registros, consultar logs, filtrar actividad de usuarios | Sin acceso a metalogs ni a funciones exclusivas del auditor |
| AUDITOR | Consultar logs y metalogs, verificar integridad, inspeccionar actividad administrativa y usar el laboratorio | No puede modificar registros operativos ni borrar evidencias |

Los roles privilegiados se validarán exclusivamente en backend. La función **VERIFICAR ACTIVIDAD DEL ADMINISTRADOR** consultará eventos reales atribuidos al administrador, incluidos accesos, consultas, modificaciones y denegaciones.

## Flujos de datos

### Operación sobre un registro

1. La interfaz envía una petición autenticada al Worker.
2. El Worker valida sesión, rol, permisos y datos de entrada.
3. En una única operación transaccional, guarda el cambio y su evento de log con actor, sesión, fecha UTC, acción, resultado y contexto disponible, incluidos valores anterior y nuevo cuando correspondan.
4. Responde con el resultado mínimo necesario; nunca devuelve secretos ni tokens.

### Supervisión y verificación

1. El Worker valida el rol AUDITOR antes de consultar metalogs o ejecutar verificaciones reservadas.
2. Las operaciones de supervisión y los accesos denegados generan metalogs sin crear recursión infinita.
3. El laboratorio trabaja sobre copias y marca cada resultado como simulación; las evidencias originales permanecen intactas.

## Entidades previstas

El esquema definitivo se diseñará en las fases autorizadas correspondientes. Se anticipan estas entidades lógicas:

- `users`: identidad educativa y estado del usuario.
- `sessions`: sesión revocable; almacenar un identificador derivado del token, no el token entregado al navegador.
- `records`: registros operativos editables conforme al rol.
- `logs`: eventos de negocio y del sistema, append-only desde las API públicas.
- `metalogs`: eventos de auditoría y supervisión, reservados al auditor y append-only desde las API públicas. El nombre definitivo del esquema se fijará en la fase correspondiente.

La auditoría y el cambio operativo deberán confirmarse juntos para evitar divergencias ante fallos.

## Decisiones de seguridad

- No confiar en controles de interfaz para proteger rutas: cada endpoint aplica autorización backend.
- No exponer endpoints públicos para editar o borrar logs y metalogs.
- No registrar credenciales, tokens de sesión ni secretos.
- Registrar eventos exitosos y fallidos pertinentes, accesos denegados y consultas administrativas.
- Usar SHA-256, HMAC-SHA-256 y encadenamiento verificable en backend; las claves nunca llegan al cliente.
- Describir WORM como una simulación educativa de restricciones de aplicación, no como garantía de inmutabilidad certificada.
- Mantener el laboratorio aislado de las evidencias originales.

## Orden de implementación

1. **Preparación y arquitectura:** este documento y decisiones de despliegue.
2. **Usuarios, sesiones y registros:** esquema y rutas de identidad y operación.
3. **Logs de trazabilidad:** captura transaccional de actividades.
4. **Metalogs y auditoría:** supervisión restringida y eventos de auditoría.
5. **Integridad criptográfica y laboratorio:** hashes, firmas, cadena y simulación en copias.
6. **Seguridad, calidad y pruebas:** revisión de controles y pruebas end-to-end.
7. **Despliegue y documentación:** configuración Cloudflare, guía y guion de exposición.

Cada fase requiere autorización propia antes de empezar. Las decisiones que dependan de límites concretos de Cloudflare se volverán a verificar durante la fase de despliegue.
