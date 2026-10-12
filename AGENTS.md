# AGENTS.md — TraceLab v1.0

## 1. Identidad del proyecto

**Proyecto:** TraceLab  
**Materia:** Ingeniería de Seguridad del Software  
**Propósito:** Demostración práctica de trazabilidad, logs, metalogs, separación de funciones, WORM simulado y verificación criptográfica.

TraceLab es una aplicación educativa que permite a estudiantes generar eventos reales de auditoría y a un administrador y un auditor supervisarlos con permisos diferenciados.

La aplicación debe ser sencilla, responsiva y desplegable gratuitamente en Cloudflare.

## 2. Instrucción principal — Caveman FULL

**OBLIGATORIO: utilizar Caveman en modo FULL como metodología principal de trabajo durante todas las fases.**

Antes de comenzar cualquier actividad:

1. Comprobar las skills instaladas y disponibles.
2. Localizar y leer las instrucciones oficiales de Caveman.
3. Identificar cómo activar correctamente su modalidad FULL.
4. Aplicar el flujo de trabajo definido por Caveman FULL.
5. Utilizar sus procedimientos de planificación, implementación, verificación y revisión, según corresponda.
6. No inventar comandos, modos ni funcionalidades de la skill.
7. Si Caveman no está disponible o el modo FULL no existe en la versión instalada, comunicarlo antes de modificar código.

Caveman FULL debe tener prioridad como metodología de ejecución, sin reemplazar las restricciones de seguridad, autorización y alcance establecidas en este archivo.

### Graphify

Utilizar Graphify como herramienta complementaria cuando aporte valor para:

- Analizar la estructura del repositorio.
- Identificar dependencias.
- Comprender flujos entre componentes.
- Detectar relaciones entre frontend, backend y base de datos.
- Analizar el impacto de cambios.
- Revisar la arquitectura antes de modificaciones importantes.

Consultar las instrucciones reales de Graphify antes de invocarlo.

No generar gráficos innecesarios ni utilizar herramientas adicionales sin una justificación técnica.

## 3. Desarrollo estrictamente por fases

El proyecto tiene siete fases:

1. Preparación y arquitectura.
2. Usuarios, sesiones y registros.
3. Logs de trazabilidad.
4. Metalogs y auditoría.
5. Integridad criptográfica y laboratorio.
6. Seguridad, calidad y pruebas.
7. Despliegue y documentación.

**Regla crítica: ejecutar solamente una fase autorizada a la vez.**

Nunca iniciar la siguiente fase automáticamente.

Al finalizar cada fase:

- Ejecutar las pruebas correspondientes.
- Corregir errores dentro del alcance autorizado.
- Identificar los archivos creados y modificados.
- Presentar evidencia de verificación.
- Informar problemas pendientes.
- Explicar las verificaciones manuales.
- Solicitar autorización expresa del usuario.
- Detener la ejecución.

No interpretar el silencio como autorización.

## 4. Tecnologías autorizadas

- React.
- Vite.
- TypeScript.
- Cloudflare Workers.
- Cloudflare D1.
- SQLite.
- Web Crypto API.
- SHA-256.
- HMAC-SHA-256.
- CSS responsivo.

No incorporar frameworks, servicios o dependencias complejas sin necesidad demostrable.

## 5. Roles y permisos

### USER

- Registrarse e ingresar con un nombre.
- Visualizar registros.
- Editar registros.
- Cerrar sesión.

Sin contraseñas ni correos para los estudiantes.

El ingreso por nombre no demuestra identidad real; debe quedar documentado como simplificación educativa.

### ADMIN

- Acceso especial validado por el backend.
- Visualizar y editar registros.
- Consultar logs.
- Filtrar actividades de usuarios.

Prohibido consultar metalogs, alterar evidencias o utilizar funciones exclusivas del auditor.

### AUDITOR

- Acceso especial independiente.
- Consultar logs y metalogs.
- Verificar integridad.
- Inspeccionar eventos del administrador.
- Ejecutar el laboratorio de manipulación.

Debe contar con la función:

**VERIFICAR ACTIVIDAD DEL ADMINISTRADOR**

Esta función mostrará eventos reales del administrador, como accesos, consultas, modificaciones e intentos denegados.

El auditor no puede modificar registros operativos ni eliminar evidencias.

## 6. Reglas obligatorias de trazabilidad

Registrar eventos relevantes, incluyendo:

- Creación de usuarios.
- Inicio y cierre de sesión.
- Modificaciones.
- Valores anteriores y nuevos.
- Acciones fallidas.
- Accesos denegados.
- Consultas administrativas.
- Verificaciones de integridad.

Cada evento debe incluir los identificadores, actor, sesión, fecha UTC, acción, resultado e información contextual disponibles.

Obtener la IP pública observada por el servidor cuando sea posible.

No afirmar que se obtiene la dirección MAC real del navegador.

Nunca registrar credenciales, tokens de sesión ni secretos.

Mantener consistencia entre los cambios de datos y sus evidencias de auditoría.

## 7. Logs y metalogs

Los logs registran actividades de negocio y operaciones del sistema.

Los metalogs registran acciones sobre la auditoría, verificaciones, accesos denegados y operaciones de supervisión.

Los metalogs deben estar restringidos al auditor.

Aplicar control de permisos también en los endpoints del backend.

Evitar generación recursiva infinita de metalogs.

No permitir edición o eliminación de logs mediante las APIs públicas.

## 8. Integridad y simulaciones

Implementar:

- Hashes SHA-256.
- Firmas HMAC-SHA-256.
- Encadenamiento verificable.
- Detección de alteraciones.
- Restricciones WORM simuladas.
- Laboratorio de manipulación sobre copias.

Las claves criptográficas deben permanecer en el backend.

Las verificaciones deben basarse en datos reales.

Las simulaciones deben identificarse explícitamente como tales.

Nunca alterar evidencias originales durante las demostraciones.

No presentar el sistema como almacenamiento WORM certificado ni como una separación absoluta de infraestructura.

## 9. Reglas de modificación

Antes de editar:

1. Inspeccionar el código afectado.
2. Identificar las dependencias pertinentes, utilizando Graphify cuando corresponda.
3. Aplicar el procedimiento compatible con Caveman FULL.
4. Determinar el cambio mínimo necesario.
5. Implementar solamente el alcance autorizado.
6. Ejecutar pruebas.
7. Revisar los cambios y posibles regresiones.

No eliminar archivos sin autorización.

No realizar cambios ajenos a la fase activa.

No crear otra carpeta raíz si el proyecto ya existe.

No realizar commits, pushes ni despliegues sin autorización expresa.

## 10. Pruebas obligatorias

Según la fase activa, ejecutar:

- Typecheck.
- Lint.
- Build.
- Pruebas unitarias.
- Pruebas de integración.
- Pruebas de autorización.
- Pruebas de trazabilidad.
- Pruebas de integridad.
- Pruebas de concurrencia.

Diferenciar siempre:

- PASS: ejecutado exitosamente.
- FAIL: ejecutado con error.
- NOT_RUN: no ejecutado.

No inventar resultados.

## 11. Despliegue y secretos

El despliegue se realizará en Cloudflare.

No publicar información sensible.

No incluir credenciales en el código fuente.

No eliminar datos de producción sin autorización.

Solicitar intervención del usuario para operaciones externas que requieran autenticación o permisos.

## 12. Documentación

Mantener documentación en español.

El README debe explicar:

- Instalación.
- Configuración.
- Ejecución local.
- Roles.
- Arquitectura.
- Logs y metalogs.
- Integridad.
- Limitaciones de la simulación.
- Despliegue.
- Guion de exposición.

Priorizar explicaciones claras y breves.

## 13. Informe obligatorio de cada fase

Al finalizar, presentar:

```text
========================================
TRACELAB — FASE X
========================================

METODOLOGÍA:
Caveman FULL: ...
Graphify: ...

IMPLEMENTADO:
- ...

ARCHIVOS:
- ...

PRUEBAS:
- PASS / FAIL / NOT_RUN

VERIFICACIÓN MANUAL:
1. ...
2. ...

PENDIENTES:
- ...

ESTADO:
COMPLETADA / BLOQUEADA

¿Autorizas continuar con la siguiente fase?

ESPERANDO AUTORIZACIÓN.
========================================
```

## 14. Prioridades

En caso de conflicto, respetar este orden:

1. Seguridad y protección de datos.
2. Autorización explícita del usuario.
3. Restricciones del proyecto y fase activa.
4. Instrucciones verificadas de Caveman FULL.
5. Análisis complementario mediante Graphify.
6. Simplicidad y mantenibilidad.

**Regla final: Caveman FULL siempre que esté disponible, Graphify cuando aporte valor, una fase a la vez y ninguna fase nueva sin autorización.**