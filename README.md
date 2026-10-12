# TraceLab v1.0

Aplicación educativa de Ingeniería de Seguridad del Software. React/Vite presenta los registros; un Worker valida sesiones y roles; D1 conserva usuarios, registros, logs, metalogs y el orden global de auditoría. Fase 6 implementada; despliegue pendiente de autorización para Fase 7. Informe: [INFORME_FASE6.md](INFORME_FASE6.md).

Alcance: práctica universitaria de unos diez minutos con aproximadamente diez participantes desde sus celulares. Los controles y pruebas existentes se conservan; no se amplía la aplicación a escenarios empresariales.

## Instalación y configuración

Requiere Node.js compatible con Vite, Wrangler y ESLint 10; usar Node 22.13+ de la rama 22 o una versión compatible posterior. Instalar con `npm ci`. Para una base nueva de demostración, las ocho migraciones crean el esquema y diez registros ficticios. No aplicar comandos de desarrollo habituales sobre la D1 principal con la incidencia de secuencia 298.

```powershell
npm run build
npm run dev:isolated
```

Abrir `http://127.0.0.1:8795`. Este comando crea una D1 nueva y secretos exclusivos de desarrollo; muestra la ruta del archivo privado `.dev.vars`, nunca sus valores. Para ADMIN/AUDITOR usar los códigos de ese archivo en el formulario; no compartirlo ni copiarlo al repositorio. Ctrl+C detiene el servidor y retira el archivo de secretos generado. Los datos aislados permanecen en `.wrangler/phase5-tests/<UUID>` y no deben reutilizarse como una cadena verificable después de retirar su clave.

La IP es la observada por Cloudflare mediante `CF-Connecting-IP`; puede faltar en desarrollo y no demuestra identidad. El navegador no proporciona la MAC real. En el entorno local ese encabezado puede falsificarse; Cloudflare lo establece en producción.

## Roles

| Rol | Registros | Logs | Metalogs | Integridad y laboratorio |
|---|---|---|---|---|
| USER | Ver y editar los diez compartidos y los propios | No | No | No |
| ADMIN | Ver y editar | Consultar | No | No |
| AUDITOR | Consultar | Consultar | Consultar | Sí |

El ingreso de estudiantes por nombre no demuestra identidad real: permite suplantar un nombre conocido y distinguir cuentas existentes. Se conserva por el objetivo educativo. Los límites de solicitudes reducen abuso; no convierten este acceso en autenticación fuerte. Los permisos se validan en el Worker con la sesión de D1; un rol enviado por el cliente no autoriza operaciones. Las ediciones exigen la revisión vigente y guardan sus valores anteriores y posteriores junto con las evidencias en una transacción D1.

## Logs, metalogs e integridad

Los logs registran autenticación, operaciones y cambios. Los metalogs registran consultas de auditoría, accesos denegados, verificación administrativa, verificación criptográfica y ejercicios del laboratorio.

Los eventos nuevos usan serialización canónica con claves ordenadas, SHA-256 y HMAC-SHA-256 sobre el hash del evento y el hash anterior. La cadena comparte `audit_order` entre logs y metalogs. Web Crypto valida la HMAC; la clave se importa una vez por verificación y no se exporta. Los históricos permanecen sin reescritura ni firma retroactiva y producen `INTEGRITY_UNVERIFIABLE`; el checkpoint detecta cambios posteriores a su creación.

El verificador recorre una instantánea con límite superior fijo y páginas de 1.000 eventos. Devuelve cantidades, errores y el primer evento inconsistente. Revisa hasta 20.000 eventos o 16 MiB de filas serializadas: superar una capacidad devuelve `INTEGRITY_UNVERIFIABLE`, nunca integridad positiva. Un error inesperado o clave ausente devuelve HTTP 503 y estado no verificable. Los errores detectados devuelven `INTEGRITY_FAILED`. Cada verificación ejecutada intenta conservar un metalog después del conjunto revisado; si falta la clave o falla D1, no se afirma que ese metalog persistió. Los historiales usan páginas de 100 y cursor `before`, disponibles mediante «Cargar anteriores».

La migración 0003 genera veinte logs de semilla sin firma antes de iniciar la cadena: incluso una instalación nueva con esas migraciones devuelve UNVERIFIABLE por ese historial. Las fixtures de criptografía y volumen excluyen únicamente esa semilla para comprobar OK desde cero. No alteran las migraciones del proyecto ni reescriben históricos.

WORM simulado: los registros son de solo adición mediante las funciones de aplicación. No es almacenamiento WORM físico ni certificado. No existen rutas públicas para editar o eliminar evidencia. El laboratorio modifica exclusivamente una copia asociada a la sesión del auditor. Su reinicio elimina esa copia de trabajo.

La cadena local sin anclaje externo no garantiza detectar eliminación completa o truncamiento final cuando también se altera el estado local. Una mejora empresarial sería anclar periódicamente el hash final en un servicio independiente. Diseño y tratamiento histórico: [FASE5_INTEGRIDAD.md](FASE5_INTEGRIDAD.md).

## Verificación local

```powershell
npm run typecheck
npm run lint
npm test
npm run test:integration
npm run test:phase5:local
npm run test:crypto:local
npm run build
```

Ejecutar un build antes de las suites locales. Todos los runners de integración crean una D1 distinta dentro de `.wrangler/phase5-tests`, aplican las migraciones, inician su Worker en 8795 y ejecutan pruebas. Generan secretos propios, retiran su archivo al finalizar y detienen su servidor. No sobrescriben `.dev.vars` ni usan la D1 principal. Las fixtures aisladas permanecen para inspección; algunas contienen alteraciones deliberadas y no sirven como datos de producción. Ejecutar los runners secuencialmente porque comparten puerto. La integración directa exige la marca del runner aislado y carece de URL predeterminada hacia la base principal.

`test:integration` incluye roles, CSRF, entradas inválidas, ausencia de secretos en el bundle/respuestas, fallos inyectados de almacenamiento, expiración de sesión y concurrencia de copias. `test:phase5:local` conserva la regresión anterior y el reporte degradado. `test:crypto:local` altera contenido, firma, enlace y orden en su fixture. `test:volume` inserta 12.000 evidencias sintéticas firmadas, verifica la cadena real y recorre 120 páginas. No crea eventos mediante el navegador.

La prueba de volumen ya se ejecutó satisfactoriamente y sus resultados se conservan. Quedó fuera de las verificaciones finales de esta práctica: no volver a ejecutarla para completar Fase 6.

La herramienta de navegador no tenía una instancia disponible en Fase 6. Las pruebas visuales, de consola y de accesibilidad interactiva están NOT_RUN. El render de React de la tabla se comprobó con pruebas unitarias; no sustituye pruebas en teléfono o navegador.

## Controles de seguridad

- JSON con máximo real de 8.192 bytes, lectura acotada y validación de tipos, campos, fechas y revisiones.
- Consultas preparadas; filtros y cursores validados. React escapa texto; CSP de producción rechaza scripts y estilos en línea, objetos y marcos. Las cabeceras también se aplican a los archivos estáticos.
- Cookies de producción `__Host-`, Secure, HttpOnly, SameSite=Lax, Path=/, sin Domain; tokens aleatorios cuyo hash se conserva en D1. Las cookies locales tienen otra denominación y no usan Secure sobre HTTP.
- Mutaciones rechazan Origin ajeno y Fetch Metadata cross-site. Clientes HTTP sin Origin siguen permitidos; los formularios del navegador usan JSON y cookies del mismo origen. No se habilita CORS para terceros.
- Ventanas de un minuto: 30 solicitudes por ruta de autenticación e IP observada, 90 escrituras y 240 lecturas por IP. El estado se actualiza atómicamente en D1; 429 incluye Retry-After. El primer rechazo de cada ventana deja evidencia; se suprimen evidencias repetidas de throttling para evitar amplificación. Las consultas `/api/session` no consumen estas ventanas. Redes compartidas pueden alcanzar el límite: esperar un minuto.
- Comparación de códigos sobre digests de longitud fija; HMAC mediante Web Crypto. Secretos ausentes o fallos de almacenamiento impiden cambios operativos sin evidencia.

Los controles son educativos: no reemplazan protección de infraestructura, anclajes externos, autenticación fuerte ni una auditoría profesional independiente.

## Guion de exposición

1. Dos estudiantes editan registros compartidos y generan cambios reales. Un conflicto de revisión exige actualizar y reintentar.
2. ADMIN consulta logs y filtra actor, acción, fecha y resultado.
3. Con sesión ADMIN, ejecutar en la consola del navegador `fetch('/api/metalogs').then(r => r.status)`: debe devolver 403.
4. AUDITOR consulta metalogs y filtra `ADMIN_METALOG_ACCESS_DENIED` para observar el intento. Usa **VERIFICAR ACTIVIDAD DEL ADMINISTRADOR**.
5. AUDITOR utiliza **VERIFICAR INTEGRIDAD**. Los históricos sin firma mantienen el resultado no verificable; los errores indican inconsistencias reales.
6. En el laboratorio, cargar eventos, seleccionar uno firmado, crear copia, simular cambio y verificar. El hash del contenido alterado falla; la HMAC original puede seguir validando el hash original. Reiniciar y comprobar que el original permanece intacto.
7. USER o ADMIN que soliciten `/api/audit/integrity` reciben 403. AUDITOR puede observar el metalog `ACCESS_DENIED` correspondiente.

## Estado y despliegue

Implementación hasta Fase 6. Fase 7 exige autorización expresa. No se crearon recursos remotos ni se desplegó.

Preparación posterior: elegir una D1 nueva, reemplazar el identificador placeholder en la configuración de despliegue y aplicar las ocho migraciones en orden a esa base. Configurar `ADMIN_ACCESS_CODE`, `AUDITOR_ACCESS_CODE` y `AUDIT_HMAC_KEY` mediante secretos protegidos del Worker. Generar códigos independientes y una clave HMAC aleatoria de al menos 32 caracteres; conservar esa clave estable y con copia protegida. El ejemplo contiene placeholders y no debe usarse como credenciales. No copiar `.wrangler`, `.dev.vars`, datos locales ni claves del runner al despliegue. `.gitignore` los excluye. El build contiene cliente y Worker; `npm run deploy` existe para la fase autorizada posterior y no se ejecutó.

Las pruebas locales no prueban cuotas ni rendimiento remoto. D1 Free permite 50 consultas por invocación; Workers tiene límites propios de CPU y memoria. Antes de exposición pública habrá que validar su compatibilidad en Fase 7, sin prometer que una verificación masiva local funcionará bajo la cuota gratuita. Fuentes: [límites D1](https://developers.cloudflare.com/d1/platform/limits/) y [límites Workers](https://developers.cloudflare.com/workers/platform/limits/).

La D1 principal conserva `HASH_LINK_MISMATCH` en secuencia 298, históricos sin firma y firmas de ensayos cuyas claves temporales no se conservaron. No está declarada íntegra. Fase 6 comprobó que los 17 archivos existentes de `.wrangler/state/v3/d1`, incluidos WAL/SHM y metadatos, mantuvieron sus hashes SHA-256. No se abrió esa base con Wrangler, no se aplicó la migración nueva allí ni se regeneraron firmas. Su manejo requiere autorización separada. Las nuevas pruebas PASS corresponden exclusivamente a fixtures aisladas.
