# TraceLab v1.0

Aplicación educativa de Ingeniería de Seguridad del Software. React/Vite presenta los registros; un Worker valida sesiones y roles; D1 conserva usuarios, registros, logs, metalogs y el orden global de auditoría. Fase 6 implementada; despliegue pendiente de autorización para Fase 7. Informe: [INFORME_FASE6.md](INFORME_FASE6.md).

Alcance: práctica universitaria de unos diez minutos con aproximadamente diez participantes desde sus celulares. Los controles y pruebas existentes se conservan; no se amplía la aplicación a escenarios empresariales.

## Instalación y configuración

Requiere Node.js compatible con Vite, Wrangler y ESLint 10; usar Node 22.13+ de la rama 22 o una versión compatible posterior. Instalar con `npm ci`. Las nueve migraciones crean el esquema. La demo local se reinició por autorización posterior del usuario y conserva diez espacios compartidos vacíos, sin estudiantes, sesiones, logs ni metalogs anteriores.

```powershell
npm run build
npm start
```

Abrir `http://127.0.0.1:8795`. `npm start` usa la D1 local principal y los secretos estables de `.dev.vars`; no crea una base aislada. Para ADMIN/AUDITOR usar los códigos privados de ese archivo, sin publicarlos. Ctrl+C detiene el servidor y conserva datos y claves para la siguiente sesión. El cliente compilado se sirve exclusivamente desde `dist/client`, excluyendo los archivos privados del Worker.

La IP es la observada por Cloudflare mediante `CF-Connecting-IP`; puede faltar en desarrollo y no demuestra identidad. El navegador no proporciona la MAC real. En el entorno local ese encabezado puede falsificarse; Cloudflare lo establece en producción.

## Roles

| Rol | Registros | Logs | Metalogs | Integridad y laboratorio |
|---|---|---|---|---|
| USER | Ver y editar los diez compartidos y los propios | No | No | No |
| ADMIN | Ver y editar | Consultar y editar contenido | No | No |
| AUDITOR | Consultar | Consultar y editar contenido | Consultar y editar contenido | Sí |

El ingreso de estudiantes por nombre no demuestra identidad real: permite suplantar un nombre conocido y distinguir cuentas existentes. Se conserva por el objetivo educativo. Los límites de solicitudes reducen abuso; no convierten este acceso en autenticación fuerte. Los permisos se validan en el Worker con la sesión de D1; un rol enviado por el cliente no autoriza operaciones. Las ediciones exigen la revisión vigente y guardan sus valores anteriores y posteriores junto con las evidencias en una transacción D1.

## Logs, metalogs e integridad

Los logs registran autenticación, visualizaciones reales de USER/ADMIN/AUDITOR y cambios. El panel muestra título legible, nombre, rol, fecha y hora UTC e IP observada. MAC aparece como no disponible: el navegador no puede obtenerla. Hay un solo filtro desplegable por título del evento; sus opciones provienen de acciones reales en D1. Los eventos más recientes aparecen primero. Los metalogs registran consultas de auditoría, accesos denegados, verificación administrativa, verificación criptográfica y ejercicios del laboratorio.

Los eventos nuevos usan serialización canónica con claves ordenadas, SHA-256 y HMAC-SHA-256 sobre el hash del evento y el hash anterior. La cadena comparte `audit_order` entre logs y metalogs. Web Crypto valida la HMAC; la clave se importa una vez por verificación y no se exporta. Los históricos permanecen sin reescritura ni firma retroactiva y producen `INTEGRITY_UNVERIFIABLE`; el checkpoint detecta cambios posteriores a su creación.

El verificador recorre una instantánea con límite superior fijo y páginas de 1.000 eventos. Devuelve cantidades, errores y el primer evento inconsistente. Revisa hasta 20.000 eventos o 16 MiB de filas serializadas: superar una capacidad devuelve `INTEGRITY_UNVERIFIABLE`, nunca integridad positiva. Un error inesperado o clave ausente devuelve HTTP 503 y estado no verificable. Los errores detectados devuelven `INTEGRITY_FAILED`. Cada verificación ejecutada intenta conservar un metalog después del conjunto revisado; si falta la clave o falla D1, no se afirma que ese metalog persistió. Los historiales usan páginas de 100 y cursor `before`, disponibles mediante «Cargar anteriores».

La migración histórica 0003 genera veinte logs de semilla. `scripts/initialize-local-demo.mjs` prepara exclusivamente una base local virgen (sin sesiones ni eventos de usuarios): deja diez espacios vacíos y retira esa actividad de bootstrap antes de iniciar la cadena. Rechaza una base con actividad. Las migraciones previas no se modificaron. Una instalación que conserve aquella semilla devuelve UNVERIFIABLE por históricos sin firma. Las fixtures de criptografía y volumen excluyen únicamente esa semilla para comprobar OK desde cero. No alteran las migraciones del proyecto ni reescriben históricos.

**Excepción educativa posterior autorizada:** ADMIN y AUDITOR pueden editar contenido de logs; solo AUDITOR puede editar metalogs. Las rutas PATCH validan rol, sesión, campo y revisión, y persisten cada edición junto con `EVIDENCE_CONTENT_EDITED`, incluyendo antes/después. Se conservan ID, secuencia, hashes y firma original: el contenido alterado provoca INTEGRITY_FAILED. La tarjeta indica que fue editada. Ningún rol elimina evidencias por API.

WORM simulado en operaciones normales, con esta excepción explícita y auditada. No es WORM físico ni certificado ni se afirma inmutabilidad de la API de edición educativa. El laboratorio de copias permanece disponible; su reinicio elimina únicamente la copia.

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

Preparación posterior: elegir una D1 nueva, reemplazar el identificador placeholder en la configuración de despliegue y aplicar las nueve migraciones en orden a esa base. Configurar `ADMIN_ACCESS_CODE`, `AUDITOR_ACCESS_CODE` y `AUDIT_HMAC_KEY` mediante secretos protegidos del Worker. Generar códigos independientes y una clave HMAC aleatoria de al menos 32 caracteres; conservar esa clave estable y con copia protegida. El ejemplo contiene placeholders y no debe usarse como credenciales. No copiar `.wrangler`, `.dev.vars`, datos locales ni claves del runner al despliegue. `.gitignore` los excluye. El build contiene cliente y Worker; `npm run deploy` existe para la fase autorizada posterior y no se ejecutó.

Las pruebas locales no prueban cuotas ni rendimiento remoto. D1 Free permite 50 consultas por invocación; Workers tiene límites propios de CPU y memoria. Antes de exposición pública habrá que validar su compatibilidad en Fase 7, sin prometer que una verificación masiva local funcionará bajo la cuota gratuita. Fuentes: [límites D1](https://developers.cloudflare.com/d1/platform/limits/) y [límites Workers](https://developers.cloudflare.com/workers/platform/limits/).

Durante el cierre original de Fase 6 se preservaron los 17 archivos del historial con la incidencia 298. **Después, el usuario autorizó explícitamente borrar todos los datos locales y comprobar la demo sobre esa misma base.** Se retiraron la D1 anterior y las fixtures anteriores, se creó la base principal desde cero y se eliminaron los datos temporales de comprobación antes de entregarla. Estado final comprobado: cero estudiantes, sesiones, logs y metalogs; diez espacios compartidos vacíos. El manifiesto SHA-256 anterior es histórico y no describe la base actual. No se repararon ni re-firmaron evidencias antiguas; se eliminaron por esa excepción autorizada.


## Inicio limpio y despliegue posterior

Los datos locales anteriores se borraron únicamente por autorización expresa. Para comprobar la UI actual: `npm run build`, `npm start`. Los filtros de logs y metalogs son desplegables por título; **Editar contenido** abre el formulario de la excepción educativa y registra el cambio en metalogs. ADMIN continúa sin acceso a metalogs. AUDITOR conserva verificación y laboratorio.

La primera publicación deberá utilizar una D1 nueva preparada sin actividad previa, con diez espacios compartidos vacíos. Después de publicar no se ejecutará limpieza ni borrado de evidencias. La Fase 7 sigue pendiente de autorización; no se crearon recursos remotos ni se desplegó.
