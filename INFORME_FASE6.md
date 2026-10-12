# TRACELAB — FASE 6

**Estado: COMPLETADA localmente.** Alcance: demo universitaria de diez minutos, unos diez participantes y diez registros compartidos. Revisión visual pendiente. Fase 7 no iniciada.

## Metodología

Caveman FULL aplicado como comunicación concisa, según su definición real. Leídos AGENTS.md, ARQUITECTURA.md e INFORME_FASE5.md; respetado el plan por fases de la conversación. Graphify revisó dependencias de Worker, escritura atómica, verificador y frontend: 255 nodos y 573 relaciones. SQL revisado directamente, sin instalar el parser opcional.

## Cambios y seguridad

- JSON acotado, validación de campos, fechas y revisiones; consultas preparadas.
- Protección de mutaciones cross-site, cookies seguras en producción y permisos basados en sesión D1.
- CSP y cabeceras también en assets: una prueba detectó su omisión inicial; corrección y repetición exitosas.
- Límites sencillos de solicitudes, respuesta 429 y evidencia del primer rechazo de cada ventana.
- Historiales paginados; verificador con instantánea fija y cierre seguro ante errores o revisión incompleta.
- Atomicidad registro/evidencia; aislamiento y revisión concurrente de copias de laboratorio.
- Tabla compartida adaptable, confirmación de guardado, mensajes de conflicto, foco visible y limpieza de información al cerrar sesión o iniciar otra verificación.

Se conservaron los controles existentes. Tras reducir el alcance no se añadieron funcionalidades ni se repitió volumen.

## Pruebas

| Verificación ejecutada | Estado |
|---|---|
| `npm run typecheck` | PASS |
| `npm run lint` — ESLint 10, sin advertencias | PASS |
| `npm run build` — build pendiente terminado correctamente | PASS |
| `npm test` — 19 pruebas | PASS |
| `npm run test:integration` — suite aislada ya obtenida | PASS |
| `npm run test:phase5:local` — integración esencial final, dos pruebas | PASS |
| Roles, sesiones falsas/revocadas/expiradas, antes/después y concurrencia | PASS |
| Fallos de registro/evidencia: reversión atómica en fixture aislada | PASS |
| SHA-256, HMAC, serialización y detección de contenido/firma/enlace/orden alterados | PASS |
| OK sin históricos; FAILED con alteraciones; UNVERIFIABLE con históricos | PASS |
| Clave ausente/error inesperado: 503 sin integridad positiva, pruebas unitarias del Worker | PASS |
| Originales del laboratorio intactos; copias por sesión; ausencia de secretos en evidencias, respuestas y bundle | PASS |
| Render de React: diez filas, botones por permisos y texto XSS escapado | PASS |
| Navegador, teléfonos, navegación, consola y accesibilidad interactiva | NOT_RUN |

La herramienta de navegador devolvió una lista vacía. El render unitario no se presenta como prueba visual.

**Volumen previo conservado, sin repetición tras reducir el alcance:** PASS; 12.000 eventos, 12.002 revisados y 120 páginas exactas. Última verificación: 2,51 s; prueba completa: 84,86 s. No demuestra rendimiento remoto.

## Archivos

**Creados:** `eslint.config.mjs`; `src/worker/security.ts`; `src/client/SharedRecords.tsx`; `migrations/0008_security_rate_limits.sql`; `tests/security.test.mjs`; `tests/worker-failure.test.mjs`; `tests/isolated-helpers.mjs`; `tests/phase6.test.mjs`; `tests/crypto-d1.test.mjs`; `tests/volume.test.mjs`; `EVIDENCIA_D1_FASE6.json`; `INFORME_FASE6.md`.

**Modificados:** `package.json`, `package-lock.json`, `wrangler.jsonc`, `README.md`; `src/worker/index.ts`, `audit-store.ts`, `integrity.ts`, `policy.ts`; `src/client/App.tsx`, `integrity.css`; `scripts/test-phase5-local.mjs`; `tests/integration.test.mjs`, `integrity.test.mjs`.

Artefactos derivados: Graphify, build y fixtures ignoradas dentro de `.wrangler`. Migraciones previas y configuraciones globales intactas.

## Incidencia D1

**Principal no modificada:** comparación final SHA-256 de sus 17 archivos SQLite/WAL/SHM/metadatos, sin cambios ni ausencias. Manifiesto: [EVIDENCIA_D1_FASE6.json](EVIDENCIA_D1_FASE6.json).

Secuencia 298, históricos sin firma y firmas de claves perdidas conservados. No se borraron evidencias, regeneraron firmas ni aplicó la migración nueva allí. No se declara íntegra. Todas las pruebas mutables usaron D1 nuevas aisladas.

## Comprobación manual

```powershell
npm run build
npm run dev:isolated
```

Abrir `http://127.0.0.1:8795`. El runner indica la ruta privada de sus códigos de desarrollo, sin imprimir valores.

1. **USER:** registrar dos nombres, editar compartidos y comprobar confirmación/conflicto.
2. **ADMIN:** filtrar logs por `record.update`, revisar antes/después. Ejecutar `fetch('/api/metalogs').then(r => r.status)`: debe devolver **403**.
3. **AUDITOR:** filtrar metalogs por `ADMIN_METALOG_ACCESS_DENIED`; verificar actividad administrativa e integridad. La semilla histórica exige UNVERIFIABLE.
4. Crear copia firmada, simular cambio, verificar discrepancia y reiniciar. Revisar teléfono, foco y consola manualmente.

Ctrl+C detiene el servidor y retira sus secretos temporales. No reutilizar esas fixtures como cadenas verificables sin su clave ni ejecutar desarrollo habitual sobre la D1 principal.

## Limitaciones y pendientes

- Revisión visual y despliegue gratuito aún no ejecutados.
- Nombre estudiantil no verifica identidad; permite suplantación y enumeración.
- WORM simulado; sin anclaje externo no garantiza detectar borrado total o truncamiento con alteración del estado.
- Capacidad actual: 20.000 eventos o 16 MiB; una revisión incompleta devuelve UNVERIFIABLE. No se amplía para esta práctica.
- Sin clave o almacenamiento no puede garantizarse el metalog de error; la operación falla cerrada.
- Despliegue posterior requiere secretos estables y D1 nueva; incidencia principal requiere decisión separada.

Sin commits, pushes ni despliegues.

**¿Has verificado la Fase 6 y autorizas continuar con la Fase 7?**

ESPERANDO AUTORIZACIÓN.
