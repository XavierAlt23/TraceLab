# TRACELAB — FASE 5

## Estado

Implementación y verificación aislada completadas. Existe una incidencia pendiente en la D1 local principal descrita abajo. Su historial no se declara íntegro. Fase 6, despliegue, commits y pushes no se ejecutaron.

## Metodología

AGENTS.md leído y respetado dentro de la Fase 5. Caveman FULL aplicado según la skill real: comprime la comunicación; no define un proceso de ingeniería ni comandos adicionales. Se siguió inspección, implementación, verificación y revisión del proyecto.

Graphify ejecutó análisis y consultas de dependencias de frontend, Worker y persistencia. Se actualizó el grafo final. Los siete SQL no pudieron extraerse por faltar `tree_sitter_sql`; se revisaron directamente. No se instalaron dependencias adicionales.

## Implementación y diseño

- Serialización canónica recursiva con claves ordenadas, arrays en su orden y UTF-8.
- SHA-256 del evento canónico. HMAC-SHA-256 de la envoltura canónica con versión, hash del contenido y hash previo. Clave exclusiva del backend: `AUDIT_HMAC_KEY` de al menos 32 caracteres.
- Cadena global de logs y metalogs sobre `audit_order`. Guard SQL y D1.batch conservan posición, hash, firma y actualización del registro en una transacción. Los campos de una modificación comparten una marca UTC.
- Estado y posición observados por cada escritura en una sola sentencia SQL; reintentos ante cambios concurrentes. El verificador obtiene eventos y estado en una instantánea SQL fija y registra el informe posteriormente.
- `GET /api/audit/integrity` exclusivo para AUDITOR. Devuelve estado, cantidades, firmas/hash válidos, errores y primer evento inconsistente. El límite es de 10.000 eventos y produce no verificable si no se revisa el conjunto completo.
- Cada verificación ejecutada genera `INTEGRITY_VERIFICATION`. Si la cadena está desalineada, la constancia se firma y marca `out_of_chain` sin reparar ni avanzar el head. Las consultas de supervisión siguen siendo observables en ese estado.
- WORM simulado, con APIs de solo adición y triggers existentes contra UPDATE/DELETE de evidencia. No hay rutas públicas de edición o eliminación de logs/metalogs.
- Laboratorio exclusivo para AUDITOR: fuentes reales, copia por sesión, alteración de copia, comprobación con la misma criptografía y reinicio. Cada ejercicio produce metalogs. El original permanece intacto.
- Panel del auditor con verificación, cantidades, errores, cadena visual y laboratorio; conserva la verificación de actividad administrativa.

## Evidencias históricas

Decisión documentada antes de aplicar las migraciones. `0006` y `0007` son aditivas; las migraciones anteriores permanecen intactas. La primera escritura firmada crea un checkpoint de la instantánea histórica con corte, cantidad y SHA-256. Los históricos no se vuelven a firmar ni se presentan como autenticados. Mantienen `INTEGRITY_UNVERIFIABLE`; el checkpoint solo detecta cambios posteriores a su creación.

## Archivos

Creado: `README.md`, `FASE5_INTEGRIDAD.md`, `INFORME_FASE5.md`, `src/worker/integrity.ts`, `src/worker/audit-store.ts`, `src/client/integrity.css`, `migrations/0006_integrity_chain.sql`, `migrations/0007_degraded_integrity_reports.sql`, `tests/integrity.test.mjs`, `tests/degraded-integrity.test.mjs`, `scripts/test-phase5-local.mjs`.

Modificado: `.dev.vars.example`, `package.json`, `src/worker/index.ts`, `src/worker/audit.ts`, `src/worker/metalog.ts`, `src/client/App.tsx`, `tests/integration.test.mjs`.

Generado/actualizado: build en `dist/`, grafo/manifest/análisis/caché en `graphify-out/`, migraciones de la D1 local y estados de D1 de pruebas en `.wrangler/`. Se retiraron únicamente configuraciones y archivos de secretos temporales creados durante los ensayos. No se eliminaron datos existentes.

## Pruebas ejecutadas

`npm run typecheck`: PASS. `npm test`: PASS, 11 pruebas. `npm run test:phase5:local`: PASS, migraciones y dos pruebas de integración completas. `npm run build`: PASS.

| N.º | Verificación obligatoria | Resultado y evidencia |
|---|---|---|
| 1 | SHA-256 | PASS: contraste con implementación independiente de Node |
| 2 | HMAC generación y validación | PASS: Node HMAC y Web Crypto |
| 3 | Serialización determinista | PASS: claves recursivas y arrays |
| 4 | Encadenamiento | PASS: continuidad y verificación del conjunto firmado en D1 |
| 5 | Integridad de logs | PASS: eventos nuevos sin errores criptográficos; históricos no verificables |
| 6 | Integridad de metalogs | PASS: firmas válidas del conjunto firmado, incluida supervisión |
| 7 | Contenido modificado | PASS: unidad y laboratorio devuelven fallo del contenido |
| 8 | Firma incorrecta | PASS: verificación unitaria rechaza firma alterada |
| 9 | Enlace incorrecto | PASS: continuidad y firma rechazan enlace alterado |
| 10 | Saltos de orden | PASS: prueba de continuidad detecta salto de secuencia |
| 11 | Históricos sin firma | PASS: D1 retorna INTEGRITY_UNVERIFIABLE y LEGACY_UNSIGNED_EVENTS |
| 12 | Escrituras concurrentes | PASS: revisión compartida y dos registros independientes mientras se verifica |
| 13 | Atomicidad | PASS: solo el ganador persiste cambio y evidencia coherentes; conflicto registrado |
| 14 | ADMIN sin acceso a verificación | PASS: HTTP 403 |
| 15 | USER sin acceso a verificación | PASS: HTTP 403 |
| 16 | AUDITOR ejecuta verificación | PASS: HTTP 200 y metalog real |
| 17 | Laboratorio conserva originales | PASS: copia alterada y hash original sin cambios |
| 18 | Ausencia de secretos en respuestas | PASS: comparación con códigos, clave HMAC y tokens reales de prueba |
| 19 | Typecheck | PASS: tsc --noEmit |
| 20 | Build | PASS: Worker y frontend compilados |
| 21 | Unitarias e integración | PASS: 11 unitarias y 2 escenarios de integración |

Adicional: PASS para exclusión de USER/ADMIN del laboratorio, negativa de edición del AUDITOR, HTTP 405/404 al intentar eliminar evidencias, consultas ADMIN y auditoría administrativa real. PASS para detectar estado de cadena alterado en D1 aislada y consultar el metalog firmado `out_of_chain`. Esa prueba altera únicamente el estado de la fixture recién creada; conserva todas sus evidencias y registros.

NOT_RUN: lint (no hay script/configuración), revisión visual interactiva del navegador, escenario de más de 10.000 eventos, cadena completa sin ningún histórico y despliegue. No se declara PASS para esos escenarios. El resultado completo de la D1 con históricos fue INTEGRITY_UNVERIFIABLE; el PASS acredita que se detecta y presenta correctamente esa condición, no que todo su pasado esté autenticado.

## Comandos y comprobación manual

```powershell
npm run typecheck
npm test
npm run test:phase5:local
npm run build
```

El runner de integración crea una base y secretos propios dentro de `.wrangler/phase5-tests`, evita la D1 principal, retira sus secretos y detiene su servidor. Su estado de pruebas se conserva. Requiere `dist/client` de un build previo. No usar la D1 principal como fixture de integración.

Para uso manual, configurar claves de desarrollo estables en `.dev.vars` a partir del ejemplo, ejecutar `npm run db:migrate:local` y `npm run dev -- --host 127.0.0.1`. El historial principal tiene la incidencia siguiente y puede fallar la verificación; no reemplazar su clave ni reanclarlo silenciosamente.

1. Con ADMIN, ejecutar `fetch('/api/audit/integrity').then(r => r.status)` en la consola del navegador: 403. `/api/metalogs` también retorna 403.
2. Con AUDITOR, consultar metalogs: filtrar `ACCESS_DENIED` para la verificación prohibida o `ADMIN_METALOG_ACCESS_DENIED` para la consulta de metalogs del ADMIN.
3. Pulsar VERIFICAR INTEGRIDAD y revisar estado, cantidades, firmas y errores. Consultar `INTEGRITY_VERIFICATION` en metalogs.
4. Cargar fuentes del laboratorio, seleccionar un evento firmado, crear copia, simular cambio, verificar y reiniciar. La discrepancia del contenido debe ser real; la HMAC puede seguir siendo válida para el hash original.

## Incidencia local y limitaciones

Las primeras iteraciones de integración se ejecutaron sobre la D1 principal. Crearon usuarios/eventos de prueba y modificaron registros de demostración. Una implementación inicial dejó un enlace incorrecto, observado como HASH_LINK_MISMATCH en secuencia 298. El error fue corregido en código. No se borró, reparó ni volvió a firmar esa evidencia. Las claves temporales de esos ensayos no se conservaron; una clave nueva no autentica firmas anteriores. Las pruebas finales aisladas no declaran sana la D1 principal. Se requiere decisión explícita sobre conservar ese historial como evidencia o utilizar una base separada; ninguna restauración/reanclaje se hizo automáticamente.

La cadena local carece de anclaje externo y no garantiza detectar borrado total/truncamiento si también se altera su estado. Mejorar mediante anclaje periódico en un servicio independiente queda propuesto, sin implementar. D1 y los controles de aplicación no constituyen WORM físico ni certificado. La pérdida o rotación de la clave HMAC afecta las verificaciones; no se implementó recuperación/rotación de claves.

¿Autorizas continuar con la Fase 6? El tratamiento del historial de la D1 principal requiere autorización aparte.

ESPERANDO AUTORIZACIÓN.
