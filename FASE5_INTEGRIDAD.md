# Fase 5 — Diseño de integridad

## Corte de evidencias históricas

Las migraciones `0006_integrity_chain.sql` y `0007_degraded_integrity_reports.sql` son aditivas. No vuelven a firmar, reordenar, modificar ni eliminar logs o metalogs ya creados por las Fases 3 y 4. Al primer evento firmado, el Worker registra un punto de inicio con el número y la cantidad de eventos históricos y el SHA-256 de su instantánea canónica. Los eventos anteriores al corte permanecen **sin firma y no verificables**; el punto de inicio permite detectar cambios respecto de esa instantánea después de su creación, pero no demuestra la autenticidad previa de esos eventos.

Los eventos nuevos incluyen una representación canónica con claves ordenadas, SHA-256 del contenido y HMAC-SHA-256 sobre el hash del evento y el hash anterior. La clave `AUDIT_HMAC_KEY` se lee solo en el Worker y debe configurarse como secreto de entorno con al menos 32 caracteres. No se escribe en la base de datos, en respuestas o en evidencias.

## Consistencia y concurrencia

Un guard de escritura compara el hash y la última secuencia del estado con el final de `audit_order`. El Worker calcula las pruebas antes de ejecutar un lote D1; el trigger del guard rechaza una base de cadena obsoleta y el lote completo se revierte. La actualización del registro y los logs generados por sus triggers usan las mismas pruebas y transacción D1. Si una verificación detecta que el estado ya está desalineado, el informe se añade como evento HMAC marcado `out_of_chain` sin avanzar la cadena dañada; así se deja constancia del resultado sin ocultar la inconsistencia.

## Límites

Los eventos previos al corte no pueden autenticarse retroactivamente. Un encadenamiento local sin anclaje externo no garantiza por sí solo detectar el borrado total o el truncamiento de su extremo final si un atacante también puede alterar el estado local. Una mejora empresarial sería publicar periódicamente el hash final en un servicio independiente con control de acceso separado o en un almacenamiento de retención certificada; esa integración queda fuera de esta fase.

El control WORM es simulado: la aplicación permite solo anexar evidencia en las rutas disponibles, pero D1 no se presenta como almacenamiento WORM físico ni certificado.

La lectura del estado y el orden máximo de cada escritura utiliza una sola sentencia SQL. La verificación obtiene los eventos y el estado de cadena en una misma instantánea SQL; las escrituras posteriores quedan fuera de ese límite. El informe se registra después y se revisa en la siguiente verificación. El límite es de 10.000 eventos: excederlo produce `INTEGRITY_UNVERIFIABLE`, sin afirmar que el resto fue revisado.

La clave HMAC debe conservarse. No hay rotación ni recuperación de claves implementadas. Sin clave configurada se rechaza la verificación con HTTP 503 y cero eventos revisados; no se presenta esa solicitud como verificación ejecutada.

## Incidencia del D1 local principal

Los primeros ensayos de integración se ejecutaron sobre la D1 habitual y dejaron operaciones de prueba y un enlace inconsistente de la implementación inicial (`HASH_LINK_MISMATCH`, observado en la secuencia 298). El error de implementación se corrigió. Las evidencias escritas permanecen intactas y no se clasifican como verificadas. La integración final se ejecuta en una D1 aislada y no valida el historial de la principal. No se ha autorizado borrar, restaurar ni volver a anclar ese historial.

Las claves de desarrollo de aquellos ensayos eran temporales y no se conservaron. Una nueva clave no permitirá autenticar esas firmas anteriores. La base principal requiere una decisión explícita sobre su conservación como evidencia de pruebas o el uso de una nueva base separada; las pruebas finales no reparan ni ocultan ese estado.
