INSERT OR IGNORE INTO users (id, display_name, normalized_name, created_at)
VALUES (
  '00000000-0000-4000-8000-000000000001',
  'TraceLab — Datos de demostración',
  'tracelab-demo',
  strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
);

INSERT INTO audit_context (
  record_id, actor_id, actor_name, actor_role, session_id, occurred_at,
  ip_address, user_agent, action
) VALUES
  ('20000000-0000-4000-8000-000000000001', 'system:seed', 'TraceLab', 'SYSTEM', NULL, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), NULL, 'migration:0003', 'record.create'),
  ('20000000-0000-4000-8000-000000000002', 'system:seed', 'TraceLab', 'SYSTEM', NULL, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), NULL, 'migration:0003', 'record.create'),
  ('20000000-0000-4000-8000-000000000003', 'system:seed', 'TraceLab', 'SYSTEM', NULL, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), NULL, 'migration:0003', 'record.create'),
  ('20000000-0000-4000-8000-000000000004', 'system:seed', 'TraceLab', 'SYSTEM', NULL, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), NULL, 'migration:0003', 'record.create'),
  ('20000000-0000-4000-8000-000000000005', 'system:seed', 'TraceLab', 'SYSTEM', NULL, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), NULL, 'migration:0003', 'record.create'),
  ('20000000-0000-4000-8000-000000000006', 'system:seed', 'TraceLab', 'SYSTEM', NULL, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), NULL, 'migration:0003', 'record.create'),
  ('20000000-0000-4000-8000-000000000007', 'system:seed', 'TraceLab', 'SYSTEM', NULL, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), NULL, 'migration:0003', 'record.create'),
  ('20000000-0000-4000-8000-000000000008', 'system:seed', 'TraceLab', 'SYSTEM', NULL, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), NULL, 'migration:0003', 'record.create'),
  ('20000000-0000-4000-8000-000000000009', 'system:seed', 'TraceLab', 'SYSTEM', NULL, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), NULL, 'migration:0003', 'record.create'),
  ('20000000-0000-4000-8000-000000000010', 'system:seed', 'TraceLab', 'SYSTEM', NULL, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), NULL, 'migration:0003', 'record.create');

INSERT INTO records (id, owner_id, title, content, created_at, updated_at, is_shared, revision)
VALUES
  ('20000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000001', 'Mantenimiento del laboratorio', 'Programar revisión preventiva de los equipos de cómputo.', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 1, 1),
  ('20000000-0000-4000-8000-000000000002', '00000000-0000-4000-8000-000000000001', 'Inventario de periféricos', 'Verificar existencia de teclados, ratones y adaptadores.', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 1, 1),
  ('20000000-0000-4000-8000-000000000003', '00000000-0000-4000-8000-000000000001', 'Solicitud de acceso al aula', 'Revisar la solicitud de acceso para la sesión práctica del viernes.', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 1, 1),
  ('20000000-0000-4000-8000-000000000004', '00000000-0000-4000-8000-000000000001', 'Actualización de software', 'Confirmar que las estaciones tengan instaladas las actualizaciones aprobadas.', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 1, 1),
  ('20000000-0000-4000-8000-000000000005', '00000000-0000-4000-8000-000000000001', 'Revisión de respaldos de práctica', 'Comprobar la disponibilidad del conjunto de datos de demostración.', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 1, 1),
  ('20000000-0000-4000-8000-000000000006', '00000000-0000-4000-8000-000000000001', 'Cambio de equipo asignado', 'Registrar la reasignación de una estación para el grupo de trabajo B.', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 1, 1),
  ('20000000-0000-4000-8000-000000000007', '00000000-0000-4000-8000-000000000001', 'Revisión de solicitud', 'Validar que la solicitud de préstamo de equipo incluya fecha de devolución.', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 1, 1),
  ('20000000-0000-4000-8000-000000000008', '00000000-0000-4000-8000-000000000001', 'Preparación de exposición', 'Confirmar la disponibilidad del proyector y la pantalla del aula.', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 1, 1),
  ('20000000-0000-4000-8000-000000000009', '00000000-0000-4000-8000-000000000001', 'Clasificación de materiales', 'Organizar los materiales de práctica por tema y nivel de acceso.', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 1, 1),
  ('20000000-0000-4000-8000-000000000010', '00000000-0000-4000-8000-000000000001', 'Cierre de actividad', 'Verificar que los equipos compartidos queden disponibles para el siguiente grupo.', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 1, 1);

DELETE FROM audit_context
 WHERE record_id BETWEEN '20000000-0000-4000-8000-000000000001' AND '20000000-0000-4000-8000-000000000010';
