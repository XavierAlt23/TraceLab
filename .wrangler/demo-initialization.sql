DROP TRIGGER records_require_audit_on_update;
DROP TRIGGER records_log_update;
UPDATE records SET title = 'Registro compartido ' || CAST(substr(id, -2) AS INTEGER), content = '', revision = 1;
UPDATE users SET display_name = 'Registros compartidos', normalized_name = 'tracelab-sistema' WHERE id = '00000000-0000-4000-8000-000000000001';
CREATE TRIGGER records_require_audit_on_update
BEFORE UPDATE ON records
BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM audit_context WHERE record_id = NEW.id
  ) THEN RAISE(ABORT, 'record update requires audit context') END;
  SELECT CASE WHEN NEW.owner_id <> OLD.owner_id
    THEN RAISE(ABORT, 'record owner is immutable') END;
  SELECT CASE WHEN NEW.revision <> OLD.revision + 1
    THEN RAISE(ABORT, 'record revision must increase by one') END;
  SELECT CASE WHEN OLD.title IS NEW.title AND OLD.content IS NEW.content AND OLD.is_shared IS NEW.is_shared
    THEN RAISE(ABORT, 'record update must change a field') END;
END;
CREATE TRIGGER records_log_update
AFTER UPDATE ON records
BEGIN
  INSERT INTO logs (
    event_id, actor_id, actor_name, actor_role, session_id, occurred_at,
    ip_address, user_agent, action, record_id, field_name, old_value, new_value, result,
    context_json, previous_hash, event_hash, signature
  )
  SELECT title_event_id, actor_id, actor_name, actor_role, session_id, occurred_at,
         ip_address, user_agent, action, NEW.id, 'title', OLD.title, NEW.title, 'SUCCESS',
         NULL, title_previous_hash, title_event_hash, title_signature
    FROM audit_context WHERE record_id = NEW.id AND OLD.title IS NOT NEW.title;

  INSERT INTO logs (
    event_id, actor_id, actor_name, actor_role, session_id, occurred_at,
    ip_address, user_agent, action, record_id, field_name, old_value, new_value, result,
    context_json, previous_hash, event_hash, signature
  )
  SELECT content_event_id, actor_id, actor_name, actor_role, session_id, occurred_at,
         ip_address, user_agent, action, NEW.id, 'content', OLD.content, NEW.content, 'SUCCESS',
         NULL, content_previous_hash, content_event_hash, content_signature
    FROM audit_context WHERE record_id = NEW.id AND OLD.content IS NOT NEW.content;

  INSERT INTO logs (
    event_id, actor_id, actor_name, actor_role, session_id, occurred_at,
    ip_address, user_agent, action, record_id, field_name, old_value, new_value, result,
    context_json, previous_hash, event_hash, signature
  )
  SELECT shared_event_id, actor_id, actor_name, actor_role, session_id, occurred_at,
         ip_address, user_agent, action, NEW.id, 'is_shared', CAST(OLD.is_shared AS TEXT), CAST(NEW.is_shared AS TEXT), 'SUCCESS',
         NULL, shared_previous_hash, shared_event_hash, shared_signature
    FROM audit_context WHERE record_id = NEW.id AND OLD.is_shared IS NOT NEW.is_shared;
END;
DROP TRIGGER logs_are_append_only_delete;
DROP TRIGGER audit_order_are_append_only_delete;
DELETE FROM logs;
DELETE FROM audit_order;
DELETE FROM sqlite_sequence WHERE name IN ('logs', 'metalogs', 'audit_order');
CREATE TRIGGER logs_are_append_only_delete
BEFORE DELETE ON logs
BEGIN
  SELECT RAISE(ABORT, 'logs are append-only');
END;
CREATE TRIGGER audit_order_are_append_only_delete
BEFORE DELETE ON audit_order
BEGIN
  SELECT RAISE(ABORT, 'audit order is append-only');
END;