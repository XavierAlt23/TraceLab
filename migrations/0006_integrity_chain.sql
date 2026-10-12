-- Fase 5: migración aditiva. Los eventos previos permanecen intactos y sin firma.
CREATE TABLE integrity_state (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  initialized INTEGER NOT NULL DEFAULT 0 CHECK (initialized IN (0, 1)),
  historical_cutoff_sequence INTEGER,
  historical_count INTEGER,
  historical_snapshot_hash TEXT,
  head_hash TEXT NOT NULL,
  last_audit_sequence INTEGER NOT NULL DEFAULT 0
);

INSERT INTO integrity_state (singleton, initialized, head_hash, last_audit_sequence)
VALUES (1, 0, printf('%064d', 0), 0);

CREATE TABLE integrity_write_guard (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  expected_head_hash TEXT NOT NULL,
  expected_sequence INTEGER NOT NULL,
  final_head_hash TEXT NOT NULL,
  final_sequence INTEGER NOT NULL
);

CREATE TRIGGER integrity_write_guard_check
BEFORE INSERT ON integrity_write_guard
WHEN NOT EXISTS (
  SELECT 1 FROM integrity_state s
   WHERE s.singleton = 1 AND s.initialized = 1
     AND s.head_hash = NEW.expected_head_hash
     AND s.last_audit_sequence = NEW.expected_sequence
     AND (SELECT COALESCE(MAX(sequence), 0) FROM audit_order) = NEW.expected_sequence
)
BEGIN
  SELECT RAISE(ABORT, 'integrity chain write conflict');
END;

CREATE TRIGGER integrity_guard_log_insert
BEFORE INSERT ON logs
WHEN NOT EXISTS (SELECT 1 FROM integrity_write_guard WHERE singleton = 1)
BEGIN
  SELECT RAISE(ABORT, 'signed integrity context required');
END;

CREATE TRIGGER integrity_guard_metalog_insert
BEFORE INSERT ON metalogs
WHEN NOT EXISTS (SELECT 1 FROM integrity_write_guard WHERE singleton = 1)
BEGIN
  SELECT RAISE(ABORT, 'signed integrity context required');
END;

CREATE TRIGGER integrity_state_advance_guard
BEFORE UPDATE OF head_hash, last_audit_sequence ON integrity_state
WHEN OLD.initialized = 1 AND NEW.initialized = 1 AND (NEW.head_hash <> OLD.head_hash OR NEW.last_audit_sequence <> OLD.last_audit_sequence)
 AND NOT EXISTS (
   SELECT 1 FROM integrity_write_guard g
    WHERE g.singleton = 1 AND g.expected_head_hash = OLD.head_hash
      AND g.expected_sequence = OLD.last_audit_sequence
      AND g.final_head_hash = NEW.head_hash
      AND g.final_sequence = NEW.last_audit_sequence
      AND (SELECT COALESCE(MAX(sequence), 0) FROM audit_order) = NEW.last_audit_sequence
 )
BEGIN
  SELECT RAISE(ABORT, 'integrity chain state can advance only with signed events');
END;

CREATE TRIGGER integrity_state_initialize_guard
BEFORE UPDATE OF initialized ON integrity_state
WHEN OLD.initialized = 0 AND NEW.initialized = 1
 AND ((SELECT COALESCE(MAX(sequence), 0) FROM audit_order) <> NEW.last_audit_sequence
      OR NEW.head_hash <> printf('%064d', 0))
BEGIN
  SELECT RAISE(ABORT, 'integrity checkpoint must match historical audit order');
END;

ALTER TABLE audit_context ADD COLUMN title_event_id TEXT;
ALTER TABLE audit_context ADD COLUMN title_previous_hash TEXT;
ALTER TABLE audit_context ADD COLUMN title_event_hash TEXT;
ALTER TABLE audit_context ADD COLUMN title_signature TEXT;
ALTER TABLE audit_context ADD COLUMN content_event_id TEXT;
ALTER TABLE audit_context ADD COLUMN content_previous_hash TEXT;
ALTER TABLE audit_context ADD COLUMN content_event_hash TEXT;
ALTER TABLE audit_context ADD COLUMN content_signature TEXT;
ALTER TABLE audit_context ADD COLUMN shared_event_id TEXT;
ALTER TABLE audit_context ADD COLUMN shared_previous_hash TEXT;
ALTER TABLE audit_context ADD COLUMN shared_event_hash TEXT;
ALTER TABLE audit_context ADD COLUMN shared_signature TEXT;

DROP TRIGGER records_log_insert;
DROP TRIGGER records_log_update;

CREATE TRIGGER records_log_insert
AFTER INSERT ON records
BEGIN
  INSERT INTO logs (
    event_id, actor_id, actor_name, actor_role, session_id, occurred_at,
    ip_address, user_agent, action, record_id, field_name, old_value, new_value, result,
    context_json, previous_hash, event_hash, signature
  )
  SELECT title_event_id, actor_id, actor_name, actor_role, session_id, occurred_at,
         ip_address, user_agent, action, NEW.id, 'title', NULL, NEW.title, 'SUCCESS',
         NULL, title_previous_hash, title_event_hash, title_signature
    FROM audit_context WHERE record_id = NEW.id;

  INSERT INTO logs (
    event_id, actor_id, actor_name, actor_role, session_id, occurred_at,
    ip_address, user_agent, action, record_id, field_name, old_value, new_value, result,
    context_json, previous_hash, event_hash, signature
  )
  SELECT content_event_id, actor_id, actor_name, actor_role, session_id, occurred_at,
         ip_address, user_agent, action, NEW.id, 'content', NULL, NEW.content, 'SUCCESS',
         NULL, content_previous_hash, content_event_hash, content_signature
    FROM audit_context WHERE record_id = NEW.id;
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

CREATE TABLE lab_copies (
  copy_id TEXT PRIMARY KEY,
  owner_session_id TEXT NOT NULL REFERENCES sessions(session_id),
  source TEXT NOT NULL CHECK (source IN ('LOG', 'METALOG')),
  source_event_id TEXT NOT NULL,
  original_json TEXT NOT NULL,
  working_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  revision INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX lab_copies_owner_idx ON lab_copies(owner_session_id, created_at DESC);
