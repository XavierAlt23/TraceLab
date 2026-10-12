ALTER TABLE sessions ADD COLUMN session_id TEXT;

UPDATE sessions
   SET session_id = lower(hex(randomblob(16)))
 WHERE session_id IS NULL;

CREATE UNIQUE INDEX sessions_session_id_unique ON sessions(session_id);

ALTER TABLE records ADD COLUMN is_shared INTEGER NOT NULL DEFAULT 0 CHECK (is_shared IN (0, 1));
ALTER TABLE records ADD COLUMN revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1);

CREATE TABLE logs (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL UNIQUE,
  actor_id TEXT,
  actor_name TEXT NOT NULL,
  actor_role TEXT NOT NULL CHECK (actor_role IN ('ANONYMOUS', 'USER', 'ADMIN', 'AUDITOR', 'SYSTEM')),
  session_id TEXT REFERENCES sessions(session_id),
  occurred_at TEXT NOT NULL,
  ip_address TEXT,
  user_agent TEXT,
  action TEXT NOT NULL,
  record_id TEXT,
  field_name TEXT,
  old_value TEXT,
  new_value TEXT,
  result TEXT NOT NULL CHECK (result IN ('SUCCESS', 'FAILED', 'DENIED', 'CONFLICT')),
  context_json TEXT,
  previous_hash TEXT,
  event_hash TEXT,
  signature TEXT
);

CREATE INDEX logs_time_sequence_idx ON logs(occurred_at DESC, sequence DESC);
CREATE INDEX logs_actor_idx ON logs(actor_id, occurred_at DESC);
CREATE INDEX logs_role_action_idx ON logs(actor_role, action, occurred_at DESC);
CREATE INDEX logs_result_idx ON logs(result, occurred_at DESC);

CREATE TABLE audit_context (
  record_id TEXT PRIMARY KEY,
  actor_id TEXT,
  actor_name TEXT NOT NULL,
  actor_role TEXT NOT NULL CHECK (actor_role IN ('USER', 'ADMIN', 'SYSTEM')),
  session_id TEXT REFERENCES sessions(session_id),
  occurred_at TEXT NOT NULL,
  ip_address TEXT,
  user_agent TEXT,
  action TEXT NOT NULL
);

CREATE TRIGGER logs_are_append_only_update
BEFORE UPDATE ON logs
BEGIN
  SELECT RAISE(ABORT, 'logs are append-only');
END;

CREATE TRIGGER logs_are_append_only_delete
BEFORE DELETE ON logs
BEGIN
  SELECT RAISE(ABORT, 'logs are append-only');
END;

CREATE TRIGGER records_require_audit_on_insert
BEFORE INSERT ON records
BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM audit_context WHERE record_id = NEW.id
  ) THEN RAISE(ABORT, 'record insert requires audit context') END;
END;

CREATE TRIGGER records_log_insert
AFTER INSERT ON records
BEGIN
  INSERT INTO logs (
    event_id, actor_id, actor_name, actor_role, session_id, occurred_at,
    ip_address, user_agent, action, record_id, field_name, old_value, new_value, result
  )
  SELECT lower(hex(randomblob(16))), actor_id, actor_name, actor_role, session_id, occurred_at,
         ip_address, user_agent, action, NEW.id, 'title', NULL, NEW.title, 'SUCCESS'
    FROM audit_context WHERE record_id = NEW.id;

  INSERT INTO logs (
    event_id, actor_id, actor_name, actor_role, session_id, occurred_at,
    ip_address, user_agent, action, record_id, field_name, old_value, new_value, result
  )
  SELECT lower(hex(randomblob(16))), actor_id, actor_name, actor_role, session_id, occurred_at,
         ip_address, user_agent, action, NEW.id, 'content', NULL, NEW.content, 'SUCCESS'
    FROM audit_context WHERE record_id = NEW.id;
END;

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
    ip_address, user_agent, action, record_id, field_name, old_value, new_value, result
  )
  SELECT lower(hex(randomblob(16))), actor_id, actor_name, actor_role, session_id, occurred_at,
         ip_address, user_agent, action, NEW.id, 'title', OLD.title, NEW.title, 'SUCCESS'
    FROM audit_context WHERE record_id = NEW.id AND OLD.title IS NOT NEW.title;

  INSERT INTO logs (
    event_id, actor_id, actor_name, actor_role, session_id, occurred_at,
    ip_address, user_agent, action, record_id, field_name, old_value, new_value, result
  )
  SELECT lower(hex(randomblob(16))), actor_id, actor_name, actor_role, session_id, occurred_at,
         ip_address, user_agent, action, NEW.id, 'content', OLD.content, NEW.content, 'SUCCESS'
    FROM audit_context WHERE record_id = NEW.id AND OLD.content IS NOT NEW.content;

  INSERT INTO logs (
    event_id, actor_id, actor_name, actor_role, session_id, occurred_at,
    ip_address, user_agent, action, record_id, field_name, old_value, new_value, result
  )
  SELECT lower(hex(randomblob(16))), actor_id, actor_name, actor_role, session_id, occurred_at,
         ip_address, user_agent, action, NEW.id, 'is_shared', CAST(OLD.is_shared AS TEXT), CAST(NEW.is_shared AS TEXT), 'SUCCESS'
    FROM audit_context WHERE record_id = NEW.id AND OLD.is_shared IS NOT NEW.is_shared;
END;
