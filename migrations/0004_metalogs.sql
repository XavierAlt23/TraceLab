CREATE TABLE metalogs (
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
  resource TEXT NOT NULL,
  result TEXT NOT NULL CHECK (result IN ('SUCCESS', 'FAILED', 'DENIED', 'CONFLICT')),
  context_json TEXT,
  previous_hash TEXT,
  event_hash TEXT,
  signature TEXT
);

CREATE INDEX metalogs_time_sequence_idx ON metalogs(occurred_at DESC, sequence DESC);
CREATE INDEX metalogs_actor_idx ON metalogs(actor_id, occurred_at DESC);
CREATE INDEX metalogs_action_idx ON metalogs(action, occurred_at DESC);
CREATE INDEX metalogs_result_idx ON metalogs(result, occurred_at DESC);

CREATE TRIGGER metalogs_are_append_only_update
BEFORE UPDATE ON metalogs
BEGIN
  SELECT RAISE(ABORT, 'metalogs are append-only');
END;

CREATE TRIGGER metalogs_are_append_only_delete
BEFORE DELETE ON metalogs
BEGIN
  SELECT RAISE(ABORT, 'metalogs are append-only');
END;
