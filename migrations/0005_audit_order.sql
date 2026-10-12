CREATE TABLE audit_order (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  source TEXT NOT NULL CHECK (source IN ('LOG', 'METALOG')),
  event_id TEXT NOT NULL,
  occurred_at TEXT NOT NULL,
  UNIQUE (source, event_id)
);

CREATE INDEX audit_order_time_idx ON audit_order(occurred_at DESC, sequence DESC);

INSERT INTO audit_order (source, event_id, occurred_at)
SELECT source, event_id, occurred_at
  FROM (
    SELECT 'LOG' AS source, event_id, occurred_at FROM logs
    UNION ALL
    SELECT 'METALOG' AS source, event_id, occurred_at FROM metalogs
  )
 ORDER BY occurred_at, source, event_id;

CREATE TRIGGER logs_add_to_audit_order
AFTER INSERT ON logs
BEGIN
  INSERT INTO audit_order (source, event_id, occurred_at)
  VALUES ('LOG', NEW.event_id, NEW.occurred_at);
END;

CREATE TRIGGER metalogs_add_to_audit_order
AFTER INSERT ON metalogs
BEGIN
  INSERT INTO audit_order (source, event_id, occurred_at)
  VALUES ('METALOG', NEW.event_id, NEW.occurred_at);
END;

CREATE TRIGGER audit_order_are_append_only_update
BEFORE UPDATE ON audit_order
BEGIN
  SELECT RAISE(ABORT, 'audit order is append-only');
END;

CREATE TRIGGER audit_order_are_append_only_delete
BEFORE DELETE ON audit_order
BEGIN
  SELECT RAISE(ABORT, 'audit order is append-only');
END;
