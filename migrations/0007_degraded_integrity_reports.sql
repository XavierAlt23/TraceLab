-- Permite dejar constancia firmada de una verificación cuando la cadena ya está desalineada.
ALTER TABLE integrity_write_guard ADD COLUMN degraded INTEGER NOT NULL DEFAULT 0 CHECK (degraded IN (0, 1));

DROP TRIGGER integrity_write_guard_check;

CREATE TRIGGER integrity_write_guard_check
BEFORE INSERT ON integrity_write_guard
WHEN (
  NEW.degraded = 0 AND NOT EXISTS (
    SELECT 1 FROM integrity_state s
     WHERE s.singleton = 1 AND s.initialized = 1
       AND s.head_hash = NEW.expected_head_hash
       AND s.last_audit_sequence = NEW.expected_sequence
       AND (SELECT COALESCE(MAX(sequence), 0) FROM audit_order) = NEW.expected_sequence
  )
) OR (
  NEW.degraded = 1 AND NOT EXISTS (
    SELECT 1 FROM integrity_state s
     WHERE s.singleton = 1 AND s.initialized = 1
       AND s.head_hash = NEW.expected_head_hash
       AND s.last_audit_sequence = NEW.expected_sequence
  )
)
BEGIN
  SELECT RAISE(ABORT, 'integrity chain write conflict');
END;
