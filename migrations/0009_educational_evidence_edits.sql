-- Excepción educativa solicitada: el contenido puede alterarse de forma auditada.
-- Hash y firma originales se conservan; el verificador detecta la discrepancia.
ALTER TABLE logs ADD COLUMN edit_revision INTEGER NOT NULL DEFAULT 0;
ALTER TABLE metalogs ADD COLUMN edit_revision INTEGER NOT NULL DEFAULT 0;
CREATE TABLE evidence_edit_guard (
  source TEXT NOT NULL CHECK(source IN ('LOG', 'METALOG')),
  event_id TEXT NOT NULL,
  expected_revision INTEGER NOT NULL,
  PRIMARY KEY(source, event_id),
  CHECK(expected_revision >= 0)
);
DROP TRIGGER logs_are_append_only_update;
CREATE TRIGGER logs_are_append_only_update BEFORE UPDATE ON logs
WHEN NOT EXISTS (SELECT 1 FROM evidence_edit_guard WHERE source='LOG' AND event_id=OLD.event_id AND expected_revision=OLD.edit_revision)
  OR NEW.event_id <> OLD.event_id OR NEW.sequence <> OLD.sequence
  OR NEW.previous_hash IS NOT OLD.previous_hash OR NEW.event_hash IS NOT OLD.event_hash OR NEW.signature IS NOT OLD.signature
BEGIN SELECT RAISE(ABORT, 'evidence edit requires audited educational context'); END;
DROP TRIGGER metalogs_are_append_only_update;
CREATE TRIGGER metalogs_are_append_only_update BEFORE UPDATE ON metalogs
WHEN NOT EXISTS (SELECT 1 FROM evidence_edit_guard WHERE source='METALOG' AND event_id=OLD.event_id AND expected_revision=OLD.edit_revision)
  OR NEW.event_id <> OLD.event_id OR NEW.sequence <> OLD.sequence
  OR NEW.previous_hash IS NOT OLD.previous_hash OR NEW.event_hash IS NOT OLD.event_hash OR NEW.signature IS NOT OLD.signature
BEGIN SELECT RAISE(ABORT, 'evidence edit requires audited educational context'); END;
