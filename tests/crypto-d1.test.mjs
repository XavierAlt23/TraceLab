import test from "node:test";
import assert from "node:assert/strict";
import { call, login, sql, quote } from "./isolated-helpers.mjs";

test("verificador D1: OK, contenido, firma, enlace y secuencia dañados", { timeout: 180000 }, async () => {
  const cookie = await login("AUDITOR");
  assert.equal((await call("/api/audit/integrity", { cookie })).data.status, "INTEGRITY_OK");
  const [result] = await sql("SELECT * FROM logs ORDER BY sequence LIMIT 1;");
  const original = result.results[0];
  await sql("DROP TRIGGER logs_are_append_only_update;");
  for (const [field, value, error] of [["action", "ALTERED", "EVENT_HASH_MISMATCH"], ["signature", "AAAA", "HMAC_SIGNATURE_INVALID"], ["previous_hash", "1".repeat(64), "HASH_LINK_MISMATCH"]]) {
    try {
      await sql(`UPDATE logs SET ${field}=${quote(value)} WHERE event_id=${quote(original.event_id)};`);
      const report = await call("/api/audit/integrity", { cookie });
      assert.equal(report.data.status, "INTEGRITY_FAILED"); assert.ok(report.data.errors.some((item) => item.code === error));
      assert.equal(report.data.firstInconsistentEvent.event_id, original.event_id);
    } finally { await sql(`UPDATE logs SET ${field}=${quote(original[field])} WHERE event_id=${quote(original.event_id)};`); }
  }
  assert.equal((await call("/api/audit/integrity", { cookie })).data.status, "INTEGRITY_OK");
  // Solo fixture: borrar una referencia interna comprueba huecos; no se restaura ni reutiliza esta base.
  await sql("DROP TRIGGER audit_order_are_append_only_delete; DELETE FROM audit_order WHERE sequence = 2;");
  const report = await call("/api/audit/integrity", { cookie });
  assert.equal(report.data.status, "INTEGRITY_FAILED");
  assert.ok(report.data.errors.some((item) => item.code === "AUDIT_SEQUENCE_GAP"));
});
