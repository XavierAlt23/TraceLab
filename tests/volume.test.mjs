import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { performance } from "node:perf_hooks";
import { canonicalJson, signEvidence } from "../src/worker/integrity.ts";
import { call, login, sql, secrets, quote } from "./isolated-helpers.mjs";

test("D1 aislada: 12000 eventos, verificación completa y paginación exacta", { timeout: 600000 }, async () => {
  const started = performance.now();
  const cookie = await login("AUDITOR");
  const [result] = await sql("SELECT head_hash, last_audit_sequence FROM integrity_state WHERE singleton = 1;");
  let head = result.results[0].head_hash;
  let sequence = result.results[0].last_audit_sequence;
  const before = sequence;
  const columns = ["event_id", "actor_id", "actor_name", "actor_role", "session_id", "occurred_at", "ip_address", "user_agent", "action", "record_id", "field_name", "old_value", "new_value", "result", "context_json"];
  // Carga sintética de prueba, fuera de la API y siempre en la fixture nueva.
  const statements = [];
  for (let index = 0; index < 12000; index++) {
    const event = { schemaVersion: 1, source: "LOG", event_id: randomUUID(), actor_id: null, actor_name: "Volumen aislado", actor_role: "SYSTEM", session_id: null,
      occurred_at: new Date().toISOString(), ip_address: null, user_agent: "Phase6-volume", action: "fixture.volume", record_id: null,
      field_name: null, old_value: null, new_value: null, resource: null, result: "SUCCESS", context_json: canonicalJson({ index }) };
    const proof = await signEvidence(event, head, secrets.AUDIT_HMAC_KEY);
    statements.push(`INSERT INTO logs (${columns.join(",")},previous_hash,event_hash,signature) VALUES (${[...columns.map((key) => event[key]), proof.previous_hash, proof.event_hash, proof.signature].map(quote).join(",")});`);
    head = proof.event_hash; sequence++;
  }
  await sql(`INSERT INTO integrity_write_guard (singleton,expected_head_hash,expected_sequence,final_head_hash,final_sequence) VALUES (1,${quote(result.results[0].head_hash)},${before},${quote(head)},${sequence});\n${statements.join("\n")}\nUPDATE integrity_state SET head_hash=${quote(head)},last_audit_sequence=${sequence} WHERE singleton=1; DELETE FROM integrity_write_guard WHERE singleton=1;`);
  const loaded = performance.now();
  const integrity = await call("/api/audit/integrity", { cookie });
  assert.equal(integrity.status, 200); assert.equal(integrity.data.status, "INTEGRITY_OK", JSON.stringify(integrity.data.errors));
  assert.equal(integrity.data.reviewed, sequence);
  assert.equal(integrity.data.counts.validSignatures, sequence);
  assert.equal(integrity.data.counts.validContentHashes, sequence);
  assert.equal(integrity.data.counts.legacy, 0);
  const verified = performance.now();
  const ids = new Set(); let cursor = null; let pages = 0;
  do {
    const response = await call(`/api/logs?action=fixture.volume${cursor ? `&before=${cursor}` : ""}`, { cookie });
    assert.equal(response.status, 200);
    for (const row of response.data.logs) { assert.ok(!ids.has(row.event_id)); ids.add(row.event_id); }
    cursor = response.data.nextCursor; pages++;
  } while (cursor !== null);
  assert.equal(ids.size, 12000); assert.equal(pages, 120);
  const final = await call("/api/audit/integrity", { cookie });
  assert.equal(final.data.status, "INTEGRITY_OK");
  console.log(JSON.stringify({ events: 12000, reviewed: integrity.data.reviewed, pages, loadSeconds: (loaded - started) / 1000, verifySeconds: (verified - loaded) / 1000, totalSeconds: (performance.now() - started) / 1000, nodeRssMiB: process.memoryUsage().rss / 1048576 }));
});
