import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { promisify } from "node:util";
import { test } from "node:test";

test("D1 aislado: inconsistencia del estado detectada y metalog firmado observable", async () => {
  const config = process.env.TRACELAB_TEST_WRANGLER_CONFIG;
  const state = process.env.TRACELAB_TEST_D1_STATE;
  const secretsPath = process.env.TRACELAB_TEST_SECRETS_FILE;
  assert.ok(config && state && secretsPath, "ejecutar mediante test:phase5:local");
  const values = new Map(readFileSync(secretsPath, "utf8").split(/\r?\n/u).map((line) => { const index = line.indexOf("="); return [line.slice(0, index), line.slice(index + 1)]; }));
  const baseUrl = process.env.TRACELAB_TEST_URL;
  const login = await fetch(`${baseUrl}/api/auth/special`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ role: "AUDITOR", code: values.get("AUDITOR_ACCESS_CODE") }) });
  assert.equal(login.status, 200);
  const cookie = login.headers.get("set-cookie").split(";", 1)[0];
  // Simulación de administrador de infraestructura en la D1 creada por este test.
  // Conserva todos los logs, metalogs, registros y filas de audit_order.
  await promisify(execFile)(process.execPath, [resolve("node_modules/wrangler/bin/wrangler.js"), "d1", "execute", "tracelab-phase5-tests", "--local", "--config", config, "--persist-to", state, "--command",
    "DROP TRIGGER integrity_state_advance_guard; UPDATE integrity_state SET last_audit_sequence = last_audit_sequence + 1 WHERE singleton = 1;"], { windowsHide: true, env: { ...process.env, WRANGLER_SEND_METRICS: "false" } });
  const response = await fetch(`${baseUrl}/api/audit/integrity`, { headers: { cookie } });
  assert.equal(response.status, 200);
  const result = await response.json();
  assert.equal(result.status, "INTEGRITY_FAILED");
  assert.ok(result.errors.some((item) => item.code === "CHAIN_HEAD_MISMATCH"));
  const metaResponse = await fetch(`${baseUrl}/api/metalogs?action=INTEGRITY_VERIFICATION`, { headers: { cookie } });
  assert.equal(metaResponse.status, 200);
  const meta = await metaResponse.json();
  const report = meta.metalogs.find((item) => JSON.parse(item.context_json).out_of_chain === true);
  assert.ok(report, "el informe debe permanecer observable aunque el estado esté desalineado");
  assert.ok(report.signature && report.event_hash);
  const serialized = JSON.stringify({ result, meta });
  for (const secret of values.values()) assert.equal(serialized.includes(secret), false);
});
