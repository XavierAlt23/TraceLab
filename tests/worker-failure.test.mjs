import test from "node:test";
import assert from "node:assert/strict";
import ts from "typescript";
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve, join } from "node:path";
import { pathToFileURL } from "node:url";
import { randomUUID } from "node:crypto";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

const directory = resolve(".wrangler/phase6-unit", randomUUID());
mkdirSync(directory, { recursive: true });
for (const file of readdirSync("src/worker")) if (file.endsWith(".ts")) {
  const emitted = ts.transpileModule(readFileSync(join("src/worker", file), "utf8"), { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 } }).outputText;
  writeFileSync(join(directory, file.replace(/\.ts$/u, ".mjs")), emitted.replace(/from "\.\/([^".]+)"/gu, 'from "./$1.mjs"'));
}
const worker = (await import(pathToFileURL(join(directory, "index.mjs")).href)).default;
for (const component of ["SharedRecords", "AuditHistory", "EvidenceEditor"]) {
  const emitted = ts.transpileModule(readFileSync(`src/client/${component}.tsx`, "utf8"), { compilerOptions: {
    module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.ReactJSX,
  } }).outputText;
  writeFileSync(join(directory, `${component}.mjs`), emitted.replace('from "./AuditHistory"', 'from "./AuditHistory.mjs"'));
}
const { SharedRecords } = await import(pathToFileURL(join(directory, "SharedRecords.mjs")).href);
const { AuditHistory } = await import(pathToFileURL(join(directory, "AuditHistory.mjs")).href);
function database(failIntegrity = false) {
  return { prepare(query) {
    return { bind() { return this; }, async run() { return { meta: { changes: 1 } }; }, async first() {
      if (query.includes("RETURNING request_count")) return { request_count: 1 };
      if (query.includes("FROM sessions")) return { session_id: "test-session", user_id: null, role: "AUDITOR", display_name: null, expires_at: "2099-01-01" };
      if (failIntegrity) throw new Error("simulated D1 outage");
      return null;
    } };
  } };
}
test("Worker: clave ausente devuelve 503 UNVERIFIABLE, nunca OK", async () => {
  const response = await worker.fetch(new Request("https://tracelab.example/api/audit/integrity", { headers: { cookie: "__Host-tracelab_session=test-only" } }), { DB: database() });
  assert.equal(response.status, 503);
  const report = await response.json(); assert.equal(report.status, "INTEGRITY_UNVERIFIABLE"); assert.equal(report.reviewed, 0);
  assert.equal(report.errors[0].code, "HMAC_KEY_UNAVAILABLE");
});
test("Worker: error inesperado D1 devuelve 503 y ninguna integridad positiva", async () => {
  const secret = "unit-only-secret-not-a-real-key-1234567890";
  const response = await worker.fetch(new Request("https://tracelab.example/api/audit/integrity", { headers: { cookie: "__Host-tracelab_session=test-only" } }), { DB: database(true), AUDIT_HMAC_KEY: secret });
  assert.equal(response.status, 503);
  const report = await response.json(); assert.equal(report.status, "INTEGRITY_UNVERIFIABLE");
  assert.equal(report.errors[0].code, "VERIFICATION_ABORTED"); assert.equal(JSON.stringify(report).includes(secret), false);
});

test("React: diez filas, USER puede editar, AUDITOR solo lectura y XSS escapado", () => {
  const records = Array.from({ length: 10 }, (_, index) => ({ id: String(index), title: '<img src=x onerror="alert(1)">', content: "Ficticio", revision: 1, updated_at: "2026-10-12T00:00:00.000Z" }));
  const editable = renderToStaticMarkup(createElement(SharedRecords, { records, editable: true, onEdit() {} }));
  const readonly = renderToStaticMarkup(createElement(SharedRecords, { records, editable: false, onEdit() {} }));
  assert.equal((editable.match(/<tr>/gu) ?? []).length, 11);
  assert.equal((editable.match(/>EDITAR</gu) ?? []).length, 10);
  assert.equal((readonly.match(/>EDITAR</gu) ?? []).length, 0);
  assert.ok(editable.includes("&lt;img")); assert.ok(!editable.includes("<img"));
});

test("React: logs con filtro select único, metadatos reales y sin MAC inventada", () => {
  const event = { event_id: "id-test", sequence: 2, actor_name: "Ana", actor_role: "USER", session_id: "session-test", occurred_at: "2026-10-12T14:15:16.000Z",
    ip_address: null, user_agent: "test", action: "record.update", result: "SUCCESS", field_name: "title", old_value: "Antes", new_value: "Después", edit_revision: 0 };
  const html = renderToStaticMarkup(createElement(AuditHistory, { source: "LOG", events: [event], actions: ["record.update"], action: "", onAction() {}, onRefresh() {}, error: "", busy: false }));
  assert.equal((html.match(/<select/gu) ?? []).length, 1);
  assert.ok(!html.includes("<input"));
  for (const value of ["Ana", "USER", "2026-10-12", "14:15:16", "No observada", "No disponible en navegador", "Editó un registro", "Antes", "Después"]) assert.ok(html.includes(value));
});
