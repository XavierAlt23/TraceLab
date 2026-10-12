import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { randomUUID } from "node:crypto";

// Prueba breve autorizada sobre la demo local. No se usa en producción ni bases aisladas.
const base = "http://127.0.0.1:8795";
const secrets = Object.fromEntries(readFileSync(".dev.vars", "utf8").split(/\r?\n/u).filter(Boolean).map((line) => {
  const separator = line.indexOf("="); return [line.slice(0, separator), line.slice(separator + 1)];
}));
async function call(path, { method = "GET", body, cookie } = {}) {
  const response = await fetch(`${base}${path}`, { method, headers: { ...(body !== undefined ? { "content-type": "application/json" } : {}), ...(cookie ? { cookie } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body) });
  return { status: response.status, data: await response.json(), cookie: response.headers.get("set-cookie")?.split(";", 1)[0] };
}
if (!process.argv.includes("--unicode-only")) {
const user = await call("/api/auth/register", { method: "POST", body: { name: `Prueba ${randomUUID().slice(0, 6)}` } });
assert.equal(user.status, 201);
const viewed = await call("/api/records", { cookie: user.cookie }); assert.equal(viewed.status, 200);
assert.equal(viewed.data.records.filter((record) => record.is_shared).length, 10);
const record = viewed.data.records[0];
const editTitle = `Cambio de comprobacion ${randomUUID().slice(0, 6)}`;
const saved = await call(`/api/records/${record.id}`, { method: "PATCH", cookie: user.cookie, body: { title: editTitle, content: "Prueba temporal", expectedRevision: record.revision } });
assert.equal(saved.status, 200, JSON.stringify(saved.data));
const admin = await call("/api/auth/special", { method: "POST", body: { role: "ADMIN", code: secrets.ADMIN_ACCESS_CODE } }); assert.equal(admin.status, 200);
const auditor = await call("/api/auth/special", { method: "POST", body: { role: "AUDITOR", code: secrets.AUDITOR_ACCESS_CODE } }); assert.equal(auditor.status, 200);
const logs = await call("/api/logs", { cookie: admin.cookie }); assert.equal(logs.status, 200);
assert.ok(logs.data.actions.includes("record.list") && logs.data.actions.includes("record.update"));
assert.deepEqual(logs.data.logs.map((event) => event.sequence), logs.data.logs.map((event) => event.sequence).sort((a, b) => b - a));
assert.ok(logs.data.logs.some((event) => event.action === "record.list" && event.actor_role === "USER"));
const target = logs.data.logs.find((event) => event.action === "record.update" && event.field_name === "title" && event.new_value === editTitle); assert.ok(target);
assert.equal((await call("/api/audit/integrity", { cookie: auditor.cookie })).data.status, "INTEGRITY_OK");
assert.equal((await call(`/api/logs/${target.event_id}`, { cookie: user.cookie, method: "PATCH", body: { field: "actor_name", value: "No permitido", expectedRevision: 0 } })).status, 403);
assert.equal((await call(`/api/logs/${target.event_id}`, { cookie: admin.cookie, method: "PATCH", body: { field: "actor_name", value: "Nombre alterado para comprobar", expectedRevision: 0 } })).status, 200);
assert.equal((await call("/api/metalogs", { cookie: admin.cookie })).status, 403);
const metas = await call("/api/metalogs?action=EVIDENCE_CONTENT_EDITED", { cookie: auditor.cookie }); assert.equal(metas.status, 200);
assert.ok(metas.data.metalogs.some((event) => event.actor_role === "ADMIN" && JSON.parse(event.context_json).event_id === target.event_id));
const changed = (await call("/api/logs?action=record.update", { cookie: admin.cookie })).data.logs.find((event) => event.event_id === target.event_id);
assert.equal(changed.signature, target.signature); assert.equal(changed.event_hash, target.event_hash);
const result = await call("/api/audit/integrity", { cookie: auditor.cookie });
assert.equal(result.data.status, "INTEGRITY_FAILED"); assert.ok(result.data.errors.some((item) => item.code === "EVENT_HASH_MISMATCH"));
const metaTarget = metas.data.metalogs[0];
assert.equal((await call(`/api/metalogs/${metaTarget.event_id}`, { cookie: auditor.cookie, method: "PATCH", body: { field: "actor_name", value: "Metalog alterado para comprobar", expectedRevision: 0 } })).status, 200);
assert.equal((await call(`/api/logs/${target.event_id}`, { cookie: auditor.cookie, method: "DELETE" })).status, 405);
assert.equal((await call(`/api/records/${record.id}`, { cookie: auditor.cookie, method: "PATCH", body: { title: "No permitido", content: "", expectedRevision: 2 } })).status, 403);
const serialized = JSON.stringify({ logs: (await call("/api/logs", { cookie: auditor.cookie })).data, metas: (await call("/api/metalogs", { cookie: auditor.cookie })).data });
for (const secret of Object.values(secrets)) assert.ok(!serialized.includes(secret));
console.log("PASS: visualización, edición operativa, orden reciente, combo de acciones, permisos, edición de logs/metalogs auditada, firmas originales conservadas y alteraciones detectadas. Datos de esta comprobación pendientes de retirada local.");
}
const unicodeUser = await call("/api/auth/register", { method: "POST", body: { name: `Jos\u00e9 ${randomUUID().slice(0, 6)}` } });
assert.equal(unicodeUser.status, 201, JSON.stringify(unicodeUser.data));
const unicodeRecords = await call("/api/records", { cookie: unicodeUser.cookie });
const unicodeRecord = unicodeRecords.data.records.at(-1);
const unicodeEdit = await call(`/api/records/${unicodeRecord.id}`, { method: "PATCH", cookie: unicodeUser.cookie,
  body: { title: "Edici\u00f3n con tildes", content: "Informaci\u00f3n", expectedRevision: unicodeRecord.revision } });
assert.equal(unicodeEdit.status, 200, JSON.stringify(unicodeEdit.data));
console.log("PASS: nombres y contenido con tildes en peticiones reales.");
