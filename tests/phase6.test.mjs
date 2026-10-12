import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { call, login, sql, secrets } from "./isolated-helpers.mjs";

test("seguridad real: sesiones, CSRF, JSON, SQL, roles y evidencia denegada", async () => {
  const name = `Seguridad ${randomUUID().slice(0, 8)}`;
  const user = await call("/api/auth/register", { method: "POST", body: { name, role: "ADMIN" } });
  assert.equal(user.status, 201); assert.equal(user.data.user.role, "USER");
  const cookie = user.cookie;
  const admin = await login("ADMIN"); const auditor = await login("AUDITOR");
  for (const path of ["/api/records", "/api/logs", "/api/metalogs", "/api/audit/integrity", "/api/audit/admin-activity", "/api/audit/lab/sources"]) {
    assert.equal((await call(path, { cookie: "tracelab_session=forged" })).status, 401);
  }
  const record = (await call("/api/records", { cookie })).data.records.find((row) => row.is_shared);
  const malicious = '<img src=x onerror="window.__xss=1">';
  const patch = { title: malicious, content: "Texto inerte", expectedRevision: record.revision };
  assert.equal((await call(`/api/records/${record.id}`, { cookie, method: "PATCH", body: patch, headers: { origin: "https://evil.example" } })).status, 403);
  assert.equal((await call(`/api/records/${record.id}`, { cookie, method: "PATCH", body: patch, headers: { "sec-fetch-site": "cross-site" } })).status, 403);
  assert.equal((await call(`/api/records/${record.id}`, { cookie, method: "PATCH", raw: "{" })).status, 400);
  assert.equal((await call(`/api/records/${record.id}`, { cookie, method: "PATCH", body: { ...patch, content: "x".repeat(9000) } })).status, 400);
  assert.equal((await call(`/api/records/${record.id}`, { cookie, method: "PATCH", body: patch })).status, 200);
  assert.equal((await call("/api/logs?before=1%20OR%201=1", { cookie: admin })).status, 400);
  assert.equal((await call("/api/logs?from=2026-02-31", { cookie: admin })).status, 400);
  assert.equal((await call("/api/logs?action='OR'1'='1", { cookie: admin })).data.logs.length, 0);
  for (const roleCookie of [cookie, admin, auditor]) for (const path of ["/api/logs", "/api/logs/event", "/api/metalogs", "/api/metalogs/event"]) {
    for (const method of ["PATCH", "DELETE"]) assert.ok([403, 405].includes((await call(path, { cookie: roleCookie, method, body: {} })).status));
  }
  const meta = await call("/api/metalogs?action=ACCESS_DENIED", { cookie: auditor });
  assert.ok(meta.data.metalogs.some((row) => row.context_json.includes("cross_site_request")));
  const values = JSON.stringify({ meta: meta.data, logs: (await call("/api/logs", { cookie: admin })).data });
  for (const secret of Object.values(secrets)) assert.equal(values.includes(secret), false);
  for (const sessionCookie of [cookie, admin, auditor]) assert.equal(values.includes(sessionCookie.split("=")[1]), false);
  assert.equal((await call("/api/auth/logout", { method: "POST", cookie })).status, 200);
  assert.equal((await call("/api/records", { cookie })).status, 401);
  const html = await fetch(`${process.env.TRACELAB_TEST_URL}/`);
  assert.equal(html.status, 200); assert.ok(html.headers.get("content-security-policy"));
  const document = await html.text();
  const assetPath = document.match(/src="([^"]+\.js)"/u)?.[1];
  assert.ok(assetPath);
  const asset = await (await fetch(new URL(assetPath, process.env.TRACELAB_TEST_URL))).text();
  for (const secret of Object.values(secrets)) assert.equal(asset.includes(secret), false, "secreto de backend en bundle");
});

test("atomicidad D1: fallos de registro y evidencia revierten el cambio completo", async () => {
  const user = await call("/api/auth/register", { method: "POST", body: { name: `Atomicidad ${randomUUID().slice(0, 8)}` } });
  const cookie = user.cookie; const auditor = await login("AUDITOR");
  const record = (await call("/api/records", { cookie })).data.records.find((row) => row.is_shared);
  for (const target of ["records", "logs"]) {
    const trigger = target === "records"
      ? `CREATE TRIGGER phase6_failure BEFORE UPDATE ON records WHEN NEW.id = '${record.id}' BEGIN SELECT RAISE(ABORT, 'fixture'); END;`
      : `CREATE TRIGGER phase6_failure BEFORE INSERT ON logs WHEN NEW.record_id = '${record.id}' AND NEW.result = 'SUCCESS' BEGIN SELECT RAISE(ABORT, 'fixture'); END;`;
    await sql(trigger);
    try {
      const result = await call(`/api/records/${record.id}`, { method: "PATCH", cookie, body: { title: `Debe revertir ${target}`, content: record.content, expectedRevision: record.revision } });
      assert.equal(result.status, 500);
      const unchanged = (await call("/api/records", { cookie })).data.records.find((row) => row.id === record.id);
      assert.equal(unchanged.title, record.title); assert.equal(unchanged.revision, record.revision);
    } finally { await sql("DROP TRIGGER phase6_failure;"); }
  }
  const check = await call("/api/audit/integrity", { cookie: auditor });
  assert.equal(check.data.status, "INTEGRITY_UNVERIFIABLE");
  assert.deepEqual(check.data.errors.map((item) => item.code), ["LEGACY_UNSIGNED_EVENTS"]);
  assert.equal(check.data.counts.signed, check.data.counts.validSignatures);
});

test("abuso: límite persistente devuelve 429 y conserva evidencia del primer rechazo", async () => {
  // IP dedicada para no consumir la ventana de las otras pruebas.
  const headers = { "cf-connecting-ip": "198.51.100.77" };
  for (let index = 0; index < 31; index++) {
    const result = await call("/api/auth/user", { method: "POST", headers, body: {} });
    assert.equal(result.status, index < 30 ? 400 : 429);
    if (index === 30) assert.equal(result.headers.get("retry-after"), "60");
  }
  const admin = await login("ADMIN");
  const events = await call("/api/logs?action=security.rate_limit", { cookie: admin });
  assert.ok(events.data.logs.some((row) => row.result === "DENIED"));
});

test("preparación: secretos ignorados, sin borrado de evidencias en Worker", () => {
  const ignored = readFileSync(".gitignore", "utf8");
  assert.ok(ignored.includes(".dev.vars") && ignored.includes(".wrangler/"));
  const source = readFileSync("src/worker/index.ts", "utf8");
  assert.ok(!/\b(?:DELETE FROM|UPDATE)\s+(?:logs|metalogs|audit_order)\b/iu.test(source));
});

test("sesión expirada, aislamiento de copias y revisión concurrente del laboratorio", async () => {
  const auditor = await login("AUDITOR");
  const other = await login("AUDITOR");
  const sources = await call("/api/audit/lab/sources", { cookie: auditor });
  const source = sources.data.sources[0];
  const created = await call("/api/audit/lab/copies", { method: "POST", cookie: auditor, body: { source: source.source, eventId: source.event_id } });
  assert.equal(created.status, 201);
  const path = `/api/audit/lab/copies/${created.data.copy.copyId}`;
  assert.equal((await call(`${path}/verify`, { method: "POST", cookie: other })).status, 404);
  const responses = await Promise.all(["A", "B"].map((value) => call(path, { method: "PATCH", cookie: auditor, body: { field: "action", value, expectedRevision: 1 } })));
  assert.deepEqual(responses.map((response) => response.status).sort(), [200, 409]);
  const winner = responses.find((response) => response.status === 200);
  assert.equal(winner.data.copy.revision, 2);
  const metas = await call("/api/metalogs?action=LAB_TAMPER_SIMULATED", { cookie: auditor });
  assert.equal(metas.data.metalogs.filter((row) => row.resource === path).length, 1);
  assert.equal((await call(path, { method: "DELETE", cookie: auditor })).status, 200);
  const token = other.slice(other.indexOf("=") + 1);
  const hash = (await import("node:crypto")).createHash("sha256").update(token).digest("hex");
  await sql(`UPDATE sessions SET expires_at='2000-01-01T00:00:00.000Z' WHERE token_hash='${hash}';`);
  assert.equal((await call("/api/audit/integrity", { cookie: other })).status, 401);
});
