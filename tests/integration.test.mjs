import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { test } from "node:test";

const baseUrl = process.env.TRACELAB_TEST_URL;
assert.equal(process.env.TRACELAB_ISOLATED_TEST, "1", "solo ejecutar mediante el runner D1 aislado");
assert.ok(baseUrl && process.env.TRACELAB_TEST_SECRETS_FILE);
const userAgent = "TraceLab-Phase4-Integration/1.0";

function developmentSecrets() {
  const file = readFileSync(process.env.TRACELAB_TEST_SECRETS_FILE, "utf8");
  const values = new Map(file.replace(/^\uFEFF/u, "").split(/\r?\n/u).filter(Boolean).map((line) => {
    const separator = line.indexOf("=");
    return [line.slice(0, separator), line.slice(separator + 1)];
  }));
  const adminCode = values.get("ADMIN_ACCESS_CODE");
  const auditorCode = values.get("AUDITOR_ACCESS_CODE");
  const hmacKey = values.get("AUDIT_HMAC_KEY");
  assert.ok(adminCode && auditorCode && hmacKey && hmacKey.length >= 32, "faltan secretos locales de prueba");
  return { adminCode, auditorCode, hmacKey };
}

async function call(path, { method = "GET", body, cookie } = {}) {
  const headers = { "user-agent": userAgent };
  if (body !== undefined) headers["content-type"] = "application/json";
  if (cookie) headers.cookie = cookie;
  const response = await fetch(new URL(path, baseUrl), {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { /* la aserción de estado informará el fallo */ }
  const setCookie = response.headers.get("set-cookie");
  return {
    status: response.status,
    data,
    cookie: setCookie ? setCookie.split(";", 1)[0] : null,
  };
}

function query(filters) {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(filters)) if (value !== undefined && value !== "") params.set(key, value);
  return `/api/logs?${params.toString()}`;
}

test("integración Fase 5: integridad criptográfica, metalogs, roles, atomicidad y laboratorio", async () => {
  const { adminCode, auditorCode, hmacKey } = developmentSecrets();
  const rawSecrets = [adminCode, auditorCode, hmacKey];
  const rawSessionTokens = [];
  const suffix = randomUUID();
  const studentName = `fase3-${suffix.slice(0, 8)}`;
  const secondName = `fase3b-${suffix.slice(0, 8)}`;
  const sharedEditTitle = `Compartido-${suffix.slice(0, 8)}`;

  const studentRegistration = await call("/api/auth/register", { method: "POST", body: { name: studentName } });
  assert.equal(studentRegistration.status, 201);
  assert.ok(studentRegistration.cookie);
  const studentCookie = studentRegistration.cookie;
  rawSessionTokens.push(studentCookie.slice(studentCookie.indexOf("=") + 1));
  const student = studentRegistration.data.user;

  const studentSession = await call("/api/session", { cookie: studentCookie });
  assert.equal(studentSession.status, 200);
  assert.equal(studentSession.data.user.id, student.id);

  const sharedList = await call("/api/records", { cookie: studentCookie });
  assert.equal(sharedList.status, 200);
  const sharedRecords = sharedList.data.records.filter((record) => record.is_shared === 1);
  assert.equal(sharedRecords.length, 10);
  assert.ok(sharedRecords.every((record) => record.owner_name === "TraceLab — Datos de demostración"));

  const sharedRecord = sharedRecords.reduce((lowest, record) => record.revision < lowest.revision ? record : lowest);
  const sharedRecordId = sharedRecord.id;
  const sharedEdit = await call(`/api/records/${sharedRecordId}`, {
    method: "PATCH", cookie: studentCookie,
    body: { title: sharedEditTitle, content: "Primera edición compartida", expectedRevision: sharedRecord.revision },
  });
  assert.equal(sharedEdit.status, 200);
  assert.equal(sharedEdit.data.record.revision, 2);

  const invalidEdit = await call(`/api/records/${sharedRecordId}`, {
    method: "PATCH", cookie: studentCookie,
      body: { title: "", content: "inválido", expectedRevision: sharedRecord.revision },
  });
  assert.equal(invalidEdit.status, 400);

  const created = await call("/api/records", {
    method: "POST", cookie: studentCookie, body: { title: "Registro privado de prueba", content: "Contenido inicial" },
  });
  assert.equal(created.status, 201);
  assert.equal(created.data.record.revision, 1);
  const recordId = created.data.record.id;

  const secondRegistration = await call("/api/auth/register", { method: "POST", body: { name: secondName } });
  assert.equal(secondRegistration.status, 201);
  const secondCookie = secondRegistration.cookie;
  rawSessionTokens.push(secondCookie.slice(secondCookie.indexOf("=") + 1));
  const secondList = await call("/api/records", { cookie: secondCookie });
  assert.equal(secondList.data.records.filter((record) => record.is_shared === 1).length, 10);
  assert.ok(!secondList.data.records.some((record) => record.id === recordId));
  const sharedConcurrency = await Promise.all([
    call(`/api/records/${sharedRecordId}`, {
      method: "PATCH", cookie: studentCookie,
      body: { title: "Edición concurrente A", content: "A", expectedRevision: sharedEdit.data.record.revision },
    }),
    call(`/api/records/${sharedRecordId}`, {
      method: "PATCH", cookie: secondCookie,
      body: { title: "Edición concurrente B", content: "B", expectedRevision: sharedEdit.data.record.revision },
    }),
  ]);
  assert.deepEqual(sharedConcurrency.map((response) => response.status).sort(), [200, 409]);
  const sharedWinner = sharedConcurrency.find((response) => response.status === 200);
  const sharedConflict = sharedConcurrency.find((response) => response.status === 409);
  const loserCookie = sharedConcurrency[0].status === 409 ? studentCookie : secondCookie;
  const sharedRefresh = await call("/api/records", { cookie: loserCookie });
  const sharedRevision = sharedRefresh.data.records.find((record) => record.id === sharedRecordId).revision;
  const sharedRetry = await call(`/api/records/${sharedRecordId}`, {
    method: "PATCH", cookie: loserCookie,
    body: { title: "Reintento tras conflicto", content: "Evidencia del segundo estudiante", expectedRevision: sharedRevision },
  });
  assert.equal(sharedRetry.status, 200);
  assert.ok(sharedWinner && sharedConflict);
  assert.equal((await call("/api/logs", { cookie: secondCookie })).status, 403);
  assert.equal((await call("/api/metalogs", { cookie: secondCookie })).status, 403);
  assert.equal((await call("/api/audit/admin-activity", { cookie: secondCookie })).status, 403);
  assert.equal((await call("/api/audit/integrity", { cookie: secondCookie })).status, 403);
  assert.equal((await call("/api/audit/lab/sources", { cookie: secondCookie })).status, 403);

  const adminLogin = await call("/api/auth/special", {
    method: "POST", body: { role: "ADMIN", code: adminCode },
  });
  assert.equal(adminLogin.status, 200);
  assert.equal(adminLogin.data.user.role, "ADMIN");
  const adminCookie = adminLogin.cookie;
  rawSessionTokens.push(adminCookie.slice(adminCookie.indexOf("=") + 1));
  assert.equal((await call("/api/metalogs", { cookie: adminCookie })).status, 403);
  assert.equal((await call("/api/audit/admin-activity", { cookie: adminCookie })).status, 403);
  assert.equal((await call("/api/audit/integrity", { cookie: adminCookie })).status, 403);
  assert.equal((await call("/api/audit/lab/sources", { cookie: adminCookie })).status, 403);
  const adminRecords = await call("/api/records", { cookie: adminCookie });
  assert.ok(adminRecords.data.records.some((record) => record.id === recordId));

  const adminEdit = await call(`/api/records/${recordId}`, {
    method: "PATCH", cookie: adminCookie,
    body: { title: "Actualizado por ADMIN", content: "Cambio con evidencia", expectedRevision: 1 },
  });
  assert.equal(adminEdit.status, 200);
  assert.equal(adminEdit.data.record.revision, 2);

  const studentEdit = await call(`/api/records/${recordId}`, {
    method: "PATCH", cookie: studentCookie,
    body: { title: "Actualizado por USER", content: "Cambio concurrente", expectedRevision: 2 },
  });
  assert.equal(studentEdit.status, 200);
  assert.equal(studentEdit.data.record.revision, 3);

  const concurrent = await Promise.all([
    call(`/api/records/${recordId}`, {
      method: "PATCH", cookie: studentCookie,
      body: { title: "Versión simultánea A", content: "A", expectedRevision: 3 },
    }),
    call(`/api/records/${recordId}`, {
      method: "PATCH", cookie: studentCookie,
      body: { title: "Versión simultánea B", content: "B", expectedRevision: 3 },
    }),
  ]);
  assert.deepEqual(concurrent.map((response) => response.status).sort(), [200, 409]);

  const today = new Date().toISOString().slice(0, 10);
  const filtered = await call(query({ user: studentName, action: "user.create", from: today, to: today, result: "SUCCESS" }), { cookie: adminCookie });
  assert.equal(filtered.status, 200);
  assert.ok(filtered.data.logs.some((event) => event.actor_id === student.id));

  const allLogs = await call("/api/logs", { cookie: adminCookie });
  assert.equal(allLogs.status, 200);
  const logs = allLogs.data.logs;
  const registrationLog = logs.find((event) => event.actor_id === student.id && event.action === "user.create");
  assert.ok(registrationLog);
  assert.equal(registrationLog.actor_role, "USER");
  assert.ok(registrationLog.event_id);
  assert.ok(registrationLog.session_id);
  assert.notEqual(registrationLog.session_id, rawSessionTokens[0]);
  assert.equal(registrationLog.user_agent, userAgent);
  assert.ok("ip_address" in registrationLog);
  const fieldChange = logs.find((event) => event.actor_id === "role:admin" && event.action === "record.update" && event.field_name === "title" && event.old_value === "Registro privado de prueba");
  assert.ok(fieldChange);
  assert.equal(fieldChange.new_value, "Actualizado por ADMIN");
  assert.equal(fieldChange.result, "SUCCESS");
  assert.ok(logs.some((event) => event.action === "record.update" && event.result === "CONFLICT"));
  assert.ok(logs.some((event) => event.action === "record.update" && event.result === "FAILED" && event.context_json?.includes("invalid_input")));
  assert.ok(logs.some((event) => event.action === "logs.access" && event.result === "DENIED" && event.actor_id === secondRegistration.data.user.id));
  assert.ok(logs.some((event) => event.action === "auth.login" && event.actor_id === student.id && event.result === "SUCCESS"));
  assert.ok(logs.some((event) => event.action === "auth.login" && event.actor_role === "ADMIN" && event.result === "SUCCESS"));
  const sharedLogs = logs.filter((event) => event.record_id === sharedRecordId && event.action === "record.update");
  assert.ok(sharedLogs.some((event) => event.actor_id === student.id && event.field_name === "title" && event.old_value === sharedRecord.title && event.new_value === sharedEditTitle));
  assert.ok(sharedLogs.some((event) => event.actor_id === secondRegistration.data.user.id && event.field_name === "title" && event.result === "SUCCESS"));
  assert.ok(sharedLogs.some((event) => event.result === "CONFLICT"));
  assert.ok(sharedLogs.filter((event) => event.result === "SUCCESS").length >= 3, "los estudiantes deben poder actualizar y conservar evidencia tras el conflicto");
  assert.ok(sharedLogs.filter((event) => event.result === "SUCCESS").every((event) => /^[0-9a-f]{64}$/u.test(event.event_hash) && event.signature && event.previous_hash), "las ediciones compartidas deben quedar firmadas y enlazadas");

  const auditorLogin = await call("/api/auth/special", {
    method: "POST", body: { role: "AUDITOR", code: auditorCode },
  });
  assert.equal(auditorLogin.status, 200);
  assert.equal(auditorLogin.data.user.role, "AUDITOR");
  const auditorCookie = auditorLogin.cookie;
  rawSessionTokens.push(auditorCookie.slice(auditorCookie.indexOf("=") + 1));
  const independentA = await call("/api/records", { method: "POST", cookie: studentCookie, body: { title: "Concurrente A", content: "Inicial A" } });
  const independentB = await call("/api/records", { method: "POST", cookie: secondCookie, body: { title: "Concurrente B", content: "Inicial B" } });
  assert.equal(independentA.status, 201);
  assert.equal(independentB.status, 201);
  const independentWrites = await Promise.all([
    call(`/api/records/${independentA.data.record.id}`, { method: "PATCH", cookie: studentCookie, body: { title: "Concurrente A final", content: "Final A", expectedRevision: 1 } }),
    call(`/api/records/${independentB.data.record.id}`, { method: "PATCH", cookie: secondCookie, body: { title: "Concurrente B final", content: "Final B", expectedRevision: 1 } }),
    call("/api/audit/integrity", { cookie: auditorCookie }),
  ]);
  assert.deepEqual(independentWrites.map((item) => item.status), [200, 200, 200]);
  assert.equal(independentWrites[2].data.status, "INTEGRITY_UNVERIFIABLE", "las escrituras concurrentes no deben generar un falso fallo del verificador");
  const integrityCheck = await call("/api/audit/integrity", { cookie: auditorCookie });
  assert.equal(integrityCheck.status, 200);
  assert.equal(integrityCheck.data.status, "INTEGRITY_UNVERIFIABLE", JSON.stringify({ status: integrityCheck.status, data: integrityCheck.data }));
  assert.ok(integrityCheck.data.errors.some((item) => item.code === "LEGACY_UNSIGNED_EVENTS"));
  assert.ok(integrityCheck.data.reviewed > 0);
  assert.ok(integrityCheck.data.counts.signed > 0);
  assert.equal(integrityCheck.data.counts.validSignatures, integrityCheck.data.counts.signed);
  assert.equal(JSON.stringify(integrityCheck.data).includes(hmacKey), false);
  const integrityEvents = await call("/api/metalogs?action=INTEGRITY_VERIFICATION", { cookie: auditorCookie });
  assert.ok(integrityEvents.data.metalogs.some((event) => event.action === "INTEGRITY_VERIFICATION"));
  const sourcesResponse = await call("/api/audit/lab/sources", { cookie: auditorCookie });
  assert.equal(sourcesResponse.status, 200);
  const source = sourcesResponse.data.sources.find((item) => item.source === "METALOG");
  assert.ok(source);
  const sourceRows = await call(`/api/metalogs?action=${encodeURIComponent(source.action)}`, { cookie: auditorCookie });
  const originalBefore = sourceRows.data.metalogs.find((item) => item.event_id === source.event_id);
  assert.ok(originalBefore);
  const labCreated = await call("/api/audit/lab/copies", { method: "POST", cookie: auditorCookie, body: { source: source.source, eventId: source.event_id } });
  assert.equal(labCreated.status, 201);
  const labId = labCreated.data.copy.copyId;
  assert.equal(labCreated.data.copy.hasSignature, true);
  assert.equal((await call(`/api/audit/lab/copies/${labId}`, { method: "PATCH", cookie: auditorCookie, body: { field: "action", value: "ALTERED_FOR_LAB", expectedRevision: labCreated.data.copy.revision } })).status, 200);
  const labVerified = await call(`/api/audit/lab/copies/${labId}/verify`, { method: "POST", cookie: auditorCookie });
  assert.equal(labVerified.data.status, "INTEGRITY_FAILED");
  assert.equal(labVerified.data.contentHashValid, false);
  assert.equal(labVerified.data.signatureValid, true, "la firma original autentica el hash original, no el contenido alterado de la copia");
  const originalAfter = (await call(`/api/metalogs?action=${encodeURIComponent(source.action)}`, { cookie: auditorCookie })).data.metalogs.find((item) => item.event_id === source.event_id);
  assert.equal(originalAfter.event_hash, originalBefore.event_hash, "el laboratorio no modifica evidencia original");
  assert.equal((await call(`/api/audit/lab/copies/${labId}`, { method: "DELETE", cookie: auditorCookie })).status, 200);
  assert.equal((await call("/api/audit/integrity", { method: "DELETE", cookie: auditorCookie })).status, 405);
  assert.equal((await call("/api/logs", { cookie: auditorCookie })).status, 200);
  assert.equal((await call("/api/metalogs", { cookie: auditorCookie })).status, 200);
  const verified = await call("/api/audit/admin-activity", { cookie: auditorCookie });
  assert.equal(verified.status, 200);
  const activitySequences = verified.data.activities.map((event) => event.global_sequence);
  assert.deepEqual(activitySequences, [...activitySequences].sort((left, right) => right - left));
  assert.ok(verified.data.activities.some((event) => event.action === "auth.login" && event.actor_role === "ADMIN" && event.source === "LOG"));
  assert.ok(verified.data.activities.some((event) => event.action === "ADMIN_LOGS_VIEWED" && event.actor_role === "ADMIN" && event.source === "METALOG"));
  assert.ok(verified.data.activities.some((event) => event.action === "ADMIN_METALOG_ACCESS_DENIED" && event.actor_role === "ADMIN" && event.result === "DENIED"));
  assert.ok(verified.data.activities.some((event) => event.action === "record.update" && event.actor_role === "ADMIN" && event.old_value === "Registro privado de prueba" && event.new_value === "Actualizado por ADMIN"));
  assert.ok(rawSecrets.every((secret) => !JSON.stringify(verified.data.activities).includes(secret)));
  assert.equal((await call("/api/audit/admin-activity", { cookie: adminCookie })).status, 403);
  assert.equal((await call("/api/logs", { method: "DELETE", cookie: auditorCookie })).status, 405);
  assert.equal((await call("/api/metalogs", { method: "DELETE", cookie: auditorCookie })).status, 405);
  assert.equal((await call(`/api/logs/${registrationLog?.event_id ?? "not-an-event"}`, { method: "DELETE", cookie: auditorCookie })).status, 405);
  const auditorRecords = await call("/api/records", { cookie: auditorCookie });
  assert.equal(auditorRecords.data.records.filter((record) => record.is_shared === 1).length, 10);
  assert.ok(auditorRecords.data.records.some((record) => record.id === recordId));
  const auditorWrite = await call(`/api/records/${recordId}`, {
    method: "PATCH", cookie: auditorCookie,
    body: { title: "No modificar", content: "", expectedRevision: 4 },
  });
  assert.equal(auditorWrite.status, 403);
  const finalLogs = await call("/api/logs", { cookie: adminCookie });
  assert.equal(finalLogs.status, 200);
  assert.ok(finalLogs.data.logs.some((event) => event.action === "record.update" && event.result === "DENIED" && event.actor_role === "AUDITOR"));
  assert.ok(finalLogs.data.logs.some((event) => event.action === "auth.login" && event.actor_role === "AUDITOR" && event.result === "SUCCESS"));
  const raceEvents = finalLogs.data.logs.filter((event) => event.actor_id === student.id && event.action === "record.update" && event.field_name === "title" && ["Versión simultánea A", "Versión simultánea B"].includes(event.new_value));
  assert.equal(raceEvents.length, 1, "solo la actualización ganadora debe persistir su evidencia");
  const finalRecord = (await call("/api/records", { cookie: adminCookie })).data.records.find((record) => record.id === recordId);
  assert.equal(finalRecord.title, raceEvents[0].new_value, "registro y evidencia deben coincidir tras la concurrencia");
  const serializedLogs = JSON.stringify(finalLogs.data.logs);
  assert.ok(rawSecrets.every((secret) => !serializedLogs.includes(secret)), "un código privilegiado llegó a los logs");
  assert.ok(rawSessionTokens.every((token) => !serializedLogs.includes(token)), "un token de sesión llegó a los logs");
  assert.ok(finalLogs.data.logs.every((event) => !Object.keys(event).some((key) => /token|credential|secret/iu.test(key))));
  const allMetalogs = await call("/api/metalogs", { cookie: auditorCookie });
  assert.equal(allMetalogs.status, 200);
  assert.ok(allMetalogs.data.metalogs.some((event) => event.action === "AUDITOR_LOGS_VIEWED" && event.result === "SUCCESS"));
  assert.ok(allMetalogs.data.metalogs.some((event) => event.action === "AUDITOR_METALOGS_VIEWED" && event.result === "SUCCESS"));
  assert.ok(allMetalogs.data.metalogs.some((event) => event.action === "ADMIN_ACTIVITY_VERIFIED" && event.result === "SUCCESS"));
  assert.ok(allMetalogs.data.metalogs.some((event) => event.action === "ADMIN_METALOG_ACCESS_DENIED" && event.result === "DENIED"));
  assert.ok(allMetalogs.data.metalogs.some((event) => event.action === "ACCESS_DENIED" && event.result === "DENIED"));
  const adminDenied = allMetalogs.data.metalogs.find((event) => event.action === "ADMIN_METALOG_ACCESS_DENIED");
  assert.ok(adminDenied);
  assert.equal(adminDenied.actor_role, "ADMIN");
  assert.ok(adminDenied.event_id && adminDenied.session_id);
  assert.equal(adminDenied.resource, "/api/metalogs");
  assert.equal(adminDenied.user_agent, userAgent);
  assert.ok(adminDenied.occurred_at.endsWith("Z"));
  const filteredMetalogs = await call("/api/metalogs?user=role%3Aadmin&action=ADMIN_METALOG_ACCESS_DENIED&result=DENIED", { cookie: auditorCookie });
  assert.equal(filteredMetalogs.status, 200);
  assert.ok(filteredMetalogs.data.metalogs.some((event) => event.event_id === adminDenied.event_id));
  const serializedMetalogs = JSON.stringify(allMetalogs.data.metalogs);
  assert.ok(rawSecrets.every((secret) => !serializedMetalogs.includes(secret)), "un secreto privilegiado llegÃ³ a los metalogs");
  assert.ok(rawSessionTokens.every((token) => !serializedMetalogs.includes(token)), "un token de sesiÃ³n llegÃ³ a los metalogs");
  assert.ok(allMetalogs.data.metalogs.every((event) => !Object.keys(event).some((key) => /token|credential|secret/iu.test(key))));
  assert.ok(allMetalogs.data.metalogs.filter((event) => event.action !== "INTEGRITY_CHAIN_STARTED").every((event) => /^[0-9a-f]{64}$/u.test(event.event_hash) && event.signature && event.previous_hash));

  const logout = await call("/api/auth/logout", { method: "POST", cookie: studentCookie });
  assert.equal(logout.status, 200);
  assert.equal((await call("/api/session", { cookie: studentCookie })).status, 401);
  const logoutLogs = await call(query({ user: studentName, action: "auth.logout", result: "SUCCESS" }), { cookie: adminCookie });
  assert.ok(logoutLogs.data.logs.some((event) => event.session_id === registrationLog.session_id));
});
