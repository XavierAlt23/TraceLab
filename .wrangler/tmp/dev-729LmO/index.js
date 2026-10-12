var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// src/worker/integrity.ts
var encoder = new TextEncoder();
function normalize(value) {
  if (Array.isArray(value)) return value.map(normalize);
  if (value !== null && typeof value === "object") {
    const object = value;
    return Object.fromEntries(Object.keys(object).sort().map((key) => [key, normalize(object[key])]));
  }
  return value;
}
__name(normalize, "normalize");
function canonicalJson(value) {
  return JSON.stringify(normalize(value));
}
__name(canonicalJson, "canonicalJson");
function evidenceContent(event) {
  return canonicalJson(event);
}
__name(evidenceContent, "evidenceContent");
async function sha256Hex(value) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
__name(sha256Hex, "sha256Hex");
function encodeBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}
__name(encodeBase64, "encodeBase64");
function decodeBase64(value) {
  return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
}
__name(decodeBase64, "decodeBase64");
async function hmacKey(secret, usage) {
  return crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, usage);
}
__name(hmacKey, "hmacKey");
async function signEvidence(event, previousHash, secret) {
  const eventHash = await sha256Hex(evidenceContent(event));
  const key = await hmacKey(secret, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(canonicalJson({ schemaVersion: 1, previous_hash: previousHash, event_hash: eventHash })));
  return { event, previous_hash: previousHash, event_hash: eventHash, signature: encodeBase64(new Uint8Array(signature)) };
}
__name(signEvidence, "signEvidence");
async function verifyEvidence(proof, secret) {
  let contentValid = false;
  let signatureValid = false;
  try {
    contentValid = await sha256Hex(evidenceContent(proof.event)) === proof.event_hash;
  } catch {
  }
  try {
    const key = await hmacKey(secret, ["verify"]);
    signatureValid = await crypto.subtle.verify(
      "HMAC",
      key,
      new Uint8Array(decodeBase64(proof.signature)),
      encoder.encode(canonicalJson({ schemaVersion: 1, previous_hash: proof.previous_hash, event_hash: proof.event_hash }))
    );
  } catch {
  }
  return { contentValid, signatureValid };
}
__name(verifyEvidence, "verifyEvidence");
async function signedCheckpoint(secret, cutoff, count, snapshotHash, at) {
  return signEvidence({
    schemaVersion: 1,
    source: "METALOG",
    event_id: crypto.randomUUID(),
    actor_id: null,
    actor_name: "Sistema",
    actor_role: "SYSTEM",
    session_id: null,
    occurred_at: at,
    ip_address: null,
    user_agent: null,
    action: "INTEGRITY_CHAIN_STARTED",
    record_id: null,
    field_name: null,
    old_value: null,
    new_value: null,
    resource: "/api/audit/integrity",
    result: "SUCCESS",
    context_json: canonicalJson({ historical_cutoff: cutoff, historical_count: count, historical_snapshot_sha256: snapshotHash })
  }, "0".repeat(64), secret);
}
__name(signedCheckpoint, "signedCheckpoint");
function rowEvidence(row, source) {
  return {
    schemaVersion: 1,
    source,
    event_id: String(row.event_id),
    actor_id: row.actor_id === null ? null : String(row.actor_id),
    actor_name: String(row.actor_name),
    actor_role: String(row.actor_role),
    session_id: row.session_id === null ? null : String(row.session_id),
    occurred_at: String(row.occurred_at),
    ip_address: row.ip_address === null ? null : String(row.ip_address),
    user_agent: row.user_agent === null ? null : String(row.user_agent),
    action: String(row.action),
    record_id: source === "LOG" && row.record_id !== null ? String(row.record_id) : null,
    field_name: source === "LOG" && row.field_name !== null ? String(row.field_name) : null,
    old_value: source === "LOG" && row.old_value !== null ? String(row.old_value) : null,
    new_value: source === "LOG" && row.new_value !== null ? String(row.new_value) : null,
    resource: source === "METALOG" && row.resource !== null ? String(row.resource) : null,
    result: String(row.result),
    context_json: row.context_json === null ? null : String(row.context_json)
  };
}
__name(rowEvidence, "rowEvidence");
function parseContext(value) {
  if (value === null) return null;
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}
__name(parseContext, "parseContext");
function decodeProof(event, previousHash, eventHash, signature) {
  if (!previousHash || !eventHash || !signature) return null;
  return { event, previous_hash: previousHash, event_hash: eventHash, signature };
}
__name(decodeProof, "decodeProof");
function continuityErrors(rows, firstSequence) {
  const errors = [];
  let expectedSequence = firstSequence;
  let expectedHash = "0".repeat(64);
  for (const row of rows) {
    if (row.sequence !== expectedSequence) errors.push({ code: "AUDIT_SEQUENCE_GAP", sequence: row.sequence });
    if (!row.previous_hash || row.previous_hash !== expectedHash) errors.push({ code: "HASH_LINK_MISMATCH", sequence: row.sequence });
    expectedSequence = row.sequence + 1;
    expectedHash = row.event_hash ?? "";
  }
  return errors;
}
__name(continuityErrors, "continuityErrors");

// src/worker/audit-store.ts
function requestMetadata(request) {
  const observedIp = request.headers.get("cf-connecting-ip")?.trim() ?? "";
  return {
    occurred_at: (/* @__PURE__ */ new Date()).toISOString(),
    ip_address: observedIp.length > 0 && observedIp.length <= 64 && !/[\u0000-\u001f\u007f]/u.test(observedIp) ? observedIp : null,
    user_agent: request.headers.get("user-agent")?.slice(0, 512) ?? null
  };
}
__name(requestMetadata, "requestMetadata");
function asLogEvidence(request, event, occurredAt) {
  const metadata = requestMetadata(request);
  return {
    schemaVersion: 1,
    source: "LOG",
    event_id: crypto.randomUUID(),
    actor_id: event.actorId,
    actor_name: event.actorName.slice(0, 120),
    actor_role: event.actorRole,
    session_id: event.sessionId ?? null,
    ...metadata,
    occurred_at: occurredAt ?? metadata.occurred_at,
    action: event.action.slice(0, 100),
    record_id: event.recordId ?? null,
    field_name: event.fieldName ?? null,
    old_value: event.oldValue ?? null,
    new_value: event.newValue ?? null,
    resource: null,
    result: event.result,
    context_json: event.context ? canonicalJson(event.context) : null
  };
}
__name(asLogEvidence, "asLogEvidence");
function asMetalogEvidence(request, event) {
  const metadata = requestMetadata(request);
  return {
    schemaVersion: 1,
    source: "METALOG",
    event_id: crypto.randomUUID(),
    actor_id: event.actorId,
    actor_name: event.actorName.slice(0, 120),
    actor_role: event.actorRole,
    session_id: event.sessionId ?? null,
    ...metadata,
    action: event.action.slice(0, 100),
    record_id: null,
    field_name: null,
    old_value: null,
    new_value: null,
    resource: event.resource.slice(0, 200),
    result: event.result,
    context_json: event.context ? canonicalJson(event.context) : null
  };
}
__name(asMetalogEvidence, "asMetalogEvidence");
function evidenceInsertStatement(db, proof) {
  const event = proof.event;
  if (event.source === "LOG") return db.prepare(
    `INSERT INTO logs (
       event_id, actor_id, actor_name, actor_role, session_id, occurred_at, ip_address, user_agent,
       action, record_id, field_name, old_value, new_value, result, context_json,
       previous_hash, event_hash, signature
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    event.event_id,
    event.actor_id,
    event.actor_name,
    event.actor_role,
    event.session_id,
    event.occurred_at,
    event.ip_address,
    event.user_agent,
    event.action,
    event.record_id,
    event.field_name,
    event.old_value,
    event.new_value,
    event.result,
    event.context_json,
    proof.previous_hash,
    proof.event_hash,
    proof.signature
  );
  return db.prepare(
    `INSERT INTO metalogs (
       event_id, actor_id, actor_name, actor_role, session_id, occurred_at, ip_address, user_agent,
       action, resource, result, context_json, previous_hash, event_hash, signature
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    event.event_id,
    event.actor_id,
    event.actor_name,
    event.actor_role,
    event.session_id,
    event.occurred_at,
    event.ip_address,
    event.user_agent,
    event.action,
    event.resource,
    event.result,
    event.context_json,
    proof.previous_hash,
    proof.event_hash,
    proof.signature
  );
}
__name(evidenceInsertStatement, "evidenceInsertStatement");
function auditContextStatement(db, recordId, actor, action, proofs) {
  const byField = new Map(proofs.map((proof) => [proof.event.field_name, proof]));
  const title = byField.get("title");
  const content = byField.get("content");
  const shared = byField.get("is_shared");
  const metadata = proofs[0]?.event;
  if (!metadata || !title && !content && !shared) throw new Error("record proof fields are incomplete");
  return db.prepare(
    `INSERT INTO audit_context (
      record_id, actor_id, actor_name, actor_role, session_id, occurred_at, ip_address, user_agent, action,
      title_event_id, title_previous_hash, title_event_hash, title_signature,
      content_event_id, content_previous_hash, content_event_hash, content_signature,
      shared_event_id, shared_previous_hash, shared_event_hash, shared_signature
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    recordId,
    actor.actorId,
    actor.actorName.slice(0, 120),
    actor.actorRole,
    actor.sessionId ?? null,
    metadata.occurred_at,
    metadata.ip_address,
    metadata.user_agent,
    action,
    title?.event.event_id ?? null,
    title?.previous_hash ?? null,
    title?.event_hash ?? null,
    title?.signature ?? null,
    content?.event.event_id ?? null,
    content?.previous_hash ?? null,
    content?.event_hash ?? null,
    content?.signature ?? null,
    shared?.event.event_id ?? null,
    shared?.previous_hash ?? null,
    shared?.event_hash ?? null,
    shared?.signature ?? null
  );
}
__name(auditContextStatement, "auditContextStatement");
async function historicalSnapshot(db, throughSequence) {
  const rows = await db.prepare(
    `SELECT * FROM (SELECT ao.sequence, ao.source, ao.event_id, l.occurred_at, l.actor_id, l.actor_name, l.actor_role, l.session_id,
            l.ip_address, l.user_agent, l.action, l.record_id, l.field_name, l.old_value, l.new_value, NULL AS resource,
            l.result, l.context_json, l.previous_hash, l.event_hash, l.signature
       FROM audit_order ao JOIN logs l ON ao.source = 'LOG' AND l.event_id = ao.event_id
      UNION ALL
     SELECT ao.sequence, ao.source, ao.event_id, m.occurred_at, m.actor_id, m.actor_name, m.actor_role, m.session_id,
            m.ip_address, m.user_agent, m.action, NULL, NULL, NULL, NULL, m.resource,
            m.result, m.context_json, m.previous_hash, m.event_hash, m.signature
       FROM audit_order ao JOIN metalogs m ON ao.source = 'METALOG' AND m.event_id = ao.event_id
     ) WHERE (? IS NULL OR sequence <= ?) ORDER BY sequence LIMIT 50001`
  ).bind(throughSequence ?? null, throughSequence ?? null).all();
  if (rows.results.length > 5e4) throw new Error("historical evidence exceeds checkpoint capacity");
  const normalized = rows.results.map((row) => ({ ...row }));
  const cutoff = normalized.length ? Number(normalized[normalized.length - 1].sequence) : 0;
  return { cutoff, count: normalized.length, hash: await sha256Hex(canonicalJson(normalized)) };
}
__name(historicalSnapshot, "historicalSnapshot");
async function appendSigned(env, entries, beforeEvidence = [], customEvidenceSteps) {
  const secret = env.AUDIT_HMAC_KEY;
  if (!secret || secret.length < 32) throw new Error("AUDIT_HMAC_KEY must contain at least 32 characters");
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const state = await env.DB.prepare("SELECT * FROM integrity_state WHERE singleton = 1").first();
    if (!state) throw new Error("integrity state missing; apply migration 0006");
    const currentMax = await env.DB.prepare("SELECT COALESCE(MAX(sequence), 0) AS value FROM audit_order").first();
    let expectedSequence = state.last_audit_sequence;
    let expectedHead = state.head_hash;
    let cutoff;
    const proofs = [];
    if (state.initialized === 0) {
      cutoff = await historicalSnapshot(env.DB);
      if (currentMax?.value !== cutoff.cutoff) continue;
      expectedSequence = cutoff.cutoff;
      expectedHead = "0".repeat(64);
      proofs.push(await signedCheckpoint(secret, cutoff.cutoff, cutoff.count, cutoff.hash, (/* @__PURE__ */ new Date()).toISOString()));
    } else if (currentMax?.value !== expectedSequence) {
      throw new Error("integrity chain is out of sync with audit order");
    }
    if (state.initialized === 1 && entries.length === 0) return [];
    let nextHash = cutoff && proofs.length ? proofs[proofs.length - 1].event_hash : expectedHead;
    for (const entry of entries) {
      const proof = await signEvidence(entry.proof.event, nextHash, secret);
      proofs.push(proof);
      nextHash = proof.event_hash;
    }
    const signedCount = proofs.length;
    const finalSequence = expectedSequence + signedCount;
    const statements = [];
    if (cutoff) statements.push(env.DB.prepare(
      `UPDATE integrity_state SET initialized = 1, historical_cutoff_sequence = ?, historical_count = ?,
         historical_snapshot_hash = ?, head_hash = ?, last_audit_sequence = ?
       WHERE singleton = 1 AND initialized = 0`
    ).bind(cutoff.cutoff, cutoff.count, cutoff.hash, expectedHead, expectedSequence));
    statements.push(env.DB.prepare(
      `INSERT INTO integrity_write_guard (singleton, expected_head_hash, expected_sequence, final_head_hash, final_sequence)
       VALUES (1, ?, ?, ?, ?)`
    ).bind(expectedHead, expectedSequence, nextHash, finalSequence));
    if (cutoff) statements.push(evidenceInsertStatement(env.DB, proofs[0]));
    statements.push(...beforeEvidence);
    if (customEvidenceSteps) statements.push(...customEvidenceSteps(proofs));
    else statements.push(...proofs.slice(cutoff ? 1 : 0).map((proof) => evidenceInsertStatement(env.DB, proof)));
    statements.push(env.DB.prepare(
      `UPDATE integrity_state SET head_hash = ?, last_audit_sequence = ?
        WHERE singleton = 1 AND head_hash = ? AND last_audit_sequence = ?`
    ).bind(nextHash, finalSequence, expectedHead, expectedSequence));
    statements.push(env.DB.prepare("DELETE FROM integrity_write_guard WHERE singleton = 1"));
    try {
      const results = await env.DB.batch(statements);
      const stateUpdateIndex = statements.length - 2;
      if ((results[stateUpdateIndex]?.meta.changes ?? 0) !== 1) throw new Error("integrity chain compare-and-swap failed");
      return proofs;
    } catch (cause) {
      const message = cause instanceof Error ? cause.message.toLowerCase() : "";
      if ((message.includes("integrity chain write conflict") || message.includes("compare-and-swap failed")) && attempt < 3) continue;
      throw cause;
    }
  }
  throw new Error("integrity chain remained busy after retries");
}
__name(appendSigned, "appendSigned");
async function appendLog(env, request, event) {
  return appendSigned(env, [{ proof: { event: asLogEvidence(request, event), previous_hash: "", event_hash: "", signature: "" } }]);
}
__name(appendLog, "appendLog");
async function initializeIntegrity(env) {
  const state = await env.DB.prepare("SELECT initialized FROM integrity_state WHERE singleton = 1").first();
  if (state?.initialized === 1) return;
  await appendSigned(env, []);
}
__name(initializeIntegrity, "initializeIntegrity");
async function appendMetalog(env, request, event) {
  return appendSigned(env, [{ proof: { event: asMetalogEvidence(request, event), previous_hash: "", event_hash: "", signature: "" } }]);
}
__name(appendMetalog, "appendMetalog");
async function appendIntegrityResult(env, request, event) {
  const secret = env.AUDIT_HMAC_KEY;
  if (!secret || secret.length < 32) throw new Error("AUDIT_HMAC_KEY must contain at least 32 characters");
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const state = await env.DB.prepare("SELECT initialized, head_hash, last_audit_sequence FROM integrity_state WHERE singleton = 1").first();
    const max = await env.DB.prepare("SELECT COALESCE(MAX(sequence), 0) AS value FROM audit_order").first();
    if (!state || state.initialized !== 1) {
      await initializeIntegrity(env);
      continue;
    }
    if (Number(max?.value ?? 0) === state.last_audit_sequence) return appendMetalog(env, request, event);
    const degradedEvent = {
      ...event,
      context: { ...event.context, out_of_chain: true, observed_sequence: Number(max?.value ?? 0), trusted_sequence: state.last_audit_sequence }
    };
    const proof = await signEvidence(asMetalogEvidence(request, degradedEvent), state.head_hash, secret);
    try {
      await env.DB.batch([
        env.DB.prepare(
          `INSERT INTO integrity_write_guard (singleton, expected_head_hash, expected_sequence, final_head_hash, final_sequence, degraded)
           VALUES (1, ?, ?, ?, ?, 1)`
        ).bind(state.head_hash, state.last_audit_sequence, proof.event_hash, state.last_audit_sequence + 1),
        evidenceInsertStatement(env.DB, proof),
        env.DB.prepare("DELETE FROM integrity_write_guard WHERE singleton = 1")
      ]);
      return [proof];
    } catch (cause) {
      const message = cause instanceof Error ? cause.message.toLowerCase() : "";
      if (message.includes("integrity chain write conflict") && attempt < 3) continue;
      throw cause;
    }
  }
  throw new Error("integrity result could not be appended");
}
__name(appendIntegrityResult, "appendIntegrityResult");
async function appendMany(env, request, logs, metalogs, beforeEvidence = []) {
  const entries = [
    ...logs.map((event) => ({ proof: { event: asLogEvidence(request, event), previous_hash: "", event_hash: "", signature: "" } })),
    ...metalogs.map((event) => ({ proof: { event: asMetalogEvidence(request, event), previous_hash: "", event_hash: "", signature: "" } }))
  ];
  return appendSigned(env, entries, beforeEvidence);
}
__name(appendMany, "appendMany");

// src/worker/policy.ts
function canWriteRecord(role, ownerId, actorId, isShared = false) {
  if (role === "ADMIN") return true;
  return role === "USER" && actorId !== null && (actorId === ownerId || isShared);
}
__name(canWriteRecord, "canWriteRecord");
function normalizeUserName(input) {
  if (typeof input !== "string" || /[\u0000-\u001f\u007f]/u.test(input)) return null;
  const displayName = input.normalize("NFKC").trim().replace(/\s+/gu, " ");
  const length = [...displayName].length;
  if (length < 2 || length > 40 || /[\u0000-\u001f\u007f]/u.test(displayName)) return null;
  return { displayName, normalizedName: displayName.toLocaleLowerCase("en-US") };
}
__name(normalizeUserName, "normalizeUserName");
function safeSecretEqual(provided, expected) {
  const encoder2 = new TextEncoder();
  const providedBytes = encoder2.encode(provided);
  const expectedBytes = encoder2.encode(expected);
  let difference = providedBytes.length ^ expectedBytes.length;
  const maxLength = Math.max(providedBytes.length, expectedBytes.length);
  for (let index = 0; index < maxLength; index += 1) {
    difference |= (providedBytes[index] ?? 0) ^ (expectedBytes[index] ?? 0);
  }
  return difference === 0 && expectedBytes.length > 0;
}
__name(safeSecretEqual, "safeSecretEqual");

// src/worker/index.ts
var SESSION_COOKIE = "__Host-tracelab_session";
var LOCAL_SESSION_COOKIE = "tracelab_session";
var SESSION_SECONDS = 12 * 60 * 60;
var MAX_BODY_BYTES = 8192;
var ANONYMOUS = { actorId: null, actorName: "An\xF3nimo", actorRole: "ANONYMOUS" };
function json(data, status = 200, headers = new Headers()) {
  headers.set("content-type", "application/json; charset=utf-8");
  headers.set("cache-control", "no-store");
  headers.set("x-content-type-options", "nosniff");
  return new Response(JSON.stringify(data), { status, headers });
}
__name(json, "json");
function error(message, status) {
  return json({ error: message }, status);
}
__name(error, "error");
function isLocalHost(request) {
  const hostname = new URL(request.url).hostname.replace(/^\[|\]$/gu, "");
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1";
}
__name(isLocalHost, "isLocalHost");
function sessionCookieName(request) {
  return isLocalHost(request) ? LOCAL_SESSION_COOKIE : SESSION_COOKIE;
}
__name(sessionCookieName, "sessionCookieName");
function cookieHeader(request, token, maxAge) {
  const secure = !isLocalHost(request);
  const name = sessionCookieName(request);
  return `${name}=${token}; Path=/; HttpOnly;${secure ? " Secure;" : ""} SameSite=Lax; Max-Age=${maxAge}`;
}
__name(cookieHeader, "cookieHeader");
function readCookie(request) {
  const cookie = request.headers.get("cookie");
  if (!cookie) return null;
  const name = sessionCookieName(request);
  for (const part of cookie.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0) continue;
    if (part.slice(0, separator).trim() === name) return part.slice(separator + 1).trim() || null;
  }
  return null;
}
__name(readCookie, "readCookie");
function toHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
__name(toHex, "toHex");
async function digestToken(token) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  return toHex(new Uint8Array(digest));
}
__name(digestToken, "digestToken");
function makeToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...bytes)).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/gu, "");
}
__name(makeToken, "makeToken");
async function requestBody(request) {
  const contentType = request.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase();
  if (contentType !== "application/json") return null;
  const declaredLength = Number(request.headers.get("content-length") ?? "0");
  if (declaredLength > MAX_BODY_BYTES) return null;
  const text = await request.text();
  if (new TextEncoder().encode(text).length > MAX_BODY_BYTES) return null;
  try {
    const value = JSON.parse(text);
    return typeof value === "object" && value !== null && !Array.isArray(value) ? value : null;
  } catch {
    return null;
  }
}
__name(requestBody, "requestBody");
function actorFor(session) {
  return {
    actorId: session.user_id ?? `role:${session.role.toLowerCase()}`,
    actorName: session.display_name ?? (session.role === "ADMIN" ? "Administrador" : "Auditor"),
    actorRole: session.role,
    sessionId: session.session_id
  };
}
__name(actorFor, "actorFor");
function auditFor(session, action, result, details = {}) {
  return { ...actorFor(session), action, result, ...details };
}
__name(auditFor, "auditFor");
async function logAnonymous(request, env, action, result, details = {}) {
  const event = { ...ANONYMOUS, action, result, ...details };
  if (result === "DENIED") {
    await appendMany(env, request, [event], [{
      ...event,
      action: "ACCESS_DENIED",
      resource: typeof event.context?.resource === "string" ? event.context.resource : action,
      context: { ...event.context, method: event.context?.method ?? request.method, reason: event.context?.reason ?? "access_denied" }
    }]);
  } else {
    await appendLog(env, request, event);
  }
}
__name(logAnonymous, "logAnonymous");
async function logFailure(request, env, session, action, result, details = {}) {
  const event = auditFor(session, action, result, details);
  if (result === "DENIED") {
    await appendMany(env, request, [event], [{
      ...event,
      action: "ACCESS_DENIED",
      resource: typeof event.context?.resource === "string" ? event.context.resource : event.recordId ? `/api/records/${event.recordId}` : action,
      context: { ...event.context, method: request.method, reason: event.context?.reason ?? "access_denied" }
    }]);
  } else {
    await appendLog(env, request, event);
  }
}
__name(logFailure, "logFailure");
async function currentSession(request, env) {
  const token = readCookie(request);
  if (!token || token.length > 128) return null;
  const tokenHash = await digestToken(token);
  const session = await env.DB.prepare(
    `SELECT s.session_id, s.user_id, s.role, s.expires_at, u.display_name
       FROM sessions s LEFT JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ? AND s.revoked_at IS NULL AND s.expires_at > ?`
  ).bind(tokenHash, (/* @__PURE__ */ new Date()).toISOString()).first();
  return session ?? null;
}
__name(currentSession, "currentSession");
async function createSession(request, env, options) {
  const token = makeToken();
  const tokenHash = await digestToken(token);
  const sessionId = crypto.randomUUID();
  const createdAt = (/* @__PURE__ */ new Date()).toISOString();
  const expiresAt = new Date(Date.now() + SESSION_SECONDS * 1e3).toISOString();
  const actorId = options.userId ?? `role:${options.role.toLowerCase()}`;
  const actorName = options.displayName ?? (options.role === "ADMIN" ? "Administrador" : "Auditor");
  await appendMany(env, request, [{
    actorId,
    actorName,
    actorRole: options.role,
    sessionId,
    action: "auth.login",
    result: "SUCCESS"
  }], [], [env.DB.prepare(
    "INSERT INTO sessions (token_hash, user_id, role, created_at, expires_at, session_id) VALUES (?, ?, ?, ?, ?, ?)"
  ).bind(tokenHash, options.userId, options.role, createdAt, expiresAt, sessionId)]);
  return { token, sessionId, expiresAt };
}
__name(createSession, "createSession");
function isDuplicateName(cause) {
  return cause instanceof Error && cause.message.includes("users.normalized_name");
}
__name(isDuplicateName, "isDuplicateName");
async function registerUser(request, env) {
  const body = await requestBody(request);
  const name = normalizeUserName(body?.name);
  if (!body || !name) {
    await logAnonymous(request, env, "user.create", "FAILED", { context: { reason: "invalid_input" } });
    return error("Indica un nombre de 2 a 40 caracteres.", 400);
  }
  const id = crypto.randomUUID();
  const sessionId = crypto.randomUUID();
  const token = makeToken();
  const tokenHash = await digestToken(token);
  const createdAt = (/* @__PURE__ */ new Date()).toISOString();
  const expiresAt = new Date(Date.now() + SESSION_SECONDS * 1e3).toISOString();
  try {
    await appendMany(env, request, [
      { actorId: id, actorName: name.displayName, actorRole: "USER", sessionId, action: "user.create", result: "SUCCESS" },
      { actorId: id, actorName: name.displayName, actorRole: "USER", sessionId, action: "auth.login", result: "SUCCESS" }
    ], [], [
      env.DB.prepare("INSERT INTO users (id, display_name, normalized_name, created_at) VALUES (?, ?, ?, ?)").bind(id, name.displayName, name.normalizedName, createdAt),
      env.DB.prepare("INSERT INTO sessions (token_hash, user_id, role, created_at, expires_at, session_id) VALUES (?, ?, 'USER', ?, ?, ?)").bind(tokenHash, id, createdAt, expiresAt, sessionId)
    ]);
    const headers = new Headers({ "set-cookie": cookieHeader(request, token, SESSION_SECONDS) });
    return json({ user: { id, name: name.displayName, role: "USER" }, expiresAt }, 201, headers);
  } catch (cause) {
    if (isDuplicateName(cause)) {
      await logAnonymous(request, env, "user.create", "DENIED", {
        actorName: name.displayName,
        context: { reason: "name_exists" }
      });
      return error("Ese nombre ya est\xE1 registrado.", 409);
    }
    await logAnonymous(request, env, "user.create", "FAILED", {
      actorName: name.displayName,
      context: { reason: "storage_error" }
    });
    return error("No se pudo crear la cuenta.", 500);
  }
}
__name(registerUser, "registerUser");
async function enterUser(request, env) {
  const body = await requestBody(request);
  const name = normalizeUserName(body?.name);
  if (!body || !name) {
    await logAnonymous(request, env, "auth.login", "FAILED", { context: { reason: "invalid_input" } });
    return error("Indica un nombre v\xE1lido.", 400);
  }
  const user = await env.DB.prepare(
    "SELECT id, display_name FROM users WHERE normalized_name = ?"
  ).bind(name.normalizedName).first();
  if (!user) {
    await logAnonymous(request, env, "auth.login", "DENIED", {
      actorName: name.displayName,
      context: { reason: "user_not_found" }
    });
    return error("No encontramos ese usuario. Reg\xEDstralo primero.", 404);
  }
  const session = await createSession(request, env, { userId: user.id, role: "USER", displayName: user.display_name });
  const headers = new Headers({ "set-cookie": cookieHeader(request, session.token, SESSION_SECONDS) });
  return json({ user: { id: user.id, name: user.display_name, role: "USER" }, expiresAt: session.expiresAt }, 200, headers);
}
__name(enterUser, "enterUser");
async function enterPrivileged(request, env) {
  const body = await requestBody(request);
  const role = body?.role;
  if (role !== "ADMIN" && role !== "AUDITOR") {
    await logAnonymous(request, env, "auth.privileged_login", "DENIED", { context: { reason: "invalid_role" } });
    return error("Acceso denegado.", 401);
  }
  const privilegedRole = role;
  const expected = privilegedRole === "ADMIN" ? env.ADMIN_ACCESS_CODE : env.AUDITOR_ACCESS_CODE;
  if (typeof body?.code !== "string" || !expected || !safeSecretEqual(body.code, expected)) {
    await logAnonymous(request, env, "auth.privileged_login", "DENIED", {
      context: { reason: "invalid_credentials", requested_role: privilegedRole }
    });
    return error("Acceso denegado.", 401);
  }
  const session = await createSession(request, env, { userId: null, role: privilegedRole, displayName: null });
  const headers = new Headers({ "set-cookie": cookieHeader(request, session.token, SESSION_SECONDS) });
  const displayName = privilegedRole === "ADMIN" ? "Administrador" : "Auditor";
  return json({ user: { id: privilegedRole.toLowerCase(), name: displayName, role: privilegedRole }, expiresAt: session.expiresAt }, 200, headers);
}
__name(enterPrivileged, "enterPrivileged");
async function logout(request, env, session) {
  if (session) {
    await appendMany(env, request, [auditFor(session, "auth.logout", "SUCCESS")], [], [
      env.DB.prepare("UPDATE sessions SET revoked_at = ? WHERE session_id = ? AND revoked_at IS NULL").bind((/* @__PURE__ */ new Date()).toISOString(), session.session_id)
    ]);
  } else {
    await logAnonymous(request, env, "auth.logout", "DENIED", { context: { reason: "no_active_session" } });
  }
  return json({ ok: true }, 200, new Headers({ "set-cookie": cookieHeader(request, "", 0) }));
}
__name(logout, "logout");
async function listRecords(request, env, session) {
  const rows = session.role === "USER" ? await env.DB.prepare(
    `SELECT r.id, r.owner_id, u.display_name AS owner_name, r.title, r.content,
              r.created_at, r.updated_at, r.is_shared, r.revision
         FROM records r JOIN users u ON u.id = r.owner_id
        WHERE r.owner_id = ? OR r.is_shared = 1
        ORDER BY r.is_shared DESC, r.updated_at DESC`
  ).bind(session.user_id).all() : await env.DB.prepare(
    `SELECT r.id, r.owner_id, u.display_name AS owner_name, r.title, r.content,
              r.created_at, r.updated_at, r.is_shared, r.revision
         FROM records r JOIN users u ON u.id = r.owner_id
        ORDER BY r.is_shared DESC, r.updated_at DESC`
  ).all();
  if (session.role === "ADMIN") {
    await appendLog(env, request, auditFor(session, "record.list", "SUCCESS", {
      context: { scope: "all_records", count: rows.results.length }
    }));
  }
  return json({ records: rows.results });
}
__name(listRecords, "listRecords");
function validRecordFields(body) {
  if (!body || typeof body.title !== "string" || typeof body.content !== "string") return null;
  const title = body.title.trim();
  const content = body.content.trim();
  if ([...title].length < 1 || [...title].length > 120 || [...content].length > 5e3) return null;
  return { title, content };
}
__name(validRecordFields, "validRecordFields");
async function createRecord(request, env, session) {
  if (session.role === "AUDITOR" || !session.user_id) {
    await logFailure(request, env, session, "record.create", "DENIED", { context: { reason: "read_only_role" } });
    return error("No tienes permiso para crear registros.", 403);
  }
  const fields = validRecordFields(await requestBody(request));
  if (!fields) {
    await logFailure(request, env, session, "record.create", "FAILED", {
      fieldName: "title,content",
      context: { reason: "invalid_input" }
    });
    return error("Revisa el t\xEDtulo y el contenido del registro.", 400);
  }
  const id = crypto.randomUUID();
  const now = (/* @__PURE__ */ new Date()).toISOString();
  try {
    const events = [
      { ...actorFor(session), action: "record.create", result: "SUCCESS", recordId: id, fieldName: "title", oldValue: null, newValue: fields.title },
      { ...actorFor(session), action: "record.create", result: "SUCCESS", recordId: id, fieldName: "content", oldValue: null, newValue: fields.content }
    ];
    const evidenceAt = (/* @__PURE__ */ new Date()).toISOString();
    await appendSigned(env, events.map((event) => ({ proof: { event: asLogEvidence(request, event, evidenceAt), previous_hash: "", event_hash: "", signature: "" } })), [], (proofs) => {
      const signedEvents = proofs.slice(-events.length);
      return [
        auditContextStatement(env.DB, id, events[0], "record.create", signedEvents),
        env.DB.prepare(
          "INSERT INTO records (id, owner_id, title, content, created_at, updated_at, is_shared, revision) VALUES (?, ?, ?, ?, ?, ?, 0, 1)"
        ).bind(id, session.user_id, fields.title, fields.content, now, now),
        env.DB.prepare("DELETE FROM audit_context WHERE record_id = ?").bind(id)
      ];
    });
  } catch {
    await logFailure(request, env, session, "record.create", "FAILED", {
      recordId: id,
      context: { reason: "storage_error" }
    });
    return error("No se pudo guardar el registro.", 500);
  }
  return json({ record: { id, owner_id: session.user_id, ...fields, created_at: now, updated_at: now, is_shared: 0, revision: 1 } }, 201);
}
__name(createRecord, "createRecord");
async function editRecord(request, env, session, id) {
  if (session.role === "AUDITOR") {
    await logFailure(request, env, session, "record.update", "DENIED", {
      recordId: id,
      context: { reason: "read_only_role" }
    });
    return error("El auditor no puede modificar registros operativos.", 403);
  }
  const body = await requestBody(request);
  const fields = validRecordFields(body);
  const expectedRevision = body?.expectedRevision;
  if (!fields || !Number.isSafeInteger(expectedRevision) || Number(expectedRevision) < 1) {
    await logFailure(request, env, session, "record.update", "FAILED", {
      recordId: id,
      fieldName: "title,content",
      context: { reason: "invalid_input" }
    });
    return error("Revisa los campos y la versi\xF3n del registro.", 400);
  }
  const record = await env.DB.prepare(
    "SELECT id, owner_id, title, content, revision, is_shared FROM records WHERE id = ?"
  ).bind(id).first();
  if (!record) {
    await logFailure(request, env, session, "record.update", "FAILED", {
      recordId: id,
      context: { reason: "record_not_found" }
    });
    return error("No encontramos el registro.", 404);
  }
  if (!canWriteRecord(session.role, record.owner_id, session.user_id, record.is_shared === 1)) {
    await logFailure(request, env, session, "record.update", "DENIED", {
      recordId: id,
      context: { reason: "not_owner" }
    });
    return error("No tienes permiso para modificar este registro.", 403);
  }
  if (record.title === fields.title && record.content === fields.content) {
    await logFailure(request, env, session, "record.update", "FAILED", {
      recordId: id,
      context: { reason: "no_field_changed" }
    });
    return error("No hay cambios para guardar.", 400);
  }
  if (record.revision !== expectedRevision) {
    await logFailure(request, env, session, "record.update", "CONFLICT", {
      recordId: id,
      context: { reason: "stale_revision", expected_revision: Number(expectedRevision), current_revision: record.revision }
    });
    return error("El registro cambi\xF3 desde que lo abriste. Actualiza la lista y vuelve a intentarlo.", 409);
  }
  const now = (/* @__PURE__ */ new Date()).toISOString();
  let changed = 0;
  try {
    const events = [];
    if (record.title !== fields.title) events.push({ ...actorFor(session), action: "record.update", result: "SUCCESS", recordId: id, fieldName: "title", oldValue: record.title, newValue: fields.title });
    if (record.content !== fields.content) events.push({ ...actorFor(session), action: "record.update", result: "SUCCESS", recordId: id, fieldName: "content", oldValue: record.content, newValue: fields.content });
    const evidenceAt = (/* @__PURE__ */ new Date()).toISOString();
    await appendSigned(env, events.map((event) => ({ proof: { event: asLogEvidence(request, event, evidenceAt), previous_hash: "", event_hash: "", signature: "" } })), [], (proofs) => {
      const signedEvents = proofs.slice(-events.length);
      return [
        auditContextStatement(env.DB, id, events[0], "record.update", signedEvents),
        env.DB.prepare(
          `UPDATE records SET title = ?, content = ?, updated_at = ?, revision = revision + 1
            WHERE id = ? AND revision = ? AND title = ? AND content = ?`
        ).bind(fields.title, fields.content, now, id, expectedRevision, record.title, record.content),
        env.DB.prepare("DELETE FROM audit_context WHERE record_id = ?").bind(id)
      ];
    });
    changed = 1;
  } catch {
    const latest = await env.DB.prepare("SELECT revision FROM records WHERE id = ?").bind(id).first();
    if (latest && latest.revision !== expectedRevision) {
      await logFailure(request, env, session, "record.update", "CONFLICT", {
        recordId: id,
        context: { reason: "concurrent_update", expected_revision: expectedRevision, current_revision: latest.revision }
      });
      return error("El registro cambi\xF3 en otra solicitud. Actualiza la lista y vuelve a intentarlo.", 409);
    }
    await logFailure(request, env, session, "record.update", "FAILED", {
      recordId: id,
      context: { reason: "storage_error" }
    });
    return error("No se pudo guardar el registro.", 500);
  }
  if (changed === 0) {
    await logFailure(request, env, session, "record.update", "CONFLICT", {
      recordId: id,
      context: { reason: "concurrent_update", expected_revision: expectedRevision }
    });
    return error("El registro cambi\xF3 en otra solicitud. Actualiza la lista y vuelve a intentarlo.", 409);
  }
  return json({ record: { id, owner_id: record.owner_id, ...fields, updated_at: now, is_shared: record.is_shared, revision: expectedRevision + 1 } });
}
__name(editRecord, "editRecord");
function validDateFilter(value) {
  if (value === null || value === "") return null;
  if (!/^\d{4}-\d{2}-\d{2}$/u.test(value)) return void 0;
  const date = /* @__PURE__ */ new Date(`${value}T00:00:00.000Z`);
  return Number.isNaN(date.getTime()) || date.toISOString().slice(0, 10) !== value ? void 0 : value;
}
__name(validDateFilter, "validDateFilter");
async function listLogs(request, env, session) {
  const url = new URL(request.url);
  const user = url.searchParams.get("user")?.trim() ?? "";
  const action = url.searchParams.get("action")?.trim() ?? "";
  const result = url.searchParams.get("result")?.trim().toUpperCase() ?? "";
  const from = validDateFilter(url.searchParams.get("from"));
  const to = validDateFilter(url.searchParams.get("to"));
  if (user.length > 120 || action.length > 100 || result && !["SUCCESS", "FAILED", "DENIED", "CONFLICT"].includes(result) || from === void 0 || to === void 0) {
    return error("Los filtros no son v\xE1lidos.", 400);
  }
  const clauses = [];
  const values = [];
  if (user) {
    clauses.push("(actor_id = ? OR instr(lower(actor_name), lower(?)) > 0)");
    values.push(user, user);
  }
  if (action) {
    clauses.push("action = ?");
    values.push(action);
  }
  if (result) {
    clauses.push("result = ?");
    values.push(result);
  }
  if (from) {
    clauses.push("occurred_at >= ?");
    values.push(`${from}T00:00:00.000Z`);
  }
  if (to) {
    const nextDay = /* @__PURE__ */ new Date(`${to}T00:00:00.000Z`);
    nextDay.setUTCDate(nextDay.getUTCDate() + 1);
    clauses.push("occurred_at < ?");
    values.push(nextDay.toISOString());
  }
  const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
  const rows = await env.DB.prepare(
    `SELECT sequence, event_id, actor_id, actor_name, actor_role, session_id, occurred_at,
            ip_address, user_agent, action, record_id, field_name, old_value, new_value,
            result, context_json, previous_hash, event_hash, signature
       FROM logs ${where}
      ORDER BY sequence DESC LIMIT 100`
  ).bind(...values).all();
  await appendMetalog(env, request, {
    ...actorFor(session),
    action: session.role === "ADMIN" ? "ADMIN_LOGS_VIEWED" : "AUDITOR_LOGS_VIEWED",
    resource: "/api/logs",
    result: "SUCCESS",
    context: { user, action, from: from ?? null, to: to ?? null, result, count: rows.results.length }
  });
  return json({ logs: rows.results, limit: 100 });
}
__name(listLogs, "listLogs");
async function listMetalogs(request, env, session) {
  const url = new URL(request.url);
  const user = url.searchParams.get("user")?.trim() ?? "";
  const action = url.searchParams.get("action")?.trim() ?? "";
  const result = url.searchParams.get("result")?.trim().toUpperCase() ?? "";
  const from = validDateFilter(url.searchParams.get("from"));
  const to = validDateFilter(url.searchParams.get("to"));
  if (user.length > 120 || action.length > 100 || result && !["SUCCESS", "FAILED", "DENIED", "CONFLICT"].includes(result) || from === void 0 || to === void 0) {
    return error("Filtros de metalogs no v\xC3\xA1lidos.", 400);
  }
  const clauses = [];
  const values = [];
  if (user) {
    clauses.push("(actor_id = ? OR instr(lower(actor_name), lower(?)) > 0)");
    values.push(user, user);
  }
  if (action) {
    clauses.push("action = ?");
    values.push(action);
  }
  if (result) {
    clauses.push("result = ?");
    values.push(result);
  }
  if (from) {
    clauses.push("occurred_at >= ?");
    values.push(`${from}T00:00:00.000Z`);
  }
  if (to) {
    const nextDay = /* @__PURE__ */ new Date(`${to}T00:00:00.000Z`);
    nextDay.setUTCDate(nextDay.getUTCDate() + 1);
    clauses.push("occurred_at < ?");
    values.push(nextDay.toISOString());
  }
  const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
  const rows = await env.DB.prepare(
    `SELECT sequence, event_id, actor_id, actor_name, actor_role, session_id, occurred_at,
            ip_address, user_agent, action, resource, result, context_json,
            previous_hash, event_hash, signature
       FROM metalogs ${where}
      ORDER BY sequence DESC LIMIT 100`
  ).bind(...values).all();
  await appendMetalog(env, request, {
    ...actorFor(session),
    action: "AUDITOR_METALOGS_VIEWED",
    resource: "/api/metalogs",
    result: "SUCCESS",
    context: { user, action, from: from ?? null, to: to ?? null, result, count: rows.results.length }
  });
  return json({ metalogs: rows.results, limit: 100 });
}
__name(listMetalogs, "listMetalogs");
async function verifyAdminActivity(request, env, session) {
  const rows = await env.DB.prepare(
    `SELECT * FROM (
       SELECT audit_order.sequence AS global_sequence, logs.event_id, actor_id, actor_name, actor_role, session_id, logs.occurred_at,
              ip_address, user_agent, action,
              CASE WHEN record_id IS NULL THEN 'logs' ELSE 'record:' || record_id END AS resource,
              record_id, field_name, old_value, new_value, result, 'LOG' AS source
         FROM logs JOIN audit_order ON audit_order.source = 'LOG' AND audit_order.event_id = logs.event_id
        WHERE actor_role = 'ADMIN'
       UNION ALL
       SELECT audit_order.sequence AS global_sequence, metalogs.event_id, actor_id, actor_name, actor_role, session_id, metalogs.occurred_at,
              ip_address, user_agent, action, resource,
              NULL AS record_id, NULL AS field_name, NULL AS old_value, NULL AS new_value,
              result, 'METALOG' AS source
         FROM metalogs JOIN audit_order ON audit_order.source = 'METALOG' AND audit_order.event_id = metalogs.event_id
        WHERE actor_role = 'ADMIN'
     ) ORDER BY global_sequence DESC LIMIT 200`
  ).all();
  await appendMetalog(env, request, {
    ...actorFor(session),
    action: "ADMIN_ACTIVITY_VERIFIED",
    resource: "/api/audit/admin-activity",
    result: "SUCCESS",
    context: { count: rows.results.length }
  });
  return json({ activities: rows.results, limit: 200 });
}
__name(verifyAdminActivity, "verifyAdminActivity");
async function integritySnapshot(env, fixedCutoff) {
  const result = await env.DB.prepare(
    `SELECT * FROM (
       SELECT ao.sequence, ao.source, ao.event_id, ao.occurred_at AS order_occurred_at, l.occurred_at, l.actor_id, l.actor_name, l.actor_role, l.session_id,
              l.ip_address, l.user_agent, l.action, l.record_id, l.field_name, l.old_value, l.new_value, NULL AS resource,
              l.result, l.context_json, l.previous_hash, l.event_hash, l.signature
         FROM audit_order ao LEFT JOIN logs l ON ao.source = 'LOG' AND l.event_id = ao.event_id
        WHERE ao.source = 'LOG'
       UNION ALL
       SELECT ao.sequence, ao.source, ao.event_id, ao.occurred_at AS order_occurred_at, m.occurred_at, m.actor_id, m.actor_name, m.actor_role, m.session_id,
              m.ip_address, m.user_agent, m.action, NULL AS record_id, NULL AS field_name, NULL AS old_value, NULL AS new_value,
              m.resource, m.result, m.context_json, m.previous_hash, m.event_hash, m.signature
         FROM audit_order ao LEFT JOIN metalogs m ON ao.source = 'METALOG' AND m.event_id = ao.event_id
        WHERE ao.source = 'METALOG'
     ) ORDER BY sequence LIMIT 10001`
  ).all();
  const actualMax = await env.DB.prepare("SELECT COALESCE(MAX(sequence), 0) AS value FROM audit_order").first();
  return { rows: result.results.filter((row) => Number(row.sequence) <= fixedCutoff).map((row) => ({ ...row, sequence: Number(row.sequence) })), actualMax: Number(actualMax?.value ?? 0) };
}
__name(integritySnapshot, "integritySnapshot");
async function verifyIntegrity(request, env, session) {
  if (!env.AUDIT_HMAC_KEY || env.AUDIT_HMAC_KEY.length < 32) {
    return json({ status: "INTEGRITY_UNVERIFIABLE", reviewed: 0, errors: [{ code: "HMAC_KEY_UNAVAILABLE" }] }, 503);
  }
  await initializeIntegrity(env);
  const state = await env.DB.prepare("SELECT * FROM integrity_state WHERE singleton = 1").first();
  const fixedMaxRow = await env.DB.prepare("SELECT COALESCE(MAX(sequence), 0) AS value FROM audit_order").first();
  const fixedCutoff = fixedMaxRow?.value ?? 0;
  const snapshot = await integritySnapshot(env, fixedCutoff);
  const errors = [];
  let firstInconsistentEvent = null;
  const fail = /* @__PURE__ */ __name((code, row) => {
    errors.push({ code, ...row ? { sequence: row.sequence, event_id: row.event_id } : {} });
    if (!firstInconsistentEvent) firstInconsistentEvent = { sequence: row?.sequence ?? 0, event_id: row?.event_id ?? "", code };
  }, "fail");
  let status = "INTEGRITY_OK";
  if (!state) {
    fail("INTEGRITY_STATE_MISSING");
    status = "INTEGRITY_FAILED";
  }
  if (snapshot.rows.length >= 10001 || fixedCutoff > 1e4) {
    errors.push({ code: "VERIFICATION_LIMIT_EXCEEDED" });
    status = "INTEGRITY_UNVERIFIABLE";
  }
  const expectedCount = Math.min(fixedCutoff, snapshot.rows.length);
  let expectedSequence = 1;
  for (const row of snapshot.rows) {
    if (row.sequence !== expectedSequence) fail("AUDIT_SEQUENCE_GAP", row);
    expectedSequence = row.sequence + 1;
    if (!row.actor_name || !row.actor_role || !row.action || !row.result || !row.occurred_at) fail("EVENT_REFERENCE_INCOMPLETE", row);
    if (row.occurred_at !== row.order_occurred_at) fail("EVENT_ORDER_TIMESTAMP_MISMATCH", row);
  }
  if (expectedCount !== fixedCutoff) fail("AUDIT_ORDER_REFERENCE_MISSING");
  if (state) {
    const historicRows = await historicalSnapshot(env.DB, state.historical_cutoff_sequence);
    if (historicRows.cutoff !== state.historical_cutoff_sequence || historicRows.count !== state.historical_count || historicRows.hash !== state.historical_snapshot_hash) {
      fail("HISTORICAL_CHECKPOINT_MISMATCH");
      status = "INTEGRITY_FAILED";
    } else if (state.historical_count > 0) {
      errors.push({ code: "LEGACY_UNSIGNED_EVENTS", sequence: state.historical_cutoff_sequence });
      status = "INTEGRITY_UNVERIFIABLE";
    }
    const chainRows = snapshot.rows.filter((row) => row.sequence > state.historical_cutoff_sequence);
    const checkpoint = chainRows[0];
    const checkpointContext = parseContext(checkpoint?.context_json ?? null) ?? {};
    if (!checkpoint || checkpoint.action !== "INTEGRITY_CHAIN_STARTED" || checkpoint.source !== "METALOG" || checkpointContext.historical_cutoff !== state.historical_cutoff_sequence || checkpointContext.historical_count !== state.historical_count || checkpointContext.historical_snapshot_sha256 !== state.historical_snapshot_hash) {
      fail("CHAIN_CHECKPOINT_MISMATCH", checkpoint);
    }
    for (const continuityError of continuityErrors(chainRows, state.historical_cutoff_sequence + 1)) {
      const row = chainRows.find((item) => item.sequence === continuityError.sequence);
      fail(continuityError.code, row);
    }
    let previousHash = "0".repeat(64);
    for (let index = 0; index < chainRows.length; index += 1) {
      const row = chainRows[index];
      if (row.actor_name === null || row.action === null || row.result === null) {
        fail("EVENT_REFERENCE_MISSING", row);
        continue;
      }
      if (!row.previous_hash || !row.event_hash || !row.signature) {
        fail("SIGNED_EVENT_PROOF_MISSING", row);
        continue;
      }
      const source = row.source;
      const event = rowEvidence(row, source);
      const proof = decodeProof(event, row.previous_hash, row.event_hash, row.signature);
      if (!proof) {
        fail("SIGNED_EVENT_PROOF_MISSING", row);
        continue;
      }
      const result = await verifyEvidence(proof, env.AUDIT_HMAC_KEY);
      if (!result.contentValid) fail("EVENT_HASH_MISMATCH", row);
      if (!result.signatureValid) fail("HMAC_SIGNATURE_INVALID", row);
      previousHash = row.event_hash;
    }
    if (state.last_audit_sequence !== fixedCutoff || state.head_hash !== previousHash) fail("CHAIN_HEAD_MISMATCH");
    if (snapshot.actualMax !== fixedCutoff) fail("AUDIT_ORDER_CHANGED_DURING_VERIFICATION");
  }
  if (errors.some((item) => !["LEGACY_UNSIGNED_EVENTS", "VERIFICATION_LIMIT_EXCEEDED"].includes(item.code))) status = "INTEGRITY_FAILED";
  else if (status !== "INTEGRITY_FAILED" && errors.length > 0) status = "INTEGRITY_UNVERIFIABLE";
  const counts = {
    logs: snapshot.rows.filter((row) => row.source === "LOG").length,
    metalogs: snapshot.rows.filter((row) => row.source === "METALOG").length,
    signed: snapshot.rows.filter((row) => row.sequence > (state?.historical_cutoff_sequence ?? 0)).length,
    legacy: state?.historical_count ?? 0
  };
  await appendIntegrityResult(env, request, {
    ...actorFor(session),
    action: "INTEGRITY_VERIFICATION",
    resource: "/api/audit/integrity",
    result: status === "INTEGRITY_OK" ? "SUCCESS" : "FAILED",
    context: { status, reviewed: snapshot.rows.length, fixed_cutoff: fixedCutoff, error_count: errors.length }
  });
  return json({ status, reviewed: snapshot.rows.length, counts, firstInconsistentEvent, errors: errors.slice(0, 100), fixedCutoff });
}
__name(verifyIntegrity, "verifyIntegrity");
function labResponse(row) {
  const original = JSON.parse(row.original_json);
  const working = JSON.parse(row.working_json);
  return { copyId: row.copy_id, source: row.source, sourceEventId: row.source_event_id, original: original.event, working, hasSignature: Boolean(original.proof), revision: row.revision };
}
__name(labResponse, "labResponse");
async function labSources(request, env, session) {
  const rows = await env.DB.prepare(
    `SELECT * FROM (
       SELECT 'LOG' AS source, event_id, occurred_at, actor_name, actor_role, action FROM logs
       UNION ALL
       SELECT 'METALOG' AS source, event_id, occurred_at, actor_name, actor_role, action FROM metalogs
     ) ORDER BY occurred_at DESC LIMIT 100`
  ).all();
  await appendMetalog(env, request, { ...actorFor(session), action: "LAB_SOURCES_VIEWED", resource: "/api/audit/lab/sources", result: "SUCCESS", context: { count: rows.results.length } });
  return json({ sources: rows.results });
}
__name(labSources, "labSources");
async function createLabCopy(request, env, session) {
  const body = await requestBody(request);
  if (body?.source !== "LOG" && body?.source !== "METALOG" || typeof body.eventId !== "string" || body.eventId.length > 64) return error("Selecciona una evidencia v\xE1lida.", 400);
  const table = body.source === "LOG" ? "logs" : "metalogs";
  const row = await env.DB.prepare(`SELECT * FROM ${table} WHERE event_id = ?`).bind(body.eventId).first();
  if (!row) return error("No encontramos la evidencia seleccionada.", 404);
  const event = rowEvidence(row, body.source);
  const proof = decodeProof(
    event,
    typeof row.previous_hash === "string" ? row.previous_hash : null,
    typeof row.event_hash === "string" ? row.event_hash : null,
    typeof row.signature === "string" ? row.signature : null
  );
  const copyId = crypto.randomUUID();
  const originalJson = canonicalJson({ event, proof });
  await appendMany(env, request, [], [{
    ...actorFor(session),
    action: "LAB_COPY_CREATED",
    resource: `/api/audit/lab/copies/${copyId}`,
    result: "SUCCESS",
    context: { source: body.source, source_event_id: body.eventId, has_signature: Boolean(proof) }
  }], [env.DB.prepare(
    `INSERT INTO lab_copies (copy_id, owner_session_id, source, source_event_id, original_json, working_json, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).bind(copyId, session.session_id, body.source, body.eventId, originalJson, canonicalJson(event), (/* @__PURE__ */ new Date()).toISOString())]);
  const created = await env.DB.prepare("SELECT * FROM lab_copies WHERE copy_id = ? AND owner_session_id = ?").bind(copyId, session.session_id).first();
  return json({ copy: labResponse(created) }, 201);
}
__name(createLabCopy, "createLabCopy");
async function mutateLabCopy(request, env, session, copyId) {
  const body = await requestBody(request);
  if (typeof body?.field !== "string" || !["action", "old_value", "new_value", "context_json", "result"].includes(body.field) || typeof body.value !== "string" || body.value.length > 5e3) return error("Campo de simulaci\xF3n no v\xE1lido.", 400);
  const row = await env.DB.prepare("SELECT * FROM lab_copies WHERE copy_id = ? AND owner_session_id = ?").bind(copyId, session.session_id).first();
  if (!row) return error("No encontramos la copia del laboratorio.", 404);
  const working = JSON.parse(row.working_json);
  working[body.field] = body.value;
  const next = canonicalJson(working);
  await appendMany(env, request, [], [{
    ...actorFor(session),
    action: "LAB_TAMPER_SIMULATED",
    resource: `/api/audit/lab/copies/${copyId}`,
    result: "SUCCESS",
    context: { source_event_id: row.source_event_id, field: body.field }
  }], [env.DB.prepare("UPDATE lab_copies SET working_json = ?, revision = revision + 1 WHERE copy_id = ? AND owner_session_id = ? AND revision = ?").bind(next, copyId, session.session_id, row.revision)]);
  const updated = await env.DB.prepare("SELECT * FROM lab_copies WHERE copy_id = ? AND owner_session_id = ?").bind(copyId, session.session_id).first();
  return json({ copy: labResponse(updated) });
}
__name(mutateLabCopy, "mutateLabCopy");
async function verifyLabCopy(request, env, session, copyId) {
  const row = await env.DB.prepare("SELECT * FROM lab_copies WHERE copy_id = ? AND owner_session_id = ?").bind(copyId, session.session_id).first();
  if (!row) return error("No encontramos la copia del laboratorio.", 404);
  const original = JSON.parse(row.original_json);
  const working = JSON.parse(row.working_json);
  let status = "INTEGRITY_UNVERIFIABLE";
  if (original.proof && env.AUDIT_HMAC_KEY) {
    const verified = await verifyEvidence({ ...original.proof, event: working }, env.AUDIT_HMAC_KEY);
    status = verified.contentValid && verified.signatureValid ? "INTEGRITY_OK" : "INTEGRITY_FAILED";
  }
  await appendMetalog(env, request, {
    ...actorFor(session),
    action: "LAB_COPY_VERIFIED",
    resource: `/api/audit/lab/copies/${copyId}`,
    result: status === "INTEGRITY_OK" ? "SUCCESS" : "FAILED",
    context: { source_event_id: row.source_event_id, status, revision: row.revision }
  });
  return json({ status, contentHashValid: status === "INTEGRITY_OK", signatureValid: status === "INTEGRITY_OK", copy: labResponse(row) });
}
__name(verifyLabCopy, "verifyLabCopy");
async function resetLabCopy(request, env, session, copyId) {
  const result = await env.DB.prepare("SELECT source_event_id FROM lab_copies WHERE copy_id = ? AND owner_session_id = ?").bind(copyId, session.session_id).first();
  if (!result) return error("No encontramos la copia del laboratorio.", 404);
  await appendMany(env, request, [], [{
    ...actorFor(session),
    action: "LAB_RESET",
    resource: `/api/audit/lab/copies/${copyId}`,
    result: "SUCCESS",
    context: { source_event_id: result.source_event_id }
  }], [env.DB.prepare("DELETE FROM lab_copies WHERE copy_id = ? AND owner_session_id = ?").bind(copyId, session.session_id)]);
  return json({ ok: true });
}
__name(resetLabCopy, "resetLabCopy");
async function handleApi(request, env) {
  const url = new URL(request.url);
  const { pathname } = url;
  if (request.method === "POST" && pathname === "/api/auth/register") return registerUser(request, env);
  if (request.method === "POST" && pathname === "/api/auth/user") return enterUser(request, env);
  if (request.method === "POST" && pathname === "/api/auth/special") return enterPrivileged(request, env);
  if (request.method === "POST" && pathname === "/api/auth/logout") {
    return logout(request, env, await currentSession(request, env));
  }
  const session = await currentSession(request, env);
  if (request.method === "GET" && pathname === "/api/session") {
    if (!session) return error("Inicia sesi\xF3n para continuar.", 401);
    const displayName = session.display_name ?? (session.role === "ADMIN" ? "Administrador" : "Auditor");
    return json({
      user: { id: session.user_id ?? `role:${session.role.toLowerCase()}`, name: displayName, role: session.role },
      expiresAt: session.expires_at
    });
  }
  const privilegedAuditPath = pathname === "/api/logs" || pathname === "/api/metalogs" || pathname.startsWith("/api/metalogs/") || pathname.startsWith("/api/audit/");
  if (pathname === "/api/records" || pathname.startsWith("/api/records/") || privilegedAuditPath) {
    if (!session) {
      await logAnonymous(request, env, "access.denied", "DENIED", {
        context: { method: request.method, resource: pathname }
      });
      return error("Inicia sesi\xF3n para continuar.", 401);
    }
  }
  if (!session) return error("Inicia sesi\xF3n para continuar.", 401);
  if (request.method === "GET" && pathname === "/api/records") return listRecords(request, env, session);
  if (request.method === "POST" && pathname === "/api/records") return createRecord(request, env, session);
  const recordMatch = pathname.match(/^\/api\/records\/([0-9a-f-]{36})$/iu);
  if (request.method === "PATCH" && recordMatch) return editRecord(request, env, session, recordMatch[1]);
  if (pathname.startsWith("/api/audit/")) {
    if (session.role !== "AUDITOR") {
      await logFailure(request, env, session, "audit.access", "DENIED", {
        context: { method: request.method, resource: pathname, reason: "auditor_role_required" }
      });
      return error("Esta funci\xF3n est\xE1 reservada al auditor.", 403);
    }
    if (pathname === "/api/audit/integrity") {
      if (request.method !== "GET") return error("La verificaci\xF3n es de solo lectura.", 405);
      return verifyIntegrity(request, env, session);
    }
    if (pathname === "/api/audit/lab/sources") {
      if (request.method !== "GET") return error("Consulta de solo lectura.", 405);
      return labSources(request, env, session);
    }
    if (pathname === "/api/audit/lab/copies") {
      if (request.method !== "POST") return error("M\xE9todo no permitido.", 405);
      return createLabCopy(request, env, session);
    }
    const labMatch = pathname.match(/^\/api\/audit\/lab\/copies\/([0-9a-f-]{36})(?:\/(verify))?$/iu);
    if (labMatch) {
      const [, copyId, verify] = labMatch;
      if (verify && request.method === "POST") return verifyLabCopy(request, env, session, copyId);
      if (!verify && request.method === "PATCH") return mutateLabCopy(request, env, session, copyId);
      if (!verify && request.method === "DELETE") return resetLabCopy(request, env, session, copyId);
      return error("M\xE9todo no permitido.", 405);
    }
  }
  if (pathname === "/api/logs") {
    if (request.method !== "GET") {
      await logFailure(request, env, session, "logs.access", "DENIED", {
        context: { method: request.method, reason: "read_only_endpoint" }
      });
      return error("Los logs son de solo lectura.", 405);
    }
    if (session.role !== "ADMIN" && session.role !== "AUDITOR") {
      await logFailure(request, env, session, "logs.access", "DENIED", { context: { reason: "role_not_allowed" } });
      return error("No tienes permiso para consultar los logs.", 403);
    }
    return listLogs(request, env, session);
  }
  if (pathname === "/api/metalogs" || pathname.startsWith("/api/metalogs/")) {
    if (session.role === "ADMIN") {
      const deniedContext = { method: request.method, reason: "role_not_allowed" };
      await appendMany(env, request, [], [
        { ...actorFor(session), action: "ADMIN_METALOG_ACCESS_DENIED", resource: pathname, result: "DENIED", context: deniedContext },
        { ...actorFor(session), action: "ACCESS_DENIED", resource: pathname, result: "DENIED", context: { ...deniedContext, attempted_action: "metalogs.read" } }
      ]);
      return error("El administrador no tiene permiso para consultar metalogs.", 403);
    }
    if (session.role !== "AUDITOR") {
      await logFailure(request, env, session, "metalog.access", "DENIED", {
        context: { method: request.method, resource: pathname, reason: "role_not_allowed" }
      });
      return error("No tienes permiso para consultar metalogs.", 403);
    }
    if (request.method !== "GET" || pathname !== "/api/metalogs") {
      await logFailure(request, env, session, "metalog.access", "DENIED", {
        context: { method: request.method, resource: pathname, reason: "read_only_endpoint" }
      });
      return error("Los metalogs son de solo lectura.", 405);
    }
    return listMetalogs(request, env, session);
  }
  if (pathname === "/api/audit/admin-activity") {
    if (session.role !== "AUDITOR") {
      await logFailure(request, env, session, "audit.admin_activity", "DENIED", {
        context: { method: request.method, resource: pathname, reason: "auditor_role_required" }
      });
      return error("Esta verificaci\xF3n est\xE1 reservada al auditor.", 403);
    }
    if (request.method !== "GET") {
      await logFailure(request, env, session, "audit.admin_activity", "DENIED", {
        context: { method: request.method, resource: pathname, reason: "read_only_endpoint" }
      });
      return error("La verificaci\xF3n es de solo lectura.", 405);
    }
    return verifyAdminActivity(request, env, session);
  }
  return error("Ruta no encontrada.", 404);
}
__name(handleApi, "handleApi");
var worker_default = {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (!url.pathname.startsWith("/api/")) return env.ASSETS.fetch(request);
    try {
      return await handleApi(request, env);
    } catch {
      return error("Ocurri\xF3 un error interno.", 500);
    }
  }
};

// node_modules/wrangler/templates/middleware/middleware-ensure-req-body-drained.ts
var drainBody = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } finally {
    try {
      if (request.body !== null && !request.bodyUsed) {
        const reader = request.body.getReader();
        while (!(await reader.read()).done) {
        }
      }
    } catch (e) {
      console.error("Failed to drain the unused request body.", e);
    }
  }
}, "drainBody");
var middleware_ensure_req_body_drained_default = drainBody;

// node_modules/wrangler/templates/middleware/middleware-miniflare3-json-error.ts
function reduceError(e) {
  return {
    name: e?.name,
    message: e?.message ?? String(e),
    stack: e?.stack,
    cause: e?.cause === void 0 ? void 0 : reduceError(e.cause)
  };
}
__name(reduceError, "reduceError");
var jsonError = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } catch (e) {
    const error2 = reduceError(e);
    const body = JSON.stringify(error2);
    const headers = {
      "Content-Type": "application/json",
      "MF-Experimental-Error-Stack": "true"
    };
    const encoded = encodeURIComponent(body);
    if (encoded.length <= 8192) {
      headers["MF-Experimental-Error-Stack-Payload"] = encoded;
    }
    return new Response(body, { status: 500, headers });
  }
}, "jsonError");
var middleware_miniflare3_json_error_default = jsonError;

// .wrangler/tmp/bundle-ruMMpO/middleware-insertion-facade.js
var __INTERNAL_WRANGLER_MIDDLEWARE__ = [
  middleware_ensure_req_body_drained_default,
  middleware_miniflare3_json_error_default
];
var middleware_insertion_facade_default = worker_default;

// node_modules/wrangler/templates/middleware/common.ts
var __facade_middleware__ = [];
function __facade_register__(...args) {
  __facade_middleware__.push(...args.flat());
}
__name(__facade_register__, "__facade_register__");
function __facade_invokeChain__(request, env, ctx, dispatch, middlewareChain) {
  const [head, ...tail] = middlewareChain;
  const middlewareCtx = {
    dispatch,
    next(newRequest, newEnv) {
      return __facade_invokeChain__(newRequest, newEnv, ctx, dispatch, tail);
    }
  };
  return head(request, env, ctx, middlewareCtx);
}
__name(__facade_invokeChain__, "__facade_invokeChain__");
function __facade_invoke__(request, env, ctx, dispatch, finalMiddleware) {
  return __facade_invokeChain__(request, env, ctx, dispatch, [
    ...__facade_middleware__,
    finalMiddleware
  ]);
}
__name(__facade_invoke__, "__facade_invoke__");

// .wrangler/tmp/bundle-ruMMpO/middleware-loader.entry.ts
var __Facade_ScheduledController__ = class ___Facade_ScheduledController__ {
  constructor(scheduledTime, cron, noRetry) {
    this.scheduledTime = scheduledTime;
    this.cron = cron;
    this.#noRetry = noRetry;
  }
  scheduledTime;
  cron;
  static {
    __name(this, "__Facade_ScheduledController__");
  }
  #noRetry;
  noRetry() {
    if (!(this instanceof ___Facade_ScheduledController__)) {
      throw new TypeError("Illegal invocation");
    }
    this.#noRetry();
  }
};
function wrapExportedHandler(worker) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return worker;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  const fetchDispatcher = /* @__PURE__ */ __name(function(request, env, ctx) {
    if (worker.fetch === void 0) {
      throw new Error("Handler does not export a fetch() function.");
    }
    return worker.fetch(request, env, ctx);
  }, "fetchDispatcher");
  return {
    ...worker,
    fetch(request, env, ctx) {
      const dispatcher = /* @__PURE__ */ __name(function(type, init) {
        if (type === "scheduled" && worker.scheduled !== void 0) {
          const controller = new __Facade_ScheduledController__(
            Date.now(),
            init.cron ?? "",
            () => {
            }
          );
          return worker.scheduled(controller, env, ctx);
        }
      }, "dispatcher");
      return __facade_invoke__(request, env, ctx, dispatcher, fetchDispatcher);
    }
  };
}
__name(wrapExportedHandler, "wrapExportedHandler");
function wrapWorkerEntrypoint(klass) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return klass;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  return class extends klass {
    #fetchDispatcher = /* @__PURE__ */ __name((request, env, ctx) => {
      this.env = env;
      this.ctx = ctx;
      if (super.fetch === void 0) {
        throw new Error("Entrypoint class does not define a fetch() function.");
      }
      return super.fetch(request);
    }, "#fetchDispatcher");
    #dispatcher = /* @__PURE__ */ __name((type, init) => {
      if (type === "scheduled" && super.scheduled !== void 0) {
        const controller = new __Facade_ScheduledController__(
          Date.now(),
          init.cron ?? "",
          () => {
          }
        );
        return super.scheduled(controller);
      }
    }, "#dispatcher");
    fetch(request) {
      return __facade_invoke__(
        request,
        this.env,
        this.ctx,
        this.#dispatcher,
        this.#fetchDispatcher
      );
    }
  };
}
__name(wrapWorkerEntrypoint, "wrapWorkerEntrypoint");
var WRAPPED_ENTRY;
if (typeof middleware_insertion_facade_default === "object") {
  WRAPPED_ENTRY = wrapExportedHandler(middleware_insertion_facade_default);
} else if (typeof middleware_insertion_facade_default === "function") {
  WRAPPED_ENTRY = wrapWorkerEntrypoint(middleware_insertion_facade_default);
}
var middleware_loader_entry_default = WRAPPED_ENTRY;
export {
  __INTERNAL_WRANGLER_MIDDLEWARE__,
  middleware_loader_entry_default as default
};
//# sourceMappingURL=index.js.map
