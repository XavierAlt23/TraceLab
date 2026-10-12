const encoder = new TextEncoder();
function normalize(value) {
  if (Array.isArray(value)) return value.map(normalize);
  if (value !== null && typeof value === "object") {
    const object = value;
    return Object.fromEntries(Object.keys(object).sort().map((key) => [key, normalize(object[key])]));
  }
  return value;
}
function canonicalJson(value) {
  return JSON.stringify(normalize(value));
}
function evidenceContent(event) {
  return canonicalJson(event);
}
async function sha256Hex(value) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
function encodeBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}
function decodeBase64(value) {
  return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
}
async function hmacKey(secret, usage) {
  return crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, usage);
}
async function signEvidence(event, previousHash, secret) {
  const eventHash = await sha256Hex(evidenceContent(event));
  const key = await hmacKey(secret, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(canonicalJson({ schemaVersion: 1, previous_hash: previousHash, event_hash: eventHash })));
  return { event, previous_hash: previousHash, event_hash: eventHash, signature: encodeBase64(new Uint8Array(signature)) };
}
async function verifyEvidence(proof, secret) {
  return (await evidenceVerifier(secret))(proof);
}
async function evidenceVerifier(secret) {
  const key = await hmacKey(secret, ["verify"]);
  return async (proof) => {
    let contentValid = false;
    let signatureValid = false;
    try {
      contentValid = await sha256Hex(evidenceContent(proof.event)) === proof.event_hash;
    } catch {
    }
    try {
      signatureValid = await crypto.subtle.verify(
        "HMAC",
        key,
        new Uint8Array(decodeBase64(proof.signature)),
        encoder.encode(canonicalJson({ schemaVersion: 1, previous_hash: proof.previous_hash, event_hash: proof.event_hash }))
      );
    } catch {
    }
    return { contentValid, signatureValid };
  };
}
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
function parseContext(value) {
  if (value === null) return null;
  try {
    const parsed = JSON.parse(value);
    return parsed !== null && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}
function decodeProof(event, previousHash, eventHash, signature) {
  if (!previousHash || !eventHash || !signature) return null;
  return { event, previous_hash: previousHash, event_hash: eventHash, signature };
}
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
const observedHeadSql = `(SELECT COALESCE(l.event_hash, m.event_hash, '') FROM audit_order a
  LEFT JOIN logs l ON a.source = 'LOG' AND l.event_id = a.event_id
  LEFT JOIN metalogs m ON a.source = 'METALOG' AND m.event_id = a.event_id
  ORDER BY a.sequence DESC LIMIT 1)`;
function requestMetadata(request) {
  const observedIp = request.headers.get("cf-connecting-ip")?.trim() ?? "";
  return {
    occurred_at: (/* @__PURE__ */ new Date()).toISOString(),
    ip_address: observedIp.length > 0 && observedIp.length <= 64 && ![...observedIp].some((c) => c.charCodeAt(0) < 32 || c.charCodeAt(0) === 127) ? observedIp : null,
    user_agent: request.headers.get("user-agent")?.slice(0, 512) ?? null
  };
}
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
async function appendSigned(env, entries, beforeEvidence = [], customEvidenceSteps) {
  const secret = env.AUDIT_HMAC_KEY;
  if (!secret || secret.length < 32) throw new Error("AUDIT_HMAC_KEY must contain at least 32 characters");
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const state = await env.DB.prepare(`SELECT s.*, (SELECT COALESCE(MAX(sequence), 0) FROM audit_order) AS observed_max,
      ${observedHeadSql} AS observed_head FROM integrity_state s WHERE singleton = 1`).first();
    if (!state) throw new Error("integrity state missing; apply migration 0006");
    let expectedSequence = state.last_audit_sequence;
    let expectedHead = state.head_hash;
    let cutoff;
    const proofs = [];
    if (state.initialized === 0) {
      cutoff = await historicalSnapshot(env.DB);
      if (state.observed_max !== cutoff.cutoff) continue;
      expectedSequence = cutoff.cutoff;
      expectedHead = "0".repeat(64);
      proofs.push(await signedCheckpoint(secret, cutoff.cutoff, cutoff.count, cutoff.hash, (/* @__PURE__ */ new Date()).toISOString()));
    } else if (state.observed_max !== expectedSequence || state.observed_head !== expectedHead) {
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
async function appendLog(env, request, event) {
  return appendSigned(env, [{ proof: { event: asLogEvidence(request, event), previous_hash: "", event_hash: "", signature: "" } }]);
}
async function initializeIntegrity(env) {
  const state = await env.DB.prepare("SELECT initialized FROM integrity_state WHERE singleton = 1").first();
  if (state?.initialized === 1) return;
  await appendSigned(env, []);
}
async function appendMetalog(env, request, event) {
  return appendSigned(env, [{ proof: { event: asMetalogEvidence(request, event), previous_hash: "", event_hash: "", signature: "" } }]);
}
async function appendIntegrityResult(env, request, event) {
  const secret = env.AUDIT_HMAC_KEY;
  if (!secret || secret.length < 32) throw new Error("AUDIT_HMAC_KEY must contain at least 32 characters");
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const state = await env.DB.prepare(`SELECT s.initialized, s.head_hash, s.last_audit_sequence,
      (SELECT COALESCE(MAX(sequence), 0) FROM audit_order) AS observed_max,
      ${observedHeadSql} AS observed_head FROM integrity_state s WHERE singleton = 1`).first();
    if (!state || state.initialized !== 1) {
      await initializeIntegrity(env);
      continue;
    }
    if (state.observed_max === state.last_audit_sequence && state.observed_head === state.head_hash) return appendMetalog(env, request, event);
    const degradedEvent = {
      ...event,
      context: { ...event.context, out_of_chain: true, observed_sequence: state.observed_max, trusted_sequence: state.last_audit_sequence }
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
async function appendMany(env, request, logs, metalogs, beforeEvidence = []) {
  const entries = [
    ...logs.map((event) => ({ proof: { event: asLogEvidence(request, event), previous_hash: "", event_hash: "", signature: "" } })),
    ...metalogs.map((event) => ({ proof: { event: asMetalogEvidence(request, event), previous_hash: "", event_hash: "", signature: "" } }))
  ];
  return appendSigned(env, entries, beforeEvidence);
}
function canWriteRecord(role, ownerId, actorId, isShared = false) {
  if (role === "ADMIN") return true;
  return role === "USER" && actorId !== null && (actorId === ownerId || isShared);
}
function normalizeUserName(input) {
  const hasControl = (value) => [...value].some((character) => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127);
  if (typeof input !== "string" || hasControl(input)) return null;
  const displayName = input.normalize("NFKC").trim().replace(/\s+/gu, " ");
  const length = [...displayName].length;
  if (length < 2 || length > 40 || hasControl(displayName)) return null;
  return { displayName, normalizedName: displayName.toLocaleLowerCase("en-US") };
}
function safeSecretEqual(provided, expected) {
  const encoder2 = new TextEncoder();
  const providedBytes = encoder2.encode(provided);
  const expectedBytes = encoder2.encode(expected);
  let difference = providedBytes.length ^ expectedBytes.length;
  const maxLength = Math.max(providedBytes.length, expectedBytes.length);
  for (let index2 = 0; index2 < maxLength; index2 += 1) {
    difference |= (providedBytes[index2] ?? 0) ^ (expectedBytes[index2] ?? 0);
  }
  return difference === 0 && expectedBytes.length > 0;
}
const MAX_BODY_BYTES = 8192;
function isLocalRequest(request) {
  const host = new URL(request.url).hostname.replace(/^\[|\]$/gu, "");
  return ["localhost", "127.0.0.1", "::1"].includes(host);
}
function makeSessionCookie(request, token, maxAge) {
  const local = isLocalRequest(request);
  return `${local ? "tracelab_session" : "__Host-tracelab_session"}=${token}; Path=/; HttpOnly;${local ? "" : " Secure;"} SameSite=Lax; Max-Age=${maxAge}`;
}
function crossSiteMutation(request) {
  if (["GET", "HEAD", "OPTIONS"].includes(request.method)) return false;
  const origin = request.headers.get("origin");
  return origin !== null && origin !== new URL(request.url).origin || request.headers.get("sec-fetch-site") === "cross-site";
}
async function boundedJson(request) {
  if (request.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase() !== "application/json") return null;
  const declared = request.headers.get("content-length");
  if (declared !== null && (!/^\d+$/u.test(declared) || Number(declared) > MAX_BODY_BYTES)) return null;
  if (!request.body) return null;
  const reader = request.body.getReader();
  const chunks = [];
  let length = 0;
  try {
    for (; ; ) {
      const { done, value: value2 } = await reader.read();
      if (done) break;
      length += value2.length;
      if (length > MAX_BODY_BYTES) {
        await reader.cancel();
        return null;
      }
      chunks.push(value2);
    }
    const bytes = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.length;
    }
    const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    return typeof value === "object" && value !== null && !Array.isArray(value) ? value : null;
  } catch {
    return null;
  } finally {
    reader.releaseLock();
  }
}
function secureResponse(request, response) {
  const headers = new Headers(response.headers);
  headers.set("x-content-type-options", "nosniff");
  headers.set("referrer-policy", "no-referrer");
  headers.set("x-frame-options", "DENY");
  headers.set("permissions-policy", "camera=(), microphone=(), geolocation=()");
  const local = isLocalRequest(request);
  headers.set("content-security-policy", `default-src 'self'; script-src 'self'${local ? " 'unsafe-inline'" : ""}; style-src 'self'${local ? " 'unsafe-inline'" : ""}; connect-src 'self'${local ? " ws://localhost:* ws://127.0.0.1:*" : ""}; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'`);
  if (!local && new URL(request.url).protocol === "https:") headers.set("strict-transport-security", "max-age=31536000");
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}
const SESSION_COOKIE = "__Host-tracelab_session";
const LOCAL_SESSION_COOKIE = "tracelab_session";
const SESSION_SECONDS = 12 * 60 * 60;
const ANONYMOUS = { actorId: null, actorName: "Anónimo", actorRole: "ANONYMOUS" };
function json(data, status = 200, headers = new Headers()) {
  headers.set("content-type", "application/json; charset=utf-8");
  headers.set("cache-control", "no-store");
  headers.set("x-content-type-options", "nosniff");
  return new Response(JSON.stringify(data), { status, headers });
}
function error(message, status) {
  return json({ error: message }, status);
}
function isLocalHost(request) {
  return isLocalRequest(request);
}
function sessionCookieName(request) {
  return isLocalHost(request) ? LOCAL_SESSION_COOKIE : SESSION_COOKIE;
}
function cookieHeader(request, token, maxAge) {
  return makeSessionCookie(request, token, maxAge);
}
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
function toHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
async function digestToken(token) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  return toHex(new Uint8Array(digest));
}
function makeToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...bytes)).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/gu, "");
}
async function requestBody(request) {
  return boundedJson(request);
}
function actorFor(session) {
  return {
    actorId: session.user_id ?? `role:${session.role.toLowerCase()}`,
    actorName: session.display_name ?? (session.role === "ADMIN" ? "Administrador" : "Auditor"),
    actorRole: session.role,
    sessionId: session.session_id
  };
}
function auditFor(session, action, result, details = {}) {
  return { ...actorFor(session), action, result, ...details };
}
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
function isDuplicateName(cause) {
  return cause instanceof Error && cause.message.includes("users.normalized_name");
}
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
      return error("Ese nombre ya está registrado.", 409);
    }
    await logAnonymous(request, env, "user.create", "FAILED", {
      actorName: name.displayName,
      context: { reason: "storage_error" }
    });
    return error("No se pudo crear la cuenta.", 500);
  }
}
async function enterUser(request, env) {
  const body = await requestBody(request);
  const name = normalizeUserName(body?.name);
  if (!body || !name) {
    await logAnonymous(request, env, "auth.login", "FAILED", { context: { reason: "invalid_input" } });
    return error("Indica un nombre válido.", 400);
  }
  const user = await env.DB.prepare(
    "SELECT id, display_name FROM users WHERE normalized_name = ?"
  ).bind(name.normalizedName).first();
  if (!user) {
    await logAnonymous(request, env, "auth.login", "DENIED", {
      actorName: name.displayName,
      context: { reason: "user_not_found" }
    });
    return error("No encontramos ese usuario. Regístralo primero.", 404);
  }
  const session = await createSession(request, env, { userId: user.id, role: "USER", displayName: user.display_name });
  const headers = new Headers({ "set-cookie": cookieHeader(request, session.token, SESSION_SECONDS) });
  return json({ user: { id: user.id, name: user.display_name, role: "USER" }, expiresAt: session.expiresAt }, 200, headers);
}
async function enterPrivileged(request, env) {
  const body = await requestBody(request);
  const role = body?.role;
  if (role !== "ADMIN" && role !== "AUDITOR") {
    await logAnonymous(request, env, "auth.privileged_login", "DENIED", { context: { reason: "invalid_role" } });
    return error("Acceso denegado.", 401);
  }
  const privilegedRole = role;
  const expected = privilegedRole === "ADMIN" ? env.ADMIN_ACCESS_CODE : env.AUDITOR_ACCESS_CODE;
  if (typeof body?.code !== "string" || body.code.length > 256 || !expected || !safeSecretEqual(await digestToken(body.code), await digestToken(expected))) {
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
  await appendLog(env, request, auditFor(session, "record.list", "SUCCESS", {
    context: { scope: session.role === "USER" ? "shared_and_owned" : "all_records", count: rows.results.length }
  }));
  return json({ records: rows.results });
}
function validRecordFields(body) {
  if (!body || typeof body.title !== "string" || typeof body.content !== "string") return null;
  const title = body.title.trim();
  const content = body.content.trim();
  if ([...title].length < 1 || [...title].length > 120 || [...content].length > 5e3) return null;
  return { title, content };
}
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
    return error("Revisa el título y el contenido del registro.", 400);
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
    return error("Revisa los campos y la versión del registro.", 400);
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
    return error("El registro cambió desde que lo abriste. Actualiza la lista y vuelve a intentarlo.", 409);
  }
  const now = (/* @__PURE__ */ new Date()).toISOString();
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
  } catch {
    const latest = await env.DB.prepare("SELECT revision FROM records WHERE id = ?").bind(id).first();
    if (latest && latest.revision !== expectedRevision) {
      await logFailure(request, env, session, "record.update", "CONFLICT", {
        recordId: id,
        context: { reason: "concurrent_update", expected_revision: expectedRevision, current_revision: latest.revision }
      });
      return error("El registro cambió en otra solicitud. Actualiza la lista y vuelve a intentarlo.", 409);
    }
    await logFailure(request, env, session, "record.update", "FAILED", {
      recordId: id,
      context: { reason: "storage_error" }
    });
    return error("No se pudo guardar el registro.", 500);
  }
  return json({ record: { id, owner_id: record.owner_id, ...fields, updated_at: now, is_shared: record.is_shared, revision: expectedRevision + 1 } });
}
function validDateFilter(value) {
  if (value === null || value === "") return null;
  if (!/^\d{4}-\d{2}-\d{2}$/u.test(value)) return void 0;
  const date = /* @__PURE__ */ new Date(`${value}T00:00:00.000Z`);
  return Number.isNaN(date.getTime()) || date.toISOString().slice(0, 10) !== value ? void 0 : value;
}
function validCursor(url) {
  const value = url.searchParams.get("before");
  if (value === null) return null;
  const cursor = Number(value);
  return /^\d+$/u.test(value) && Number.isSafeInteger(cursor) && cursor > 0 ? cursor : void 0;
}
async function listLogs(request, env, session) {
  const url = new URL(request.url);
  const before = validCursor(url);
  if (before === void 0) return error("Cursor no válido.", 400);
  const user = url.searchParams.get("user")?.trim() ?? "";
  const action = url.searchParams.get("action")?.trim() ?? "";
  const result = url.searchParams.get("result")?.trim().toUpperCase() ?? "";
  const from = validDateFilter(url.searchParams.get("from"));
  const to = validDateFilter(url.searchParams.get("to"));
  if (user.length > 120 || action.length > 100 || result && !["SUCCESS", "FAILED", "DENIED", "CONFLICT"].includes(result) || from === void 0 || to === void 0) {
    return error("Los filtros no son válidos.", 400);
  }
  const clauses = [];
  const values = [];
  if (before !== null) {
    clauses.push("sequence < ?");
    values.push(before);
  }
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
            result, context_json, previous_hash, event_hash, signature, edit_revision
       FROM logs ${where}
      ORDER BY sequence DESC LIMIT 101`
  ).bind(...values).all();
  await appendIntegrityResult(env, request, {
    ...actorFor(session),
    action: session.role === "ADMIN" ? "ADMIN_LOGS_VIEWED" : "AUDITOR_LOGS_VIEWED",
    resource: "/api/logs",
    result: "SUCCESS",
    context: { user, action, from: from ?? null, to: to ?? null, result, count: rows.results.length }
  });
  const page = rows.results.slice(0, 100);
  const options = await env.DB.prepare("SELECT DISTINCT action FROM logs ORDER BY action").all();
  return json({ logs: page, actions: options.results.map((row) => row.action), limit: 100, nextCursor: rows.results.length > 100 ? page[page.length - 1].sequence : null });
}
async function listMetalogs(request, env, session) {
  const url = new URL(request.url);
  const before = validCursor(url);
  if (before === void 0) return error("Cursor no válido.", 400);
  const user = url.searchParams.get("user")?.trim() ?? "";
  const action = url.searchParams.get("action")?.trim() ?? "";
  const result = url.searchParams.get("result")?.trim().toUpperCase() ?? "";
  const from = validDateFilter(url.searchParams.get("from"));
  const to = validDateFilter(url.searchParams.get("to"));
  if (user.length > 120 || action.length > 100 || result && !["SUCCESS", "FAILED", "DENIED", "CONFLICT"].includes(result) || from === void 0 || to === void 0) {
    return error("Filtros de metalogs no válidos.", 400);
  }
  const clauses = [];
  const values = [];
  if (before !== null) {
    clauses.push("sequence < ?");
    values.push(before);
  }
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
            previous_hash, event_hash, signature, edit_revision
       FROM metalogs ${where}
      ORDER BY sequence DESC LIMIT 101`
  ).bind(...values).all();
  await appendIntegrityResult(env, request, {
    ...actorFor(session),
    action: "AUDITOR_METALOGS_VIEWED",
    resource: "/api/metalogs",
    result: "SUCCESS",
    context: { user, action, from: from ?? null, to: to ?? null, result, count: rows.results.length }
  });
  const page = rows.results.slice(0, 100);
  const options = await env.DB.prepare("SELECT DISTINCT action FROM metalogs ORDER BY action").all();
  return json({ metalogs: page, actions: options.results.map((row) => row.action), limit: 100, nextCursor: rows.results.length > 100 ? page[page.length - 1].sequence : null });
}
async function editEvidence(request, env, session, source, eventId) {
  const resource = `/api/${source === "LOG" ? "logs" : "metalogs"}/${eventId}`;
  if (session.role !== "AUDITOR" && !(source === "LOG" && session.role === "ADMIN")) {
    await logFailure(request, env, session, "evidence.edit", "DENIED", { context: { resource, reason: "role_not_allowed" } });
    return error("No tienes permiso para editar esta evidencia.", 403);
  }
  const body = await requestBody(request);
  const fields = ["actor_name", "ip_address", "action", "result", "occurred_at", "actor_role", ...source === "LOG" ? ["old_value", "new_value"] : []];
  if (!body || typeof body.field !== "string" || !fields.includes(body.field) || typeof body.value !== "string" || body.value.length > 5e3 || !Number.isSafeInteger(body.expectedRevision) || Number(body.expectedRevision) < 0) {
    return error("Selecciona un campo y un valor válidos.", 400);
  }
  const secrets = [env.ADMIN_ACCESS_CODE, env.AUDITOR_ACCESS_CODE, env.AUDIT_HMAC_KEY, readCookie(request)].filter((value) => Boolean(value));
  const proposedValue = body.value;
  if (secrets.some((secret) => proposedValue.includes(secret))) return error("El campo no puede contener credenciales ni secretos.", 400);
  if (body.field === "result" && !["SUCCESS", "FAILED", "DENIED", "CONFLICT"].includes(body.value) || body.field === "actor_role" && !["USER", "ADMIN", "AUDITOR", "SYSTEM", "ANONYMOUS"].includes(body.value) || body.field === "occurred_at" && (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(body.value) || Number.isNaN(Date.parse(body.value))) || ["actor_name", "action"].includes(body.field) && (!body.value.trim() || body.value.length > 100) || body.field === "ip_address" && body.value.length > 64) return error("El valor no corresponde al campo seleccionado.", 400);
  const table = source === "LOG" ? "logs" : "metalogs";
  const row = await env.DB.prepare(`SELECT * FROM ${table} WHERE event_id = ?`).bind(eventId).first();
  if (!row) return error("No encontramos la evidencia.", 404);
  if (row.edit_revision !== body.expectedRevision) return error("La evidencia cambió. Actualiza el historial.", 409);
  const previous = row[body.field];
  if (previous === body.value) return error("No hay cambios para guardar.", 400);
  const guardId = crypto.randomUUID();
  try {
    await appendMany(env, request, [], [{
      ...actorFor(session),
      action: "EVIDENCE_CONTENT_EDITED",
      resource,
      result: "SUCCESS",
      context: {
        source,
        event_id: eventId,
        field: body.field,
        previous_value: previous,
        new_value: body.value,
        educational_exception: true,
        original_signature_preserved: true
      }
    }], [
      env.DB.prepare(`INSERT INTO mutation_guards (guard_id, allowed) SELECT ?, CASE WHEN EXISTS
        (SELECT 1 FROM ${table} WHERE event_id = ? AND edit_revision = ?) THEN 1 ELSE 0 END`).bind(guardId, eventId, body.expectedRevision),
      env.DB.prepare("INSERT INTO evidence_edit_guard (source,event_id,expected_revision) VALUES (?,?,?)").bind(source, eventId, body.expectedRevision),
      env.DB.prepare(`UPDATE ${table} SET ${body.field} = ?, edit_revision = edit_revision + 1 WHERE event_id = ? AND edit_revision = ?`).bind(body.value, eventId, body.expectedRevision),
      env.DB.prepare("DELETE FROM evidence_edit_guard WHERE source = ? AND event_id = ?").bind(source, eventId),
      env.DB.prepare("DELETE FROM mutation_guards WHERE guard_id = ?").bind(guardId)
    ]);
  } catch {
    return error("No se guardó la edición. Actualiza el historial y vuelve a intentar.", 409);
  }
  return json({ ok: true, editRevision: Number(body.expectedRevision) + 1, originalSignaturePreserved: true });
}
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
  await appendIntegrityResult(env, request, {
    ...actorFor(session),
    action: "ADMIN_ACTIVITY_VERIFIED",
    resource: "/api/audit/admin-activity",
    result: "SUCCESS",
    context: { count: rows.results.length }
  });
  return json({ activities: rows.results, limit: 200 });
}
async function integritySnapshot(env) {
  const state = await env.DB.prepare(`SELECT historical_cutoff_sequence, historical_count, historical_snapshot_hash, head_hash, last_audit_sequence,
    (SELECT COALESCE(MAX(sequence), 0) FROM audit_order) AS snapshot_cutoff FROM integrity_state WHERE singleton = 1`).first();
  const fixedCutoff = Number(state?.snapshot_cutoff ?? 0);
  const rows = [];
  let after = 0;
  let bytes = 0;
  let limited = fixedCutoff > 2e4;
  let memoryLimit = false;
  while (after < fixedCutoff && rows.length < 2e4 && !memoryLimit) {
    const result = await env.DB.prepare(
      `SELECT evidence.*
       FROM (
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
     ) evidence WHERE evidence.sequence > ? AND evidence.sequence <= ?
       ORDER BY evidence.sequence LIMIT 1000`
    ).bind(after, fixedCutoff).all();
    if (!result.results.length) break;
    for (const row of result.results) {
      bytes += new TextEncoder().encode(JSON.stringify(row)).length;
      if (bytes > 16 * 1024 * 1024) {
        memoryLimit = true;
        limited = true;
        break;
      }
      rows.push({ ...row, sequence: Number(row.sequence) });
    }
    if (!rows.length) break;
    after = rows[rows.length - 1].sequence;
  }
  return { rows, fixedCutoff, state, limited };
}
async function verifyIntegrity(request, env, session) {
  if (!env.AUDIT_HMAC_KEY || env.AUDIT_HMAC_KEY.length < 32) {
    return json({ status: "INTEGRITY_UNVERIFIABLE", reviewed: 0, errors: [{ code: "HMAC_KEY_UNAVAILABLE" }] }, 503);
  }
  await initializeIntegrity(env);
  const snapshot = await integritySnapshot(env);
  const { state, fixedCutoff } = snapshot;
  const limited = snapshot.limited;
  const checkProof = await evidenceVerifier(env.AUDIT_HMAC_KEY);
  const errors = [];
  let firstInconsistentEvent = null;
  const fail = (code, row) => {
    errors.push({ code, ...row ? { sequence: row.sequence, event_id: row.event_id } : {} });
    if (!firstInconsistentEvent || row && firstInconsistentEvent.sequence > row.sequence) firstInconsistentEvent = { sequence: row?.sequence ?? 0, event_id: row?.event_id ?? "", code };
  };
  let status = "INTEGRITY_OK";
  let contentHashesValid = 0;
  let validSignatures = 0;
  if (!state) {
    fail("INTEGRITY_STATE_MISSING");
    status = "INTEGRITY_FAILED";
  }
  if (limited) {
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
  if (!limited && expectedCount !== fixedCutoff) fail("AUDIT_ORDER_REFERENCE_MISSING");
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
    if ((!limited || checkpoint) && (!checkpoint || checkpoint.action !== "INTEGRITY_CHAIN_STARTED" || checkpoint.source !== "METALOG" || checkpointContext.historical_cutoff !== state.historical_cutoff_sequence || checkpointContext.historical_count !== state.historical_count || checkpointContext.historical_snapshot_sha256 !== state.historical_snapshot_hash)) {
      fail("CHAIN_CHECKPOINT_MISMATCH", checkpoint);
    }
    for (const continuityError of continuityErrors(chainRows, state.historical_cutoff_sequence + 1)) {
      const row = chainRows.find((item) => item.sequence === continuityError.sequence);
      fail(continuityError.code, row);
    }
    let previousHash = "0".repeat(64);
    for (let index2 = 0; index2 < chainRows.length; index2 += 1) {
      const row = chainRows[index2];
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
      const result = await checkProof(proof);
      if (result.contentValid) contentHashesValid += 1;
      if (result.signatureValid) validSignatures += 1;
      if (!result.contentValid) fail("EVENT_HASH_MISMATCH", row);
      if (!result.signatureValid) fail("HMAC_SIGNATURE_INVALID", row);
      previousHash = row.event_hash;
    }
    if (state.last_audit_sequence !== fixedCutoff || !limited && state.head_hash !== previousHash) fail("CHAIN_HEAD_MISMATCH");
  }
  if (errors.some((item) => !["LEGACY_UNSIGNED_EVENTS", "VERIFICATION_LIMIT_EXCEEDED"].includes(item.code))) status = "INTEGRITY_FAILED";
  else if (status !== "INTEGRITY_FAILED" && errors.length > 0) status = "INTEGRITY_UNVERIFIABLE";
  const counts = {
    logs: snapshot.rows.filter((row) => row.source === "LOG").length,
    metalogs: snapshot.rows.filter((row) => row.source === "METALOG").length,
    signed: snapshot.rows.filter((row) => row.sequence > (state?.historical_cutoff_sequence ?? 0)).length,
    validContentHashes: contentHashesValid,
    validSignatures,
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
function labResponse(row) {
  const original = JSON.parse(row.original_json);
  const working = JSON.parse(row.working_json);
  return { copyId: row.copy_id, source: row.source, sourceEventId: row.source_event_id, original: original.event, working, hasSignature: Boolean(original.proof), revision: row.revision };
}
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
async function createLabCopy(request, env, session) {
  const body = await requestBody(request);
  if (body?.source !== "LOG" && body?.source !== "METALOG" || typeof body.eventId !== "string" || body.eventId.length > 64) return error("Selecciona una evidencia válida.", 400);
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
async function mutateLabCopy(request, env, session, copyId) {
  const body = await requestBody(request);
  if (typeof body?.field !== "string" || !["action", "old_value", "new_value", "context_json", "result"].includes(body.field) || typeof body.value !== "string" || body.value.length > 5e3 || !Number.isSafeInteger(body.expectedRevision) || Number(body.expectedRevision) < 1) return error("Campo o revisión de simulación no válidos.", 400);
  const row = await env.DB.prepare("SELECT * FROM lab_copies WHERE copy_id = ? AND owner_session_id = ?").bind(copyId, session.session_id).first();
  if (!row) {
    await logFailure(request, env, session, "audit.lab", "DENIED", { context: { resource: `/api/audit/lab/copies/${copyId}`, reason: "copy_not_available_for_session" } });
    return error("No encontramos la copia del laboratorio.", 404);
  }
  if (row.revision !== body.expectedRevision) return error("La revisión de la copia está obsoleta. Crea una copia nueva.", 409);
  const working = JSON.parse(row.working_json);
  working[body.field] = body.value;
  const next = canonicalJson(working);
  const guardId = crypto.randomUUID();
  try {
    await appendMany(env, request, [], [{
      ...actorFor(session),
      action: "LAB_TAMPER_SIMULATED",
      resource: `/api/audit/lab/copies/${copyId}`,
      result: "SUCCESS",
      context: { source_event_id: row.source_event_id, field: body.field }
    }], [
      env.DB.prepare(`INSERT INTO mutation_guards (guard_id, allowed) SELECT ?, CASE WHEN EXISTS
      (SELECT 1 FROM lab_copies WHERE copy_id = ? AND owner_session_id = ? AND revision = ?) THEN 1 ELSE 0 END`).bind(guardId, copyId, session.session_id, row.revision),
      env.DB.prepare("UPDATE lab_copies SET working_json = ?, revision = revision + 1 WHERE copy_id = ? AND owner_session_id = ? AND revision = ?").bind(next, copyId, session.session_id, row.revision),
      env.DB.prepare("DELETE FROM mutation_guards WHERE guard_id = ?").bind(guardId)
    ]);
  } catch {
    return error("La copia cambió en otra solicitud. Crea una copia nueva e intenta otra vez.", 409);
  }
  const updated = await env.DB.prepare("SELECT * FROM lab_copies WHERE copy_id = ? AND owner_session_id = ?").bind(copyId, session.session_id).first();
  return json({ copy: labResponse(updated) });
}
async function verifyLabCopy(request, env, session, copyId) {
  const row = await env.DB.prepare("SELECT * FROM lab_copies WHERE copy_id = ? AND owner_session_id = ?").bind(copyId, session.session_id).first();
  if (!row) {
    await logFailure(request, env, session, "audit.lab", "DENIED", { context: { resource: `/api/audit/lab/copies/${copyId}`, reason: "copy_not_available_for_session" } });
    return error("No encontramos la copia del laboratorio.", 404);
  }
  const original = JSON.parse(row.original_json);
  const working = JSON.parse(row.working_json);
  let status = "INTEGRITY_UNVERIFIABLE";
  let contentHashValid = null;
  let signatureValid = null;
  if (original.proof && env.AUDIT_HMAC_KEY) {
    const verified = await verifyEvidence({ ...original.proof, event: working }, env.AUDIT_HMAC_KEY);
    contentHashValid = verified.contentValid;
    signatureValid = verified.signatureValid;
    status = contentHashValid && signatureValid ? "INTEGRITY_OK" : "INTEGRITY_FAILED";
  }
  await appendMetalog(env, request, {
    ...actorFor(session),
    action: "LAB_COPY_VERIFIED",
    resource: `/api/audit/lab/copies/${copyId}`,
    result: status === "INTEGRITY_OK" ? "SUCCESS" : "FAILED",
    context: { source_event_id: row.source_event_id, status, revision: row.revision, content_hash_valid: contentHashValid, signature_valid: signatureValid }
  });
  return json({ status, contentHashValid, signatureValid, copy: labResponse(row) });
}
async function resetLabCopy(request, env, session, copyId) {
  const result = await env.DB.prepare("SELECT source_event_id FROM lab_copies WHERE copy_id = ? AND owner_session_id = ?").bind(copyId, session.session_id).first();
  if (!result) {
    await logFailure(request, env, session, "audit.lab", "DENIED", { context: { resource: `/api/audit/lab/copies/${copyId}`, reason: "copy_not_available_for_session" } });
    return error("No encontramos la copia del laboratorio.", 404);
  }
  await appendMany(env, request, [], [{
    ...actorFor(session),
    action: "LAB_RESET",
    resource: `/api/audit/lab/copies/${copyId}`,
    result: "SUCCESS",
    context: { source_event_id: result.source_event_id }
  }], [env.DB.prepare("DELETE FROM lab_copies WHERE copy_id = ? AND owner_session_id = ?").bind(copyId, session.session_id)]);
  return json({ ok: true });
}
async function handleApi(request, env) {
  const url = new URL(request.url);
  const { pathname } = url;
  if (crossSiteMutation(request)) {
    const session2 = await currentSession(request, env);
    const details = { context: { resource: pathname, reason: "cross_site_request" } };
    if (session2) await logFailure(request, env, session2, "security.csrf", "DENIED", details);
    else await logAnonymous(request, env, "security.csrf", "DENIED", details);
    return error("Solicitud de otro sitio rechazada.", 403);
  }
  if (pathname !== "/api/session") {
    const auth = pathname.startsWith("/api/auth/");
    const limit = auth ? 30 : request.method === "GET" ? 240 : 90;
    const ip = request.headers.get("cf-connecting-ip")?.slice(0, 64) ?? "local";
    const authBucket = ["/api/auth/register", "/api/auth/user", "/api/auth/special", "/api/auth/logout"].includes(pathname) ? pathname : "auth:other";
    const bucket = await digestToken(`${ip}|${auth ? authBucket : request.method === "GET" ? "read" : "write"}`);
    const window = Math.floor(Date.now() / 6e4);
    const counter = await env.DB.prepare(`INSERT INTO request_limits (bucket_key, window_start, request_count) VALUES (?, ?, 1)
      ON CONFLICT(bucket_key) DO UPDATE SET request_count = CASE WHEN window_start = excluded.window_start THEN request_count + 1 ELSE 1 END,
      window_start = excluded.window_start RETURNING request_count`).bind(bucket, window).first();
    if (!counter) throw new Error("rate limit unavailable");
    if (counter.request_count > limit) {
      if (counter.request_count === limit + 1) {
        const session2 = await currentSession(request, env);
        const details = { context: { resource: pathname, reason: "rate_limit", limit } };
        if (session2) await logFailure(request, env, session2, "security.rate_limit", "DENIED", details);
        else await logAnonymous(request, env, "security.rate_limit", "DENIED", details);
      }
      return json({ error: "Demasiadas solicitudes. Espera un minuto e intenta de nuevo." }, 429, new Headers({ "retry-after": "60" }));
    }
    await env.DB.prepare("DELETE FROM request_limits WHERE window_start < ?").bind(window - 2).run();
  }
  if (request.method === "POST" && pathname === "/api/auth/register") return registerUser(request, env);
  if (request.method === "POST" && pathname === "/api/auth/user") return enterUser(request, env);
  if (request.method === "POST" && pathname === "/api/auth/special") return enterPrivileged(request, env);
  if (request.method === "POST" && pathname === "/api/auth/logout") {
    return logout(request, env, await currentSession(request, env));
  }
  const session = await currentSession(request, env);
  if (request.method === "GET" && pathname === "/api/session") {
    if (!session) return error("Inicia sesión para continuar.", 401);
    const displayName = session.display_name ?? (session.role === "ADMIN" ? "Administrador" : "Auditor");
    return json({
      user: { id: session.user_id ?? `role:${session.role.toLowerCase()}`, name: displayName, role: session.role },
      expiresAt: session.expires_at
    });
  }
  const privilegedAuditPath = pathname === "/api/logs" || pathname.startsWith("/api/logs/") || pathname === "/api/metalogs" || pathname.startsWith("/api/metalogs/") || pathname.startsWith("/api/audit/");
  if (pathname === "/api/records" || pathname.startsWith("/api/records/") || privilegedAuditPath) {
    if (!session) {
      await logAnonymous(request, env, "access.denied", "DENIED", {
        context: { method: request.method, resource: pathname }
      });
      return error("Inicia sesión para continuar.", 401);
    }
  }
  if (!session) return error("Inicia sesión para continuar.", 401);
  if (request.method === "GET" && pathname === "/api/records") return listRecords(request, env, session);
  if (request.method === "POST" && pathname === "/api/records") return createRecord(request, env, session);
  const recordMatch = pathname.match(/^\/api\/records\/([0-9a-f-]{36})$/iu);
  if (request.method === "PATCH" && recordMatch) return editRecord(request, env, session, recordMatch[1]);
  if (pathname === "/api/records" || pathname.startsWith("/api/records/")) {
    await logFailure(request, env, session, "record.access", "DENIED", { context: { resource: pathname, reason: "unsupported_operation" } });
    return error("Operación de registros no permitida.", 405);
  }
  if (pathname.startsWith("/api/audit/")) {
    if (session.role !== "AUDITOR") {
      await logFailure(request, env, session, "audit.access", "DENIED", {
        context: { method: request.method, resource: pathname, reason: "auditor_role_required" }
      });
      return error("Esta función está reservada al auditor.", 403);
    }
    if (pathname === "/api/audit/integrity") {
      if (request.method !== "GET") {
        await logFailure(request, env, session, "audit.integrity", "DENIED", { context: { resource: pathname, reason: "read_only_endpoint" } });
        return error("La verificación es de solo lectura.", 405);
      }
      return verifyIntegrity(request, env, session);
    }
    if (pathname === "/api/audit/lab/sources") {
      if (request.method !== "GET") {
        await logFailure(request, env, session, "audit.lab", "DENIED", { context: { resource: pathname, reason: "read_only_endpoint" } });
        return error("Consulta de solo lectura.", 405);
      }
      return labSources(request, env, session);
    }
    if (pathname === "/api/audit/lab/copies") {
      if (request.method !== "POST") {
        await logFailure(request, env, session, "audit.lab", "DENIED", { context: { resource: pathname, reason: "unsupported_operation" } });
        return error("Método no permitido.", 405);
      }
      return createLabCopy(request, env, session);
    }
    const labMatch = pathname.match(/^\/api\/audit\/lab\/copies\/([0-9a-f-]{36})(?:\/(verify))?$/iu);
    if (labMatch) {
      const [, copyId, verify] = labMatch;
      if (verify && request.method === "POST") return verifyLabCopy(request, env, session, copyId);
      if (!verify && request.method === "PATCH") return mutateLabCopy(request, env, session, copyId);
      if (!verify && request.method === "DELETE") return resetLabCopy(request, env, session, copyId);
      await logFailure(request, env, session, "audit.lab", "DENIED", { context: { resource: pathname, reason: "unsupported_operation" } });
      return error("Método no permitido.", 405);
    }
  }
  if (pathname === "/api/logs" || pathname.startsWith("/api/logs/")) {
    const match = pathname.match(/^\/api\/logs\/([0-9a-f-]{36})$/iu);
    if (match && request.method === "PATCH") return editEvidence(request, env, session, "LOG", match[1]);
    if (request.method !== "GET" || pathname !== "/api/logs") {
      await logFailure(request, env, session, "logs.access", "DENIED", {
        context: { method: request.method, reason: "read_only_endpoint" }
      });
      return error("Operación no permitida sobre logs. No se pueden eliminar evidencias.", 405);
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
    const match = pathname.match(/^\/api\/metalogs\/([0-9a-f-]{36})$/iu);
    if (match && request.method === "PATCH") return editEvidence(request, env, session, "METALOG", match[1]);
    if (request.method !== "GET" || pathname !== "/api/metalogs") {
      await logFailure(request, env, session, "metalog.access", "DENIED", {
        context: { method: request.method, resource: pathname, reason: "read_only_endpoint" }
      });
      return error("Operación no permitida sobre metalogs. No se pueden eliminar evidencias.", 405);
    }
    return listMetalogs(request, env, session);
  }
  if (pathname === "/api/audit/admin-activity") {
    if (session.role !== "AUDITOR") {
      await logFailure(request, env, session, "audit.admin_activity", "DENIED", {
        context: { method: request.method, resource: pathname, reason: "auditor_role_required" }
      });
      return error("Esta verificación está reservada al auditor.", 403);
    }
    if (request.method !== "GET") {
      await logFailure(request, env, session, "audit.admin_activity", "DENIED", {
        context: { method: request.method, resource: pathname, reason: "read_only_endpoint" }
      });
      return error("La verificación es de solo lectura.", 405);
    }
    return verifyAdminActivity(request, env, session);
  }
  return error("Ruta no encontrada.", 404);
}
const index = {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (!url.pathname.startsWith("/api/")) return secureResponse(request, await env.ASSETS.fetch(request));
    try {
      return secureResponse(request, await handleApi(request, env));
    } catch {
      if (url.pathname === "/api/audit/integrity" && env.AUDIT_HMAC_KEY && env.AUDIT_HMAC_KEY.length >= 32) {
        try {
          const session = await currentSession(request, env);
          if (session?.role === "AUDITOR") await appendIntegrityResult(env, request, {
            ...actorFor(session),
            action: "INTEGRITY_VERIFICATION",
            resource: url.pathname,
            result: "FAILED",
            context: { status: "INTEGRITY_UNVERIFIABLE", reason: "verification_aborted" }
          });
        } catch {
        }
      }
      const response = url.pathname === "/api/audit/integrity" ? json({ error: "La verificación no pudo completarse.", status: "INTEGRITY_UNVERIFIABLE", reviewed: 0, errors: [{ code: "VERIFICATION_ABORTED" }] }, 503) : error("Ocurrió un error interno.", 500);
      return secureResponse(request, response);
    }
  }
};
const workerEntry = index ?? {};
export {
  workerEntry as default
};
