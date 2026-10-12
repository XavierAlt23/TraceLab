import { type AuditActor, type AuditEvent } from "./audit";
import { appendIntegrityResult, appendMany, appendLog, appendMetalog, appendSigned, asLogEvidence, auditContextStatement, historicalSnapshot, initializeIntegrity } from "./audit-store";
import { canonicalJson, continuityErrors, decodeProof, evidenceVerifier, parseContext, rowEvidence, verifyEvidence, type CanonicalEvidence, type SignedEvidence } from "./integrity";
import { canWriteRecord, normalizeUserName, safeSecretEqual, type Role } from "./policy";
import { boundedJson, crossSiteMutation, isLocalRequest, makeSessionCookie, secureResponse } from "./security";

interface Env {
  DB: D1Database;
  ASSETS: Fetcher;
  ADMIN_ACCESS_CODE?: string;
  AUDITOR_ACCESS_CODE?: string;
  AUDIT_HMAC_KEY?: string;
}

interface SessionRow {
  session_id: string;
  user_id: string | null;
  role: Role;
  display_name: string | null;
  expires_at: string;
}

interface RecordRow {
  id: string;
  owner_id: string;
  owner_name: string;
  title: string;
  content: string;
  created_at: string;
  updated_at: string;
  is_shared: number;
  revision: number;
}

interface LogRow {
  edit_revision: number;
  sequence: number;
  event_id: string;
  actor_id: string | null;
  actor_name: string;
  actor_role: string;
  session_id: string | null;
  occurred_at: string;
  ip_address: string | null;
  user_agent: string | null;
  action: string;
  record_id: string | null;
  field_name: string | null;
  old_value: string | null;
  new_value: string | null;
  result: string;
  context_json: string | null;
  previous_hash: string | null;
  event_hash: string | null;
  signature: string | null;
}

interface MetalogRow {
  edit_revision: number;
  sequence: number;
  event_id: string;
  actor_id: string | null;
  actor_name: string;
  actor_role: string;
  session_id: string | null;
  occurred_at: string;
  ip_address: string | null;
  user_agent: string | null;
  action: string;
  resource: string;
  result: string;
  context_json: string | null;
  previous_hash: string | null;
  event_hash: string | null;
  signature: string | null;
}

interface RecordFields {
  title: string;
  content: string;
}

const SESSION_COOKIE = "__Host-tracelab_session";
const LOCAL_SESSION_COOKIE = "tracelab_session";
const SESSION_SECONDS = 12 * 60 * 60;
const ANONYMOUS = { actorId: null, actorName: "Anónimo", actorRole: "ANONYMOUS" } as const;

function json(data: unknown, status = 200, headers = new Headers()): Response {
  headers.set("content-type", "application/json; charset=utf-8");
  headers.set("cache-control", "no-store");
  headers.set("x-content-type-options", "nosniff");
  return new Response(JSON.stringify(data), { status, headers });
}

function error(message: string, status: number): Response {
  return json({ error: message }, status);
}

function isLocalHost(request: Request): boolean {
  return isLocalRequest(request);
}

function sessionCookieName(request: Request): string {
  return isLocalHost(request) ? LOCAL_SESSION_COOKIE : SESSION_COOKIE;
}

function cookieHeader(request: Request, token: string, maxAge: number): string {
  return makeSessionCookie(request, token, maxAge);
}

function readCookie(request: Request): string | null {
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

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function digestToken(token: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  return toHex(new Uint8Array(digest));
}

function makeToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...bytes)).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/gu, "");
}

async function requestBody(request: Request): Promise<Record<string, unknown> | null> {
  return boundedJson(request);
}

function actorFor(session: SessionRow): AuditActor {
  return {
    actorId: session.user_id ?? `role:${session.role.toLowerCase()}`,
    actorName: session.display_name ?? (session.role === "ADMIN" ? "Administrador" : "Auditor"),
    actorRole: session.role,
    sessionId: session.session_id,
  };
}

function auditFor(session: SessionRow, action: string, result: AuditEvent["result"], details: Partial<AuditEvent> = {}): AuditEvent {
  return { ...actorFor(session), action, result, ...details };
}

async function logAnonymous(
  request: Request,
  env: Env,
  action: string,
  result: AuditEvent["result"],
  details: Partial<AuditEvent> = {},
): Promise<void> {
  const event = { ...ANONYMOUS, action, result, ...details };
  if (result === "DENIED") {
    await appendMany(env, request, [event], [{
        ...event,
        action: "ACCESS_DENIED",
        resource: typeof event.context?.resource === "string" ? event.context.resource : action,
        context: { ...event.context, method: event.context?.method ?? request.method, reason: event.context?.reason ?? "access_denied" },
      }]);
  } else {
    await appendLog(env, request, event);
  }
}

async function logFailure(
  request: Request,
  env: Env,
  session: SessionRow,
  action: string,
  result: AuditEvent["result"],
  details: Partial<AuditEvent> = {},
): Promise<void> {
  const event = auditFor(session, action, result, details);
  if (result === "DENIED") {
    await appendMany(env, request, [event], [{
        ...event,
        action: "ACCESS_DENIED",
        resource: typeof event.context?.resource === "string"
          ? event.context.resource
          : event.recordId ? `/api/records/${event.recordId}` : action,
        context: { ...event.context, method: request.method, reason: event.context?.reason ?? "access_denied" },
      }]);
  } else {
    await appendLog(env, request, event);
  }
}

async function currentSession(request: Request, env: Env): Promise<SessionRow | null> {
  const token = readCookie(request);
  if (!token || token.length > 128) return null;
  const tokenHash = await digestToken(token);
  const session = await env.DB.prepare(
    `SELECT s.session_id, s.user_id, s.role, s.expires_at, u.display_name
       FROM sessions s LEFT JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ? AND s.revoked_at IS NULL AND s.expires_at > ?`,
  ).bind(tokenHash, new Date().toISOString()).first<SessionRow>();
  return session ?? null;
}

async function createSession(
  request: Request,
  env: Env,
  options: { userId: string | null; role: Role; displayName: string | null },
): Promise<{ token: string; sessionId: string; expiresAt: string }> {
  const token = makeToken();
  const tokenHash = await digestToken(token);
  const sessionId = crypto.randomUUID();
  const createdAt = new Date().toISOString();
  const expiresAt = new Date(Date.now() + SESSION_SECONDS * 1_000).toISOString();
  const actorId = options.userId ?? `role:${options.role.toLowerCase()}`;
  const actorName = options.displayName ?? (options.role === "ADMIN" ? "Administrador" : "Auditor");
  await appendMany(env, request, [{
    actorId, actorName, actorRole: options.role, sessionId,
    action: "auth.login", result: "SUCCESS",
  }], [], [env.DB.prepare(
      "INSERT INTO sessions (token_hash, user_id, role, created_at, expires_at, session_id) VALUES (?, ?, ?, ?, ?, ?)",
    ).bind(tokenHash, options.userId, options.role, createdAt, expiresAt, sessionId)]);
  return { token, sessionId, expiresAt };
}

function isDuplicateName(cause: unknown): boolean {
  return cause instanceof Error && cause.message.includes("users.normalized_name");
}

async function registerUser(request: Request, env: Env): Promise<Response> {
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
  const createdAt = new Date().toISOString();
  const expiresAt = new Date(Date.now() + SESSION_SECONDS * 1_000).toISOString();
  try {
    await appendMany(env, request, [
      { actorId: id, actorName: name.displayName, actorRole: "USER", sessionId, action: "user.create", result: "SUCCESS" },
      { actorId: id, actorName: name.displayName, actorRole: "USER", sessionId, action: "auth.login", result: "SUCCESS" },
    ], [], [
      env.DB.prepare("INSERT INTO users (id, display_name, normalized_name, created_at) VALUES (?, ?, ?, ?)")
        .bind(id, name.displayName, name.normalizedName, createdAt),
      env.DB.prepare("INSERT INTO sessions (token_hash, user_id, role, created_at, expires_at, session_id) VALUES (?, ?, 'USER', ?, ?, ?)")
        .bind(tokenHash, id, createdAt, expiresAt, sessionId),
    ]);
    const headers = new Headers({ "set-cookie": cookieHeader(request, token, SESSION_SECONDS) });
    return json({ user: { id, name: name.displayName, role: "USER" }, expiresAt }, 201, headers);
  } catch (cause) {
    if (isDuplicateName(cause)) {
      await logAnonymous(request, env, "user.create", "DENIED", {
        actorName: name.displayName, context: { reason: "name_exists" },
      });
      return error("Ese nombre ya está registrado.", 409);
    }
    await logAnonymous(request, env, "user.create", "FAILED", {
      actorName: name.displayName, context: { reason: "storage_error" },
    });
    return error("No se pudo crear la cuenta.", 500);
  }
}

async function enterUser(request: Request, env: Env): Promise<Response> {
  const body = await requestBody(request);
  const name = normalizeUserName(body?.name);
  if (!body || !name) {
    await logAnonymous(request, env, "auth.login", "FAILED", { context: { reason: "invalid_input" } });
    return error("Indica un nombre válido.", 400);
  }
  const user = await env.DB.prepare(
    "SELECT id, display_name FROM users WHERE normalized_name = ?",
  ).bind(name.normalizedName).first<{ id: string; display_name: string }>();
  if (!user) {
    await logAnonymous(request, env, "auth.login", "DENIED", {
      actorName: name.displayName, context: { reason: "user_not_found" },
    });
    return error("No encontramos ese usuario. Regístralo primero.", 404);
  }
  const session = await createSession(request, env, { userId: user.id, role: "USER", displayName: user.display_name });
  const headers = new Headers({ "set-cookie": cookieHeader(request, session.token, SESSION_SECONDS) });
  return json({ user: { id: user.id, name: user.display_name, role: "USER" }, expiresAt: session.expiresAt }, 200, headers);
}

async function enterPrivileged(request: Request, env: Env): Promise<Response> {
  const body = await requestBody(request);
  const role = body?.role;
  if (role !== "ADMIN" && role !== "AUDITOR") {
    await logAnonymous(request, env, "auth.privileged_login", "DENIED", { context: { reason: "invalid_role" } });
    return error("Acceso denegado.", 401);
  }
  const privilegedRole: "ADMIN" | "AUDITOR" = role;
  const expected = privilegedRole === "ADMIN" ? env.ADMIN_ACCESS_CODE : env.AUDITOR_ACCESS_CODE;
  if (typeof body?.code !== "string" || body.code.length > 256 || !expected
      || !safeSecretEqual(await digestToken(body.code), await digestToken(expected))) {
    await logAnonymous(request, env, "auth.privileged_login", "DENIED", {
      context: { reason: "invalid_credentials", requested_role: privilegedRole },
    });
    return error("Acceso denegado.", 401);
  }
  const session = await createSession(request, env, { userId: null, role: privilegedRole, displayName: null });
  const headers = new Headers({ "set-cookie": cookieHeader(request, session.token, SESSION_SECONDS) });
  const displayName = privilegedRole === "ADMIN" ? "Administrador" : "Auditor";
  return json({ user: { id: privilegedRole.toLowerCase(), name: displayName, role: privilegedRole }, expiresAt: session.expiresAt }, 200, headers);
}

async function logout(request: Request, env: Env, session: SessionRow | null): Promise<Response> {
  if (session) {
    await appendMany(env, request, [auditFor(session, "auth.logout", "SUCCESS")], [], [
      env.DB.prepare("UPDATE sessions SET revoked_at = ? WHERE session_id = ? AND revoked_at IS NULL")
        .bind(new Date().toISOString(), session.session_id),
    ]);
  } else {
    await logAnonymous(request, env, "auth.logout", "DENIED", { context: { reason: "no_active_session" } });
  }
  return json({ ok: true }, 200, new Headers({ "set-cookie": cookieHeader(request, "", 0) }));
}

async function listRecords(request: Request, env: Env, session: SessionRow): Promise<Response> {
  const rows = session.role === "USER"
    ? await env.DB.prepare(
      `SELECT r.id, r.owner_id, u.display_name AS owner_name, r.title, r.content,
              r.created_at, r.updated_at, r.is_shared, r.revision
         FROM records r JOIN users u ON u.id = r.owner_id
        WHERE r.owner_id = ? OR r.is_shared = 1
        ORDER BY r.is_shared DESC, r.updated_at DESC`,
    ).bind(session.user_id).all<RecordRow>()
    : await env.DB.prepare(
      `SELECT r.id, r.owner_id, u.display_name AS owner_name, r.title, r.content,
              r.created_at, r.updated_at, r.is_shared, r.revision
         FROM records r JOIN users u ON u.id = r.owner_id
        ORDER BY r.is_shared DESC, r.updated_at DESC`,
    ).all<RecordRow>();

  await appendLog(env, request, auditFor(session, "record.list", "SUCCESS", {
    context: { scope: session.role === "USER" ? "shared_and_owned" : "all_records", count: rows.results.length },
  }));
  return json({ records: rows.results });
}

function validRecordFields(body: Record<string, unknown> | null): RecordFields | null {
  if (!body || typeof body.title !== "string" || typeof body.content !== "string") return null;
  const title = body.title.trim();
  const content = body.content.trim();
  if ([...title].length < 1 || [...title].length > 120 || [...content].length > 5_000) return null;
  return { title, content };
}

async function createRecord(request: Request, env: Env, session: SessionRow): Promise<Response> {
  if (session.role === "AUDITOR" || !session.user_id) {
    await logFailure(request, env, session, "record.create", "DENIED", { context: { reason: "read_only_role" } });
    return error("No tienes permiso para crear registros.", 403);
  }
  const fields = validRecordFields(await requestBody(request));
  if (!fields) {
    await logFailure(request, env, session, "record.create", "FAILED", {
      fieldName: "title,content", context: { reason: "invalid_input" },
    });
    return error("Revisa el título y el contenido del registro.", 400);
  }

  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  try {
    const events: AuditEvent[] = [
      { ...actorFor(session), action: "record.create", result: "SUCCESS", recordId: id, fieldName: "title", oldValue: null, newValue: fields.title },
      { ...actorFor(session), action: "record.create", result: "SUCCESS", recordId: id, fieldName: "content", oldValue: null, newValue: fields.content },
    ];
    const evidenceAt = new Date().toISOString();
    await appendSigned(env, events.map((event) => ({ proof: { event: asLogEvidence(request, event, evidenceAt), previous_hash: "", event_hash: "", signature: "" } })), [], (proofs) => {
      const signedEvents = proofs.slice(-events.length);
      return [
      auditContextStatement(env.DB, id, events[0], "record.create", signedEvents),
      env.DB.prepare(
        "INSERT INTO records (id, owner_id, title, content, created_at, updated_at, is_shared, revision) VALUES (?, ?, ?, ?, ?, ?, 0, 1)",
      ).bind(id, session.user_id, fields.title, fields.content, now, now),
      env.DB.prepare("DELETE FROM audit_context WHERE record_id = ?").bind(id),
    ];
    });
  } catch {
    await logFailure(request, env, session, "record.create", "FAILED", {
      recordId: id, context: { reason: "storage_error" },
    });
    return error("No se pudo guardar el registro.", 500);
  }
  return json({ record: { id, owner_id: session.user_id, ...fields, created_at: now, updated_at: now, is_shared: 0, revision: 1 } }, 201);
}

async function editRecord(request: Request, env: Env, session: SessionRow, id: string): Promise<Response> {
  if (session.role === "AUDITOR") {
    await logFailure(request, env, session, "record.update", "DENIED", {
      recordId: id, context: { reason: "read_only_role" },
    });
    return error("El auditor no puede modificar registros operativos.", 403);
  }
  const body = await requestBody(request);
  const fields = validRecordFields(body);
  const expectedRevision = body?.expectedRevision;
  if (!fields || !Number.isSafeInteger(expectedRevision) || Number(expectedRevision) < 1) {
    await logFailure(request, env, session, "record.update", "FAILED", {
      recordId: id, fieldName: "title,content", context: { reason: "invalid_input" },
    });
    return error("Revisa los campos y la versión del registro.", 400);
  }

  const record = await env.DB.prepare(
    "SELECT id, owner_id, title, content, revision, is_shared FROM records WHERE id = ?",
  ).bind(id).first<Pick<RecordRow, "id" | "owner_id" | "title" | "content" | "revision" | "is_shared">>();
  if (!record) {
    await logFailure(request, env, session, "record.update", "FAILED", {
      recordId: id, context: { reason: "record_not_found" },
    });
    return error("No encontramos el registro.", 404);
  }
  if (!canWriteRecord(session.role, record.owner_id, session.user_id, record.is_shared === 1)) {
    await logFailure(request, env, session, "record.update", "DENIED", {
      recordId: id, context: { reason: "not_owner" },
    });
    return error("No tienes permiso para modificar este registro.", 403);
  }
  if (record.title === fields.title && record.content === fields.content) {
    await logFailure(request, env, session, "record.update", "FAILED", {
      recordId: id, context: { reason: "no_field_changed" },
    });
    return error("No hay cambios para guardar.", 400);
  }
  if (record.revision !== expectedRevision) {
    await logFailure(request, env, session, "record.update", "CONFLICT", {
      recordId: id, context: { reason: "stale_revision", expected_revision: Number(expectedRevision), current_revision: record.revision },
    });
    return error("El registro cambió desde que lo abriste. Actualiza la lista y vuelve a intentarlo.", 409);
  }

  const now = new Date().toISOString();
  try {
    const events: AuditEvent[] = [];
    if (record.title !== fields.title) events.push({ ...actorFor(session), action: "record.update", result: "SUCCESS", recordId: id, fieldName: "title", oldValue: record.title, newValue: fields.title });
    if (record.content !== fields.content) events.push({ ...actorFor(session), action: "record.update", result: "SUCCESS", recordId: id, fieldName: "content", oldValue: record.content, newValue: fields.content });
    const evidenceAt = new Date().toISOString();
    await appendSigned(env, events.map((event) => ({ proof: { event: asLogEvidence(request, event, evidenceAt), previous_hash: "", event_hash: "", signature: "" } })), [], (proofs) => {
      const signedEvents = proofs.slice(-events.length);
      return [
        auditContextStatement(env.DB, id, events[0], "record.update", signedEvents),
        env.DB.prepare(
          `UPDATE records SET title = ?, content = ?, updated_at = ?, revision = revision + 1
            WHERE id = ? AND revision = ? AND title = ? AND content = ?`,
        ).bind(fields.title, fields.content, now, id, expectedRevision, record.title, record.content),
        env.DB.prepare("DELETE FROM audit_context WHERE record_id = ?").bind(id),
      ];
    });
  } catch {
    const latest = await env.DB.prepare("SELECT revision FROM records WHERE id = ?").bind(id).first<{ revision: number }>();
    if (latest && latest.revision !== expectedRevision) {
      await logFailure(request, env, session, "record.update", "CONFLICT", {
        recordId: id, context: { reason: "concurrent_update", expected_revision: expectedRevision, current_revision: latest.revision },
      });
      return error("El registro cambió en otra solicitud. Actualiza la lista y vuelve a intentarlo.", 409);
    }
    await logFailure(request, env, session, "record.update", "FAILED", {
      recordId: id, context: { reason: "storage_error" },
    });
    return error("No se pudo guardar el registro.", 500);
  }
  return json({ record: { id, owner_id: record.owner_id, ...fields, updated_at: now, is_shared: record.is_shared, revision: expectedRevision + 1 } });
}

function validDateFilter(value: string | null): string | null | undefined {
  if (value === null || value === "") return null;
  if (!/^\d{4}-\d{2}-\d{2}$/u.test(value)) return undefined;
  const date = new Date(`${value}T00:00:00.000Z`);
  return Number.isNaN(date.getTime()) || date.toISOString().slice(0, 10) !== value ? undefined : value;
}

function validCursor(url: URL): number | null | undefined {
  const value = url.searchParams.get("before");
  if (value === null) return null;
  const cursor = Number(value);
  return /^\d+$/u.test(value) && Number.isSafeInteger(cursor) && cursor > 0 ? cursor : undefined;
}

async function listLogs(request: Request, env: Env, session: SessionRow): Promise<Response> {
  const url = new URL(request.url);
  const before = validCursor(url);
  if (before === undefined) return error("Cursor no válido.", 400);
  const user = url.searchParams.get("user")?.trim() ?? "";
  const action = url.searchParams.get("action")?.trim() ?? "";
  const result = url.searchParams.get("result")?.trim().toUpperCase() ?? "";
  const from = validDateFilter(url.searchParams.get("from"));
  const to = validDateFilter(url.searchParams.get("to"));
  if (user.length > 120 || action.length > 100 || (result && !["SUCCESS", "FAILED", "DENIED", "CONFLICT"].includes(result)) || from === undefined || to === undefined) {
    return error("Los filtros no son válidos.", 400);
  }

  const clauses: string[] = [];
  const values: (string | number | null)[] = [];
  if (before !== null) { clauses.push("sequence < ?"); values.push(before); }
  if (user) {
    clauses.push("(actor_id = ? OR instr(lower(actor_name), lower(?)) > 0)");
    values.push(user, user);
  }
  if (action) { clauses.push("action = ?"); values.push(action); }
  if (result) { clauses.push("result = ?"); values.push(result); }
  if (from) { clauses.push("occurred_at >= ?"); values.push(`${from}T00:00:00.000Z`); }
  if (to) {
    const nextDay = new Date(`${to}T00:00:00.000Z`);
    nextDay.setUTCDate(nextDay.getUTCDate() + 1);
    clauses.push("occurred_at < ?"); values.push(nextDay.toISOString());
  }
  const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
  const rows = await env.DB.prepare(
    `SELECT sequence, event_id, actor_id, actor_name, actor_role, session_id, occurred_at,
            ip_address, user_agent, action, record_id, field_name, old_value, new_value,
            result, context_json, previous_hash, event_hash, signature, edit_revision
       FROM logs ${where}
      ORDER BY sequence DESC LIMIT 101`,
  ).bind(...values).all<LogRow>();
  await appendIntegrityResult(env, request, {
    ...actorFor(session),
    action: session.role === "ADMIN" ? "ADMIN_LOGS_VIEWED" : "AUDITOR_LOGS_VIEWED",
    resource: "/api/logs",
    result: "SUCCESS",
    context: { user, action, from: from ?? null, to: to ?? null, result, count: rows.results.length },
  });
  const page = rows.results.slice(0, 100);
  const options = await env.DB.prepare("SELECT DISTINCT action FROM logs ORDER BY action").all<{ action: string }>();
  return json({ logs: page, actions: options.results.map((row) => row.action), limit: 100, nextCursor: rows.results.length > 100 ? page[page.length - 1].sequence : null });
}

async function listMetalogs(request: Request, env: Env, session: SessionRow): Promise<Response> {
  const url = new URL(request.url);
  const before = validCursor(url);
  if (before === undefined) return error("Cursor no válido.", 400);
  const user = url.searchParams.get("user")?.trim() ?? "";
  const action = url.searchParams.get("action")?.trim() ?? "";
  const result = url.searchParams.get("result")?.trim().toUpperCase() ?? "";
  const from = validDateFilter(url.searchParams.get("from"));
  const to = validDateFilter(url.searchParams.get("to"));
  if (user.length > 120 || action.length > 100 || (result && !["SUCCESS", "FAILED", "DENIED", "CONFLICT"].includes(result)) || from === undefined || to === undefined) {
    return error("Filtros de metalogs no válidos.", 400);
  }
  const clauses: string[] = [];
  const values: (string | number | null)[] = [];
  if (before !== null) { clauses.push("sequence < ?"); values.push(before); }
  if (user) { clauses.push("(actor_id = ? OR instr(lower(actor_name), lower(?)) > 0)"); values.push(user, user); }
  if (action) { clauses.push("action = ?"); values.push(action); }
  if (result) { clauses.push("result = ?"); values.push(result); }
  if (from) { clauses.push("occurred_at >= ?"); values.push(`${from}T00:00:00.000Z`); }
  if (to) {
    const nextDay = new Date(`${to}T00:00:00.000Z`);
    nextDay.setUTCDate(nextDay.getUTCDate() + 1);
    clauses.push("occurred_at < ?"); values.push(nextDay.toISOString());
  }
  const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
  const rows = await env.DB.prepare(
    `SELECT sequence, event_id, actor_id, actor_name, actor_role, session_id, occurred_at,
            ip_address, user_agent, action, resource, result, context_json,
            previous_hash, event_hash, signature, edit_revision
       FROM metalogs ${where}
      ORDER BY sequence DESC LIMIT 101`,
  ).bind(...values).all<MetalogRow>();
  await appendIntegrityResult(env, request, {
    ...actorFor(session), action: "AUDITOR_METALOGS_VIEWED", resource: "/api/metalogs", result: "SUCCESS",
    context: { user, action, from: from ?? null, to: to ?? null, result, count: rows.results.length },
  });
  const page = rows.results.slice(0, 100);
  const options = await env.DB.prepare("SELECT DISTINCT action FROM metalogs ORDER BY action").all<{ action: string }>();
  return json({ metalogs: page, actions: options.results.map((row) => row.action), limit: 100, nextCursor: rows.results.length > 100 ? page[page.length - 1].sequence : null });
}

async function editEvidence(request: Request, env: Env, session: SessionRow, source: "LOG" | "METALOG", eventId: string): Promise<Response> {
  const resource = `/api/${source === "LOG" ? "logs" : "metalogs"}/${eventId}`;
  if (session.role !== "AUDITOR" && !(source === "LOG" && session.role === "ADMIN")) {
    await logFailure(request, env, session, "evidence.edit", "DENIED", { context: { resource, reason: "role_not_allowed" } });
    return error("No tienes permiso para editar esta evidencia.", 403);
  }
  const body = await requestBody(request);
  const fields = ["actor_name", "ip_address", "action", "result", "occurred_at", "actor_role", ...(source === "LOG" ? ["old_value", "new_value"] : [])];
  if (!body || typeof body.field !== "string" || !fields.includes(body.field) || typeof body.value !== "string"
      || body.value.length > 5000 || !Number.isSafeInteger(body.expectedRevision) || Number(body.expectedRevision) < 0) {
    return error("Selecciona un campo y un valor válidos.", 400);
  }
  const secrets = [env.ADMIN_ACCESS_CODE, env.AUDITOR_ACCESS_CODE, env.AUDIT_HMAC_KEY, readCookie(request)].filter((value): value is string => Boolean(value));
  const proposedValue = body.value;
  if (secrets.some((secret) => proposedValue.includes(secret))) return error("El campo no puede contener credenciales ni secretos.", 400);
  if ((body.field === "result" && !["SUCCESS", "FAILED", "DENIED", "CONFLICT"].includes(body.value))
      || (body.field === "actor_role" && !["USER", "ADMIN", "AUDITOR", "SYSTEM", "ANONYMOUS"].includes(body.value))
      || (body.field === "occurred_at" && (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(body.value) || Number.isNaN(Date.parse(body.value))))
      || (["actor_name", "action"].includes(body.field) && (!body.value.trim() || body.value.length > 100))
      || (body.field === "ip_address" && body.value.length > 64)) return error("El valor no corresponde al campo seleccionado.", 400);
  const table = source === "LOG" ? "logs" : "metalogs";
  const row = await env.DB.prepare(`SELECT * FROM ${table} WHERE event_id = ?`).bind(eventId).first<Record<string, unknown>>();
  if (!row) return error("No encontramos la evidencia.", 404);
  if (row.edit_revision !== body.expectedRevision) return error("La evidencia cambió. Actualiza el historial.", 409);
  const previous = row[body.field] as string | null;
  if (previous === body.value) return error("No hay cambios para guardar.", 400);
  const guardId = crypto.randomUUID();
  try {
    await appendMany(env, request, [], [{
      ...actorFor(session), action: "EVIDENCE_CONTENT_EDITED", resource, result: "SUCCESS",
      context: { source, event_id: eventId, field: body.field, previous_value: previous, new_value: body.value,
        educational_exception: true, original_signature_preserved: true },
    }], [
      env.DB.prepare(`INSERT INTO mutation_guards (guard_id, allowed) SELECT ?, CASE WHEN EXISTS
        (SELECT 1 FROM ${table} WHERE event_id = ? AND edit_revision = ?) THEN 1 ELSE 0 END`).bind(guardId, eventId, body.expectedRevision),
      env.DB.prepare("INSERT INTO evidence_edit_guard (source,event_id,expected_revision) VALUES (?,?,?)").bind(source, eventId, body.expectedRevision),
      env.DB.prepare(`UPDATE ${table} SET ${body.field} = ?, edit_revision = edit_revision + 1 WHERE event_id = ? AND edit_revision = ?`).bind(body.value, eventId, body.expectedRevision),
      env.DB.prepare("DELETE FROM evidence_edit_guard WHERE source = ? AND event_id = ?").bind(source, eventId),
      env.DB.prepare("DELETE FROM mutation_guards WHERE guard_id = ?").bind(guardId),
    ]);
  } catch {
    return error("No se guardó la edición. Actualiza el historial y vuelve a intentar.", 409);
  }
  return json({ ok: true, editRevision: Number(body.expectedRevision) + 1, originalSignaturePreserved: true });
}

async function verifyAdminActivity(request: Request, env: Env, session: SessionRow): Promise<Response> {
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
     ) ORDER BY global_sequence DESC LIMIT 200`,
  ).all<Record<string, unknown>>();
  await appendIntegrityResult(env, request, {
    ...actorFor(session), action: "ADMIN_ACTIVITY_VERIFIED", resource: "/api/audit/admin-activity", result: "SUCCESS",
    context: { count: rows.results.length },
  });
  return json({ activities: rows.results, limit: 200 });
}

interface IntegrityOrderRow extends Record<string, unknown> {
  sequence: number; source: "LOG" | "METALOG"; event_id: string; occurred_at: string; order_occurred_at: string;
  actor_id: string | null; actor_name: string | null; actor_role: string | null; session_id: string | null;
  ip_address: string | null; user_agent: string | null; action: string | null; record_id: string | null;
  field_name: string | null; old_value: string | null; new_value: string | null; resource: string | null;
  result: string | null; context_json: string | null; previous_hash: string | null; event_hash: string | null; signature: string | null;
}

interface IntegrityStateSnapshot {
  historical_cutoff_sequence: number; historical_count: number; historical_snapshot_hash: string;
  head_hash: string; last_audit_sequence: number;
}

async function integritySnapshot(env: Env): Promise<{ rows: IntegrityOrderRow[]; fixedCutoff: number; state: IntegrityStateSnapshot | null; limited: boolean }> {
  const state = await env.DB.prepare(`SELECT historical_cutoff_sequence, historical_count, historical_snapshot_hash, head_hash, last_audit_sequence,
    (SELECT COALESCE(MAX(sequence), 0) FROM audit_order) AS snapshot_cutoff FROM integrity_state WHERE singleton = 1`)
    .first<IntegrityStateSnapshot & { snapshot_cutoff: number }>();
  const fixedCutoff = Number(state?.snapshot_cutoff ?? 0);
  const rows: IntegrityOrderRow[] = [];
  let after = 0;
  let bytes = 0;
  let limited = fixedCutoff > 20000;
  let memoryLimit = false;
  // La instantánea fija excluye eventos añadidos durante la verificación.
  while (after < fixedCutoff && rows.length < 20000 && !memoryLimit) {
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
       ORDER BY evidence.sequence LIMIT 1000`,
  ).bind(after, fixedCutoff).all<IntegrityOrderRow>();
  if (!result.results.length) break;
  for (const row of result.results) {
    bytes += new TextEncoder().encode(JSON.stringify(row)).length;
    if (bytes > 16 * 1024 * 1024) { memoryLimit = true; limited = true; break; }
    rows.push({ ...row, sequence: Number(row.sequence) });
  }
  if (!rows.length) break;
  after = rows[rows.length - 1].sequence;
  }
  return { rows, fixedCutoff, state, limited };
}

async function verifyIntegrity(request: Request, env: Env, session: SessionRow): Promise<Response> {
  if (!env.AUDIT_HMAC_KEY || env.AUDIT_HMAC_KEY.length < 32) {
    return json({ status: "INTEGRITY_UNVERIFIABLE", reviewed: 0, errors: [{ code: "HMAC_KEY_UNAVAILABLE" }] }, 503);
  }
  await initializeIntegrity(env);
  const snapshot = await integritySnapshot(env);
  const { state, fixedCutoff } = snapshot;
  const limited = snapshot.limited;
  const checkProof = await evidenceVerifier(env.AUDIT_HMAC_KEY);
  const errors: Array<{ code: string; sequence?: number; event_id?: string }> = [];
  let firstInconsistentEvent: { sequence: number; event_id: string; code: string } | null = null;
  const fail = (code: string, row?: IntegrityOrderRow) => {
    errors.push({ code, ...(row ? { sequence: row.sequence, event_id: row.event_id } : {}) });
    if (!firstInconsistentEvent || (row && firstInconsistentEvent.sequence > row.sequence)) firstInconsistentEvent = { sequence: row?.sequence ?? 0, event_id: row?.event_id ?? "", code };
  };
  let status: "INTEGRITY_OK" | "INTEGRITY_FAILED" | "INTEGRITY_UNVERIFIABLE" = "INTEGRITY_OK";
  let contentHashesValid = 0;
  let validSignatures = 0;
  if (!state) {
    fail("INTEGRITY_STATE_MISSING"); status = "INTEGRITY_FAILED";
  }
  if (limited) {
    errors.push({ code: "VERIFICATION_LIMIT_EXCEEDED" }); status = "INTEGRITY_UNVERIFIABLE";
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
    if ((!limited || checkpoint) && (!checkpoint || checkpoint.action !== "INTEGRITY_CHAIN_STARTED" || checkpoint.source !== "METALOG"
        || checkpointContext.historical_cutoff !== state.historical_cutoff_sequence
        || checkpointContext.historical_count !== state.historical_count
        || checkpointContext.historical_snapshot_sha256 !== state.historical_snapshot_hash)) {
      fail("CHAIN_CHECKPOINT_MISMATCH", checkpoint);
    }
    for (const continuityError of continuityErrors(chainRows, state.historical_cutoff_sequence + 1)) {
      const row = chainRows.find((item) => item.sequence === continuityError.sequence);
      fail(continuityError.code, row);
    }
    let previousHash = "0".repeat(64);
    for (let index = 0; index < chainRows.length; index += 1) {
      const row = chainRows[index];
      if (row.actor_name === null || row.action === null || row.result === null) { fail("EVENT_REFERENCE_MISSING", row); continue; }
      if (!row.previous_hash || !row.event_hash || !row.signature) { fail("SIGNED_EVENT_PROOF_MISSING", row); continue; }
      const source = row.source;
      const event = rowEvidence(row, source);
      const proof = decodeProof(event, row.previous_hash, row.event_hash, row.signature);
      if (!proof) { fail("SIGNED_EVENT_PROOF_MISSING", row); continue; }
      const result = await checkProof(proof);
      if (result.contentValid) contentHashesValid += 1;
      if (result.signatureValid) validSignatures += 1;
      if (!result.contentValid) fail("EVENT_HASH_MISMATCH", row);
      if (!result.signatureValid) fail("HMAC_SIGNATURE_INVALID", row);
      previousHash = row.event_hash;
    }
    if (state.last_audit_sequence !== fixedCutoff || (!limited && state.head_hash !== previousHash)) fail("CHAIN_HEAD_MISMATCH");
  }
  if (errors.some((item) => !["LEGACY_UNSIGNED_EVENTS", "VERIFICATION_LIMIT_EXCEEDED"].includes(item.code))) status = "INTEGRITY_FAILED";
  else if (status !== "INTEGRITY_FAILED" && errors.length > 0) status = "INTEGRITY_UNVERIFIABLE";
  const counts = {
    logs: snapshot.rows.filter((row) => row.source === "LOG").length,
    metalogs: snapshot.rows.filter((row) => row.source === "METALOG").length,
    signed: snapshot.rows.filter((row) => row.sequence > (state?.historical_cutoff_sequence ?? 0)).length,
    validContentHashes: contentHashesValid,
    validSignatures,
    legacy: state?.historical_count ?? 0,
  };
  await appendIntegrityResult(env, request, {
    ...actorFor(session), action: "INTEGRITY_VERIFICATION", resource: "/api/audit/integrity",
    result: status === "INTEGRITY_OK" ? "SUCCESS" : "FAILED",
    context: { status, reviewed: snapshot.rows.length, fixed_cutoff: fixedCutoff, error_count: errors.length },
  });
  return json({ status, reviewed: snapshot.rows.length, counts, firstInconsistentEvent, errors: errors.slice(0, 100), fixedCutoff });
}

function labResponse(row: { copy_id: string; source: string; source_event_id: string; original_json: string; working_json: string; revision: number }) {
  const original = JSON.parse(row.original_json) as { event: CanonicalEvidence; proof: SignedEvidence | null };
  const working = JSON.parse(row.working_json) as CanonicalEvidence;
  return { copyId: row.copy_id, source: row.source, sourceEventId: row.source_event_id, original: original.event, working, hasSignature: Boolean(original.proof), revision: row.revision };
}

async function labSources(request: Request, env: Env, session: SessionRow): Promise<Response> {
  const rows = await env.DB.prepare(
    `SELECT * FROM (
       SELECT 'LOG' AS source, event_id, occurred_at, actor_name, actor_role, action FROM logs
       UNION ALL
       SELECT 'METALOG' AS source, event_id, occurred_at, actor_name, actor_role, action FROM metalogs
     ) ORDER BY occurred_at DESC LIMIT 100`,
  ).all<{ source: "LOG" | "METALOG"; event_id: string; occurred_at: string; actor_name: string; actor_role: string; action: string }>();
  await appendMetalog(env, request, { ...actorFor(session), action: "LAB_SOURCES_VIEWED", resource: "/api/audit/lab/sources", result: "SUCCESS", context: { count: rows.results.length } });
  return json({ sources: rows.results });
}

async function createLabCopy(request: Request, env: Env, session: SessionRow): Promise<Response> {
  const body = await requestBody(request);
  if ((body?.source !== "LOG" && body?.source !== "METALOG") || typeof body.eventId !== "string" || body.eventId.length > 64) return error("Selecciona una evidencia válida.", 400);
  const table = body.source === "LOG" ? "logs" : "metalogs";
  const row = await env.DB.prepare(`SELECT * FROM ${table} WHERE event_id = ?`).bind(body.eventId).first<Record<string, unknown>>();
  if (!row) return error("No encontramos la evidencia seleccionada.", 404);
  const event = rowEvidence(row, body.source);
  const proof = decodeProof(event, typeof row.previous_hash === "string" ? row.previous_hash : null,
    typeof row.event_hash === "string" ? row.event_hash : null, typeof row.signature === "string" ? row.signature : null);
  const copyId = crypto.randomUUID();
  const originalJson = canonicalJson({ event, proof });
  await appendMany(env, request, [], [{
    ...actorFor(session), action: "LAB_COPY_CREATED", resource: `/api/audit/lab/copies/${copyId}`, result: "SUCCESS",
    context: { source: body.source, source_event_id: body.eventId, has_signature: Boolean(proof) },
  }], [env.DB.prepare(
    `INSERT INTO lab_copies (copy_id, owner_session_id, source, source_event_id, original_json, working_json, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
  ).bind(copyId, session.session_id, body.source, body.eventId, originalJson, canonicalJson(event), new Date().toISOString())]);
  const created = await env.DB.prepare("SELECT * FROM lab_copies WHERE copy_id = ? AND owner_session_id = ?").bind(copyId, session.session_id).first<{ copy_id: string; source: string; source_event_id: string; original_json: string; working_json: string; revision: number }>();
  return json({ copy: labResponse(created!) }, 201);
}

async function mutateLabCopy(request: Request, env: Env, session: SessionRow, copyId: string): Promise<Response> {
  const body = await requestBody(request);
  if (typeof body?.field !== "string" || !["action", "old_value", "new_value", "context_json", "result"].includes(body.field)
      || typeof body.value !== "string" || body.value.length > 5_000 || !Number.isSafeInteger(body.expectedRevision)
      || Number(body.expectedRevision) < 1) return error("Campo o revisión de simulación no válidos.", 400);
  const row = await env.DB.prepare("SELECT * FROM lab_copies WHERE copy_id = ? AND owner_session_id = ?")
    .bind(copyId, session.session_id).first<{ copy_id: string; source: string; source_event_id: string; original_json: string; working_json: string; revision: number }>();
  if (!row) {
    await logFailure(request, env, session, "audit.lab", "DENIED", { context: { resource: `/api/audit/lab/copies/${copyId}`, reason: "copy_not_available_for_session" } });
    return error("No encontramos la copia del laboratorio.", 404);
  }
  if (row.revision !== body.expectedRevision) return error("La revisión de la copia está obsoleta. Crea una copia nueva.", 409);
  const working = JSON.parse(row.working_json) as Record<string, unknown>;
  working[body.field] = body.value;
  const next = canonicalJson(working);
  const guardId = crypto.randomUUID();
  try {
  await appendMany(env, request, [], [{
    ...actorFor(session), action: "LAB_TAMPER_SIMULATED", resource: `/api/audit/lab/copies/${copyId}`, result: "SUCCESS",
    context: { source_event_id: row.source_event_id, field: body.field },
  }], [env.DB.prepare(`INSERT INTO mutation_guards (guard_id, allowed) SELECT ?, CASE WHEN EXISTS
      (SELECT 1 FROM lab_copies WHERE copy_id = ? AND owner_session_id = ? AND revision = ?) THEN 1 ELSE 0 END`)
      .bind(guardId, copyId, session.session_id, row.revision),
    env.DB.prepare("UPDATE lab_copies SET working_json = ?, revision = revision + 1 WHERE copy_id = ? AND owner_session_id = ? AND revision = ?")
      .bind(next, copyId, session.session_id, row.revision),
    env.DB.prepare("DELETE FROM mutation_guards WHERE guard_id = ?").bind(guardId)]);
  } catch {
    return error("La copia cambió en otra solicitud. Crea una copia nueva e intenta otra vez.", 409);
  }
  const updated = await env.DB.prepare("SELECT * FROM lab_copies WHERE copy_id = ? AND owner_session_id = ?")
    .bind(copyId, session.session_id).first<typeof row>();
  return json({ copy: labResponse(updated!) });
}

async function verifyLabCopy(request: Request, env: Env, session: SessionRow, copyId: string): Promise<Response> {
  const row = await env.DB.prepare("SELECT * FROM lab_copies WHERE copy_id = ? AND owner_session_id = ?")
    .bind(copyId, session.session_id).first<{ copy_id: string; source: string; source_event_id: string; original_json: string; working_json: string; revision: number }>();
  if (!row) {
    await logFailure(request, env, session, "audit.lab", "DENIED", { context: { resource: `/api/audit/lab/copies/${copyId}`, reason: "copy_not_available_for_session" } });
    return error("No encontramos la copia del laboratorio.", 404);
  }
  const original = JSON.parse(row.original_json) as { proof: SignedEvidence | null };
  const working = JSON.parse(row.working_json) as CanonicalEvidence;
  let status: "INTEGRITY_OK" | "INTEGRITY_FAILED" | "INTEGRITY_UNVERIFIABLE" = "INTEGRITY_UNVERIFIABLE";
  let contentHashValid: boolean | null = null;
  let signatureValid: boolean | null = null;
  if (original.proof && env.AUDIT_HMAC_KEY) {
    const verified = await verifyEvidence({ ...original.proof, event: working }, env.AUDIT_HMAC_KEY);
    contentHashValid = verified.contentValid;
    signatureValid = verified.signatureValid;
    status = contentHashValid && signatureValid ? "INTEGRITY_OK" : "INTEGRITY_FAILED";
  }
  await appendMetalog(env, request, {
    ...actorFor(session), action: "LAB_COPY_VERIFIED", resource: `/api/audit/lab/copies/${copyId}`,
    result: status === "INTEGRITY_OK" ? "SUCCESS" : "FAILED",
    context: { source_event_id: row.source_event_id, status, revision: row.revision, content_hash_valid: contentHashValid, signature_valid: signatureValid },
  });
  return json({ status, contentHashValid, signatureValid, copy: labResponse(row) });
}

async function resetLabCopy(request: Request, env: Env, session: SessionRow, copyId: string): Promise<Response> {
  const result = await env.DB.prepare("SELECT source_event_id FROM lab_copies WHERE copy_id = ? AND owner_session_id = ?")
    .bind(copyId, session.session_id).first<{ source_event_id: string }>();
  if (!result) {
    await logFailure(request, env, session, "audit.lab", "DENIED", { context: { resource: `/api/audit/lab/copies/${copyId}`, reason: "copy_not_available_for_session" } });
    return error("No encontramos la copia del laboratorio.", 404);
  }
  await appendMany(env, request, [], [{
    ...actorFor(session), action: "LAB_RESET", resource: `/api/audit/lab/copies/${copyId}`, result: "SUCCESS",
    context: { source_event_id: result.source_event_id },
  }], [env.DB.prepare("DELETE FROM lab_copies WHERE copy_id = ? AND owner_session_id = ?").bind(copyId, session.session_id)]);
  return json({ ok: true });
}

async function handleApi(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const { pathname } = url;

  if (crossSiteMutation(request)) {
    const session = await currentSession(request, env);
    const details = { context: { resource: pathname, reason: "cross_site_request" } };
    if (session) await logFailure(request, env, session, "security.csrf", "DENIED", details);
    else await logAnonymous(request, env, "security.csrf", "DENIED", details);
    return error("Solicitud de otro sitio rechazada.", 403);
  }
  // Límites atómicos por IP observada y ruta; solo el primer rechazo de la ventana genera evidencia.
  if (pathname !== "/api/session") {
    const auth = pathname.startsWith("/api/auth/");
    const limit = auth ? 30 : request.method === "GET" ? 240 : 90;
    const ip = request.headers.get("cf-connecting-ip")?.slice(0, 64) ?? "local";
    const authBucket = ["/api/auth/register", "/api/auth/user", "/api/auth/special", "/api/auth/logout"].includes(pathname) ? pathname : "auth:other";
    const bucket = await digestToken(`${ip}|${auth ? authBucket : request.method === "GET" ? "read" : "write"}`);
    const window = Math.floor(Date.now() / 60000);
    const counter = await env.DB.prepare(`INSERT INTO request_limits (bucket_key, window_start, request_count) VALUES (?, ?, 1)
      ON CONFLICT(bucket_key) DO UPDATE SET request_count = CASE WHEN window_start = excluded.window_start THEN request_count + 1 ELSE 1 END,
      window_start = excluded.window_start RETURNING request_count`).bind(bucket, window).first<{ request_count: number }>();
    if (!counter) throw new Error("rate limit unavailable");
    if (counter.request_count > limit) {
      if (counter.request_count === limit + 1) {
        const session = await currentSession(request, env);
        const details = { context: { resource: pathname, reason: "rate_limit", limit } };
        if (session) await logFailure(request, env, session, "security.rate_limit", "DENIED", details);
        else await logAnonymous(request, env, "security.rate_limit", "DENIED", details);
      }
      return json({ error: "Demasiadas solicitudes. Espera un minuto e intenta de nuevo." }, 429, new Headers({ "retry-after": "60" }));
    }
    // Mantener el estado acotado sin eliminar ninguna evidencia.
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
      expiresAt: session.expires_at,
    });
  }

  const privilegedAuditPath = pathname === "/api/logs" || pathname.startsWith("/api/logs/") || pathname === "/api/metalogs" || pathname.startsWith("/api/metalogs/")
    || pathname.startsWith("/api/audit/");
  if (pathname === "/api/records" || pathname.startsWith("/api/records/") || privilegedAuditPath) {
    if (!session) {
      await logAnonymous(request, env, "access.denied", "DENIED", {
        context: { method: request.method, resource: pathname },
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
        context: { method: request.method, resource: pathname, reason: "auditor_role_required" },
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
        context: { method: request.method, reason: "read_only_endpoint" },
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
        { ...actorFor(session), action: "ACCESS_DENIED", resource: pathname, result: "DENIED", context: { ...deniedContext, attempted_action: "metalogs.read" } },
      ]);
      return error("El administrador no tiene permiso para consultar metalogs.", 403);
    }
    if (session.role !== "AUDITOR") {
      await logFailure(request, env, session, "metalog.access", "DENIED", {
        context: { method: request.method, resource: pathname, reason: "role_not_allowed" },
      });
      return error("No tienes permiso para consultar metalogs.", 403);
    }
    const match = pathname.match(/^\/api\/metalogs\/([0-9a-f-]{36})$/iu);
    if (match && request.method === "PATCH") return editEvidence(request, env, session, "METALOG", match[1]);
    if (request.method !== "GET" || pathname !== "/api/metalogs") {
      await logFailure(request, env, session, "metalog.access", "DENIED", {
        context: { method: request.method, resource: pathname, reason: "read_only_endpoint" },
      });
      return error("Operación no permitida sobre metalogs. No se pueden eliminar evidencias.", 405);
    }
    return listMetalogs(request, env, session);
  }

  if (pathname === "/api/audit/admin-activity") {
    if (session.role !== "AUDITOR") {
      await logFailure(request, env, session, "audit.admin_activity", "DENIED", {
        context: { method: request.method, resource: pathname, reason: "auditor_role_required" },
      });
      return error("Esta verificación está reservada al auditor.", 403);
    }
    if (request.method !== "GET") {
      await logFailure(request, env, session, "audit.admin_activity", "DENIED", {
        context: { method: request.method, resource: pathname, reason: "read_only_endpoint" },
      });
      return error("La verificación es de solo lectura.", 405);
    }
    return verifyAdminActivity(request, env, session);
  }
  return error("Ruta no encontrada.", 404);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (!url.pathname.startsWith("/api/")) return secureResponse(request, await env.ASSETS.fetch(request));
    try {
      return secureResponse(request, await handleApi(request, env));
    } catch {
      if (url.pathname === "/api/audit/integrity" && env.AUDIT_HMAC_KEY && env.AUDIT_HMAC_KEY.length >= 32) {
        try {
          const session = await currentSession(request, env);
          if (session?.role === "AUDITOR") await appendIntegrityResult(env, request, {
            ...actorFor(session), action: "INTEGRITY_VERIFICATION", resource: url.pathname, result: "FAILED",
            context: { status: "INTEGRITY_UNVERIFIABLE", reason: "verification_aborted" },
          });
        } catch { /* Si D1 también falla, no fingir que la evidencia persistió. */ }
      }
      const response = url.pathname === "/api/audit/integrity"
        ? json({ error: "La verificación no pudo completarse.", status: "INTEGRITY_UNVERIFIABLE", reviewed: 0, errors: [{ code: "VERIFICATION_ABORTED" }] }, 503)
        : error("Ocurrió un error interno.", 500);
      return secureResponse(request, response);
    }
  },
};
