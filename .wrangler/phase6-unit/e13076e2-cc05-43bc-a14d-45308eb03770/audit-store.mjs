import { canonicalJson, sha256Hex, signEvidence, signedCheckpoint, } from "./integrity.mjs";
const observedHeadSql = `(SELECT COALESCE(l.event_hash, m.event_hash, '') FROM audit_order a
  LEFT JOIN logs l ON a.source = 'LOG' AND l.event_id = a.event_id
  LEFT JOIN metalogs m ON a.source = 'METALOG' AND m.event_id = a.event_id
  ORDER BY a.sequence DESC LIMIT 1)`;
function requestMetadata(request) {
    const observedIp = request.headers.get("cf-connecting-ip")?.trim() ?? "";
    return {
        occurred_at: new Date().toISOString(),
        ip_address: observedIp.length > 0 && observedIp.length <= 64 && ![...observedIp].some((c) => c.charCodeAt(0) < 32 || c.charCodeAt(0) === 127) ? observedIp : null,
        user_agent: request.headers.get("user-agent")?.slice(0, 512) ?? null,
    };
}
export function asLogEvidence(request, event, occurredAt) {
    const metadata = requestMetadata(request);
    return {
        schemaVersion: 1, source: "LOG", event_id: crypto.randomUUID(), actor_id: event.actorId,
        actor_name: event.actorName.slice(0, 120), actor_role: event.actorRole, session_id: event.sessionId ?? null,
        ...metadata, occurred_at: occurredAt ?? metadata.occurred_at, action: event.action.slice(0, 100), record_id: event.recordId ?? null,
        field_name: event.fieldName ?? null, old_value: event.oldValue ?? null, new_value: event.newValue ?? null,
        resource: null, result: event.result, context_json: event.context ? canonicalJson(event.context) : null,
    };
}
export function asMetalogEvidence(request, event) {
    const metadata = requestMetadata(request);
    return {
        schemaVersion: 1, source: "METALOG", event_id: crypto.randomUUID(), actor_id: event.actorId,
        actor_name: event.actorName.slice(0, 120), actor_role: event.actorRole, session_id: event.sessionId ?? null,
        ...metadata, action: event.action.slice(0, 100), record_id: null, field_name: null,
        old_value: null, new_value: null, resource: event.resource.slice(0, 200), result: event.result,
        context_json: event.context ? canonicalJson(event.context) : null,
    };
}
export function evidenceInsertStatement(db, proof) {
    const event = proof.event;
    if (event.source === "LOG")
        return db.prepare(`INSERT INTO logs (
       event_id, actor_id, actor_name, actor_role, session_id, occurred_at, ip_address, user_agent,
       action, record_id, field_name, old_value, new_value, result, context_json,
       previous_hash, event_hash, signature
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(event.event_id, event.actor_id, event.actor_name, event.actor_role, event.session_id, event.occurred_at, event.ip_address, event.user_agent, event.action, event.record_id, event.field_name, event.old_value, event.new_value, event.result, event.context_json, proof.previous_hash, proof.event_hash, proof.signature);
    return db.prepare(`INSERT INTO metalogs (
       event_id, actor_id, actor_name, actor_role, session_id, occurred_at, ip_address, user_agent,
       action, resource, result, context_json, previous_hash, event_hash, signature
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(event.event_id, event.actor_id, event.actor_name, event.actor_role, event.session_id, event.occurred_at, event.ip_address, event.user_agent, event.action, event.resource, event.result, event.context_json, proof.previous_hash, proof.event_hash, proof.signature);
}
export function auditContextStatement(db, recordId, actor, action, proofs) {
    const byField = new Map(proofs.map((proof) => [proof.event.field_name, proof]));
    const title = byField.get("title");
    const content = byField.get("content");
    const shared = byField.get("is_shared");
    const metadata = proofs[0]?.event;
    if (!metadata || (!title && !content && !shared))
        throw new Error("record proof fields are incomplete");
    return db.prepare(`INSERT INTO audit_context (
      record_id, actor_id, actor_name, actor_role, session_id, occurred_at, ip_address, user_agent, action,
      title_event_id, title_previous_hash, title_event_hash, title_signature,
      content_event_id, content_previous_hash, content_event_hash, content_signature,
      shared_event_id, shared_previous_hash, shared_event_hash, shared_signature
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(recordId, actor.actorId, actor.actorName.slice(0, 120), actor.actorRole, actor.sessionId ?? null, metadata.occurred_at, metadata.ip_address, metadata.user_agent, action, title?.event.event_id ?? null, title?.previous_hash ?? null, title?.event_hash ?? null, title?.signature ?? null, content?.event.event_id ?? null, content?.previous_hash ?? null, content?.event_hash ?? null, content?.signature ?? null, shared?.event.event_id ?? null, shared?.previous_hash ?? null, shared?.event_hash ?? null, shared?.signature ?? null);
}
export async function historicalSnapshot(db, throughSequence) {
    const rows = await db.prepare(`SELECT * FROM (SELECT ao.sequence, ao.source, ao.event_id, l.occurred_at, l.actor_id, l.actor_name, l.actor_role, l.session_id,
            l.ip_address, l.user_agent, l.action, l.record_id, l.field_name, l.old_value, l.new_value, NULL AS resource,
            l.result, l.context_json, l.previous_hash, l.event_hash, l.signature
       FROM audit_order ao JOIN logs l ON ao.source = 'LOG' AND l.event_id = ao.event_id
      UNION ALL
     SELECT ao.sequence, ao.source, ao.event_id, m.occurred_at, m.actor_id, m.actor_name, m.actor_role, m.session_id,
            m.ip_address, m.user_agent, m.action, NULL, NULL, NULL, NULL, m.resource,
            m.result, m.context_json, m.previous_hash, m.event_hash, m.signature
       FROM audit_order ao JOIN metalogs m ON ao.source = 'METALOG' AND m.event_id = ao.event_id
     ) WHERE (? IS NULL OR sequence <= ?) ORDER BY sequence LIMIT 50001`).bind(throughSequence ?? null, throughSequence ?? null).all();
    if (rows.results.length > 50_000)
        throw new Error("historical evidence exceeds checkpoint capacity");
    const normalized = rows.results.map((row) => ({ ...row }));
    const cutoff = normalized.length ? Number(normalized[normalized.length - 1].sequence) : 0;
    return { cutoff, count: normalized.length, hash: await sha256Hex(canonicalJson(normalized)) };
}
export async function appendSigned(env, entries, beforeEvidence = [], customEvidenceSteps) {
    const secret = env.AUDIT_HMAC_KEY;
    if (!secret || secret.length < 32)
        throw new Error("AUDIT_HMAC_KEY must contain at least 32 characters");
    for (let attempt = 0; attempt < 4; attempt += 1) {
        const state = await env.DB.prepare(`SELECT s.*, (SELECT COALESCE(MAX(sequence), 0) FROM audit_order) AS observed_max,
      ${observedHeadSql} AS observed_head FROM integrity_state s WHERE singleton = 1`).first();
        if (!state)
            throw new Error("integrity state missing; apply migration 0006");
        let expectedSequence = state.last_audit_sequence;
        let expectedHead = state.head_hash;
        let cutoff;
        const proofs = [];
        if (state.initialized === 0) {
            cutoff = await historicalSnapshot(env.DB);
            if (state.observed_max !== cutoff.cutoff)
                continue;
            expectedSequence = cutoff.cutoff;
            expectedHead = "0".repeat(64);
            proofs.push(await signedCheckpoint(secret, cutoff.cutoff, cutoff.count, cutoff.hash, new Date().toISOString()));
        }
        else if (state.observed_max !== expectedSequence || state.observed_head !== expectedHead) {
            throw new Error("integrity chain is out of sync with audit order");
        }
        if (state.initialized === 1 && entries.length === 0)
            return [];
        let nextHash = cutoff && proofs.length ? proofs[proofs.length - 1].event_hash : expectedHead;
        for (const entry of entries) {
            const proof = await signEvidence(entry.proof.event, nextHash, secret);
            proofs.push(proof);
            nextHash = proof.event_hash;
        }
        const signedCount = proofs.length;
        const finalSequence = expectedSequence + signedCount;
        const statements = [];
        if (cutoff)
            statements.push(env.DB.prepare(`UPDATE integrity_state SET initialized = 1, historical_cutoff_sequence = ?, historical_count = ?,
         historical_snapshot_hash = ?, head_hash = ?, last_audit_sequence = ?
       WHERE singleton = 1 AND initialized = 0`).bind(cutoff.cutoff, cutoff.count, cutoff.hash, expectedHead, expectedSequence));
        statements.push(env.DB.prepare(`INSERT INTO integrity_write_guard (singleton, expected_head_hash, expected_sequence, final_head_hash, final_sequence)
       VALUES (1, ?, ?, ?, ?)`).bind(expectedHead, expectedSequence, nextHash, finalSequence));
        if (cutoff)
            statements.push(evidenceInsertStatement(env.DB, proofs[0]));
        statements.push(...beforeEvidence);
        if (customEvidenceSteps)
            statements.push(...customEvidenceSteps(proofs));
        else
            statements.push(...proofs.slice(cutoff ? 1 : 0).map((proof) => evidenceInsertStatement(env.DB, proof)));
        statements.push(env.DB.prepare(`UPDATE integrity_state SET head_hash = ?, last_audit_sequence = ?
        WHERE singleton = 1 AND head_hash = ? AND last_audit_sequence = ?`).bind(nextHash, finalSequence, expectedHead, expectedSequence));
        statements.push(env.DB.prepare("DELETE FROM integrity_write_guard WHERE singleton = 1"));
        try {
            const results = await env.DB.batch(statements);
            const stateUpdateIndex = statements.length - 2;
            if ((results[stateUpdateIndex]?.meta.changes ?? 0) !== 1)
                throw new Error("integrity chain compare-and-swap failed");
            return proofs;
        }
        catch (cause) {
            const message = cause instanceof Error ? cause.message.toLowerCase() : "";
            if ((message.includes("integrity chain write conflict") || message.includes("compare-and-swap failed")) && attempt < 3)
                continue;
            throw cause;
        }
    }
    throw new Error("integrity chain remained busy after retries");
}
export async function appendLog(env, request, event) {
    return appendSigned(env, [{ proof: { event: asLogEvidence(request, event), previous_hash: "", event_hash: "", signature: "" } }]);
}
export async function initializeIntegrity(env) {
    const state = await env.DB.prepare("SELECT initialized FROM integrity_state WHERE singleton = 1").first();
    if (state?.initialized === 1)
        return;
    await appendSigned(env, []);
}
export async function appendMetalog(env, request, event) {
    return appendSigned(env, [{ proof: { event: asMetalogEvidence(request, event), previous_hash: "", event_hash: "", signature: "" } }]);
}
export async function appendIntegrityResult(env, request, event) {
    const secret = env.AUDIT_HMAC_KEY;
    if (!secret || secret.length < 32)
        throw new Error("AUDIT_HMAC_KEY must contain at least 32 characters");
    for (let attempt = 0; attempt < 4; attempt += 1) {
        const state = await env.DB.prepare(`SELECT s.initialized, s.head_hash, s.last_audit_sequence,
      (SELECT COALESCE(MAX(sequence), 0) FROM audit_order) AS observed_max,
      ${observedHeadSql} AS observed_head FROM integrity_state s WHERE singleton = 1`)
            .first();
        if (!state || state.initialized !== 1) {
            await initializeIntegrity(env);
            continue;
        }
        if (state.observed_max === state.last_audit_sequence && state.observed_head === state.head_hash)
            return appendMetalog(env, request, event);
        const degradedEvent = {
            ...event,
            context: { ...event.context, out_of_chain: true, observed_sequence: state.observed_max, trusted_sequence: state.last_audit_sequence },
        };
        const proof = await signEvidence(asMetalogEvidence(request, degradedEvent), state.head_hash, secret);
        try {
            await env.DB.batch([
                env.DB.prepare(`INSERT INTO integrity_write_guard (singleton, expected_head_hash, expected_sequence, final_head_hash, final_sequence, degraded)
           VALUES (1, ?, ?, ?, ?, 1)`).bind(state.head_hash, state.last_audit_sequence, proof.event_hash, state.last_audit_sequence + 1),
                evidenceInsertStatement(env.DB, proof),
                env.DB.prepare("DELETE FROM integrity_write_guard WHERE singleton = 1"),
            ]);
            return [proof];
        }
        catch (cause) {
            const message = cause instanceof Error ? cause.message.toLowerCase() : "";
            if (message.includes("integrity chain write conflict") && attempt < 3)
                continue;
            throw cause;
        }
    }
    throw new Error("integrity result could not be appended");
}
export async function appendMany(env, request, logs, metalogs, beforeEvidence = []) {
    const entries = [
        ...logs.map((event) => ({ proof: { event: asLogEvidence(request, event), previous_hash: "", event_hash: "", signature: "" } })),
        ...metalogs.map((event) => ({ proof: { event: asMetalogEvidence(request, event), previous_hash: "", event_hash: "", signature: "" } })),
    ];
    return appendSigned(env, entries, beforeEvidence);
}
