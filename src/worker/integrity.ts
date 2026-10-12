export type EvidenceSource = "LOG" | "METALOG";

export interface CanonicalEvidence {
  schemaVersion: number;
  source: EvidenceSource;
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
  resource: string | null;
  result: string;
  context_json: string | null;
}

export interface SignedEvidence {
  event: CanonicalEvidence;
  previous_hash: string;
  event_hash: string;
  signature: string;
}

const encoder = new TextEncoder();

function normalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(normalize);
  if (value !== null && typeof value === "object") {
    const object = value as Record<string, unknown>;
    return Object.fromEntries(Object.keys(object).sort().map((key) => [key, normalize(object[key])]));
  }
  return value;
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(normalize(value));
}

export function evidenceContent(event: CanonicalEvidence): string {
  return canonicalJson(event);
}

export async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function encodeBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function decodeBase64(value: string): Uint8Array {
  return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
}

async function hmacKey(secret: string, usage: KeyUsage[]): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, usage);
}

export async function signEvidence(event: CanonicalEvidence, previousHash: string, secret: string): Promise<SignedEvidence> {
  const eventHash = await sha256Hex(evidenceContent(event));
  const key = await hmacKey(secret, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(canonicalJson({ schemaVersion: 1, previous_hash: previousHash, event_hash: eventHash })));
  return { event, previous_hash: previousHash, event_hash: eventHash, signature: encodeBase64(new Uint8Array(signature)) };
}

export async function verifyEvidence(proof: SignedEvidence, secret: string): Promise<{ contentValid: boolean; signatureValid: boolean }> {
  return (await evidenceVerifier(secret))(proof);
}

// Importar una vez por verificación; clave no exportable, limitada a esta petición.
export async function evidenceVerifier(secret: string): Promise<(proof: SignedEvidence) => Promise<{ contentValid: boolean; signatureValid: boolean }>> {
  const key = await hmacKey(secret, ["verify"]);
  return async (proof) => {
  let contentValid = false;
  let signatureValid = false;
  try { contentValid = await sha256Hex(evidenceContent(proof.event)) === proof.event_hash; } catch { /* invalid content */ }
  try {
    signatureValid = await crypto.subtle.verify(
      "HMAC", key, new Uint8Array(decodeBase64(proof.signature)),
      encoder.encode(canonicalJson({ schemaVersion: 1, previous_hash: proof.previous_hash, event_hash: proof.event_hash })),
    );
  } catch { /* missing or malformed proof */ }
  return { contentValid, signatureValid };
  };
}

export async function signedCheckpoint(secret: string, cutoff: number, count: number, snapshotHash: string, at: string): Promise<SignedEvidence> {
  return signEvidence({
    schemaVersion: 1, source: "METALOG", event_id: crypto.randomUUID(), actor_id: null, actor_name: "Sistema",
    actor_role: "SYSTEM", session_id: null, occurred_at: at, ip_address: null, user_agent: null,
    action: "INTEGRITY_CHAIN_STARTED", record_id: null, field_name: null, old_value: null, new_value: null,
    resource: "/api/audit/integrity", result: "SUCCESS",
    context_json: canonicalJson({ historical_cutoff: cutoff, historical_count: count, historical_snapshot_sha256: snapshotHash }),
  }, "0".repeat(64), secret);
}

export function rowEvidence(row: Record<string, unknown>, source: EvidenceSource): CanonicalEvidence {
  return {
    schemaVersion: 1, source, event_id: String(row.event_id), actor_id: row.actor_id === null ? null : String(row.actor_id),
    actor_name: String(row.actor_name), actor_role: String(row.actor_role), session_id: row.session_id === null ? null : String(row.session_id),
    occurred_at: String(row.occurred_at), ip_address: row.ip_address === null ? null : String(row.ip_address),
    user_agent: row.user_agent === null ? null : String(row.user_agent), action: String(row.action),
    record_id: source === "LOG" && row.record_id !== null ? String(row.record_id) : null,
    field_name: source === "LOG" && row.field_name !== null ? String(row.field_name) : null,
    old_value: source === "LOG" && row.old_value !== null ? String(row.old_value) : null,
    new_value: source === "LOG" && row.new_value !== null ? String(row.new_value) : null,
    resource: source === "METALOG" && row.resource !== null ? String(row.resource) : null,
    result: String(row.result), context_json: row.context_json === null ? null : String(row.context_json),
  };
}

export function parseContext(value: string | null): Record<string, unknown> | null {
  if (value === null) return null;
  try { const parsed: unknown = JSON.parse(value); return parsed !== null && typeof parsed === "object" && !Array.isArray(parsed) ? parsed as Record<string, unknown> : null; } catch { return null; }
}

export function decodeProof(event: CanonicalEvidence, previousHash: string | null, eventHash: string | null, signature: string | null): SignedEvidence | null {
  if (!previousHash || !eventHash || !signature) return null;
  return { event, previous_hash: previousHash, event_hash: eventHash, signature };
}

export function continuityErrors(rows: Array<{ sequence: number; previous_hash: string | null; event_hash: string | null }>, firstSequence: number): Array<{ code: string; sequence: number }> {
  const errors: Array<{ code: string; sequence: number }> = [];
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

