import assert from "node:assert/strict";
import { createHmac, createHash } from "node:crypto";
import { test } from "node:test";
import { canonicalJson, continuityErrors, sha256Hex, signEvidence, verifyEvidence } from "../src/worker/integrity.ts";

const evidence = {
  schemaVersion: 1, source: "LOG", event_id: "event-1", actor_id: "user-1", actor_name: "Estudiante",
  actor_role: "USER", session_id: "session-id", occurred_at: "2026-10-12T00:00:00.000Z", ip_address: null,
  user_agent: "test", action: "record.update", record_id: "record-1", field_name: "title",
  old_value: "A", new_value: "B", resource: null, result: "SUCCESS", context_json: null,
};

test("SHA-256 produce el vector conocido", async () => {
  assert.equal(await sha256Hex("abc"), createHash("sha256").update("abc").digest("hex"));
});

test("serialización canónica ordena claves recursivamente y conserva arrays", () => {
  assert.equal(canonicalJson({ z: 1, a: { y: 2, b: [3, 1] } }), '{"a":{"b":[3,1],"y":2},"z":1}');
});

test("HMAC-SHA-256 se valida con la envoltura canónica", async () => {
  const secret = "local-test-key-with-at-least-32-characters";
  const proof = await signEvidence(evidence, "0".repeat(64), secret);
  const envelope = canonicalJson({ schemaVersion: 1, previous_hash: proof.previous_hash, event_hash: proof.event_hash });
  const expected = createHmac("sha256", secret).update(envelope).digest("base64");
  assert.equal(proof.signature, expected);
  assert.deepEqual(await verifyEvidence(proof, secret), { contentValid: true, signatureValid: true });
});

test("el verificador detecta contenido, firma y enlace alterados", async () => {
  const secret = "local-test-key-with-at-least-32-characters";
  const proof = await signEvidence(evidence, "0".repeat(64), secret);
  const altered = await verifyEvidence({ ...proof, event: { ...evidence, new_value: "C" } }, secret);
  assert.deepEqual(altered, { contentValid: false, signatureValid: true });
  const badSignature = await verifyEvidence({ ...proof, signature: "AAAA" }, secret);
  assert.equal(badSignature.signatureValid, false);
  const badLink = await verifyEvidence({ ...proof, previous_hash: "1".repeat(64) }, secret);
  assert.equal(badLink.signatureValid, false);
});

test("la continuidad detecta saltos de secuencia y enlaces", () => {
  const rows = [
    { sequence: 8, previous_hash: "0".repeat(64), event_hash: "a".repeat(64) },
    { sequence: 10, previous_hash: "b".repeat(64), event_hash: "c".repeat(64) },
  ];
  assert.deepEqual(continuityErrors(rows, 8), [
    { code: "AUDIT_SEQUENCE_GAP", sequence: 10 },
    { code: "HASH_LINK_MISMATCH", sequence: 10 },
  ]);
});

test("clave HMAC incorrecta y firma malformada fallan cerradas", async () => {
  const proof = await signEvidence(evidence, "0".repeat(64), "test-only-key-not-used-in-production-12345");
  assert.deepEqual(await verifyEvidence(proof, "another-test-key-with-at-least-32-bytes"), { contentValid: true, signatureValid: false });
  assert.equal((await verifyEvidence({ ...proof, signature: "not base64!!!" }, "test-key")).signatureValid, false);
});
