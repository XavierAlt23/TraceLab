import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { canReadRecord, canWriteRecord, normalizeUserName, safeSecretEqual } from "../src/worker/policy.ts";

describe("permisos de registros", () => {
  it("limita USER a sus registros", () => {
    assert.equal(canReadRecord("USER", "u1", "u1"), true);
    assert.equal(canReadRecord("USER", "u2", "u1"), false);
    assert.equal(canWriteRecord("USER", "u1", "u1"), true);
    assert.equal(canWriteRecord("USER", "u2", "u1"), false);
  });

  it("permite a ADMIN consultar y modificar y mantiene AUDITOR en solo lectura", () => {
    assert.equal(canReadRecord("ADMIN", "u2", null), true);
    assert.equal(canWriteRecord("ADMIN", "u2", null), true);
    assert.equal(canReadRecord("AUDITOR", "u2", null), true);
    assert.equal(canWriteRecord("AUDITOR", "u2", null), false);
  });

  it("permite a USER modificar registros compartidos, con validación backend", () => {
    assert.equal(canWriteRecord("USER", "owner-demo", "student-1", true), true);
    assert.equal(canWriteRecord("USER", "other-user", "student-1", false), false);
    assert.equal(canWriteRecord("AUDITOR", "owner-demo", "auditor-1", true), false);
  });
});

describe("identidad educativa", () => {
  it("normaliza espacios, compatibilidad Unicode y mayúsculas", () => {
    assert.deepEqual(normalizeUserName("  Ａna   Pérez "), { displayName: "Ana Pérez", normalizedName: "ana pérez" });
  });

  it("rechaza nombres demasiado cortos, demasiado largos y controles", () => {
    assert.equal(normalizeUserName("a"), null);
    assert.equal(normalizeUserName("x".repeat(41)), null);
    assert.equal(normalizeUserName("ab\ncd"), null);
  });

  it("compara códigos especiales sin aceptar secreto vacío", () => {
    assert.equal(safeSecretEqual("same-code", "same-code"), true);
    assert.equal(safeSecretEqual("different", "same-code"), false);
    assert.equal(safeSecretEqual("", ""), false);
  });
});
