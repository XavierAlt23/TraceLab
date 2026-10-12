import test from "node:test";
import assert from "node:assert/strict";
import { boundedJson, crossSiteMutation, makeSessionCookie, secureResponse } from "../src/worker/security.ts";

test("cookies de producción: __Host, Secure, HttpOnly, SameSite y revocación", () => {
  const request = new Request("https://tracelab.example/api/auth/user");
  const value = makeSessionCookie(request, "test-only", 43200);
  for (const part of ["__Host-tracelab_session=", "Secure;", "HttpOnly;", "SameSite=Lax", "Path=/", "Max-Age=43200"]) assert.ok(value.includes(part));
  assert.ok(!value.includes("Domain="));
  assert.ok(makeSessionCookie(request, "", 0).includes("Max-Age=0"));
  assert.ok(!makeSessionCookie(new Request("http://127.0.0.1/api"), "test", 1).includes("Secure;"));
});

test("CSRF: origen, Fetch Metadata y clientes HTTP sin Origin", () => {
  const make = (headers, method = "POST") => new Request("https://tracelab.example/api", { method, headers });
  assert.equal(crossSiteMutation(make({ origin: "https://evil.example" })), true);
  assert.equal(crossSiteMutation(make({ origin: "null" })), true);
  assert.equal(crossSiteMutation(make({ "sec-fetch-site": "cross-site" })), true);
  assert.equal(crossSiteMutation(make({ origin: "https://tracelab.example" })), false);
  assert.equal(crossSiteMutation(make({})), false);
});

test("JSON: límites reales, tipos, contenido malformado y UTF-8 inválido", async () => {
  const body = (value, headers = {}) => new Request("https://tracelab.example", { method: "POST", headers: { "content-type": "application/json", ...headers }, body: value });
  assert.deepEqual(await boundedJson(body('{"name":"Ana"}')), { name: "Ana" });
  for (const value of ["[]", "null", "true", "{", JSON.stringify({ name: "x".repeat(9000) })]) assert.equal(await boundedJson(body(value)), null);
  assert.equal(await boundedJson(body("{}", { "content-type": "text/plain" })), null);
  assert.equal(await boundedJson(body("{}", { "content-length": "9000" })), null);
  assert.equal(await boundedJson(body(new Uint8Array([255, 255]))), null);
});

test("cabeceras: CSP estricta en producción y sin caché de información sensible", () => {
  const response = secureResponse(new Request("https://tracelab.example"), new Response("ok", { headers: { "cache-control": "no-store" } }));
  assert.ok(response.headers.get("content-security-policy").includes("frame-ancestors 'none'"));
  assert.ok(!response.headers.get("content-security-policy").includes("unsafe-inline"));
  assert.equal(response.headers.get("x-frame-options"), "DENY");
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.ok(response.headers.has("strict-transport-security"));
});
