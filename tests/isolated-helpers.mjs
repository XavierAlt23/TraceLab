import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve, dirname, join, sep } from "node:path";
import { promisify } from "node:util";
import { randomUUID } from "node:crypto";

assert.equal(process.env.TRACELAB_ISOLATED_TEST, "1", "requiere runner aislado");
export const base = process.env.TRACELAB_TEST_URL;
export const secrets = Object.fromEntries(readFileSync(process.env.TRACELAB_TEST_SECRETS_FILE, "utf8").split(/\r?\n/u).filter(Boolean).map((line) => {
  const index = line.indexOf("="); return [line.slice(0, index), line.slice(index + 1)];
}));
const config = process.env.TRACELAB_TEST_WRANGLER_CONFIG;
const state = process.env.TRACELAB_TEST_D1_STATE;
const allowed = resolve(".wrangler/phase5-tests") + sep;
assert.ok(resolve(config).startsWith(allowed) && resolve(state).startsWith(allowed), "nunca usar la D1 principal");
export async function sql(command) {
  const file = join(dirname(config), `fixture-${randomUUID()}.sql`);
  writeFileSync(file, command);
  const { stdout } = await promisify(execFile)(process.execPath, [resolve("node_modules/wrangler/bin/wrangler.js"), "d1", "execute", "tracelab-phase5-tests", "--local", "--config", config, "--persist-to", state, "--file", file, "--json"], {
    windowsHide: true, maxBuffer: 16 * 1024 * 1024, env: { ...process.env, WRANGLER_SEND_METRICS: "false" },
  });
  return JSON.parse(stdout);
}
export async function call(path, { method = "GET", body, cookie, headers = {}, raw } = {}) {
  const response = await fetch(`${base}${path}`, { method, headers: { "cf-connecting-ip": "198.51.100.6", ...(body !== undefined || raw !== undefined ? { "content-type": "application/json" } : {}), ...(cookie ? { cookie } : {}), ...headers }, body: raw ?? (body === undefined ? undefined : JSON.stringify(body)), signal: AbortSignal.timeout(120000) });
  const data = await response.json();
  return { status: response.status, data, headers: response.headers, cookie: response.headers.get("set-cookie")?.split(";", 1)[0] };
}
export async function login(role) {
  const response = await call("/api/auth/special", { method: "POST", body: { role, code: secrets[`${role}_ACCESS_CODE`] } });
  assert.equal(response.status, 200); return response.cookie;
}
export const quote = (value) => value === null ? "NULL" : `'${String(value).replaceAll("'", "''")}'`;
