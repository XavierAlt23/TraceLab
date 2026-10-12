import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { resolve } from "node:path";
import { promisify } from "node:util";

// Solo bootstrap de una base local recién migrada, sin sesiones ni eventos de usuarios.
const root = process.cwd();
const wrangler = resolve(root, "node_modules/wrangler/bin/wrangler.js");
if (!existsSync(resolve(root, ".dev.vars"))) writeFileSync(resolve(root, ".dev.vars"),
  ["ADMIN_ACCESS_CODE", "AUDITOR_ACCESS_CODE", "AUDIT_HMAC_KEY"].map((key) => `${key}=${randomBytes(48).toString("base64")}`).join("\n"), { mode: 0o600 });

const invoke = (args) => promisify(execFile)(process.execPath, [wrangler, ...args], { cwd: root, windowsHide: true, maxBuffer: 8 * 1024 * 1024,
  env: { ...process.env, WRANGLER_SEND_METRICS: "false" } });
const { stdout } = await invoke(["d1", "execute", "tracelab-db", "--local", "--command", "SELECT (SELECT initialized FROM integrity_state) AS initialized, (SELECT COUNT(*) FROM sessions) AS sessions, (SELECT COUNT(*) FROM users) AS users, (SELECT COUNT(*) FROM logs WHERE actor_role <> 'SYSTEM' OR user_agent IS NOT 'migration:0003') AS real_events, (SELECT COUNT(*) FROM metalogs) AS metalogs;", "--json"]);
const state = JSON.parse(stdout)[0].results[0];
if (state.initialized !== 0 || state.sessions !== 0 || state.users !== 1 || state.real_events !== 0 || state.metalogs !== 0) throw new Error("Inicialización rechazada: la base ya contiene actividad. No se borró ninguna evidencia.");
const trigger = (file, name) => {
  const match = readFileSync(resolve(root, file), "utf8").match(new RegExp(`CREATE TRIGGER ${name}\\b[\\s\\S]*?^END;`, "mu"));
  if (!match) throw new Error(`No encontramos el trigger ${name}`); return match[0];
};
const sql = `DROP TRIGGER records_require_audit_on_update;
DROP TRIGGER records_log_update;
UPDATE records SET title = 'Registro compartido ' || CAST(substr(id, -2) AS INTEGER), content = '', revision = 1;
UPDATE users SET display_name = 'Registros compartidos', normalized_name = 'tracelab-sistema' WHERE id = '00000000-0000-4000-8000-000000000001';
${trigger("migrations/0002_tracing_logs.sql", "records_require_audit_on_update")}
${trigger("migrations/0006_integrity_chain.sql", "records_log_update")}
DROP TRIGGER logs_are_append_only_delete;
DROP TRIGGER audit_order_are_append_only_delete;
DELETE FROM logs;
DELETE FROM audit_order;
DELETE FROM sqlite_sequence WHERE name IN ('logs', 'metalogs', 'audit_order');
${trigger("migrations/0002_tracing_logs.sql", "logs_are_append_only_delete")}
${trigger("migrations/0005_audit_order.sql", "audit_order_are_append_only_delete")}`;
mkdirSync(resolve(root, ".wrangler"), { recursive: true });
const file = resolve(root, ".wrangler/demo-initialization.sql");
writeFileSync(file, sql);
await invoke(["d1", "execute", "tracelab-db", "--local", "--file", file, "--json"]);
console.log("PASS: demo local inicializada; diez espacios compartidos vacíos, cero sesiones, logs y metalogs. Secretos locales configurados sin imprimir valores.");
