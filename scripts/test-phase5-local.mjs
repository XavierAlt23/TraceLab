import { spawn } from "node:child_process";
import { randomBytes, randomUUID } from "node:crypto";
import { mkdirSync, writeFileSync, unlinkSync, readdirSync, copyFileSync } from "node:fs";
import { resolve, join } from "node:path";

const root = process.cwd();
const phase6 = process.argv.includes("--phase6");
const volume = process.argv.includes("--volume");
const serve = process.argv.includes("--serve");
const cryptoTests = process.argv.includes("--crypto");
const runDirectory = resolve(root, ".wrangler", "phase5-tests", randomUUID());
mkdirSync(runDirectory, { recursive: true });
const configPath = join(runDirectory, "wrangler.json");
const secretsPath = join(runDirectory, ".dev.vars");
const statePath = join(runDirectory, "state");
const secretValues = [randomBytes(36).toString("base64"), randomBytes(36).toString("base64"), randomBytes(48).toString("base64")];
const redact = (value) => secretValues.reduce((text, secret) => text.replaceAll(secret, "[REDACTED]"), value);
const wrangler = resolve(root, "node_modules", "wrangler", "bin", "wrangler.js");
let migrations = resolve(root, "migrations");
if (volume || cryptoTests) {
  // Fixture nueva sin datos históricos: permite comprobar INTEGRITY_OK sin reescribir evidencias.
  migrations = join(runDirectory, "migrations"); mkdirSync(migrations);
  for (const file of readdirSync(resolve(root, "migrations"))) if (file.endsWith(".sql") && !file.startsWith("0003_")) copyFileSync(join(root, "migrations", file), join(migrations, file));
}
writeFileSync(configPath, JSON.stringify({
  name: "tracelab-phase5-tests", main: resolve(root, "src/worker/index.ts"), compatibility_date: "2026-10-12",
  assets: { directory: resolve(root, "dist/client"), binding: "ASSETS", not_found_handling: "single-page-application", run_worker_first: true },
  d1_databases: [{ binding: "DB", database_name: "tracelab-phase5-tests", database_id: randomUUID(), migrations_dir: migrations }],
}, null, 2));
writeFileSync(secretsPath, ["ADMIN_ACCESS_CODE", "AUDITOR_ACCESS_CODE", "AUDIT_HMAC_KEY"].map((key, index) => `${key}=${secretValues[index]}`).join("\n"), { mode: 0o600 });

function run(args, environment = {}) {
  return new Promise((resolveRun, reject) => {
    const child = spawn(process.execPath, args, { cwd: root, env: { ...process.env, WRANGLER_SEND_METRICS: "false", ...environment }, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
    let output = "";
    child.stdout.on("data", (chunk) => { output += chunk; });
    child.stderr.on("data", (chunk) => { output += chunk; });
    child.on("error", reject);
    child.on("exit", (code) => code === 0 ? resolveRun(redact(output)) : reject(new Error(redact(output))));
  });
}

let server;
let serverOutput = "";
try {
  await run([wrangler, "d1", "migrations", "apply", "tracelab-phase5-tests", "--local", "--config", configPath, "--persist-to", statePath]);
  console.log("PASS: migraciones en D1 aislado.");
  server = spawn(process.execPath, [wrangler, "dev", "--local", "--config", configPath, "--persist-to", statePath, "--ip", "127.0.0.1", "--port", "8795"], { cwd: root, env: { ...process.env, WRANGLER_SEND_METRICS: "false" }, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
  server.stdout.on("data", (chunk) => { serverOutput += chunk; });
  server.stderr.on("data", (chunk) => { serverOutput += chunk; });
  server.on("error", (cause) => { serverOutput += cause.message; });
  let ready = false;
  for (let attempt = 0; attempt < 60; attempt += 1) {
    if (server.exitCode !== null) throw new Error(redact(serverOutput));
    try {
      const response = await fetch("http://127.0.0.1:8795/api/session", { signal: AbortSignal.timeout(1000) });
      if (response.status === 401 && serverOutput.includes("Ready on http://127.0.0.1:8795")) { ready = true; break; }
    } catch { /* el Worker todavía inicia */ }
    await new Promise((resolveWait) => setTimeout(resolveWait, 500));
  }
  if (!ready) throw new Error(`Worker no disponible. ${redact(serverOutput)}`);
  const testEnvironment = {
    TRACELAB_TEST_URL: "http://127.0.0.1:8795", TRACELAB_TEST_SECRETS_FILE: secretsPath,
    TRACELAB_TEST_WRANGLER_CONFIG: configPath, TRACELAB_TEST_D1_STATE: statePath, TRACELAB_ISOLATED_TEST: "1",
  };
  if (serve) {
    console.log(`D1 aislada lista: http://127.0.0.1:8795\nSecretos de desarrollo: ${secretsPath}\nConfiguración: ${configPath}`);
    await new Promise((resolveStop) => { process.once("SIGINT", resolveStop); process.once("SIGTERM", resolveStop); });
  } else if (volume) {
    console.log((await run(["--experimental-strip-types", "--test", "--test-isolation=none", "tests/volume.test.mjs"], testEnvironment)).trim());
  } else if (cryptoTests) {
    console.log((await run(["--experimental-strip-types", "--test", "--test-isolation=none", "tests/crypto-d1.test.mjs"], testEnvironment)).trim());
  } else {
  const output = await run(["--experimental-strip-types", "--test", "--test-isolation=none", "tests/integration.test.mjs"], {
    TRACELAB_TEST_URL: "http://127.0.0.1:8795", TRACELAB_TEST_SECRETS_FILE: secretsPath,
    TRACELAB_ISOLATED_TEST: "1",
  });
  console.log(output.trim());
  if (phase6) console.log((await run(["--experimental-strip-types", "--test", "--test-isolation=none", "tests/phase6.test.mjs"], testEnvironment)).trim());
  const degradedOutput = await run(["--experimental-strip-types", "--test", "--test-isolation=none", "tests/degraded-integrity.test.mjs"], {
    TRACELAB_TEST_URL: "http://127.0.0.1:8795", TRACELAB_TEST_SECRETS_FILE: secretsPath,
    TRACELAB_TEST_WRANGLER_CONFIG: configPath, TRACELAB_TEST_D1_STATE: statePath,
  });
  console.log(degradedOutput.trim());
  }
} catch (cause) {
  console.error(redact(cause instanceof Error ? cause.message : String(cause)));
  process.exitCode = 1;
} finally {
  if (server?.pid && server.exitCode === null) {
    if (process.platform === "win32") await new Promise((resolveStop) => {
      const stop = spawn("taskkill", ["/PID", String(server.pid), "/T", "/F"], { windowsHide: true, stdio: "ignore" });
      stop.on("error", resolveStop); stop.on("exit", resolveStop);
    });
    else server.kill("SIGTERM");
  }
  unlinkSync(secretsPath);
}
