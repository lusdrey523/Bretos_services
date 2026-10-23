#!/usr/bin/env node
// Non-destructive checks only. Never submits credentials or mutates data.
const raw = process.env.SECURITY_GATE_BASE_URL;
if (!raw) {
  console.error("BLOCKED: SECURITY_GATE_BASE_URL is missing.");
  process.exit(2);
}
let base;
try { base = new URL(raw); } catch {
  console.error("BLOCKED: SECURITY_GATE_BASE_URL is not a valid URL.");
  process.exit(2);
}
if (base.protocol !== "https:" || ["localhost", "127.0.0.1"].includes(base.hostname) ||
    base.username || base.password || base.search || base.hash) {
  console.error("BLOCKED: target must be a non-local HTTPS URL without credentials, query, or fragment.");
  process.exit(2);
}
const results = [];
async function check(name, pathname, validate) {
  const url = new URL(pathname, base);
  try {
    const response = await fetch(url, {
      method: "GET",
      redirect: "manual",
      signal: AbortSignal.timeout(8000),
      headers: { "User-Agent": "Bretos-Security-Gate/1.0" }
    });
    const headers = Object.fromEntries(response.headers.entries());
    const body = (await response.text()).slice(0, 12000);
    results.push({ name, url: url.origin + url.pathname, ...validate({ response, headers, body }) });
  } catch (error) {
    results.push({ name, url: url.origin + url.pathname, status: "FAIL", reason: error?.name || "network-error" });
  }
}
await check("root-responds", "/", ({ response }) =>
  response.status >= 200 && response.status < 400
    ? { status: "PASS", http_status: response.status }
    : { status: "FAIL", http_status: response.status, reason: "unexpected root status" });
await check("admin-access-control-signal", "/admin", ({ response, headers, body }) => {
  const contentType = headers["content-type"] || "";
  const location = headers.location || "";
  const loginSignal = body.toLowerCase().includes("panel de administración") ||
    body.toLowerCase().includes("contraseña");
  const protectedSignal = response.status === 401 || response.status === 403 ||
    (response.status === 200 && contentType.includes("text/html") && loginSignal) ||
    (response.status === 302 && location === "/admin");
  return protectedSignal
    ? { status: "PASS", http_status: response.status, signal: "login-or-access-control-response" }
    : { status: "FAIL", http_status: response.status, reason: "no expected admin access-control signal" };
});
const failed = results.some(r => r.status !== "PASS");
const report = {
  schema_version: "1.0",
  gate: "breto-security-gate-runtime",
  decision: failed ? "BLOCKED" : "PASS",
  generated_at: new Date().toISOString(),
  target_origin: base.origin,
  checks: results
};
console.log(JSON.stringify(report, null, 2));
if (failed) process.exit(1);
