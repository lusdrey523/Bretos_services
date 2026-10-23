#!/usr/bin/env node
// Dependency-free triage gate. This is not a complete SAST or penetration test.
import fs from "node:fs";
import path from "node:path";

const findings = [];
const checks = [];
function record(id, status, severity, message, file = null) {
  const item = { id, status, severity, message, file };
  checks.push(item);
  if (status === "FAIL") findings.push(item);
}
function read(rel) {
  const full = path.join(process.cwd(), rel);
  return fs.existsSync(full) ? fs.readFileSync(full, "utf8") : null;
}
function required(rel) {
  const data = read(rel);
  record("required:" + rel, data === null ? "FAIL" : "PASS", "critical",
    data === null ? "Required file missing: " + rel : "Required file exists.", rel);
  return data;
}
function forbid(id, rel, data, regex, severity, failure, success) {
  const bad = regex.test(data);
  record(id, bad ? "FAIL" : "PASS", severity, bad ? failure : success, rel);
}
const config = required("wrangler.toml");
const source = required("src/index.js");
const skill = required(".claude/skills/bretos-security-gate/SKILL.md");

if (config !== null) {
  forbid("config.inline-secret", "wrangler.toml", config,
    /(?:ADMIN_PASSWORD|API_KEY|SECRET|TOKEN)\s*=\s*["'][^"']+["']/i,
    "critical", "Possible inline secret in Wrangler configuration.", "No obvious inline secret assignment found.");
  const binding = /binding\s*=\s*["']DEVICES["']/.test(config);
  record("config.devices-binding", binding ? "PASS" : "FAIL", "high",
    binding ? "DEVICES KV binding declared." : "Expected DEVICES binding missing.", "wrangler.toml");
}
if (source !== null) {
  forbid("auth.static-cookie", "src/index.js", source,
    /cookie\.includes\(\s*["']breto_admin=1["']\s*\)/,
    "critical", "Admin authorization trusts a forgeable static cookie.", "No known static-cookie authorization pattern found.");
  forbid("session.constant-cookie", "src/index.js", source,
    /breto_admin=1;\s*Path=/,
    "critical", "Login issues a constant admin cookie, not a server-validated session.", "No known constant admin-cookie pattern found.");
  forbid("redirect.unvalidated-destination", "src/index.js", source,
    /Response\.redirect\(\s*data\.reviewUrl\s*,\s*302\s*\)/,
    "critical", "Stored reviewUrl is redirected without visible HTTPS host allowlisting.", "No direct stored-reviewUrl redirect pattern found.");
  forbid("html.unescaped-business-name", "src/index.js", source,
    /\$\{d\.businessName\}/,
    "high", "businessName is interpolated into HTML without visible contextual escaping.", "No direct businessName interpolation pattern found.");
  forbid("html.unescaped-stored-values", "src/index.js", source,
    /\$\{data\.businessName\}|\$\{data\.reviewUrl\}/,
    "high", "Stored form values are interpolated into HTML without visible contextual escaping.", "No direct stored-value interpolation pattern found.");
  forbid("csrf.form-posts", "src/index.js", source,
    /request\.method\s*===\s*["']POST["'][\s\S]*?formData\(\)/,
    "critical", "State-changing browser POST routes require CSRF protection review and tests.", "No form POST pattern requiring CSRF review found.");
  forbid("headers.csp", "src/index.js", source,
    /Content-Security-Policy/,
    "medium", "No CSP reference found; define and verify an appropriate policy.", "CSP reference exists; effective headers still require runtime verification.");
  forbid("request.body-limits", "src/index.js", source,
    /content-length|MAX_BODY|request\.body\.getReader/i,
    "medium", "No request body-size guard found.", "Request-size guard reference exists; behavior still requires tests.");
  forbid("logs.sensitive-data", "src/index.js", source,
    /console\.(?:log|error)\([^\n]*(?:password|token|cookie|reviewUrl|businessName)/i,
    "high", "Potential sensitive-field logging; inspect and redact.", "No obvious sensitive-field logging pattern found.");
}
if (skill !== null) {
  const failClosed = /BLOCKED/.test(skill) && /missing critical evidence/i.test(skill);
  record("skill.fail-closed-policy", failClosed ? "PASS" : "FAIL", "high",
    failClosed ? "Skill documents fail-closed policy." : "Skill must explicitly fail closed on missing critical evidence.",
    ".claude/skills/bretos-security-gate/SKILL.md");
}
if (!process.env.SECURITY_GATE_BASE_URL) {
  record("runtime.evidence", "NOT_TESTED", "critical",
    "No runtime URL supplied. Post-deployment checks have not run; this is not deployment approval.");
}
const blocked = findings.length > 0 || checks.some(c => c.status === "NOT_TESTED" && c.severity === "critical");
const report = {
  schema_version: "1.0",
  gate: "breto-security-gate",
  decision: blocked ? "BLOCKED" : "PASS",
  generated_at: new Date().toISOString(),
  repository: process.env.GITHUB_REPOSITORY || "local",
  commit: process.env.GITHUB_SHA || "unknown",
  summary: {
    checks: checks.length,
    passed: checks.filter(c => c.status === "PASS").length,
    failed: checks.filter(c => c.status === "FAIL").length,
    not_tested: checks.filter(c => c.status === "NOT_TESTED").length
  },
  checks,
  findings
};
fs.mkdirSync("security-reports", { recursive: true });
fs.writeFileSync("security-reports/security-gate.json", JSON.stringify(report, null, 2) + "\n");
console.log(JSON.stringify(report, null, 2));
if (blocked) process.exit(1);
