---
name: bretos-security-gate
description: Run mandatory security checks before changing, reviewing, or deploying Breto's Services.
---

# Breto's Security Gate

Use this skill before code changes, PR review, deployment, or incident response. Inspect the latest repository and deployment evidence; do not reuse old results.

Fail closed: a failed required check, critical/high finding, scanner error, or missing critical evidence means BLOCKED. A test not run is not a pass. Never weaken a check just to get a green result.

Review authentication/session integrity, authorization, CSRF, contextual HTML escaping, redirect destination allowlists, request limits, security headers, safe logs, secrets, dependencies, GitHub Actions permissions, Wrangler bindings, data minimization/retention, runtime configuration, and rollback readiness.

Never expose secrets, session tokens, customer data, or raw KV contents in logs or reports. Do not run destructive production tests or change Cloudflare DNS/settings/secrets/KV/deployment without explicit authorization and a verified target. Do not guess the production hostname.

Before merge, run the repository gate and relevant tests on the exact commit. Before deployment, verify required GitHub checks, branch/ruleset settings, Cloudflare target/configuration, and all critical/high findings. If access or evidence is missing, block deployment. After deployment, run non-destructive checks against the verified HTTPS URL and record the deployed version.

Decisions: PASS only when all applicable mandatory checks ran and passed; BLOCKED for failures or missing critical evidence; REQUIRES_REVIEW for human decisions (not deployment approval); NOT_APPLICABLE only with written evidence.

Report the decision and commit SHA, inspected scope, tests and exit statuses, findings with file evidence, untested areas, remediation, and runtime evidence. Never claim a site is completely secure.

References: https://asvs.owasp.org/ ; https://docs.github.com/en/actions/reference/security/secure-use ; https://developers.cloudflare.com/workers/best-practices/workers-best-practices/
