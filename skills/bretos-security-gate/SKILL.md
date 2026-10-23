---
name: bretos-security-gate
description: Mandatory security and privacy verification before code changes, reviews, and deployment of Breto's Services.
---

# Breto's Security Gate

Use this procedure before changing code, reviewing a pull request, deploying the Worker, or responding to an incident.

## Fail-closed policy
A failed mandatory check, unresolved critical/high finding, missing critical evidence, scanner error, or unavailable required test means BLOCKED. A test not run is not a pass. Human review is not deployment approval. Never weaken a check merely to obtain a green result.

## Required workflow
1. Inspect the current commit, diff, repository tree, Worker code, Wrangler configuration, workflows, and deployment settings. Do not reuse old audit results as current evidence.
2. Map routes, inputs, storage, bindings, external destinations, authentication, logs, and personal-data flows.
3. Check session integrity, authorization, CSRF, contextual HTML escaping, URL allowlists, request limits, security headers, safe logs, secret handling, dependency risk, GitHub Actions permissions, Wrangler bindings, privacy retention, and rollback readiness.
4. Run all applicable automated tests against the exact revision. Record commands, exit statuses, findings, and untested areas.
5. Block release for critical/high findings or missing critical evidence. Do not expose secrets, session tokens, customer records, or raw KV values in reports.
6. Never run destructive production tests or change DNS, Cloudflare settings, secrets, KV data, or production state without explicit authorization and a verified target.
7. Verify GitHub rulesets and Cloudflare deployment details using authorized current evidence. If unavailable, mark them unverified and block deployment. Do not guess a hostname or claim protection is enforced when it is not.
8. After deployment, run only non-destructive smoke checks against the verified HTTPS URL and record the deployed version and results.

## Repository facts currently established
The repository uses a Cloudflare Worker configured in wrangler.toml, with src/index.js as entrypoint, Worker name redirects, KV binding DEVICES, and admin routes under /admin. Production hostname, active deployment, Cloudflare dashboard settings, secrets, KV contents, and branch protection are not verified by repository source alone.

## Decision values
- PASS: all applicable mandatory checks ran and passed with evidence.
- BLOCKED: a required check failed, critical/high issue remains, or critical evidence is missing.
- REQUIRES_REVIEW: a human decision is required; not a pass.
- NOT_APPLICABLE: written evidence-based justification required.

## Required report
Include decision and commit SHA; scope and commands run; severity-ranked findings with file evidence; pass/fail/not-tested states; unverified risks; remediation owner; and deployment/post-deployment evidence or an explicit statement that deployment was not verified.

## References
- OWASP ASVS 5.0.0: https://asvs.owasp.org/
- GitHub Actions secure use: https://docs.github.com/en/actions/reference/security/secure-use
- Cloudflare Workers best practices: https://developers.cloudflare.com/workers/best-practices/workers-best-practices/
