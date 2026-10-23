# Breto's Services — Security Architecture Baseline

**Status:** Partial repository baseline. Production infrastructure not independently verified.  
**Inspection date:** 2026-10-22  
**Repository:** lusdrey523/Bretos_services  
**Default branch inspected:** main

## Verified from repository source

| Item | Evidence | Observed state |
|---|---|---|
| Repository | GitHub metadata | Public |
| Runtime | wrangler.toml and src/index.js | Cloudflare Worker |
| Worker name | wrangler.toml | redirects |
| Entry point | wrangler.toml | src/index.js |
| Storage binding | wrangler.toml | KV binding DEVICES |
| Admin UI | src/index.js | /admin routes |
| Redirect behavior | src/index.js | Stored reviewUrl is used as redirect target |
| Existing tests/workflows | recursive main tree | None visible before this change |

## Not verified

The GitHub integration could not read branch protection (HTTP 403). The inspected tree did not establish a production hostname. No authorized Cloudflare account connector was available for direct inspection.

Unknown, not presumed secure:
- Production hostname and DNS.
- Active Worker version and environment.
- Effective TLS, WAF, rate limiting, Access, response headers, and origin exposure.
- Worker secret configuration and rotation state.
- Production KV contents, retention, and access.
- GitHub rulesets, branch protection, required checks, and bypass permissions.
- Backup/restore and alerting.

Never add secret values, customer data, device codes, or raw KV contents here.

## Initial source-level high-risk observations

1. Admin authorization checks a static cookie value (breto_admin=1), which is forgeable by a client.
2. Login issues that constant cookie rather than a server-validated session.
3. Stored reviewUrl is passed to Response.redirect without an explicit HTTPS host allowlist.
4. Business names and stored form values are interpolated into HTML templates without visible contextual escaping.
5. State-changing form POST routes have no visible CSRF token validation.
6. Source has no visible Content Security Policy or request body-size guard.

These are source-level observations, not evidence of a production exploit. Remediate and test them before release.
