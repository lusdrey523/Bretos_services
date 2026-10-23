# Breto's Security Gate — Deployment Criteria

## Decision policy
Fail closed. A missing required check, missing critical evidence, failed check, scanner error, or unresolved critical/high vulnerability means BLOCKED. Human review is not a pass.

## Required GitHub status checks
After the workflow has run, configure these exact checks as required on the default branch:
- security-gate / static
- security-gate / runtime-evidence

If GitHub cannot enforce required checks, record the limitation. Do not claim that the deployment barrier is enforced.

## Runtime evidence
Set repository variable SECURITY_GATE_BASE_URL to the verified HTTPS deployment URL. Do not guess it. If absent, runtime evidence fails.

The smoke test is non-destructive and limited. It does not prove absence of vulnerabilities, inspect Cloudflare dashboard settings, authenticate to admin, or test state-changing admin operations.

## Cloudflare deployment boundary
No automated Cloudflare deploy job is added: the repository does not establish the production hostname, environment mapping, deployment credentials, or approval policy. Do not deploy automatically until these are verified.

When deployment is later configured:
1. Use a protected GitHub production environment.
2. Use short-lived/OIDC credentials if supported; otherwise use a scoped protected token.
3. Make deployment depend on every required security job.
4. Deploy only the exact reviewed commit.
5. Run post-deployment smoke checks and record the deployed version.
6. Maintain rollback instructions and a known-good version reference.

## Manual setup checklist
- [ ] Set SECURITY_GATE_BASE_URL to the verified HTTPS hostname.
- [ ] Run the workflow and inspect current findings.
- [ ] Remediate all critical/high source findings.
- [ ] Verify checks pass on the intended revision and target.
- [ ] Require both named checks in branch protection/rulesets.
- [ ] Restrict direct pushes and bypass permissions.
- [ ] Verify Cloudflare settings and document evidence.
- [ ] Add protected deployment only after the architecture is confirmed.

A successful CI run proves only the checks that actually ran, not that the site is secure.
