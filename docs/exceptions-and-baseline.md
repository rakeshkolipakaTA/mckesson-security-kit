# Baselines and exceptions

Two tools for two different situations.

| | **Baseline** | **Exception** |
|---|---|---|
| For | "We inherited 200 old findings; do not block every PR because of them" | "This one finding is a false positive / cannot be fixed yet" |
| Scope | All findings that exist today | One finding (or one rule in one file) |
| Needs approval | Agree with your lead | **Yes**: a named approver |
| Expires | No, but shrink it over time | **Yes**, mandatory expiry date |
| File | `.security/baseline.json` | `.security/exceptions.json` |

## Baseline (legacy apps)
```bash
.security/warden baseline      # runs a scan and records every current finding as "existing"
git add .security/baseline.json && git commit -m "Security baseline"
```
After that, on pull requests: **new** Critical/High findings block, **existing** ones are tracked but do not block (existing *Critical* still blocks on the `pr` gate; see [policy.md](policy.md)).
A finding stays "existing" when code above it moves or when another tool reports the same CVE under a different id. Refresh the baseline only when you have fixed things (never to hide new findings).

## Exceptions
`.security/exceptions.json`:
```json
[
  {"rule": "B310", "path": "src/app/client.py",
   "reason": "URL scheme is validated by validate_url() before urlopen()",
   "approved_by": "Jane Doe (security)", "expires": "2027-03-31"},
  {"fingerprint": "a1b2c3d4e5f60718",
   "reason": "No fixed version of python-jose exists; not reachable (only HS256 used)",
   "approved_by": "Jane Doe (security)", "expires": "2027-01-31"}
]
```
- Match by `fingerprint` (exact finding; copy it from `findings.json`) or by `rule` (+ optional `path`).
- **All of `reason`, `approved_by`, `expires` are mandatory.** The scan refuses to run with an incomplete entry.
- Expired exceptions stop applying and are listed in the report, so they come back to you. Recommended maximum: 6 months.
- Test-data false positives for secrets: prefer an allowlist in `.security/gitleaks.toml`.
- Put the approval in the pull request that adds the exception, and protect `.security/` with CODEOWNERS ([ci-github-actions.md](ci-github-actions.md)).

## What you cannot do
You cannot weaken the severity policy from inside a repository (a `policy.json` in `.security/` is ignored). Policy changes go through the platform/security team and ship with the next kit upgrade.
