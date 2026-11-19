# Security policy (proposed defaults, plan section 7)
Defined in `configs/policies/policy.json`. These are proposed internal defaults to agree with McKesson's security team, not McKesson policy.

| Severity | PR gate | Release gate |
|---|---|---|
| Critical | block (new and existing) | block |
| High | block new findings only | block new and existing |
| Medium / Low / Info | report | report |

- **New vs existing**: a finding is *existing* if its fingerprint is in `baseline.json`; without a baseline everything is *new*.
- **Fingerprints** are stable across tools and line moves where possible (package+CVE, secret location, rule+file+code).
- **Duplicates** across tools (Trivy + pip-audit on the same CVE, gitleaks + Trivy + Sonar on the same secret) are merged into one finding; the highest *known* severity wins.
- **pip-audit** reports no severity; its findings are treated as `unknown_severity_as` (default HIGH) unless Trivy supplies a real severity for the same CVE.
- **Report-only vs enforce**: without `--enforce` the gate prints what would block and exits 0. Start there for pilots.
- **Fail closed**: with `--enforce`, a scanner that did not produce a valid report fails the gate (a broken scanner must not look like a pass).
- **SonarQube** quality-gate failure also fails the gate.
- **SLA targets** (`sla_days`): Critical 3, High 14, Medium 60, Low 90 days — recorded in the policy file; SLA breach tracking is not automated yet.

## What a project can and cannot change
A project controls *whether* it enforces (`SEC_PRESET` / `SEC_ENFORCE`), which gate it uses on normal builds (`SEC_GATE`), optional tools (required tools stay on unless a time-boxed waiver exists, see [configuration.md](configuration.md)), baseline and exceptions. **It cannot change the severity thresholds**: a `policy.json` placed in `.security/` is ignored, and `config.env` is parsed as data (unsafe values are ignored), so a pull request cannot weaken the gate or run code on the scanner. Protect `.security/` with CODEOWNERS so skip lists and exceptions get reviewed.

## Exceptions
`exceptions.json`: list of `{fingerprint | rule[+path], reason, approved_by, expires}`; all of reason, approved_by and expires are mandatory (the gate refuses to run otherwise). Expired entries stop applying and are listed in the report.
Prefer fixing the cause: for scanner false positives in test data, an allowlist in `gitleaks.toml` (see `examples/project-config/claude-cost-kit/`) is better than an exception.
