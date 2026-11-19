# Reading your report

Open it with `.security/secscan open` (file: `.security/reports/latest/summary.html`). In CI download the **security-report** artifact.

## Top of the page
- **PASS / FAIL**: whether the gate would block. In report-only mode FAIL does *not* fail your build; it tells you what *would* block once enforcement is on.
- **Severity cards**: open findings per severity, and how many are **new** (not in your baseline). Only new Critical/High block on pull requests.
- **Reduced coverage**: a warning that a tool could only partly check something (for example a `requirements.txt` whose pins conflict, or a `package.json` without a lockfile). Fix the cause; the audit is weaker until you do.
- **Tools table**: every tool that was *supposed* to run and whether it did. Anything other than `ok` means that check did not happen. With enforcement on, a broken tool fails the gate (so a broken scanner never looks like a pass).

## The findings table
Filter by severity/tool or tick *blocking only*. Highlighted rows block the gate.

| Column | Meaning |
|---|---|
| Severity | CRITICAL, HIGH, MEDIUM, LOW, INFO (policy: [policy.md](policy.md)) |
| Tool | Which tool(s) reported it. `gitleaks+trivy-fs` = two tools found the same thing; it is counted once |
| Rule | The tool's rule id (`B602`, `CVE-2024-…`, `GHSA-…`, `security/detect-eval-with-expression`) |
| Where | `file:line`, or `requirements.txt: package version` for dependencies, or a URL path for ZAP |
| What | Description, and **Fix:** when the tool knows the fixed version |

## Types of finding
| Type | Examples | What to do |
|---|---|---|
| Secrets | `github-pat`, `generic-api-key`, `aws-access-key-id` | Treat as leaked: rotate it, then remove it. [fixing-findings.md](fixing-findings.md#secrets) |
| Dependencies (SCA) | `CVE-…`/`GHSA-…` with a package and version | Upgrade to the *Fix* version |
| Code (SAST) | Bandit `B602`, Semgrep `subprocess-shell-true`, ESLint `security/…` | Change the code; see the cookbook |
| Dockerfile / image | `DS-0002` (root user), OS package CVEs | Fix the Dockerfile; rebuild on a newer base image |
| DAST | ZAP alerts on a running app | Triage by a human; missing headers are usually quick wins |

## Things that surprise people
- **One problem, several rows**: different *code* scanners (Semgrep, Bandit, Sonar, ESLint) can flag the same line separately. Dependencies and secrets are merged across tools, code findings are not (yet), so one risky line can show 2-3 rows.
- **Counts of dependency findings can be large** (hundreds) because one old package carries many CVEs. Upgrading one package often clears dozens of rows.
- **pip-audit has no severity**: its findings are treated as HIGH unless Trivy supplies a real severity for the same CVE.
- **False positives exist.** Test data (dummy tokens) and safe uses of "dangerous" functions are flagged. Do not ignore the whole report: add a justified, time-boxed exception ([exceptions-and-baseline.md](exceptions-and-baseline.md)) or an allowlist.
- **"No findings" is not "secure".** In our test app, path traversal and reflected XSS slipped past every static code scanner. These tools find *known* patterns.

## Files next to summary.html
| File | Use |
|---|---|
| `summary.md` | Same summary in markdown (shown on the pipeline run page) |
| `findings.json` | All findings, machine-readable, with stable ids (`fingerprint`) |
| `summary.json` | Totals and tool status, for dashboards |
| `results.sarif` | Source-code findings for GitHub code scanning / Azure DevOps |
| `raw/` | Original tool output. **Can contain code and secret metadata: never commit, upload publicly or paste into tickets** |
