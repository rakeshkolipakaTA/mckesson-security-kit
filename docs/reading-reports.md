# Reading your report

Two reports are written on every scan:
- **`summary.html`**: the working report for developers (below): charts, every finding, filters.
- **`assessment.html`**: the **assessment report** for a security or audit team: one document with a verdict and the evidence behind it. Open it with `.security/warden open assessment`, or from the link at the top of `summary.html`. See [The assessment report](#the-assessment-report).

Open it with `.security/warden open` (file: `.security/reports/latest/summary.html`). In CI download the **security-report** artifact.

## Top of the page
- **PASS / FAIL**: whether the gate would block. In report-only mode FAIL does *not* fail your build; it tells you what *would* block once enforcement is on.
- **Severity cards**: open findings per severity, and how many are **new** (not in your baseline). Only new Critical/High block on pull requests.
- **Charts**: five charts under the cards, built from the open findings (excepted ones are left out). Hover or tab to a bar for the exact number; every chart also has a **Table view** with the same numbers, and the page needs no internet.
  - *Open findings by severity*: how many Critical, High, Medium, Low.
  - *Category by severity*: a grid of what kind of problem (code, libraries, secrets, config) against how serious. The number is the count and a darker cell means more. Read it to see where the serious findings sit.
  - *Findings by category*: the same kinds of problem as ranked bars.
  - *Findings by tool*: which scanner reported how much. A finding two tools both report counts once for each tool.
  - *Top files*: the ten files with the most open findings. It is usually the quickest place to start fixing (one old `requirements.txt` can carry hundreds of library findings).
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

## The assessment report
`assessment.html` is for the person who has to decide whether the code is acceptable, not for the person fixing it. It prints on A4 (use the browser's Print, then Save as PDF) and needs no internet.

| Section | What it tells the reviewer |
|---|---|
| Header | Application, commit, branch, date, Warden version, and the type of assessment |
| **Verdict** | **PASSED**: every check that applies ran and nothing breaks the policy. **PASSED WITH CONDITIONS**: nothing breaks the policy, but something limits the meaning (a check switched off or waived, paths left out, overdue findings, open High findings that do not block). **INCOMPLETE**: a check gave no result, so the code was not fully assessed. **FAILED**: findings break the policy. The reasons and conditions are listed under it |
| Summary | Open findings per severity, how many are new, and which severities block under this policy |
| Findings that break the policy | The most serious ones, with file, line and fix |
| What was checked | Each check in its area (secrets, libraries, code, infrastructure, pipelines, SBOM, AI, running app): checked with its result, turned off, not run with the reason, or failed to run |
| Policy applied | Gate, preset, what blocks, fix deadlines, whether a baseline is used |
| Accepted exceptions and waivers | What was excused, by whom, until when. Expired ones are flagged |
| Controls evidenced | Where findings map to a control framework, when one is configured |
| Basis and limits | It is an automated assessment, not a penetration test, a person's review or a certification, and it is valid for that commit only |
| Evidence | SHA-256 of the scan output, so a copy of the report can be matched to the original |
| Review and sign-off | A blank block for a named reviewer to decide and sign, if your process needs one. Warden does not fill it in |

In report-only mode the build is not blocked, and the report says so: the verdict is how the code is judged under the policy, so it is what would happen once the gate is enforced. The verdict follows the policy. If your policy is lenient, a PASSED verdict means "within that policy", which the report states in the Policy applied table.
