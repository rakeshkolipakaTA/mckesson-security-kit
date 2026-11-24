# 9. Gate, policy and reporting: who decides pass or fail, and how are results tracked?

Scanners produce raw findings. This layer turns them into **one decision** and **one place to read the result**. It is what makes the checks in pages 1 to 8 protective rather than informational.

## What it protects against
* **Alert fatigue.** The same CVE from three tools, or hundreds of old findings, would bury the new ones. Merging and baselines keep the signal.
* **Quiet failure.** A scanner that crashed, timed out or was switched off must not look like a clean result.
* **Quiet weakening.** A pull request that loosens the rules, or an exception that never expires.
* **Findings that rot.** Known problems nobody fixes.

## Checks and controls

| Control | What it does | Why it protects |
|---|---|---|
| **Policy gate** | Applies the thresholds in `configs/policies/policy.json` (table below) | The decision is automatic, the same for every repo, and central |
| **De-duplication and stable fingerprints** | Merges the same finding from several tools (same package and id, same secret location). Fingerprints survive line moves | One row per problem; baselines and exceptions keep matching |
| **Baseline** | `warden baseline` records current findings as "existing", so only **new** ones block | A team can adopt the scan on a legacy app on day one |
| **Dated baseline with SLA ageing** | A known finding older than its fix deadline blocks again (Critical 3 days, High 14, Medium 60, Low 90) | A baseline cannot become a permanent hiding place. Old-format baselines do not age: re-create once with `warden baseline` |
| **Time-boxed exceptions and tool waivers** | `reason`, `approved_by` and `expires` are mandatory; an incomplete entry stops the scan; an expired one stops applying and is listed in the report | Risk acceptance is named, reviewed and temporary |
| **Required-tool lock** | gitleaks, Semgrep and Trivy (plus agent-scan and modelscan where they apply) cannot be turned off in `config.env` | A repo cannot opt out of the basics |
| **Fail closed on tool errors** | With enforcement on, a scanner with no valid report fails the gate. Anything skipped is listed under *Reduced coverage* | A broken scanner never looks like a pass |
| **Central, un-editable policy** | A `policy.json` in `.security/` is ignored; `config.env` is parsed as data (unsafe values ignored), never run | A pull request cannot weaken the gate or run code on the scanner |
| **Reports** | HTML, Markdown, JSON and SARIF per scan, plus an SBOM | Readable by people, and by code-scanning UIs |
| **GitHub-native reporting** (`warden ci-report`) | Run summary, markers on risky lines (up to 10 errors for Critical and 10 warnings for High, only on real repo files), and **one** pull request comment that is updated on each run | Results are where developers already look, with no server |
| **Compliance crosswalk** | Maps every finding to the control it evidences and to NIST AI RMF, NIST CSF 2.0, ISO 42001, OWASP LLM, the EU AI Act and supervisory themes (`crosswalk.csv` per scan) | Evidence for audits. It is a heuristic mapping, not a compliance verdict |
| **DefectDojo publishing** (optional) | Sends the merged findings of each `main` scan to DefectDojo by reimport: new findings opened, fixed ones closed, approved exceptions as accepted risk, no duplicates | One company-wide register with owners, deadlines and management reports. See [../integrations/defectdojo.md](../integrations/defectdojo.md) |
| **Dependency-Track upload** (optional) | Sends the SBOM of each `main` scan; Dependency-Track keeps checking it and alerts on new CVEs after release | Libraries you already shipped stay watched between scans. See [../integrations/dependency-track.md](../integrations/dependency-track.md) |
| **Central dashboard** (optional) | Portfolio and per-repo views across all tools, trend lines, stale repos (no scan in 14 days), tool problems, first-seen age and overdue tiles | One view for security and engineering leads |
| **Alerts** (optional) | Slack or Teams style webhooks when a gate flips to FAIL, a new Critical appears, an SLA is newly breached, or a repo goes stale | Someone is told, not just a page updated |
| **Tickets** (optional) | Creates GitHub, Jira or Azure Boards issues for new or overdue Critical and High findings; de-duplicated; dry run by default | Findings get an owner and a due date |

## The gate in numbers

| Severity | Pull request gate | Release gate |
|---|---|---|
| Critical | Blocks new and known | Blocks |
| High | Blocks new; blocks known findings once overdue | Blocks new and known |
| Medium, Low, Info | Report | Report |

Presets pick the behaviour for a team (`SEC_PRESET`):

| Preset | Enforces? | Gate | Extras |
|---|---|---|---|
| `starter` (default) | No. Shows "would block" | pull request | Git history, SonarQube, Dependency-Check off |
| `standard` | Yes | pull request | same as starter |
| `strict` | Yes | release | Git history on; SonarQube and Dependency-Check run when configured |

Start on `starter` for 2 to 4 weeks, run `warden baseline` if the app is old, then move to `standard`. Details: [../policy.md](../policy.md), [../exceptions-and-baseline.md](../exceptions-and-baseline.md), [../configuration.md](../configuration.md).

## How GitHub reporting is kept safe
* Untrusted text (a finding title, a file name) is escaped before it goes into a summary or comment.
* The tool edits only a comment written by a bot, marked with a hidden tag. It never edits a person's comment.
* Fork pull requests get no comment, because their token is read-only. Reporting never fails the build.

## Limits
* Thresholds are **proposed defaults** to agree with your security team, not an organisational policy.
* The crosswalk is a mapping aid. It does not say you are compliant.
* DefectDojo and Dependency-Track publishing is tested on real containers (DefectDojo 3.5.300, Dependency-Track 4.14.7) and mock servers, not yet from a GitHub Actions runner. DefectDojo's CI token must belong to a superuser (the Community edition has no import-only role).
* The dashboard has one shared login, speaks plain HTTP (put TLS in front, or restrict the port), and starts counting SLA age at its first scan after an upgrade.
* Alerts and tickets are tested against mock Slack, Teams, Jira, GitHub and Azure servers, **not** real tenants. The GitHub comment logic is tested against a mock API and a real report, but has **not yet been seen on a live pull request**.
* Status: **Verified** for the gate, baseline, exceptions, SLA, required-tool lock, fail-closed logic, reports, crosswalk and the dashboard. **Verified (partial)** for GitHub-native reporting, alerts and tickets, as stated above.
