# Version 1: GitHub only, no server

Everything runs inside GitHub Actions. You do not install, host or pay for anything else.
The results are shown **in GitHub itself**. A dashboard is optional and can be added later with two settings.

## Set it up (about 5 minutes)
```bash
warden init                  # detects your stack, adds .security/ and .github/workflows/security-scan.yml
git add .security .github && git commit -m "Add Warden security scanning (report-only)" && git push
```
Open a pull request. That is all. It starts **report-only**: nothing can block a merge until your team chooses (`warden config set SEC_PRESET standard`).

## Where you see the results (all inside GitHub)
| Where | What you see | Needs |
|---|---|---|
| **Pull request comment** | One comment with the verdict, new Critical/High counts and the top findings. It is **updated on every push**, never duplicated. | `pull-requests: write` (already in the generated workflow) |
| **"Files changed" tab** | Markers on the exact lines: red for Critical, yellow for High (up to 10 of each; GitHub's limit per step). | nothing |
| **Run page > Summary** | Verdict, counts by severity, which checks ran (and which did **not**), the top findings with links to the file and line, the full text summary. | nothing |
| **Artifacts** (`security-report`) | The full HTML report, markdown summary, SBOM (`sbom.cdx.json`) and SARIF. Kept 14 days. | nothing |
| **Security tab** (optional) | Findings listed as code-scanning alerts that track over time. | Public repo (free) or GitHub Advanced Security. Uncomment `security-events: write` in the workflow and set the repository variable `WARDEN_CODE_SCANNING=true`. |

A check that could not run is shown as **"Did not complete"**, never as clean.

## What runs with nothing but GitHub
| Check | Runs by default? | Notes |
|---|---|---|
| Secrets in files and git history (gitleaks) | Yes | Needs full history for the history scan; the generated workflow checks out normally, set `fetch-depth: 0` to scan all history |
| Code analysis (Semgrep, plus Bandit for Python, ESLint for Node) | Yes | |
| Dependencies with known vulnerabilities (Trivy, pip-audit, npm audit), licences, SBOM | Yes | |
| Dockerfile, Terraform, CloudFormation, Kubernetes manifests (Trivy, kubescape) | Yes, when such files exist | |
| GitHub workflow security (zizmor) | Yes, when workflows exist | |
| AI agent checks (static rules, model files) | Yes, for agent repos | |
| Container image scan, CIS Docker | When you build an image in the workflow | Set `SEC_IMAGE` (see the release template) |
| Dynamic scan (ZAP), API fuzzing, exposure checks | When a QA URL exists | Needs a **running** QA app reachable from the runner (`SEC_ZAP_URL`, `SEC_API_SPEC`, `SEC_EXPOSURE_TARGETS`); see the DAST template |
| AI red-team probes | When a QA agent URL exists | `SEC_REDTEAM_URL` |
| Repository settings check (branch protection, SECURITY.md, ...) | No | Needs a token that can read settings: pass a `GITHUB_TOKEN` with admin read to the scan step |
| SonarQube | No | Needs a SonarQube **server** (`SONAR_HOST_URL`, `SONAR_TOKEN`); off by default |

Penetration testing by people, and network-level testing, are separate from the pipeline: see [the point-of-view deck](warden-pov-presentation.html).

## Settings you may want
| Setting | Where | Effect |
|---|---|---|
| `SEC_PRESET=starter / standard / strict` | `.security/config.env` | Report-only, block new Critical/High, release gate |
| `WARDEN_PR_COMMENT=off` | repository variable | No pull request comment (summary and markers stay) |
| remove `pull-requests: write` | workflow file | Same, and the token cannot write to pull requests at all |
| `SEC_EXCLUDE_PATHS=vendor/**` | `.security/config.env` | Skip folders |

## Pull requests from forks
GitHub gives workflows on fork pull requests a read-only token. The scan, the run summary and the file markers still work; the pull request comment is skipped with a note in the log. This is a GitHub rule, not a Warden limitation.

## Adding the dashboard later (optional)
When a team has a Warden dashboard server ([dashboard.md](dashboard.md)), add two things and nothing else changes:
1. Repository variable or `config.env` line: `SEC_DASHBOARD_URL=https://your-dashboard`
2. Repository secret: `WARDEN_DASHBOARD_TOKEN`

Every scan is then also sent to the dashboard (portfolio view, trends, overdue findings). If the dashboard is down, the build is not affected. GitHub-hosted runners can only reach a dashboard that is reachable from the internet (or use a self-hosted runner inside your network).

## Honest limits of GitHub-only
- **No history or trends** across repositories; each run stands alone (the dashboard adds this).
- **Annotations are capped** at 10 Critical + 10 High per run; the rest are in the summary and the artifact.
- **Artifacts expire** after 14 days (change `retention-days`).
- **The Security tab** needs a public repo or GitHub Advanced Security.
- **Not yet validated on a real pull request in GitHub**: the comment logic is tested against a mock GitHub API; the first live pull request is the real proof.
