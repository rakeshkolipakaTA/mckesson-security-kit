# Configuration: what to switch on or off

Everything a team can change lives in **one file**: `.security/config.env`. Run `.security/warden config show` at any time to see what is running on your repo and why.

Order of precedence (highest first): command-line flags, environment variables, `config.env`, the **preset**, built-in defaults.

## 1. Pick a preset

| Preset | Behaviour | Use it when |
|---|---|---|
| `starter` (default) | Report-only: scans run, nothing can fail the build | First 2-4 weeks on a repo |
| `standard` | Fails the build when a change adds a new Critical/High finding | The team has cleaned up or baselined |
| `strict` | `standard` plus the stricter `release` gate; SonarQube and Dependency-Check run when configured | Release branches, regulated apps |

Change it with `warden config set SEC_PRESET standard`. `SEC_ENFORCE` and `SEC_GATE` override single pieces of a preset if you need to.
The preset definitions live in the central policy (`configs/policies/policy.json`), so the platform team can adjust them for everyone.

## 2. Tools: `auto`, `on`, `off`

`auto` runs a tool when it fits the project; `on` always runs it; `off` never runs it. Set them as `SEC_<TOOL>=...`.

| Tool | Setting | Default | Runs when (auto) | Can a team turn it off? |
|---|---|---|---|---|
| gitleaks (secrets) | `SEC_GITLEAKS` | auto | always | **No: required** |
| Semgrep (code analysis) | `SEC_SEMGREP` | auto | always | **No: required** |
| Trivy fs (dependency CVEs, secrets, Dockerfile/IaC) | `SEC_TRIVY` | auto | always | **No: required** |
| agent-scan (agent registry/inventory) | `SEC_AGENT_SCAN` | auto | AI agent code detected | **No for agent repos** |
| modelscan (malicious model files) | `SEC_MODELSCAN` | auto | model files exist | **No when model files exist** |
| Bandit | `SEC_BANDIT` | auto | Python project | Yes |
| pip-audit | `SEC_PIP_AUDIT` | auto | Python project | Yes |
| npm audit | `SEC_NPM_AUDIT` | auto | Node project | Yes |
| ESLint security rules | `SEC_ESLINT` | auto | Node project | Yes |
| Trivy image | `SEC_TRIVY_IMAGE` | auto | `SEC_IMAGE` is set | Yes |
| SonarQube | `SEC_SONAR` | off (`strict`: auto) | `SONAR_HOST_URL` and `SONAR_TOKEN` are set | Yes |
| Dependency-Check | `SEC_DEPCHECK` | off (`strict`: auto) | Java project | Yes |
| OWASP ZAP | `SEC_ZAP` | auto | `SEC_ZAP_URL` is set | Yes |
| AI red-team probes | `SEC_REDTEAM` | auto | `SEC_REDTEAM_URL` is set | Yes |
| Secrets in git history | `SEC_GITLEAKS_HISTORY` | **off** on starter and standard, on for strict | the folder is a git checkout | Yes. Also `SEC_HISTORY_COMMITS=N` (how many newest commits, default 3000) and `SEC_HISTORY_FETCH` (see below) |
| SBOM (CycloneDX) | `SEC_SBOM` | auto | always | Yes |
| GitHub Actions security (zizmor) | `SEC_WORKFLOW_SCAN` | auto | `.github/workflows` exists | Yes |
| Kubernetes posture (kubescape) | `SEC_K8S_POSTURE` | auto | Kubernetes manifests exist | Yes |
| GitHub repository settings | `SEC_REPO_POSTURE` | auto | GitHub repo detected and `GITHUB_TOKEN` set | Yes |
| API fuzzing (Schemathesis) | `SEC_API_FUZZ` | auto | `SEC_API_SPEC` is set | Yes |
| Exposure scan (TLS, headers, paths, ports) | `SEC_EXPOSURE` | auto | `SEC_EXPOSURE_TARGETS` is set | Yes |

`on` for a tool that has no target (for example `SEC_ZAP=on` without `SEC_ZAP_URL`) stops the scan with a clear message instead of silently doing nothing.
The older `SEC_SKIP=a,b` list and `--skip` still work; they mean "off" for those tools.

### Waiving a required tool
If a required tool genuinely cannot run (for example Semgrep rules are blocked on a locked-down network), add a time-boxed waiver to `.security/exceptions.json`:
```json
[{"tool": "semgrep", "reason": "rules host blocked until the proxy is opened", "approved_by": "jane.doe", "expires": "2026-12-31"}]
```
Reason, approver and expiry are all mandatory. After the expiry date the waiver is ignored and the tool runs again. Waivers and anything that did not run are listed in the report under *Reduced coverage*.
Protect `.security/` with CODEOWNERS so waivers get reviewed.

## 3. Targets
Setting a target switches the matching tool on (in `auto`): `SEC_IMAGE` (Docker image to scan), `SEC_ZAP_URL` (a running QA app you own), `SEC_REDTEAM_URL` (a running QA agent you own), `SEC_API_SPEC` (OpenAPI URL to fuzz), `SEC_EXPOSURE_TARGETS` (hosts to check from outside). Never point ZAP or the red-team probes at production.

Details, limits and how to read each of these: [new-checks.md](new-checks.md).

## 4. Scope
`SEC_EXCLUDE_PATHS=vendor/**,legacy/**` leaves code and secret findings under those paths out of the result. **Dependency CVEs are never excluded** (that would hide real risk). The count of findings left out is shown in the report.

## What a team cannot change
Severity thresholds, the required-tool list, scanner versions and the approved-model registry are central. A `policy.json` placed in `.security/` is ignored, and `config.env` is parsed as data, never executed.

## Commands
| Command | Does |
|---|---|
| `warden config show` | Prints preset, enforce/gate, detected stacks and, for each tool, run/skip and the reason |
| `warden config set KEY VALUE` | Edits one setting in `.security/config.env` (rejects unsafe values) |


## Git history scanning (optional)
Scanning past commits finds secrets that were deleted later but are still valid. It is **off by default** on `starter` and `standard` (it needs more history and time) and on for `strict`. Turn it on in `.security/config.env`:
```ini
SEC_GITLEAKS_HISTORY=on     # scan past commits too
SEC_HISTORY_COMMITS=500     # only the newest 500 commits (default 3000); smaller is faster
SEC_HISTORY_FETCH=auto      # shallow CI checkout: fetch just that many commits (auto = when the workflow passes WARDEN_GIT_TOKEN, which the generated GitHub workflow does)
```
No `fetch-depth: 0` is needed: the scan fetches only the last `SEC_HISTORY_COMMITS` commits. If it cannot (no access to origin), it scans what is available and the report says so. When the limit cuts off older commits, the report notes that too.
