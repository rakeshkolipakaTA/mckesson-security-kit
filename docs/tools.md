# Tool guide
| Tool | Purpose | How it runs | Config | Report |
|---|---|---|---|---|
| Semgrep 1.185 | Multi-language code analysis (SQL/command injection, SSRF, deserialization, weak crypto, CORS...) with registry rule packs `p/default`, `p/security-audit`, `p/cwe-top-25`, injection, JWT and framework packs (`SEC_SEMGREP_PACKS`), `p/owasp-top-ten` + per-stack packs | pinned image, `--metrics=off` | `SEC_SEMGREP_RULES` for offline/approved rules | `raw/semgrep.json` |
| ESLint 9 + security plugins | JS/TS security rules (`eslint-plugin-security`, `no-unsanitized`) | `warden-scanner-node` image | `configs/eslint/eslint.config.mjs` | `raw/eslint.json` |
| `npm audit` | Node dependency CVEs, one run per `package-lock.json` | `warden-scanner-node` image | — | `raw/npm-audit-<n>.json` |
| Agent Semgrep rules | 16 rules for agent anti-patterns: tool parameter reaching file/network/exec/SQL, fail-open guardrails, unauthenticated agent routes, hardcoded LLM keys, unsafe model loading, dangerous REPL/shell tools, sensitive data in logs, unbounded loops. Each has positive and negative tests | profile `agent` | `configs/semgrep/agentic/` (`agentic.yaml` + `agentic.py` tests) | in `raw/semgrep.json` |
| agent-scan (`scripts/agent_scan.py`) | Inventory of frameworks, models, LLM endpoints, tools (decorator-registered), MCP servers; checks vs the central registry; risky tools; MCP pinning/secrets/privileges; secrets in prompt files | profile `agent` (host python, stdlib) | `configs/agentic/approved-models.json` (central, **example content**) | `raw/agent-scan.json` |
| modelscan 0.8.8 | Malicious payloads in pickle/PyTorch/Keras model files | scanner image, only if model files exist | — | `raw/modelscan.json` |
| red-team harness (`scripts/redteam.py`) | 18 deterministic attack probes against a RUNNING agent (QA only) | `--redteam-url` | `.security/redteam.json` | `raw/redteam.json` |
| Bandit 1.9.4 | Python SAST | scanner image | `configs/bandit/bandit.yaml` (excludes tests/venv/build) | `raw/bandit.json` |
| pip-audit 2.10.1 | Python SCA incl. transitive deps | scanner image, once per `requirements*.txt` found anywhere in the repo (and root `pyproject.toml`/`setup.py`) | — | `raw/pip-audit-<n>.json` + `pip-audit.manifests` |
| Trivy 0.76.2 | fs: vulnerabilities, secrets, Dockerfile/IaC misconfig; `--image` for images | pinned image + cache volume `warden-trivy-cache` | `configs/trivy/trivy.yaml` | `raw/trivy-fs.json`, `trivy-image.json` |
| gitleaks 8.30.1 | secret scan | pinned image | `configs/gitleaks/gitleaks.toml` | `raw/gitleaks.json` |
| SonarQube | core SAST + quality gate | `--sonar` | [sonar-setup.md](sonar-setup.md) | `raw/sonarqube.json` |
| OWASP Dependency-Check | SCA, mainly Java | `--depcheck`, data volume `warden-depcheck-data`; needs `NVD_API_KEY` | `configs/dependency-check/suppression.xml` | `raw/dependency-check.json` |

**Safety vs pip-audit**: the plan lists Safety, which needs an account/licence for CI use. pip-audit (PyPA, free) covers the same need and the plan flags this overlap for evaluation; switch if your organisation licenses Safety.
**Trivy/CIS**: Trivy checks Dockerfile misconfiguration and image vulnerabilities; it is not a full CIS Docker Benchmark assessment (plan section 9.6).
**Not run in this framework**: pip-audit and Trivy never modify the repo; `npm audit fix` style auto-fixes are deliberately absent.

**pip-audit and unresolvable manifests**: pip-audit normally resolves the whole tree and fails when pins conflict (e.g. `fastapi` needs `anyio<4` while `mcp` needs `anyio>=4.5`). In that case `scan.sh` retries on the pinned lines only (no resolution, no transitive deps, unpinned lines skipped), and the report lists the manifest under *Reduced coverage*. If the manifest has no pinned lines to audit, no report is produced and the gate treats that as a tool error, never as "no vulnerabilities". Findings are tracked per manifest, so the same CVE in two manifests is two findings.
**Report confidentiality**: `reports/` can contain code snippets (Bandit) and metadata about secrets. Gitleaks runs with `--redact` and hardcoded-password messages are redacted, but treat reports as confidential and never publish them.

**Safety**: not included. It needs an account/licence for CI use and pip-audit covers the same need (plan section 9.5 asks to evaluate this overlap). If your organisation licenses Safety, add it as a tool and parser.
**Dependency-Check**: wired (`SEC_DEPCHECK=1`, database via `scripts/depcheck-update.sh`) but not validated end to end here: it needs an NVD API key, which was not available.
**Overlaps**: Trivy and pip-audit/`npm audit` report the same CVE under different ids; findings of the same package + id (or any shared alias) in the same manifest are merged. When `npm audit` ran for a lockfile, Trivy's duplicate findings for that lockfile are dropped. Different *code* scanners are not merged: one risky line can appear from Semgrep, Bandit and ESLint separately.

**Semgrep tuning (v1)**: `configs/semgrep/exclude-rules.txt` drops rules that are noise for everyone (currently the Python 3.7 compatibility rule). `configs/policies/policy.json` > `semgrep_severity_cap` caps heuristic rules that cannot tell parameterised from concatenated SQL (`sqlalchemy-execute-raw-query`, which fired 99 times on one real repo) at MEDIUM: they stay visible but do not block on their own, consistent with Bandit B608. Change these centrally, never per project. Semgrep severities map ERROR to HIGH, WARNING to MEDIUM, INFO to LOW. Semgrep's own secret rules merge with gitleaks/Trivy.
