# Status (v1, 2026-11-19)

## Verified (run on this machine)
| Area | Evidence |
|---|---|
| Tools: gitleaks, Trivy (fs + image), Semgrep, Bandit, pip-audit, `npm audit`, ESLint security, SonarQube, ZAP (baseline/api/full) | fixtures `fastapi-sample`, `node-sample`, `java-sample`, `vulnerable-python`; a real small repo and a real larger private application repo |
| Gate: enforce/report-only, baseline, approved + expired exceptions, fail-closed, cross-tool dedupe, stable ids | `scripts/selftest.sh` (21 checks) + `scripts/test_gate.py` (28 unit tests) + `scripts/test_toolplan.py` (13 unit tests) |
| Developer journey on python, node, java, clean: `init` > `doctor` > first scan > enforce > upgrade keeps edits | `scripts/test-onboarding.sh` (83 checks) |
| Config: presets, per-tool `auto/on/off`, required-tool lock, time-boxed tool waivers, `SEC_EXCLUDE_PATHS`, `config show/set` | `test_toolplan.py`, `test-onboarding.sh` (switches, lock, waivers, unsafe values), `test_gate.py` |
| Central dashboard (portfolio + repo pages, ingest API, login, hostile-input handling) and CI publisher; deployed on this server with SonarQube | `scripts/test_dashboard.py` (20 tests); live on `:8090` with real scan data from 5 repos incl. the pilot branch |
| Package: `pip install` into a clean venv, thin `init`, self-installing launcher pinned by `secscan.lock`, `disable/enable/upgrade/uninstall/reinstall`, vendored mode | `scripts/test-package.sh` (46 checks; one real scan) |
| **Real GitHub Actions run** on a private application repo (a pilot branch, vendored kit, starter preset) | Run succeeded in 4m10s; report artifact produced. Found one real bug (npm audit failed on a peer-dependency conflict, now fixed + regression test) |
| `config.env` is parsed, never executed; project `policy.json` is ignored | same test (malicious `config.env`, relaxed policy attempt) |
| Reports: HTML (escaped, filterable), markdown, JSON, SARIF | unit tests + generated on every run |
| GitHub workflows (PR, release gate, DAST, reusable, caller) | `actionlint` clean; the commands they run are the ones exercised above |
| Central mode and per-project kit give identical findings | 12 = 12 on `claude-cost-kit` (earlier run) |
| A real larger application repo (read-only) | Hundreds of Critical/High findings, mostly dependency CVEs, plus hardcoded secrets and container-as-root; used to tune results. Details are kept in the private report, not here |

## AI agents (added after the presentation review; details in agentic-security.md)
- **Verified**: `make e2e-agent` (12 assertions): vulnerable vs hardened agent, static + inventory + Semgrep agent rules + 23 red-team checks + model-file scan; 24 `agentsec` unit tests; 16 Semgrep rules with positive/negative tests; 4 new gate-parser unit tests; developer journey for an agent repo.
- **Template, not run end to end**: DeepTeam (wiring verified by `--dry-run` for 5 frameworks; no LLM available for a full run) and promptfoo (not run at all).
- **Not provided**: code-execution sandbox, vault/rotation, IdP/token exchange, WORM audit storage, runtime detection, output-integrity/lineage checks, LLM09 misinformation.
- **Limits**: tests use a mock LLM (they prove application controls and the harness, not a real model's jailbreak resistance); the model registry is example content; injection screening is heuristic (RT-INJ-03 fails on the hardened sample on purpose).

## Penetration-test gaps (found when the programme was reviewed against a VAPT checklist)
Not built yet, in the roadmap as *Planned*: Nmap port and service discovery, Nuclei CVE and misconfiguration templates, testssl.sh deep TLS, a BOLA / IDOR authorisation test pack, session and token checks (JWT, cookies, rate limits), subdomain and DNS-email checks, mobile (MobSF). Manual penetration test, red team, social engineering and load / denial-of-service testing need a human engagement; the process kit has the templates, but no test has been commissioned. See [the point-of-view deck](secscan-pov-presentation.html).

## Latest full regression (2026-11-19)
selftest 21, onboarding 83, package 46, new-tools 22, e2e-agent 12, unit suites (gate 28, tool plan 16, dashboard 20, tickets 11, templates 10, tools 7), agentic library 24 + 54, Docker sandbox 17, Vault 8: all pass (379 checks). The one failure seen during the run (an unpinned action in the cloud-posture template) was fixed and re-tested.

## NOT validated yet
- **Real CI runs**: only the GitHub Actions PR workflow has run on a real runner (vendored mode, push trigger). Thin mode on a runner (needs the package published), pull_request events, the release/DAST workflows, Jenkins and Azure DevOps have not; the Azure YAML parses but was not run; the Jenkins snippets/Groovy step were not syntax-checked at all. The reusable workflow needs `<ORG>` replaced and the templates repo published.
- **Dependency-Check**: wired with a database updater, but not run: no NVD API key was available.
- **Safety**: deliberately not included (needs licence; pip-audit replaces it).
- **SonarQube** on node/java fixtures (only Python was run); Community Build has no taint analysis or PR decoration.
- Windows-native shells (WSL2/Git Bash expected), proxies/offline networks, very large monorepos (timing not measured).

## Known limitations (documented for developers)
- **Detection gaps**: in `examples/fastapi-sample` path traversal and reflected XSS were missed by all static tools (ZAP found the XSS); Sonar CE missed the SQL injection that Bandit and Semgrep caught. A hardcoded JWT secret in the Node fixture, and a hardcoded password and a command injection in the Java fixture, went undetected. "No findings" is not "secure".
- **DAST**: baseline finds little on pure APIs; `api` mode missed injection bugs; `full` mode found XSS/CORS but missed SQLi in a URL path and path traversal, and POST bodies / authenticated scans are not covered (see fastapi-e2e.md).
- **Duplicates**: different *code* scanners report the same line separately (not merged yet); `npm audit` vs Trivy duplicates for lockfiles are handled.
- **Severity policy values are proposals** to agree with McKesson security.

## Not built (later phases)
Go/.NET/PHP/Ruby profiles, ZAP authenticated + POST scans and automation plans, SLA-breach tracking, central dashboard beyond `aggregate.py`, PR comments, license compliance, pre-built scanner images in a registry, Terraform/Kubernetes policies beyond Trivy.

## Test target notes
`claude-cost-kit` with its project config: PASS enforced (0 Critical, 0 High, 12 Medium, 7 Low). Three Medium are heuristic Semgrep SQL hits on f-string SQL built from internal constants (probable false positives; triage with an exception if confirmed).
