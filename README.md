# McKesson Security Scanning Framework (v1)

Reference implementation of a central DevSecOps scanning plan: one framework, tools for every layer, templates for GitHub Actions / Jenkins / Azure DevOps,
and guides written so that **a developer with no DevOps help can onboard a repo in about 10 minutes**.

**Start here: [docs/GETTING-STARTED.md](docs/GETTING-STARTED.md)**

```bash
pip install "git+https://github.com/rakeshkolipakaTA/mckesson-security-kit.git@v1.0.0"   # once, in a venv (team lead)
cd your-repo
secscan init                                 # add scanning (+ GitHub workflow); report-only preset "starter"
.security/secscan doctor                     # check Docker/network
.security/secscan scan                       # first scan, never breaks your build
.security/secscan config show                # what runs and why; settings live in .security/config.env
.security/secscan open                       # HTML report
```
Teammates and CI install nothing: the repo pins the version and the launcher fetches it. Settings: [docs/configuration.md](docs/configuration.md).

## Tools (all pinned, run in Docker, repo mounted read-only)
_AI agents:_ see [docs/agentic-security.md](docs/agentic-security.md): agent-specific Semgrep rules, inventory/registry scan, model-file scan, deterministic red-team probes, and the `agentsec` runtime-controls library.

| Layer | Tools |
|---|---|
| Secrets | gitleaks, Trivy |
| SAST | Semgrep (all stacks), Bandit (Python), ESLint security rules (JS/TS), SonarQube (optional) |
| SCA | pip-audit (Python), `npm audit` (Node), Trivy (all, incl. Java), OWASP Dependency-Check (optional, Java) |
| Container / IaC | Trivy (Dockerfile + built image) |
| DAST | OWASP ZAP (baseline / api / full, QA only) |
| **AI agents** | 16 agent Semgrep rules, inventory + model-registry scan (models, endpoints, tools, MCP servers, prompt secrets), `modelscan` (malicious model files), red-team probes (`secscan redteam`), `agentsec` runtime library; DeepTeam/promptfoo templates |
| Gate + reports | `scripts/gate.py`: dedupe across tools, baseline, exceptions, severity policy; HTML, markdown, JSON, SARIF |

## What we test (85 checks in 10 categories)
Full detail, filterable: **[docs/security-test-coverage.xlsx](docs/security-test-coverage.xlsx)** (Excel) or [docs/test-coverage.md](docs/test-coverage.md). Both are generated from one data file (`tools/coverage_data.py`).

| Category | Question it answers | Checks | Tools |
|---|---|---|---|
| Secrets | Is a password, token or key sitting in the code? | 5 | gitleaks, Trivy, Semgrep, agent-scan |
| Code analysis (SAST) | Does our own code contain insecure patterns? | 4 | Semgrep, Bandit, ESLint security, SonarQube (optional) |
| Dependencies (SCA) | Do the libraries we use have known vulnerabilities? | 4 | pip-audit, npm audit, Trivy, Dependency-Check (optional) |
| Container & IaC | Are Dockerfiles, images and Kubernetes manifests configured safely? | 3 | Trivy (Dockerfile, Kubernetes/Helm, image) |
| Dynamic testing (DAST) | Can a running app be attacked from outside? | 3 | OWASP ZAP (baseline, API, full) |
| AI agent: static checks | Is the agent built unsafely (tools, guardrails, models, MCP, prompts)? | 27 | 16 Semgrep agent rules, 12 agent-scan checks, modelscan |
| AI agent: red-team probes | Does a running agent resist real attack attempts? | 20 | 18 deterministic probes; DeepTeam and promptfoo templates |
| AI agent: runtime controls (library) | Reusable code that gives an agent guardrails, authorisation, audit. | 9 | agentsec (9 modules) |
| Gate, policy & reporting | Decides pass/fail, reports and tracks results. | 8 | gate.py, dashboard, reports |
| Developer workflow | Catches problems on the developer's machine before CI. | 2 | pre-push hook, pre-commit, PR template |
| **Total** |  | **85** | 14 scanner tools plus the library and gate |

**What cyber security means:** protecting systems, applications and data from unauthorised access, damage or disruption, and being able to detect and recover when something goes wrong (confidentiality, integrity, availability). These scans cover the *application and delivery-pipeline* slice. Network, cloud posture, runtime detection and response, and people and process need other tools and activities; the prioritised list of what to add next is in the Roadmap sheet.

**Coverage of the Agentic Security presentation:** 97 items checked: 33 covered, 44 partial, 20 not covered. Scanning, pipeline gates, red-team probes and the runtime-controls library are covered; platform services (sandbox runtime, identity provider / vault, policy admin UI, runtime detection) and some data and output-integrity items are not. The Presentation coverage sheet lists every item.

## Documentation
| For | Read |
|---|---|
| **Developers** | [GETTING-STARTED](docs/GETTING-STARTED.md) · [reading reports](docs/reading-reports.md) · [fixing findings (cookbook)](docs/fixing-findings.md) · [baseline & exceptions](docs/exceptions-and-baseline.md) · [what runs per stack](docs/stacks.md) · [troubleshooting](docs/troubleshooting.md) |
| **CI/CD** | [GitHub Actions](docs/ci-github-actions.md) · [Jenkins](docs/ci-jenkins.md) · [Azure DevOps](docs/ci-azure-devops.md) · [CD release gates & DAST](docs/cd-release-gates.md) |
| **Team leads** | [configuration (presets, tool switches)](docs/configuration.md) · [setup & integration (Sonar URL, tokens, CI)](docs/integrations.md) · [dashboard](docs/dashboard.md) · [onboarding checklist](docs/onboarding-checklist.md) · [policy](docs/policy.md) |
| **Platform / security team** | [setup & integration](docs/integrations.md) · [dashboard](docs/dashboard.md) · [platform setup](docs/platform-setup.md) · [central mode](docs/central-mode.md) · [per-project mode](docs/per-project-mode.md) · [tools](docs/tools.md) · [SonarQube](docs/sonar-setup.md) |
| **AI agents** | [agentic security overview + coverage map](docs/agentic-security.md) · [red teaming](docs/agentic-redteam.md) · [agentsec runtime library](docs/agentic-runtime-library.md) |
| **Evidence** | [what we test, by category](docs/test-coverage.md) · [what is verified / not](docs/status.md) · [end-to-end test on a vulnerable app](docs/fastapi-e2e.md) |

## Repository layout
```
scripts/      secscan (CLI) · scan.sh (runner) · gate.py (policy + reports) · agent_scan.py · redteam.py · e2e-agent.sh · selftest.sh · test-onboarding.sh · test_gate.py · aggregate.py · sonar-bootstrap.sh · depcheck-update.sh
configs/      tool configs and policies/policy.json (severity gates, SLAs)
docker/       scanner images (python, node) · SonarQube compose
modes/        per-project kit installer + CI templates
.github/      reusable GitHub workflow (security-scan-reusable.yml)
agentic/      agentsec runtime-controls library + unit tests
examples/     intentionally vulnerable fixtures (python/fastapi, node, java, AI agent) + a hardened agent, a clean one, project-config example
docs/         guides
```

## Test the framework itself
```bash
make selftest            # gate logic: enforce/report-only/baseline/exceptions/fail-closed + unit tests (~2 min)
make test-onboarding     # the developer journey on python, node, java (~6 min)
make e2e-fastapi         # vulnerable FastAPI app incl. image scan and ZAP DAST (~6 min)
make e2e-agent           # vulnerable vs hardened AI agent: static + inventory + red-team probes, with assertions (~2 min)
```
