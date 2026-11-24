# Warden: Security Scanning Framework (v1)

Reference implementation of a central DevSecOps scanning plan: one framework, tools for every layer, templates for GitHub Actions / Jenkins / Azure DevOps,
and guides written so that **a developer with no DevOps help can onboard a repo in about 10 minutes**.

**Start here: [docs/GETTING-STARTED.md](docs/GETTING-STARTED.md)**. Version 1 runs entirely in GitHub Actions and shows results in GitHub (pull request comment, file markers, run summary, report artifact): [docs/github-only-quickstart.md](docs/github-only-quickstart.md). The dashboard is optional and can be added later. Release notes: [CHANGELOG.md](CHANGELOG.md).

```bash
pip install "git+https://github.com/rakeshkolipakaTA/mckesson-security-kit.git@v1.0.2"   # once, in a venv (team lead)
cd your-repo
warden init                                 # add scanning (+ GitHub workflow); report-only preset "starter"
.security/warden doctor                     # check Docker/network
.security/warden scan                       # first scan, never breaks your build
.security/warden config show                # what runs and why; settings live in .security/config.env
.security/warden open                       # HTML report
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
| **AI agents** | 16 agent Semgrep rules, inventory + model-registry scan (models, endpoints, tools, MCP servers, prompt secrets), `modelscan` (malicious model files), red-team probes (`warden redteam`), `agentsec` runtime library; DeepTeam/promptfoo templates |
| Gate + reports | `scripts/gate.py`: dedupe across tools, baseline, exceptions, severity policy; HTML, markdown, JSON, SARIF |

## What we test
Category by category, with what each check looks for and how it protects: **[docs/checks/](docs/checks/README.md)** (secrets, code analysis, dependencies, containers and IaC, dynamic testing, supply chain, AI agents, gate and reporting, workflow and process).

Full detail, filterable: **[docs/security-test-coverage.xlsx](docs/security-test-coverage.xlsx)** (Excel) or [docs/test-coverage.md](docs/test-coverage.md). Both are generated from one data file (`tools/coverage_data.py`).

<!-- coverage:start -->
| Category | Question it answers | Checks | Tools |
|---|---|---|---|
| Secrets | Is a password, token or key sitting in the code? | 6 | gitleaks (tree + git history), Trivy, Semgrep, agent-scan |
| Code analysis (SAST) | Does our own code contain insecure patterns? | 6 | Semgrep, Bandit, ESLint security, SonarQube (optional) |
| Dependencies (SCA) | Do the libraries we use have known vulnerabilities? | 7 | pip-audit, npm audit, Trivy (CVEs, licences, SBOM), Dependency-Check (optional) |
| Container & IaC | Are Dockerfiles, images and Kubernetes manifests configured safely? | 10 | Trivy (Dockerfile, Kubernetes/Helm, Terraform/CloudFormation, image, CIS), kubescape; cluster/cloud docs + template |
| Dynamic testing (DAST) | Can a running app be attacked from outside? | 7 | OWASP ZAP (baseline, API, full, authenticated), Schemathesis, exposure scan |
| Supply chain & CI/CD | Can our pipeline or our dependencies be tampered with? | 5 | zizmor, repo-settings check, Dependabot/Renovate, signing + Scorecard templates |
| AI agent: static checks | Is the agent built unsafely (tools, guardrails, models, MCP, prompts)? | 29 | 17 Semgrep agent rules, 13 agent-scan checks, modelscan |
| AI agent: red-team probes | Does a running agent resist real attack attempts? | 21 | 19 deterministic probes; DeepTeam (7 frameworks) and promptfoo templates |
| AI agent: runtime controls (library) | Reusable code that gives an agent guardrails, authorisation, audit. | 16 | agentsec (16 modules) |
| Gate, policy & reporting | Decides pass/fail, reports and tracks results. | 14 | gate.py, crosswalk, SLA, dashboard, alerts, tickets |
| Developer workflow | Catches problems on the developer's machine before CI. | 5 | pre-push hook, pre-commit, PR template, IDE recommendations |
| Detection & response | Would we notice and react if something went wrong in production? | 2 | Falco rules (template), SIEM recipe |
| Process & governance | Do people have the procedures that tools cannot provide? | 1 | 9 process documents |
| **Total** |  | **129** | 21 scanner tools plus the library and gate |

**Coverage of the Agentic Security presentation:** 97 items checked: 47 covered, 47 partial, 3 not covered. Details and the list of what is not covered are in [docs/test-coverage.md](docs/test-coverage.md). Roadmap: 16 done, 6 partly, 1 documented only, 7 planned (penetration-test gaps).
<!-- coverage:end -->

**What cyber security means:** protecting systems, applications and data from unauthorised access, damage or disruption, and being able to detect and recover when something goes wrong (confidentiality, integrity, availability). These scans cover the *application and delivery-pipeline* slice. Network, cloud posture, runtime detection and response, and people and process need other tools and activities; the prioritised list of what to add next is in the Roadmap sheet.

## Integrations
Results always show in GitHub with no server. Optional tools can also receive each scan; each has a guide for developers (three steps: address in `config.env`, one CI secret, done) and for the platform team (start it, get the token). Details and a "which tool for which question" table: **[docs/integrations/](docs/integrations/README.md)**.

| Tool | Job | Guide |
|---|---|---|
| **SonarQube** | Code quality and code-security review with a quality gate | [docs/integrations/sonarqube.md](docs/integrations/sonarqube.md) |
| **DefectDojo** | One register of all findings across all repos: owners, deadlines, accepted risks, tickets | [docs/integrations/defectdojo.md](docs/integrations/defectdojo.md) |
| **Dependency-Track** | Watches the SBOM of every app and alerts on new CVEs after release | [docs/integrations/dependency-track.md](docs/integrations/dependency-track.md) |
| **Wiz** (needs a licence) | Wiz CLI scans in the pipeline (GitHub Actions, Azure DevOps) and the steps to connect Wiz to Azure | [docs/integrations/wiz.md](docs/integrations/wiz.md) |

```bash
scripts/platform-up.sh --defectdojo --dtrack       # platform team: start them (localhost only until you add --expose)
```

## Documentation
| For | Read |
|---|---|
| **Developers** | [GETTING-STARTED](docs/GETTING-STARTED.md) · [reading reports](docs/reading-reports.md) · [fixing findings (cookbook)](docs/fixing-findings.md) · [baseline & exceptions](docs/exceptions-and-baseline.md) · [what runs per stack](docs/stacks.md) · [troubleshooting](docs/troubleshooting.md) |
| **CI/CD** | [GitHub Actions](docs/ci-github-actions.md) · [Jenkins](docs/ci-jenkins.md) · [Azure DevOps](docs/ci-azure-devops.md) · [CD release gates & DAST](docs/cd-release-gates.md) |
| **Team leads** | [configuration (presets, tool switches)](docs/configuration.md) · [integrations: SonarQube, DefectDojo, Dependency-Track](docs/integrations/README.md) · [setup & integration (URLs, tokens, CI)](docs/integrations.md) · [dashboard](docs/dashboard.md) · [onboarding checklist](docs/onboarding-checklist.md) · [policy](docs/policy.md) |
| **Platform / security team** | [integrations](docs/integrations/README.md) · [setup & integration](docs/integrations.md) · [dashboard](docs/dashboard.md) · [platform setup](docs/platform-setup.md) · [central mode](docs/central-mode.md) · [per-project mode](docs/per-project-mode.md) · [tools](docs/tools.md) · [SonarQube](docs/sonar-setup.md) |
| **AI agents** | [agentic security overview + coverage map](docs/agentic-security.md) · [red teaming](docs/agentic-redteam.md) · [agentsec runtime library](docs/agentic-runtime-library.md) |
| **Evidence** | [point-of-view deck (HTML, cyber security and VAPT)](docs/warden-pov-presentation.html) · [logged-in scans, SSO and test credentials](docs/zap-authentication.md) · [what we test, by category](docs/test-coverage.md) · [what is verified / not](docs/status.md) · [end-to-end test on a vulnerable app](docs/fastapi-e2e.md) |

## Repository layout
```
scripts/      warden (CLI) · scan.sh (runner) · gate.py (policy + reports) · agent_scan.py · redteam.py · e2e-agent.sh · selftest.sh · test-onboarding.sh · test_gate.py · aggregate.py · sonar-bootstrap.sh · depcheck-update.sh
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
