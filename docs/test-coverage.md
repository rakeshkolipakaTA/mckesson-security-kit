# What we test: coverage by category

Generated from `tools/coverage_data.py` on 2026-11-19. The same data is in [security-test-coverage.xlsx](security-test-coverage.xlsx) (filterable, with roadmap and glossary).

## 1. Categories and how many checks each has

| Category | Question it answers | Checks | Tools |
|---|---|---|---|
| Secrets | Is a password, token or key sitting in the code? | 6 | gitleaks (tree + git history), Trivy, Semgrep, agent-scan |
| Code analysis (SAST) | Does our own code contain insecure patterns? | 6 | Semgrep, Bandit, ESLint security, SonarQube (optional) |
| Dependencies (SCA) | Do the libraries we use have known vulnerabilities? | 6 | pip-audit, npm audit, Trivy (CVEs, licences, SBOM), Dependency-Check (optional) |
| Container & IaC | Are Dockerfiles, images and Kubernetes manifests configured safely? | 8 | Trivy (Dockerfile, Kubernetes/Helm, Terraform/CloudFormation, image, CIS), kubescape; cluster/cloud docs + template |
| Dynamic testing (DAST) | Can a running app be attacked from outside? | 6 | OWASP ZAP (baseline, API, full, authenticated), Schemathesis, exposure scan |
| Supply chain & CI/CD | Can our pipeline or our dependencies be tampered with? | 5 | zizmor, repo-settings check, Dependabot/Renovate, signing + Scorecard templates |
| AI agent: static checks | Is the agent built unsafely (tools, guardrails, models, MCP, prompts)? | 29 | 17 Semgrep agent rules, 13 agent-scan checks, modelscan |
| AI agent: red-team probes | Does a running agent resist real attack attempts? | 21 | 19 deterministic probes; DeepTeam (7 frameworks) and promptfoo templates |
| AI agent: runtime controls (library) | Reusable code that gives an agent guardrails, authorisation, audit. | 16 | agentsec (16 modules) |
| Gate, policy & reporting | Decides pass/fail, reports and tracks results. | 13 | gate.py, crosswalk, SLA, dashboard, alerts, tickets |
| Developer workflow | Catches problems on the developer's machine before CI. | 4 | pre-push hook, pre-commit, PR template, IDE recommendations |
| Detection & response | Would we notice and react if something went wrong in production? | 2 | Falco rules (template), SIEM recipe |
| Process & governance | Do people have the procedures that tools cannot provide? | 1 | 9 process documents |
| **Total** |  | **123** | 21 scanner tools plus the library, gate and process kit |

A *check* is one rule, probe or control we can name. Scanner tools such as Semgrep contain thousands of rules; they are counted once. Categories 1-8 find problems (scanners, probes, template/doc checks); the rest are controls you embed, decision logic and process.

## 2. Status of every check

| Status | Meaning | Count |
|---|---|---|
| Verified | run end to end in this repo or on a real app | 90 |
| Verified (partial) | run, with a stated limit | 7 |
| Wired, not run | wired up but never run (needs a key) | 1 |
| Template | shipped template, not run with a real LLM | 8 |
| Reference library | working code with unit tests that you must wire into your platform | 14 |
| Not enforced | described in policy but not enforced | 0 |
| Documented | procedure or recipe, not code | 3 |

## 3. Coverage of the Agentic Security presentation

97 items checked (pillars, threats, controls, red-team frameworks, pipeline and tool slides, auth engine): **47 covered (48%), 47 partial (48%), 3 not covered (3%)**.

**Short answer: no, not everything in the presentation is covered.** Scanning, pipeline gates, red-team probes and the runtime-controls library are covered. Platform services (sandbox runtime, identity provider / vault, policy admin UI, runtime detection) and several data and output-integrity items are not, because they are not things a scanner can provide.

**What the words mean.** *Covered*: we ship working, tested code or a check for it (platform wiring, such as routing your agent through the sandbox, stays with the team). *Partial*: part of it is covered, or it is a template / recipe that has not run in a live environment. *Not covered*: nothing provided.

Not covered:

- **OWASP Agents: rogue agents** (Red-team frameworks): not provided
- **OWASP Agents: inter-agent communication** (Red-team frameworks): not provided
- **Platform services (policy engines, secure vault, resource registry, external RBAC, API gateway)** (Auth engine (PDP/PEP)): Platform components, not scanning

The full item-by-item table is in the Excel sheet *Presentation coverage*.

## 4. What cyber security means

Cyber security is protecting systems, networks, applications and data from unauthorised access, damage or disruption, and being able to detect and recover when something goes wrong. It is usually described by three goals: **confidentiality** (only the right people see the data), **integrity** (nothing is changed without permission, and tampering is noticed) and **availability** (the service keeps working).

| Area | Meaning | In this framework |
|---|---|---|
| Application security (AppSec) | Finding weaknesses in code and running apps before attackers do. | SAST, DAST, secrets, red-team probes |
| Software supply chain | Everything you pull in: libraries, base images, models, CI actions. | SCA, image scan, model scan; SBOM / signing missing |
| Infrastructure and cloud | Servers, containers, Kubernetes, networks, cloud settings. | Dockerfile / Kubernetes manifests only |
| Identity and access | Who or what is allowed to do what. | Authorisation checks, agent identity (reference) |
| Data protection and privacy | Classifying, minimising, masking and retaining personal data. | Partial |
| Detection and response | Monitoring production, alerting, handling incidents. | Not covered |
| Governance, risk and compliance | Policies, SLAs, audits, mapping to standards. | Gate, exceptions and dashboard; SLA and crosswalk missing |
| People and process | Training, reviews, threat modelling, penetration tests. | Not a tool: needs to be run by the team |

Our scans are **application and delivery-pipeline security** (the first rows), plus runtime controls for AI agents and starter kits for detection and process. That is one slice of cyber security: network, endpoint, cloud operations and people still need their own tools and activities.

## 5. Roadmap: what was added and what is still open

16 done, 6 partly, 1 documented only, 7 planned and not built (30 items incl. extras and the pen-test gaps).

| Priority | Area | Check | Status | What exists / what is missing |
|---|---|---|---|---|
| High | Secrets | Scan git history, not just the current files | Done | SEC_GITLEAKS_HISTORY: verified, shallow clones flagged |
| High | Supply chain | SBOM generation + licence compliance | Done | SEC_SBOM and Trivy licences: verified; licence data only where manifests carry it |
| High | Supply chain | Automated dependency-update pull requests | Done | warden init generates the config; GitHub's service not run here |
| High | Process | Enforce remediation SLAs and create tickets | Done | Gate + dashboard verified; tickets and alerts tested against mock servers |
| High | DAST | Authenticated and body-aware API testing | Done | Both verified; ZAP token reaches every request, fuzzer found 5xx on the sample |
| Medium | Supply chain | Image signing, build provenance, pinned CI actions | Partly | zizmor + pinned templates verified; signing/provenance and Scorecard are templates, never run |
| Medium | Kubernetes | Cluster posture and CIS benchmarks | Partly | Manifests (kubescape) and CIS Docker benchmark verified; live-cluster commands documented only |
| Medium | Cloud / IaC | Terraform / CloudFormation and cloud-posture checks | Partly | Terraform / CloudFormation verified; Prowler workflow is a template (no cloud account) |
| Medium | Exposure | External attack-surface and TLS checks | Done | Verified on mock servers and a live container; nuclei / testssl not used |
| Medium | Runtime | Runtime threat detection and alerting | Partly | Webhooks verified (mock); Falco rules validated but never run live; SIEM wiring is a recipe |
| Medium | AI | Real-LLM red teaming + content-safety datasets | Partly | BeaverTails and Aegis wired (dry-run); no real model run: needs an approved endpoint |
| Medium | AI | Output integrity / hallucination validation | Done | Library + optional probe, unit tested; you supply the certified source values |
| Medium | AI | Agent code-execution sandbox | Done | Verified on real Docker against hostile code; gVisor untested |
| Medium | Data | Data classification, stronger PII detection, retention and residency checks | Done | Libraries unit tested; Presidio optional; wiring is the platform's |
| Medium | Secrets | Vault integration and rotation checks | Done | Verified against a real Vault dev server; cloud secret managers not implemented |
| Low | Governance | Compliance crosswalk (NIST AI RMF, CSF 2.0, ISO 42001, EU AI Act, BFS) | Done | Verified; heuristic mapping, not a compliance verdict |
| Low | Developer | IDE plug-ins | Done | Template files written by init; not exercised in an IDE |
| Low | Testing | Fuzzing of parsers and APIs | Partly | API fuzzing verified; parser fuzzing (Atheris) not implemented |
| Low | Auth engine | PIP / PAP components | Done | Libraries unit tested; no admin UI |
| Low | People & process | Threat modelling, manual penetration test, code review, security training, incident-response runbook, access reviews | Documented | Templates and checklists only: people have to run them |
| High | Extra | GitHub repository settings check (branch protection, secret scanning ...) | Done | Added beyond the roadmap; verified on a real repo and mock API |
| Medium | Extra | GitHub Actions security (zizmor) | Done | Added beyond the roadmap; verified |
| Medium | Extra | Non-constant-time secret comparison rule | Done | Added beyond the roadmap; verified |
| High | Pen test | Port and service discovery (Nmap) on authorised hosts | Planned | Exposure scan covers a fixed list of risky ports only; full discovery not built |
| High | Pen test | Known-CVE and misconfiguration templates (Nuclei) | Planned | ZAP baseline only today |
| High | Pen test | Authorisation test pack (BOLA / IDOR, role escalation) | Planned | Schemathesis fuzzing does not check who may see which object |
| Medium | Pen test | Deep TLS testing | Planned | Basic TLS check exists in the exposure scan |
| Medium | Pen test | Session and token testing (JWT, cookies, rate limits, lockout) | Planned | Not covered |
| Medium | Pen test | Subdomain / asset discovery and DNS-email checks (SPF, DKIM, DMARC, takeover) | Planned | Not covered |
| Low | Pen test | Mobile application testing | Planned | Decide after the asset inventory |

## 6. How we know the framework itself works

| Suite | What it proves | Checks |
|---|---|---|
| scripts/selftest.sh | Gate logic, fail-closed, baseline, exceptions, degraded manifests, npm peer-conflict, tool plan, dashboard, platform templates, GitHub reporting | 22 |
| scripts/test-onboarding.sh | Developer journey on python / node / java / clean / agent repos; malicious config; tool switches; waivers | 83 |
| scripts/test-package.sh | pip install in a clean venv, thin init, shim, disable/enable, upgrade, uninstall, vendored mode, ci-report, auto-update channel, pin, release script | 83 |
| scripts/test-newtools.sh | SBOM, licences, git history, workflow scan, cluster posture, IaC, exposure, repo posture, API fuzz, authenticated ZAP, extra SAST packs | 29 |
| scripts/e2e-agent.sh | Vulnerable vs hardened agent: rules, probes, inventory, model scan, audit chain | 12 |
| scripts/test_gate.py | Finding identity, de-duplication, exclusions, waivers, dated baseline, SLA, control mapping (unit) | 28 |
| scripts/test_toolplan.py | Presets, per-tool switches, required-tool lock, waivers (unit) | 16 |
| scripts/test_dashboard.py | Dashboard auth, ingest, hostile input, views, SLA, alerts, publisher (unit) | 20 |
| scripts/test_tickets.py | Ticket creation for Jira / GitHub / Azure Boards against local stand-ins (unit) | 11 |
| scripts/test_platform_templates.py | Dependabot / Renovate, CI templates pinned and least-privilege, GitHub-native reporting wiring, Falco rules, process kit, SLA text (unit) | 11 |
| scripts/test_gh_report.py | GitHub summary, annotations, one pull request comment, escaping, limits, fork degradation (mock GitHub API) | 17 |
| scripts/test_tools.py | Exposure, repo-posture and API-fuzz helpers (unit) | 7 |
| agentic/tests/test_agentsec.py | Runtime-controls library (unit) | 24 |
| agentic/tests/test_agentsec_extra.py | Lineage, classification, retention, encrypted store, policy admin, network egress (unit) | 54 |
| agentic/tests/test_sandbox_docker.py | Agent code-execution sandbox in real Docker: no network, read-only, limits | 17 |
| agentic/tests/test_vault_docker.py | Vault secrets and rotation against a real Vault container | 8 |
| **Total** |  | **442** |
