# What we test: coverage by category

Generated from `tools/coverage_data.py` on 2026-11-19. The same data is in [security-test-coverage.xlsx](security-test-coverage.xlsx) (filterable, with roadmap and glossary).

## 1. Categories and how many checks each has

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

A *check* is one rule, probe or control we can name. Scanner tools such as Semgrep contain thousands of rules; they are counted once. The first seven categories are tests that find problems; the last three are controls, decision logic and workflow.

## 2. Status of every check

| Status | Meaning | Count |
|---|---|---|
| Verified | run end to end in this repo or on a real app | 69 |
| Verified (partial) | run, with a stated limit | 3 |
| Wired, not run | wired up but never run (needs a key) | 1 |
| Template | shipped template, not run with a real LLM | 2 |
| Reference library | working code with unit tests that you must wire into your platform | 9 |
| Not enforced | described in policy but not enforced | 1 |

## 3. Coverage of the Agentic Security presentation

97 items checked (pillars, threats, controls, red-team frameworks, pipeline and tool slides, auth engine): **33 covered (34%), 44 partial (45%), 20 not covered (21%)**.

**Short answer: no, not everything in the presentation is covered.** Scanning, pipeline gates, red-team probes and the runtime-controls library are covered. Platform services (sandbox runtime, identity provider / vault, policy admin UI, runtime detection) and several data and output-integrity items are not, because they are not things a scanner can provide.

Not covered:

- **2. Tool isolation & sandboxing** (Key pillars): No sandbox runtime: use gVisor / Firecracker / ephemeral containers
- **Erroneous analytical output (hallucination)** (Threat catalog P3): No output validation / lineage checks
- **Unencrypted agent state & memory at rest** (Threat catalog P5): Not checked
- **Undetected agent compromise** (Threat catalog P8): No runtime detection, baseline or alerting
- **P2 Hardened Execution Sandbox** (Architectural controls): No sandbox runtime
- **P3 Output Integrity & Lineage** (Architectural controls): No validation of reported figures
- **NIST AI RMF / NIST CSF 2.0 / ISO 42001 / EU AI Act / BFS themes mapping** (Governance crosswalk): The presentation has the mapping; a per-finding crosswalk is not built
- **BeaverTails** (Red-team frameworks): Not wired
- **Aegis** (Red-team frameworks): Not wired
- **OWASP Agents: rogue agents** (Red-team frameworks): not provided
- **OWASP Agents: inter-agent communication** (Red-team frameworks): not provided
- **Automated PR remediation (Snyk-style fix PRs)** (DevSecOps pipeline): Add Dependabot or Renovate
- **IDE extension scanners** (DevSecOps pipeline): Not provided
- **eBPF runtime observability** (DevSecOps pipeline): Not provided (Falco / Tetragon)
- **Dynamic secret rotation** (DevSecOps pipeline): Not provided
- **Private cluster ingress** (DevSecOps pipeline): Infrastructure setting, not a scan
- **PIP: policy information point** (Auth engine (PDP/PEP)): not provided
- **PAP: policy administration point (UI / API)** (Auth engine (PDP/PEP)): Policies are code / config
- **Platform services (policy engines, secure vault, resource registry, external RBAC, API gateway)** (Auth engine (PDP/PEP)): Platform components, not scanning
- **Agent sandbox execution (linked design doc)** (Auth engine (PDP/PEP)): Not provided

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

Our scans are **application and delivery-pipeline security** (the first rows). That is one slice of cyber security: network, endpoint, cloud, detection and response, and people and process need other tools and activities.

## 5. Other checks worth adding (priority order)

| Priority | Area | Missing check | Why | Suggested tool | Effort |
|---|---|---|---|---|---|
| High | Secrets | Scan git history, not just the current files | A secret deleted in a later commit is still in the history and still valid | gitleaks git mode | Small |
| High | Supply chain | SBOM generation + licence compliance | Know exactly what ships; block disallowed licences; answer 'are we affected by CVE-X?' in minutes | Trivy / Syft (CycloneDX, SPDX) | Small |
| High | Supply chain | Automated dependency-update pull requests | Turns the report into fixes (presentation: Snyk-style remediation) | Dependabot or Renovate | Small |
| High | Process | Enforce remediation SLAs and create tickets | Findings only get fixed when they have an owner and a deadline; policy lists SLAs but nothing enforces them | Dashboard age tracking + Jira / Azure Boards / GitHub issues | Medium |
| High | DAST | Authenticated and body-aware API testing | Most real bugs sit behind login; current ZAP runs are unauthenticated | ZAP automation plans, Schemathesis (from OpenAPI) | Medium |
| Medium | Supply chain | Image signing, build provenance, pinned CI actions | Proves the image you deploy is the one you built; stops tampered CI steps | cosign, SLSA provenance, zizmor / pinact, OpenSSF Scorecard | Medium |
| Medium | Kubernetes | Cluster posture and CIS benchmarks | Manifests are scanned, but the live cluster (RBAC, network policy) is not | Kubescape, kube-bench, Trivy compliance profiles | Medium |
| Medium | Cloud / IaC | Terraform / CloudFormation and cloud-posture checks | Public buckets, open security groups, unnecessary load balancers (presentation item) | Trivy config / Checkov, Prowler | Medium |
| Medium | Exposure | External attack-surface and TLS checks | Finds public OTEL / debug endpoints and weak TLS from the outside | nuclei, nmap, testssl.sh | Medium |
| Medium | Runtime | Runtime threat detection and alerting | Spots a compromised agent or container in production (presentation: eBPF, SIEM) | Falco / Tetragon, Sentinel / Datadog integration | Large |
| Medium | AI | Real-LLM red teaming + content-safety datasets | The mock-LLM tests prove app controls, not model robustness | DeepTeam / promptfoo with an approved model; BeaverTails, Aegis | Medium |
| Medium | AI | Output integrity / hallucination validation | Plausible wrong numbers reaching a business decision (OWASP LLM09) | Schema + source-lineage checks, evaluation sets | Large |
| Medium | AI | Agent code-execution sandbox | Contains an agent that is tricked into running code | gVisor, Firecracker, ephemeral containers | Large |
| Medium | Data | Data classification, stronger PII detection, retention and residency checks | Regex masking misses names and addresses; no retention or region enforcement | Microsoft Presidio, DLP tooling | Large |
| Medium | Secrets | Vault integration and rotation checks | Static unrotated keys are a listed threat | HashiCorp Vault / cloud secret manager | Large |
| Low | Governance | Compliance crosswalk (NIST AI RMF, CSF 2.0, ISO 42001, EU AI Act, BFS) | Auditors ask which control covers which requirement | Generated mapping per finding / control | Small |
| Low | Developer | IDE plug-ins | Catch issues while typing | Semgrep / Sonar IDE extensions | Small |
| Low | Testing | Fuzzing of parsers and APIs | Finds crashes and memory bugs static tools miss | Atheris, Schemathesis | Medium |
| Low | Auth engine | PIP / PAP components | Context-aware decisions and a policy admin interface | OPA / Cedar with an admin UI | Large |
| Low | People & process | Threat modelling, manual penetration test, code review, security training, incident-response runbook, access reviews | Tools find known patterns; people find design flaws and handle incidents | Recurring human activities | Ongoing |

## 6. How we know the framework itself works

| Suite | What it proves | Checks |
|---|---|---|
| scripts/selftest.sh | Gate logic, fail-closed, baseline, exceptions, degraded manifests, npm peer-conflict, tool plan, dashboard | 16 |
| scripts/test-onboarding.sh | Developer journey on python / node / java / clean / agent repos; malicious config; tool switches; waivers | 83 |
| scripts/test-package.sh | pip install in a clean venv, thin init, shim, disable/enable, upgrade, uninstall, vendored mode | 46 |
| scripts/e2e-agent.sh | Vulnerable vs hardened agent: rules, probes, inventory, model scan, audit chain | 12 |
| scripts/test_gate.py | Finding identity, de-duplication, exclusions, waivers (unit) | 19 |
| scripts/test_toolplan.py | Presets, per-tool switches, required-tool lock, waivers (unit) | 14 |
| scripts/test_dashboard.py | Dashboard auth, ingest, hostile input, views, publisher (unit) | 10 |
| agentic/tests/test_agentsec.py | Runtime-controls library (unit) | 24 |
| **Total** |  | **224** |
