# Agentic AI security: what the framework covers

Companion to the *Agentic Security* presentation (domains P1-P8, the threat catalog and the architectural controls). Same pipeline as the rest of the
framework (`secscan`), plus agent-specific checks that switch on automatically when a repo uses an agent framework, an LLM SDK or MCP.

## How the pieces fit
| Phase (presentation) | What runs | Where |
|---|---|---|
| **Design / build**: runtime controls | `agentsec` reference library: policy engine (PDP/PEP), fail-closed guardrails, safe paths, egress control, PII masking, approval gate, budgets, hash-chained audit log | `agentic/agentsec/` ([guide](agentic-runtime-library.md)) |
| **Pull request**: static checks | 16 agent-specific Semgrep rules; inventory + registry scan (models, endpoints, tools, MCP servers, prompt secrets); model-file scan (malicious pickle/PyTorch); plus the normal SAST/SCA/secrets/IaC | `secscan scan` (profile `agent` is auto-detected) |
| **Deployment**: pipeline gates | image scan, release gate, DAST | [cd-release-gates.md](cd-release-gates.md) |
| **QA / pre-release**: dynamic testing | deterministic red-team probes (canary based, no LLM needed); LLM-driven red teaming templates (DeepTeam, promptfoo) | `secscan redteam` ([guide](agentic-redteam.md)) |
| **Runtime** | the controls inside your app (above) and the audit log | not a monitoring product: see gaps |

## Coverage by domain
Status legend: **Verified** = exercised end to end in this repo; **Reference** = working code with unit tests that you must wire into your platform;
**Template** = shipped but not run end to end; **Gap** = not covered (an honest list, below each row where relevant).

| Domain / control (presentation) | What is provided | Status |
|---|---|---|
| **P1** Centralised Authorization Proxy | `PDP`/`PEP` (default-deny, roles, scopes, argument constraints, `require_owner` incl. cross-tenant). Detection: Semgrep `unauthenticated-route` (heuristic); probes RT-AUTH-01/02/03 (anonymous access, IDOR, admin exposure) | Verified (probes + library) |
| **P1** Agent Identity & Credential Broker | `CredentialBroker`: distinct agent principal, short-lived tokens scoped to one audience + scopes, naming the human acted for. Detection: tools taking credential parameters (AG-TOOL-003), hardcoded keys | Reference. **Gap**: not an IdP/vault; real token exchange with third-party apps (the Token Exchange slide) is an architecture task |
| **P2** Hardened Execution Sandbox | Detection only: code/shell tools (Semgrep, AG-TOOL-001, MCP shell/privileged AG-MCP-005), probes RT-EXEC-01/02 | **Gap**: no sandbox runtime is provided (use gVisor / Firecracker / an ephemeral container service) |
| **P2** Resilience & Safe Failure | `Budget` (steps, tool calls, time, output), `RateLimiter`, generic error handling. Detection: unbounded loop rule; probes RT-DOS-01/02, RT-ERR-01 | Verified |
| **P3** Deterministic Guardrail Plane | `enforce()` fail-closed guards (error, timeout, `None`, non-boolean, empty list all block). Detection: guardrail fail-open rules; probe RT-GUARD-01 | Verified |
| **P3** Trusted I/O Boundary | `safe_path`; Semgrep taint rules (tool parameter to file/network/exec/SQL); probe RT-TOOL-01 | Verified |
| **P3** Output Integrity & Lineage | none | **Gap** (hallucination validation, figure lineage) |
| **P3** Retrieval Corpus Integrity | `wrap_untrusted`, `detect_injection` (heuristic); probes RT-INJ-02/03/RT-AGENCY-01 | Verified, **with a known limit**: paraphrased injections pass the heuristic (RT-INJ-03 fails on the hardened sample on purpose) |
| **P4** Egress Control | `safe_fetch`/`validate_url` (allow-list, public IPs only, redirect re-validation, connection pinned to the validated IP, TLS on); taint rule; probe RT-TOOL-02 with a harness-run canary server | Verified |
| **P4** Container & Cluster Hardening | Trivy checks Dockerfiles (root user, ADD, secrets in ENV) and image contents | Verified for Dockerfile/image. Kubernetes manifest checks come from Trivy's built-in misconfiguration scanner, **not tested here**; default-deny cluster policy is out of scope |
| **P5** Secrets Lifecycle | gitleaks/Trivy/Semgrep/AG-PROMPT-001 (secrets in prompts and MCP env); `redact`/`redact_obj`; broker tokens | Verified (detection), Reference (masking). **Gap**: no vault/rotation service |
| **P6** Supply Chain Assurance | pip-audit, `npm audit`, Trivy, Dependency-Check; `modelscan` for model files; Semgrep unsafe-model rules; MCP server pinning checks | Verified (Dependency-Check wired, not run) |
| **P6** Model Governance & Provenance | Registry check (`configs/agentic/approved-models.json`): unregistered/floating models and unapproved LLM endpoints (AG-MODEL-001/002, AG-NET-001) | Verified. The registry content is an **example**; the platform team owns it. **Gap**: nothing blocks an unregistered model at run time |
| **P7** Data Protection & Minimisation | `redact` (emails, phones, cards with Luhn, SSN, Aadhaar, PAN, tokens, JWTs, keys); Semgrep sensitive-data-in-logs; endpoint approval | Reference. **Gap**: regex masking misses names/addresses; no classification, residency or retention enforcement |
| **P8** Human Oversight & Autonomy Bounds | `PEP` approval gate (only an explicit `True` approves; error = no); AG-TOOL-002; probes RT-AGENCY-01/02 | Verified. **Gap**: the approval *workflow/UI* is yours; the library calls your `approver` callback |
| **P8** Immutable Audit & Non-Repudiation | `AuditLog`: JSON lines, each record hashed with the previous (optional HMAC), PII masked, `verify_chain` finds edits/deletions | Reference. **Gap**: ship to WORM storage / SIEM; reasoning-path logging is app specific |
| **P8** Continuous Assurance & Detection | Red-team probes in CI on a schedule; DeepTeam/promptfoo templates | Probes verified; LLM-driven tools = Template. **Gap**: runtime detection (Datadog / Sentinel / eBPF) is not part of this framework |

## OWASP LLM Top 10 (2025) quick map
| Risk | Covered by |
|---|---|
| LLM01 Prompt injection | RT-INJ-01/02/03, RT-GUARD-01, `detect_injection`, guard rules |
| LLM02 Sensitive information disclosure | RT-SEC-01, AG-PROMPT-001, redact, logging rule |
| LLM03 Supply chain | pip-audit/Trivy/modelscan, AG-MODEL/MCP rules, unsafe-load rules |
| LLM04 Data/model poisoning | RT-INJ-02/03 (RAG), modelscan; no training-pipeline coverage |
| LLM05 Improper output handling | llm-output-to-sink and tool-param taint rules, RT-EXEC-01/02, XSS rules |
| LLM06 Excessive agency | PEP/approval, AG-TOOL-001/002, RT-AGENCY-01/02, RT-AUTH-* |
| LLM07 System prompt leakage | RT-INJ-01, AG-PROMPT-001 |
| LLM08 Vector/embedding weaknesses | partial: RAG ingestion probes only |
| LLM09 Misinformation | **not covered** |
| LLM10 Unbounded consumption | Budget, RateLimiter, RT-DOS-01/02, loop rule |

## What was tested, and how
`make e2e-agent` builds a deliberately **vulnerable** agent and the **same agent hardened with agentsec**, both driven by the same naive mock LLM, and asserts (12 checks):
the vulnerable one fails the gate with 18+ red-team failures, 12+ governance findings and every agent Semgrep rule firing; the hardened one has no agent findings, passes
all probes except the paraphrased-injection one, and its audit chain verifies; a malicious pickle is flagged CRITICAL.
**Limits to keep in mind**: the mock LLM is a stand-in, so results prove the *application's* controls (auth, tools, guardrails, egress) and the *harness*, not the robustness of
any real model to jailbreaks. The registry is an example. Nothing here has been run against a real production agent platform.
