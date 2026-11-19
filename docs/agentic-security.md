# Agentic AI security: what the framework covers

Companion to the *Agentic Security* presentation (domains P1-P8, the threat catalog and the architectural controls). Same pipeline as the rest of the
framework (`warden`), plus agent-specific checks that switch on automatically when a repo uses an agent framework, an LLM SDK or MCP.

## How the pieces fit
| Phase (presentation) | What runs | Where |
|---|---|---|
| **Design / build**: runtime controls | `agentsec` reference library: policy engine (PDP/PEP), fail-closed guardrails, safe paths, egress control, PII masking, approval gate, budgets, hash-chained audit log | `agentic/agentsec/` ([guide](agentic-runtime-library.md)) |
| **Pull request**: static checks | 17 agent-specific Semgrep rules (incl. non-constant-time secret comparison); inventory + registry scan (models, endpoints, tools, MCP servers, prompt secrets); model-file scan (malicious pickle/PyTorch); plus the normal SAST/SCA/secrets/IaC | `warden scan` (profile `agent` is auto-detected) |
| **Deployment**: pipeline gates | image scan, release gate, DAST | [cd-release-gates.md](cd-release-gates.md) |
| **QA / pre-release**: dynamic testing | deterministic red-team probes (canary based, no LLM needed); LLM-driven red teaming templates (DeepTeam, promptfoo) | `warden redteam` ([guide](agentic-redteam.md)) |
| **Runtime** | the controls inside your app (above) and the audit log | not a monitoring product: see gaps |

## Coverage by domain
Status legend: **Verified** = exercised end to end in this repo; **Reference** = working code with unit tests that you must wire into your platform;
**Template** = shipped but not run end to end; **Gap** = not covered (an honest list, below each row where relevant).

| Domain / control (presentation) | What is provided | Status |
|---|---|---|
| **P1** Centralised Authorization Proxy | `PDP`/`PEP` (default-deny, roles, scopes, argument constraints, `require_owner` incl. cross-tenant). **PIP**: `PDP(policy, context=[provider])` feeds attributes (risk score, device, hours ...) into `conditions`; a failing provider or missing attribute denies. **PAP**: `PolicyStore` validates (typos are errors), versions, atomically writes, enables/disables agents or tools (kill switch) and logs every change to the audit chain; `python -m agentsec.policy_admin validate FILE`. Detection: Semgrep `unauthenticated-route` (heuristic); probes RT-AUTH-01/02/03 | Verified (probes + library, 30+ unit tests). **Gap**: the proxy/gateway deployment and an admin UI/RBAC for the store are yours |
| **P1** Agent Identity & Credential Broker | `CredentialBroker`: distinct agent principal, short-lived tokens scoped to one audience + scopes, naming the human acted for. Detection: tools taking credential parameters (AG-TOOL-003), hardcoded keys | Reference. **Gap**: not an IdP/vault; real token exchange with third-party apps (the Token Exchange slide) is an architecture task |
| **P2** Hardened Execution Sandbox | `agentsec.sandbox.run_python/run_command`: throw-away Docker container with no network, read-only root, tmpfs-only writes, non-root, all capabilities dropped, no-new-privileges, pid/memory/cpu/fd limits, wall-clock kill, capped output, no host mounts or env, `runtime="runsc"` for gVisor; refuses (never runs on the host) if Docker or the image is missing. Detection: code/shell tools (Semgrep, AG-TOOL-001, MCP AG-MCP-005), probes RT-EXEC-01/02 | Verified with real Docker (17 tests: network, writes, fork bomb, memory bomb, infinite loop, output flood, host files, capabilities). **Limit**: containers share the host kernel; gVisor/Firecracker/a separate node pool is the stronger boundary and was **not tested here** (runsc not installed) |
| **P2** Resilience & Safe Failure | `Budget` (steps, tool calls, time, output), `RateLimiter`, generic error handling. Detection: unbounded loop rule; probes RT-DOS-01/02, RT-ERR-01 | Verified |
| **P3** Deterministic Guardrail Plane | `enforce()` fail-closed guards (error, timeout, `None`, non-boolean, empty list all block). Detection: guardrail fail-open rules; probe RT-GUARD-01 | Verified |
| **P3** Trusted I/O Boundary | `safe_path`; Semgrep taint rules (tool parameter to file/network/exec/SQL); probe RT-TOOL-01 | Verified |
| **P3** Output Integrity & Lineage | `agentsec.output`: every figure in an answer must match a certified source value (tool result) within rounding + tolerance (scaled units, percents, optional derived values); schema validation; structured violations, `require_valid()` fails closed, any checker error rejects. Probe RT-OUT-01 (needs `output_lineage` in the red-team contract; skipped, never passed, when unset) | Verified (unit tests + probe against a fake agent). **Limits**: checks numbers, not whether a *claim* is true; correct numbers in a misleading sentence pass; answers without figures are not checked |
| **P3** Retrieval Corpus Integrity | `wrap_untrusted`, `detect_injection` (heuristic); probes RT-INJ-02/03/RT-AGENCY-01 | Verified, **with a known limit**: paraphrased injections pass the heuristic (RT-INJ-03 fails on the hardened sample on purpose) |
| **P4** Egress Control | `safe_fetch`/`validate_url` (allow-list, public IPs only, redirect re-validation, connection pinned to the validated IP, TLS on); taint rule; probe RT-TOOL-02 with a harness-run canary server | Verified |
| **P4** Container & Cluster Hardening | Trivy checks Dockerfiles (root user, ADD, secrets in ENV) and image contents | Verified for Dockerfile/image. Kubernetes manifest checks come from Trivy's built-in misconfiguration scanner, **not tested here**; default-deny cluster policy is out of scope |
| **P5** Secrets Lifecycle | gitleaks/Trivy/Semgrep/AG-PROMPT-001 (secrets in prompts and MCP env); `redact`/`redact_obj`; broker tokens. `agentsec.secrets`: env / file / **HashiCorp Vault KV v2** providers (token or AppRole, namespace, TTL cache, re-login on expiry), `Secret` that never prints, `RotatingSecret` + `age_report()` (age from Vault `created_time`, unknown age = needs rotation). `agentsec.state.EncryptedStore`: agent memory encrypted at rest (Fernet, bound to key name, key rotation). Semgrep `non-constant-time-compare` | Vault provider verified against a **real dev-mode Vault container** (8 tests) and a mock; EncryptedStore unit-tested (needs `cryptography`). **Gaps**: rotation of third-party credentials is your refresh callback; no lease renewal/dynamic secrets; cloud secret managers (AWS/Azure/GCP) are not implemented |
| **P6** Supply Chain Assurance | pip-audit, `npm audit`, Trivy, Dependency-Check; `modelscan` for model files; Semgrep unsafe-model rules; MCP server pinning checks | Verified (Dependency-Check wired, not run) |
| **P6** Model Governance & Provenance | Registry check (`configs/agentic/approved-models.json`): unregistered/floating models and unapproved LLM endpoints (AG-MODEL-001/002, AG-NET-001) | Verified. The registry content is an **example**; the platform team owns it. **Gap**: nothing blocks an unregistered model at run time |
| **P7** Data Protection & Minimisation | `redact` (emails, phones, Luhn cards, SSN, Aadhaar, PAN, tokens, JWTs, keys, **names after an honorific, simple street addresses**; optional `presidio=True` for free-text names/places). `agentsec.classify`: PUBLIC/INTERNAL/CONFIDENTIAL/RESTRICTED with PHI, MNPI, financial, HR, legal rules, pluggable, `enforce_max_level()` gate before data reaches a model. `agentsec.retention`: purge JSONL/sqlite by age, dry-run default, minimum-retention floor, audit chain stays verifiable. Residency: `AG-NET-002` flags endpoints/Bedrock clients outside `approved_regions`. Semgrep sensitive-data-in-logs; endpoint approval | Unit-tested; Presidio verified in a scratch venv with `en_core_web_sm`. **Gaps**: rule-based classification (no ML), names without an honorific and non-US addresses are missed by the regex layer, retention is file/table level only (not vector stores, object storage or backups), residency is a static code check of regions named in code, not runtime enforcement |
| **P8** Human Oversight & Autonomy Bounds | `PEP` approval gate (only an explicit `True` approves; error = no); AG-TOOL-002; probes RT-AGENCY-01/02 | Verified. **Gap**: the approval *workflow/UI* is yours; the library calls your `approver` callback |
| **P8** Immutable Audit & Non-Repudiation | `AuditLog`: JSON lines, each record hashed with the previous (optional HMAC), PII masked, `verify_chain` finds edits/deletions; `retention.purge_jsonl` keeps the chain verifiable through an anchor file; policy changes are audited too | Reference. **Gap**: ship to WORM storage / SIEM; reasoning-path logging is app specific |
| **P8** Continuous Assurance & Detection | Red-team probes in CI on a schedule; DeepTeam/promptfoo templates | Probes verified; LLM-driven tools = Template. **Gap**: runtime detection (Datadog / Sentinel / eBPF) is not part of this framework |

## OWASP LLM Top 10 (2025) quick map
| Risk | Covered by |
|---|---|
| LLM01 Prompt injection | RT-INJ-01/02/03, RT-GUARD-01, `detect_injection`, guard rules |
| LLM02 Sensitive information disclosure | RT-SEC-01, AG-PROMPT-001, redact, classify, logging rule, AG-NET-002 |
| LLM03 Supply chain | pip-audit/Trivy/modelscan, AG-MODEL/MCP rules, unsafe-load rules |
| LLM04 Data/model poisoning | RT-INJ-02/03 (RAG), modelscan; no training-pipeline coverage |
| LLM05 Improper output handling | llm-output-to-sink and tool-param taint rules, RT-EXEC-01/02, XSS rules |
| LLM06 Excessive agency | PEP/approval, AG-TOOL-001/002, RT-AGENCY-01/02, RT-AUTH-* |
| LLM07 System prompt leakage | RT-INJ-01, AG-PROMPT-001 |
| LLM08 Vector/embedding weaknesses | partial: RAG ingestion probes only |
| LLM09 Misinformation | partial: `agentsec.output` (figures must trace to certified sources) and probe RT-OUT-01; claims without figures are not checked |
| LLM10 Unbounded consumption | Budget, RateLimiter, RT-DOS-01/02, loop rule |

## What was tested, and how
`make e2e-agent` builds a deliberately **vulnerable** agent and the **same agent hardened with agentsec**, both driven by the same naive mock LLM, and asserts (12 checks):
the vulnerable one fails the gate with 18+ red-team failures, 12+ governance findings and every agent Semgrep rule firing; the hardened one has no agent findings, passes
all probes except the paraphrased-injection one, and its audit chain verifies; a malicious pickle is flagged CRITICAL.
**Limits to keep in mind**: the mock LLM is a stand-in, so results prove the *application's* controls (auth, tools, guardrails, egress) and the *harness*, not the robustness of
any real model to jailbreaks. The registry is an example. Nothing here has been run against a real production agent platform.
