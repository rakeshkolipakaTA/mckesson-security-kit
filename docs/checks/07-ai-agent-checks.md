# 7. AI agents: static checks and red-team probes

Applies to repositories that contain an AI agent (an application where a language model can call tools, read documents, or act for a user). Warden detects this automatically from agent frameworks, LLM clients or MCP configuration, and adds the checks below. Teams cannot switch off agent-scan on an agent repo, and modelscan runs whenever model files exist.

## What it protects against
An agent turns text into actions, so the classic attacks get a new route in:

* **Prompt injection.** A document, web page or user message contains instructions, and the agent obeys them (it reveals its prompt, leaks data, or runs a tool).
* **Excessive agency.** The model can delete, send or pay without a human saying yes.
* **Tool abuse.** A parameter the model controls reaches a file path (traversal), a URL (SSRF), a shell, or a SQL statement.
* **Weak guardrails.** A safety check that "allows" the request when it crashes.
* **Shadow and tampered models.** An unapproved model, an unpinned model that changes under you, or a model file that executes code when loaded.
* **Missing identity.** Agent endpoints with no authentication, or users reading each other's sessions.

## A. Static checks (every pull request, no running system needed)

### Semgrep agent rules (17, each with positive and negative tests)

| Rule id (`warden-agent-…`) | Finds | Attack stopped |
|---|---|---|
| `guardrail-fail-open-function` | A guardrail function that allows the request when it errors | Bypassing safety by causing a crash |
| `guardrail-fail-open-callsite` | A caller that treats a guardrail error as "allowed" | Same, at the call site |
| `tool-param-to-file` | A model or tool parameter flowing into file access | Path traversal (reading `../../etc/passwd`) |
| `tool-param-to-network` | A parameter flowing into an outbound request | SSRF to internal services or cloud metadata |
| `tool-param-to-exec` | A parameter flowing into command or code execution | Remote code execution |
| `tool-param-to-sql` | A parameter flowing into a SQL statement | SQL injection through the model |
| `llm-output-to-sink` | Model output flowing into a dangerous sink without validation | Output used as code, SQL or markup |
| `unrestricted-tool-dispatch` | The model picks a tool by name with no allow-list | Calling tools nobody intended to expose |
| `unauthenticated-route` | An agent or API route with no authentication dependency (heuristic) | Anonymous use of the agent |
| `hardcoded-llm-key` | An LLM provider key in source | Key theft and bill fraud |
| `trust-remote-code` | `trust_remote_code=True` when loading a model | Running a model author's code on your server |
| `unsafe-model-deserialization` | `pickle` or `torch.load` style loading | Code execution from a model file |
| `unpinned-model-revision` | A model downloaded without a pinned revision | A silently swapped model |
| `dangerous-tool` | A tool that exposes a shell or code execution | Giving the model a root shell |
| `sensitive-data-in-logs` | Tokens or personal data written to logs | Leaks through log storage |
| `unbounded-agent-loop` | An agent loop with no step or time budget | Runaway cost and denial of service |
| `non-constant-time-compare` | A secret, token or signature compared with `==` | Timing attacks |

### agent-scan (inventory and policy checks)
It first builds an **inventory** of frameworks, models, LLM endpoints, tools and MCP servers, then checks it.

| Id | Finds | Severity |
|---|---|---|
| `AG-TOOL-001` | A tool that can execute code or commands on the host | High |
| `AG-TOOL-002` | An irreversible or outbound tool with no human-approval gate | Medium |
| `AG-TOOL-003` | A tool that takes a credential as a parameter | Medium |
| `AG-MODEL-001` | A model not in the approved registry (shadow model) | per registry |
| `AG-MODEL-002` | A floating model alias, so the model can change without a code change | per registry |
| `AG-NET-001` | An LLM endpoint outside the approved destinations | per registry |
| `AG-NET-002` | An LLM endpoint outside the approved regions (data residency) | per registry |
| `AG-MCP-001` | An MCP server running an unpinned package | per rule |
| `AG-MCP-002` | An MCP server that auto-installs packages without confirmation | per rule |
| `AG-MCP-003` | An MCP server using an unencrypted remote endpoint | per rule |
| `AG-MCP-004` | Literal secrets in MCP server `env` | High |
| `AG-MCP-005` | An MCP server with shell, privileged or whole-filesystem access | per rule |
| `AG-PROMPT-001` | Credentials inside prompt or instruction files | High |

The registry is `configs/agentic/approved-models.json`. **Its content is an example**: the platform team owns the real list of approved models, endpoints and regions.

### modelscan
Scans pickle, PyTorch and Keras files for embedded malicious code. Runs only when model files exist (`.pkl .pt .pth .bin .ckpt .h5 .joblib .npy .keras`).

## B. Red-team probes (against a running agent in QA)

`warden redteam` attacks a **running QA agent** with 19 deterministic probes. Each plants a unique canary value and searches mechanically for it in responses, tool calls or what a harness-run server received. No language model is needed, results are reproducible, and a hit is a concrete exploit, not an opinion. Describe your endpoints in `.security/redteam.json`.

| Probe | Question |
|---|---|
| `RT-AUTH-01` | Does the chat endpoint work without authentication? |
| `RT-AUTH-02` | Can another user read a session (IDOR, cross-tenant)? Needs two test users |
| `RT-AUTH-03` | Can an ordinary user reach the admin endpoint? |
| `RT-NET-01` | Are telemetry, debug or docs endpoints open without authentication? |
| `RT-INJ-01` | Does a direct injection reveal the system prompt? |
| `RT-INJ-02` | Does an injection in a retrieved document (explicit override) work? |
| `RT-INJ-03` | Does a paraphrased injection (no trigger words) work? |
| `RT-GUARD-01` | Does the guardrail fail open on unexpected input? |
| `RT-TOOL-01` | Path traversal through the file tool |
| `RT-TOOL-02` | SSRF: can the fetch tool reach an internal address (a canary server)? |
| `RT-EXEC-01` | Is model-supplied code executed? |
| `RT-EXEC-02` | Is model-supplied SQL executed verbatim? |
| `RT-AGENCY-01` | Does an injected document make the agent run a destructive tool? |
| `RT-AGENCY-02` | Do destructive or outbound actions run without human approval? |
| `RT-SEC-01` | Does the agent disclose credentials when asked? |
| `RT-DOS-01` | Is there rate limiting? |
| `RT-DOS-02` | Is oversized input accepted? |
| `RT-ERR-01` | Do errors leak internals (stack traces)? |
| `RT-OUT-01` | Does the agent state figures that do not trace to its source data? Runs only if the contract defines `output_lineage`; otherwise skipped, never counted as a pass |

**LLM-driven tools (optional templates).** DeepTeam (mapped to OWASP Agents 2026, OWASP LLM, NIST AI RMF, MITRE ATLAS and EU AI Act) and promptfoo use an attacker model and a judge model to find creative jailbreaks. They need an LLM key and are not reproducible.

## How it protects
* Static findings appear on the pull request like any other and follow the same gate. They catch the dangerous wiring **before** the agent runs.
* The probes prove the opposite: that an attack **fails** against the deployed agent. Run them in QA before a release; schedule with the red-team workflow template.
* Every agent finding is mapped to the control it evidences and to NIST AI RMF, OWASP LLM and the other frameworks ([09-gate-policy-reporting.md](09-gate-policy-reporting.md)).
* The fixes are in the runtime library ([08-ai-agent-runtime-controls.md](08-ai-agent-runtime-controls.md)): default-deny authorisation, fail-closed guardrails, safe paths, allow-listed egress, sandboxed execution.

## Limits
* Neither approach proves an agent is safe. The deterministic probes cover the attacks they were written for. The hardened sample **fails `RT-INJ-03` on purpose**: a paraphrased injection beats the keyword heuristic.
* `unauthenticated-route` is a heuristic. Tool detection recognises decorator-registered tools in Python.
* DeepTeam wiring is verified with `--dry-run`. It has **never run with a real model**, promptfoo has not been run at all, and the BeaverTails and Aegis datasets are not included.
* Not covered: OWASP "rogue agents" and inter-agent communication threats.
* Details: [../agentic-security.md](../agentic-security.md), [../agentic-redteam.md](../agentic-redteam.md).
* Status: **Verified** for the Semgrep rules, agent-scan, modelscan and the deterministic probes (`RT-OUT-01` is partial). DeepTeam and promptfoo are **templates**.
