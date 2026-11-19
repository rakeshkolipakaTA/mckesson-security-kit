# agent-sample-secure (reference: the same agent, hardened with `agentic/agentsec`)
Same endpoints and the **same naive mock LLM** as `../agent-sample/`. The model is just as gullible; the *application* no longer trusts it.
Run the red-team harness against both: the vulnerable one fails most probes, this one passes them (`scripts/e2e-agent.sh`).

| Control (presentation) | How it is done here |
|---|---|
| P1 Authorization proxy / identity | bearer token verified per request (`CredentialBroker`), object ownership on sessions (404 for others), admin role for `/admin/*`, per-user tenant |
| P2 Sandbox / safe failure | `python_exec` and `sql_query` are not in the policy (denied); step + tool-call budget; rate limit; generic error responses |
| P3 Deterministic guardrails / trusted I/O | output guards **fail closed** (`agentsec.enforce`); `safe_path` for files; RAG ingestion screened with `detect_injection`; untrusted data envelope |
| P4 Egress | `safe_fetch` with an allow-list, public IPs only, pinned connection, TLS verify on |
| P5 Secrets / PII | secrets only from the environment; the system prompt contains none; prompts and logs pass through `redact` |
| P6 Provenance | registered, version-pinned model id; pinned MCP servers; no dangerous framework flags |
| P8 Oversight / audit | PDP/PEP default-deny; destructive tools need human approval (`pending_approval`); every decision in a hash-chained audit log |
Limits: the injection screen is heuristic; the mock model is not a real LLM; this is a reference, not a certified design.
