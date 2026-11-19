# agent-sample (TEST FIXTURE - intentionally vulnerable AI agent service)
A small FastAPI "agent" with a deterministic **mock LLM** (no API key, no network): it behaves like a naive, instruction-following model.
The weaknesses are in the *application* (auth, tools, guardrails, logging, supply chain), which is where most agent incidents happen.
Secrets are fake. Never deploy. The hardened counterpart is `../agent-sample-secure/`.

| Area (presentation domain) | Planted weakness |
|---|---|
| P1 identity | no authentication on `/chat`, `/admin/agents`, `/metrics`; sequential session ids with no ownership check (IDOR / cross-tenant) |
| P2 execution | `python_exec` tool runs model-supplied code; `sql_query` runs model-supplied SQL; unbounded agent loop; no rate limit |
| P3 logic | guardrail **fails open** on errors; `read_file` path traversal; indirect prompt injection through RAG documents; no tool allow-list |
| P4 network | `http_fetch` tool is an SSRF primitive (no egress control, TLS verification off) |
| P5 secrets | hardcoded LLM API key, key inside the system prompt, prompts + PII written to logs |
| P6 supply chain | unregistered/unpinned model id, unpinned MCP server (`npx -y`), plaintext MCP endpoint with a literal token, dangerous framework flags |
| P8 oversight | destructive tools (`delete_records`, `send_email`) run with no human approval; no audit trail |
