# agentsec: runtime controls for agents (reference library)

Python, **standard library only**, `agentic/agentsec/`. Copy it into your service: `.security/secscan agentlib` (creates `./agentsec/`).
These are building blocks and reference implementations: review them, then connect them to your IdP, vault, gateway and SIEM. 24 unit tests: `python3 -I agentic/tests/test_agentsec.py`.
A complete hardened agent using all of them: `examples/agent-sample-secure/`.

| Need | Use | Behaviour worth knowing |
|---|---|---|
| Who may call which tool | `PDP(policy)`, `PEP(pdp, audit, approver)` | default-deny; unknown agent/tool/role/scope = deny; a policy bug = deny; argument rules (`max_len`, `enum`, `regex`) checked before anything runs |
| Human approval for risky tools | `"approval": true` in policy + `approver` callback | only an explicit `True` approves; `None`, errors, truthy non-booleans = `ApprovalRequired` (return "pending approval" to the user) |
| Only my own data | `require_owner(principal, owner, tenant)` | cross-tenant is always denied (even admins); return the same 404 for missing and forbidden |
| Agent identity, scoped tokens | `CredentialBroker(secret).issue(...)` / `.verify(token, audience=..., scope=...)` | short-lived, one audience, few scopes, `act` names the human; constant-time compare. **Reference only**: use your IdP/vault in production |
| Guardrails that cannot fail open | `enforce(text, [check1, check2], timeout=2)` | an exception, timeout, `None`, non-bool or empty list = block |
| Files from model/user input | `safe_path(base, user_path)` | rejects `..`, absolute paths, NUL, symlinks leaving the base |
| Web access from a tool | `safe_fetch(url, allow_hosts=[...])` / `validate_url` | allow-list required; public IPs only (blocks loopback, private, link-local, metadata); redirects re-validated; connection pinned to the validated IP; TLS verification always on |
| Masking secrets/PII in logs, prompts | `redact(text)`, `redact_obj(dict)` | emails, phones, Luhn-valid cards, SSN, Aadhaar, PAN, JWTs, API keys; sensitive keys removed. **Regex only**: not a complete PII detector |
| Retrieved text is data | `wrap_untrusted(text, source)`, `detect_injection(text)` | random per-call envelope; the detector is heuristic and misses paraphrases |
| Bounded runs | `Budget(max_steps, max_tool_calls, max_seconds, max_output_bytes)`, `RateLimiter(n, seconds)` | raise `BudgetExceeded` / return False |
| Tamper-evident audit | `AuditLog(path, key=...)`, `verify_chain(path, key=...)` | hash-chained (optionally HMAC); PII masked; detects edits, deletions, reordering. Ship to WORM storage/SIEM too |
| Leak detection in tests | `make_canary()` | unique marker to plant and search for |

## Wiring sketch (FastAPI)
```python
from agentsec import PDP, PEP, AuditLog, CredentialBroker, Principal, Budget, enforce, redact, safe_path
pep = PEP(PDP(POLICY), AuditLog("/var/log/agent-audit.jsonl", key=os.environ["AUDIT_KEY"]), approver=None)

def call_tool(principal, agent_id, name, args):            # the model proposes; code decides
    return pep.call(principal, agent_id, name, TOOLS[name], **args)
# every tool implementation validates its own inputs too: safe_path(...), safe_fetch(...)
```
Principle (slide: *Deterministic Guardrail Plane*): the model may *propose* an action, but authorization, limits, approval and output filtering are decided by code that the model cannot talk its way past.
