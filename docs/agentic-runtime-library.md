# agentsec: runtime controls for agents (reference library)

Python, **standard library only**, `agentic/agentsec/`. Copy it into your service: `.security/warden agentlib` (creates `./agentsec/`).
These are building blocks and reference implementations: review them, then connect them to your IdP, vault, gateway and SIEM. Tests (all runnable from a checkout): `python3 -W ignore -I agentic/tests/test_agentsec.py` (24), `test_agentsec_extra.py` (54, no Docker), `test_sandbox_docker.py` (17, real Docker), `test_vault_docker.py` (8, a real throw-away Vault; skipped if Docker/image is missing).
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
| Run model-written code | `run_python(code, timeout=10, memory="128m", pids=64)` / `run_command(argv)` from `agentsec.sandbox` | throw-away container: no network, read-only root, 16 MB tmpfs, non-root, no capabilities, killed at the timeout, output capped. **Refuses** (`ok=False`, `error`) if Docker or the image is missing: never runs on the host. Needs the `docker` CLI and a local image (`python:3.12-slim`). Same kernel as the host: use `runtime="runsc"` (gVisor) for more |
| Answers must match the data | `validate_figures(answer, tool_results)`, `require_valid(...)`, `validate_schema(obj, schema)` from `agentsec.output` | every number must match a certified source value (rounding-aware, % and k/M/B units); no sources + a figure = reject; a checker error = reject. It checks numbers, not truth |
| What may this text be sent to? | `classify(text)`, `Classifier().add_rule(...)`, `enforce_max_level(payload, "INTERNAL")` | highest of PII, PHI, MNPI, financial, HR, legal rules wins; result lists rule names, never the text. Pattern based: tune rules to your data |
| Delete old data | `purge_jsonl(path, days=, dry_run=True)`, `purge_sqlite(db, table, ts_col, days=)`, `RetentionPolicy(min_days={"audit": 365})` | dry-run by default; undated lines are kept; a minimum floor refuses too-short periods; hash-chained audit files stay verifiable (anchor file) |
| Agent memory at rest | `EncryptedStore(path, key)` from `agentsec.state` (`pip install cryptography`) | Fernet; each value bound to its key name; `[new, old]` keys + `rotate()`; file mode 0600, atomic writes. Protects the file, not RAM |
| Secrets from a vault | `VaultKV2Provider(addr, token=... or role_id=, secret_id=)`, `EnvProvider`, `FileProvider`, `RotatingSecret(provider, name, max_age_days=90, refresh=cb)`, `age_report([...])` from `agentsec.secrets` | `Secret` never prints (`.reveal()` at the point of use); https required except localhost; errors never contain tokens; TTL cache; re-login on expiry; unknown age counts as "needs rotation". You write the refresh callback |
| Context-aware decisions (PIP) | `PDP(policy, context=[provider])` + `"conditions": [{"attr": "risk_score", "max": 0.5}]` in a tool's policy | a provider that raises or a missing attribute = deny |
| Manage policies (PAP) | `PolicyStore(path, audit=AuditLog(...))`: `put`, `disable(agent, tool)`, `enable`; `PDP(store)`; CLI `python -m agentsec.policy_admin validate FILE` | validated (unknown keys/typos are errors), versioned with a digest, atomic, every change audited; hand-edits or a corrupt file make the PDP deny |

## Wiring sketch (FastAPI)
```python
from agentsec import PDP, PEP, AuditLog, CredentialBroker, Principal, Budget, enforce, redact, safe_path
pep = PEP(PDP(POLICY), AuditLog("/var/log/agent-audit.jsonl", key=os.environ["AUDIT_KEY"]), approver=None)

def call_tool(principal, agent_id, name, args):            # the model proposes; code decides
    return pep.call(principal, agent_id, name, TOOLS[name], **args)
# every tool implementation validates its own inputs too: safe_path(...), safe_fetch(...)
```
### What is verified for real, and what is not
| Piece | Verified how | Not verified |
|---|---|---|
| `sandbox` | 17 tests with real Docker: network, read-only root, writes, non-root, capabilities, fork bomb, memory bomb, timeout, output flood, host files/env, seccomp (mount/userns), no leftover containers | gVisor (`runsc`), Kata, rootless Docker; a kernel escape |
| `secrets` Vault provider | 8 tests against a real dev-mode Vault 1.18 (token, AppRole, least-privilege 403, expired-token re-login, cache, versions, rotation) plus a mock server | Vault Enterprise namespaces on a real server, TLS with a private CA, lease renewal, AWS/Azure/GCP secret managers |
| `pii` + Presidio | unit tests; Presidio run in a scratch venv with `en_core_web_sm` (`AGENTSEC_SPACY_MODEL`) | the larger `en_core_web_lg` model, non-English text |
| `state` | unit tests incl. wrong key, tamper, swap, rotation | key management (that is your vault) |
| `output`, `classify`, `retention`, `policy_admin`, PIP | unit tests | behaviour on your real data and policies |

Principle (slide: *Deterministic Guardrail Plane*): the model may *propose* an action, but authorization, limits, approval and output filtering are decided by code that the model cannot talk its way past.
