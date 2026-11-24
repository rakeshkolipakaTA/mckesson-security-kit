# 8. AI agents: runtime controls library (`agentsec`)

The scans in [07-ai-agent-checks.md](07-ai-agent-checks.md) **find** unsafe agent code. This library is the other half: **reusable code that makes an agent safe to run**. It is Python, standard library only (except optional encryption and Presidio), in `agentic/agentsec/`. Copy it into your service with `.security/warden agentlib`. A complete hardened example is `examples/agent-sample-secure/`.

**Principle:** the model may *propose* an action, but authorisation, limits, approval and output filtering are decided by **ordinary code that the model cannot talk its way past**. Every control below fails **closed**: an error, a timeout or an unexpected answer means "no".

**These are building blocks, not a platform.** Review them, then connect them to your identity provider, vault, API gateway and SIEM. Your team must wire them in; scanning cannot do that for you.

## Modules

| Module | What it does | Threat it stops |
|---|---|---|
| `policy` (PDP / PEP / PIP) | Default-deny decisions on which agent may call which tool, with which role, scope and arguments (`max_len`, `enum`, `regex`). Unknown agent, tool, role or scope = deny. A tool marked `approval: true` needs an explicit human "yes". Context providers (for example a risk score) that fail = deny. `require_owner` blocks cross-tenant access, even for admins | Excessive agency, privilege escalation, one user reading another's data |
| `policy_admin` (PAP) | Validate, version, enable and disable policies, with an audit trail. `disable(agent, tool)` is a **kill switch** for one tool or a whole agent | Slow incident response, unreviewed policy changes |
| `broker` | Gives each agent its own identity and **short-lived tokens limited to one audience and a few scopes**, naming the human it acts for. A tool never sees the user's own token or a long-lived key | Credential theft, the "confused deputy" |
| `guard` | `enforce(text, [checks], timeout=2)`: a guardrail that raises, times out, returns `None` or a non-boolean **blocks** | Guardrails that fail open |
| `paths` | `safe_path(base, user_path)`: rejects `..`, absolute paths, NUL bytes and symlinks leaving the base | Path traversal |
| `egress` | `safe_fetch` and `validate_url`: allow-listed hosts, public IPs only (blocks loopback, private, link-local, cloud metadata), every redirect re-validated, the connection pinned to the checked IP (no DNS rebinding), response size capped | SSRF, data exfiltration |
| `untrusted` | `wrap_untrusted` labels retrieved text as data in a random per-call envelope. `detect_injection` flags hidden instructions | Indirect prompt injection (RAG poisoning) |
| `limits` | Budgets for steps, tool calls, time and output size, plus a rate limiter | Runaway loops, cost abuse, denial of service |
| `sandbox` | Runs model-written code in a throw-away Docker container: no network, read-only root, small tmpfs, non-root, all capabilities dropped, no-new-privileges, CPU, memory and process limits, timeout, capped output, no host mounts or environment. If Docker is missing the run is **refused**, never done on the host | Code execution on the agent host, fork and memory bombs |
| `pii` | Masks emails, phones, Luhn-valid card numbers, SSN, Aadhaar, PAN, JWTs and API keys; removes sensitive keys; masks names after an honorific and simple street addresses. Optional Presidio integration for regulated data | Personal data and secrets in logs, prompts and traces |
| `classify` | Labels text PUBLIC, INTERNAL, CONFIDENTIAL or RESTRICTED (PHI, MNPI, financial, HR, legal rules; add your own). `enforce_max_level` refuses to send text to a destination not approved for that level | Sending sensitive data to the wrong model or service |
| `retention` | Deletes audit or conversation files and tables older than their retention period. **Dry run by default**; a minimum age protects audit records | Keeping data longer than allowed |
| `state` (`EncryptedStore`) | Agent memory and conversation state encrypted at rest (Fernet), each value bound to its key name, key rotation, file mode 0600 | Memory theft, swapped entries |
| `secrets` | Providers for environment, mounted files and HashiCorp Vault KV v2 (token or AppRole), TTL cache, rotation age tracking. A secret's `repr` never shows the value | Secrets in source or logs, stale keys |
| `output` | `validate_figures` checks every number in an answer against certified source values, within a tolerance; `validate_schema`; fail-closed helper | Hallucinated or altered figures presented as facts |
| `audit` | Append-only log where each record carries the hash of the previous one (optionally an HMAC key). Detects edits, deletions and reordering; PII is masked | Tampering with the record of what the agent did |

## How it protects
* **Deterministic, not persuadable.** A prompt injection can change what the model *asks for*. It cannot change what the policy engine *allows*. This is why least privilege, approval and the sandbox matter more than any attempt to detect injections.
* The red-team probes ([07-ai-agent-checks.md](07-ai-agent-checks.md)) test that these controls are really in place on a running agent.
* Every module has unit tests (24 + 54 in `agentic/tests/`), plus real-Docker and real-Vault tests (below).

## Limits and honesty
* **Reference code.** `broker` is a test double, not an identity provider. Run production tokens through your IdP and vault with the same claims and checks.
* `pii` is pattern based. Names without an honorific cue and non-US address styles are **not** caught; use Presidio or a DLP service for regulated data.
* `untrusted.detect_injection` is a heuristic; paraphrased injections pass it. Treat it as a tripwire, never the defence.
* `audit` on the same host is evidence, not a vault: ship records to write-once storage or your SIEM.
* `state` needs `pip install cryptography`; key management is yours.
* No platform services are provided: policy admin UI, identity provider, API gateway, resource registry, external RBAC.
* Status: **Verified** on real infrastructure: `sandbox` (17 tests on real Docker against hostile code: network, fork bomb, memory bomb, host files; the gVisor option is untested) and the Vault provider (8 tests on a real dev Vault; cloud secret managers are not implemented). **Reference library** (unit tested, you wire it in): all other modules.
