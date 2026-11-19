# Secure code-review checklist

For reviewers of pull requests. The scanners already run on every PR; this checklist is for what they cannot judge: **intent, design, and context**. Skim the sections that match the change; a typical PR touches one or two.

First look at the **security scan result** on the PR. A new Critical/High finding is not a "maybe": fix it or get a time-boxed exception approved. Then:

## Always
- [ ] No secrets, tokens, keys, internal hostnames or personal data in code, tests, fixtures, logs or comments.
- [ ] Dependencies: new ones are needed, maintained, from the expected source, pinned (lockfile updated), and the licence is acceptable.
- [ ] Errors do not leak stack traces, queries or internal paths to callers; failures **fail closed** (deny), not open.
- [ ] Logging includes enough to investigate (who, what, when) and nothing sensitive.
- [ ] Tests cover the security-relevant behaviour (denied access, bad input), not only the happy path.

## Authentication and authorisation
- [ ] Every new route / function checks **who** the caller is **and** that they may touch **this object** (ownership / tenant check, not just "logged in").
- [ ] Admin or privileged actions check the role on the server side; nothing relies on the UI hiding a button.
- [ ] Identifiers from the client (ids, filenames, tenant ids) are never trusted for access decisions.
- [ ] Tokens and sessions: short-lived, scoped, not logged, not placed in URLs.

## Input, output and data
- [ ] All external input is validated (type, length, range, allow-list); queries are parameterised; no string-built SQL, shell commands or templates.
- [ ] File paths are normalised and confined to an allowed base directory; uploads are type- and size-checked and stored outside the web root.
- [ ] Output is encoded for its context (HTML, JSON, shell); user content is never rendered as raw HTML.
- [ ] Outbound requests go only to allow-listed hosts; user-supplied URLs cannot reach internal addresses (SSRF).
- [ ] Personal / regulated data is minimised, masked in logs, encrypted in transit and at rest, and retained only as long as needed.
- [ ] Cryptography uses standard libraries and current algorithms; no home-made crypto; comparisons of secrets are constant-time; keys come from a secret store.

## Concurrency, resources, configuration
- [ ] Limits on size, count, time and rate (no unbounded loops, uploads or fan-out).
- [ ] Defaults are safe (debug off, CORS not wildcard with credentials, cookies `Secure`/`HttpOnly`/`SameSite`).
- [ ] Containers run as non-root with a read-only root filesystem where possible; Kubernetes manifests set a security context.
- [ ] CI changes: workflow permissions minimal; third-party actions pinned to a commit; no secrets echoed.

## When the change touches an AI agent
- [ ] New or changed **tools**: purpose, parameters validated, least privilege, destructive or outbound actions behind human approval, no credentials accepted as parameters.
- [ ] Untrusted content (documents, web pages, tool output) is treated as **data**, wrapped or delimited, and cannot change which tools run.
- [ ] Guardrails are enforced in code (not only in the prompt) and **fail closed** on error or timeout.
- [ ] Model and endpoint are on the approved registry, version-pinned; no `trust_remote_code`, no unsafe deserialisation of model files.
- [ ] Budgets exist (steps, tool calls, time, tokens); rate limiting on the agent's entry point.
- [ ] Secrets are not in prompts or MCP configuration; system prompts hold nothing that must stay secret.
- [ ] Actions are written to the audit log with the agent and the human they acted for.
- [ ] A red-team probe or test covers the new risk (see `secscan redteam`).

## Before approving
- [ ] I understood the change well enough to explain how it could be abused.
- [ ] Any exception is time-boxed, has a reason and an approver (see the [policy](vulnerability-management-policy.md)).
- [ ] If the design changed materially, the [threat model](threat-model-template.md) was updated.
- [ ] For high-risk changes (auth, payments, new tool with side effects) a second reviewer or the security champion looked at it.
