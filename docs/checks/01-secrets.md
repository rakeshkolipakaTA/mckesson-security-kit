# 1. Secrets: is a password, token or key in the code?

## What it protects against
A key committed to a repository is a key that has leaked. Clones, forks, CI logs and build caches copy it, and removing it later does not un-leak it. Attackers scan public and stolen code for cloud keys, tokens and passwords, and use them within minutes. These checks stop a secret before it is merged, and find ones that are already there.

## Checks

| Check | What it looks for | Example | Severity | Stage |
|---|---|---|---|---|
| **gitleaks** (current files) | API keys, tokens, private keys and passwords in any file, using its default rule set (hundreds of key formats: GitHub, AWS, Azure, Slack, Stripe, private-key blocks, generic high-entropy keys) | `AWS_KEY = "AKIA..."`, a `-----BEGIN PRIVATE KEY-----` block | High | every PR / push |
| **gitleaks on git history** (optional) | Secrets in **past commits**, even if deleted since. Grouped per file: number of commits, first commit, date | A key added in March and removed in April is still valid and still in history | High | PR / push, when switched on |
| **Trivy secret scanner** | Secrets in files **and inside Docker image layers** | A token baked into an image by `ENV` or `COPY .env` | High | PR; image gate on release |
| **Semgrep hard-coded credential rules** | Passwords and keys assigned in Python, Node and Java code | `password = "Pa55w0rd"` | by rule (usually High) | every PR / push |
| **agent-scan: secrets in prompts** (AG-PROMPT-001) | Credentials inside prompt or instruction files | An API key pasted into a system prompt | High | PR (AI agent repos) |
| **agent-scan: MCP secrets** (AG-MCP-004) | Literal secrets in an MCP server's `env` config | `"env": {"TOKEN": "ghp_..."}` in `.mcp.json` | High | PR (AI agent repos) |
| **Warden's own config check** | A secret typed into `.security/config.env` | `ZAP_AUTH_PASSWORD=...` | refused with a message | every scan |

Several tools looking for the same thing is deliberate. gitleaks, Trivy and Semgrep find different formats, and Warden **merges** a secret that more than one tool found into one finding, at its exact location.

## How it protects
* The pull request gate blocks a **new** secret (High). Without enforcement (`starter` preset) it is shown as "would block".
* gitleaks runs with `--redact`, and password messages are redacted, so the report itself does not repeat the secret. Treat `reports/` as confidential anyway.
* gitleaks and Trivy cannot be switched off by a team (required tools).
* Secrets for **testing** (a QA login for ZAP, for example) are never read from files in git. They come from CI secrets, a file path, a local store outside the repo or a prompt. See [../zap-authentication.md](../zap-authentication.md).

## Turn on history scanning (optional)
Off by default on `starter` and `standard` (it takes longer and needs more history), on for `strict`. In `.security/config.env`:
```ini
SEC_GITLEAKS_HISTORY=on
SEC_HISTORY_COMMITS=500      # only the newest 500 commits (default 3000)
SEC_HISTORY_FETCH=auto       # in a shallow CI checkout, fetch just that many commits
```
A shallow clone that cannot see the history is flagged as *reduced coverage* rather than reported clean.

## When it fires
1. **Rotate the secret first.** Assume it is public.
2. Move it to an environment variable or a secret manager.
3. For dummy values in tests, add a justified allow-list entry in `.security/gitleaks.toml` instead of an exception.
4. Rewriting git history is optional once the secret is rotated.

Step-by-step with before/after code: [../fixing-findings.md](../fixing-findings.md).

## Limits
* A secret with no recognisable format (a short, human-made password in a config value) can be missed.
* History scanning covers the newest N commits only. Older commits and other branches that are not fetched are not checked.
* Secrets stored **outside** the repository (wikis, tickets, chat, laptops) are out of reach.
* Status: **Verified** for gitleaks, Trivy, Semgrep and the agent checks. History scanning is verified, including the commit limit and shallow fetch.
