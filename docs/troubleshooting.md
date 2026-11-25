# Troubleshooting
| Symptom | Cause / fix |
|---|---|
| `Result: FAIL (with tool errors: X=missing)` | Tool X produced no report. Check `reports/.../raw/` and, for Sonar, `sonar-scanner.log`. By design an enforced gate fails closed. |
| Trivy `mkdir /cache/db: permission denied` | Cache volume not writable by the non-root scan user. `scan.sh` fixes it automatically; if you use your own volume: `chmod 777` it. |
| Trivy cannot download its DB | Needs `mirror.gcr.io` / `ghcr.io`. In restricted networks mirror the DB and set `TRIVY_DB_REPOSITORY`. |
| Sonar `Unable to create directory ... .sonar/cache` | Scanner runs non-root; `scan.sh` sets `SONAR_USER_HOME=/cache` on a volume. |
| `sonar-bootstrap.sh`: password rejected | Policy: 12+ chars with upper, lower, digit, special. |
| Sonar `EXECUTION FAILURE` with `connection refused` | `SONAR_HOST_URL` unreachable from the scanner container (it uses `--network host`). |
| pip-audit "no dependency manifest" | Repo has no `requirements*.txt`/`pyproject.toml`/`setup.py`; tool is skipped. |
| Many `pip-audit` HIGH findings with no CVSS | pip-audit gives no severity; see [policy.md](policy.md). |
| Secret false positive in test data | Allowlist in `.security/gitleaks.toml`, or a time-boxed exception. |
| Dependency-Check very slow first time | NVD download without `NVD_API_KEY`; request a key and keep the `warden-depcheck-data` volume. |
| `warden doctor` shows a host as NOT reachable | A proxy/firewall blocks it. Ask the platform team to allow it or mirror it (see platform-setup.md). |
| Semgrep: `Failed to download` / no rules | `semgrep.dev` blocked (the gate fails closed: "semgrep=missing"). Download the rules once where it is reachable (`warden rules fetch`), then `warden config set SEC_SEMGREP_RULES .security/semgrep-rules`: [offline-and-blocked-networks.md](offline-and-blocked-networks.md). |
| `npm-audit` shows `invalid` | The audit returned an error (no network to the npm registry, or private registry auth). Check `<report>/npm-audit-<n>.log`. |
| "no lockfile ... audited versions were freshly resolved" | Commit `package-lock.json`. |
| eslint `invalid` / missing | ESLint crashed (see the scan output); check that your JS/TS files are valid syntax. |
| config.env: "ignoring unknown key / unsupported characters" | Only the documented `SEC_*` keys and simple values (letters, digits, `_ . : / @ , = ? & % + -`) are accepted. Secrets never belong there. |
| CI check is green but the report says FAIL | Report-only mode (`SEC_PRESET=starter`). Set `SEC_PRESET=standard` to enforce. |
| Windows: `bash: warden: command not found` | Use WSL2 or Git Bash and run `.security/warden` from the repo root. |
| First scan is slow | Images are downloaded once. `warden pull` does it ahead of time; CI agents benefit from pre-baked images. |
| redteam: "refusing to report results that would pass only because every request is anonymous" | The agent rejected the test credential (HTTP 401/403). Set `REDTEAM_TOKEN` (and `REDTEAM_TOKEN_B`) to valid QA test-user tokens. |
| redteam shows `missing` / "red team did not complete" | The harness could not reach the agent or crashed: see `<report>/redteam.log`. In Docker use `--redteam-network` and the container hostname. |
| Many red-team probes SKIPPED | Fill the matching keys in `.security/redteam.json` (skips are never counted as passes). |
| `agent-scan` reports no tools | Only decorator-registered tools (`@tool`, `@mcp.tool()`, `@function_tool`, `@kernel_function`) are detected; tools registered by other means are invisible to the inventory (the Semgrep rules still see `@tool` functions). |
| agent-scan says my model is "not registered" | The central registry is the platform team's file (`configs/agentic/approved-models.json`); ask them to register the model. A project cannot add its own approvals. |
| Semgrep agent rule `unauthenticated-route` on a route that IS protected | Authentication applied app-wide / at router level is invisible to the rule. Add a justified, time-boxed exception. |
