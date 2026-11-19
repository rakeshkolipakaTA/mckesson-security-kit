# Central dashboard

One page that shows every repository's latest security scan, from all tools (gitleaks, Semgrep, Trivy, Bandit, pip-audit, npm audit, ESLint, ZAP, agent checks, red team ...), not only SonarQube's. SonarQube stays the place for code-quality drill-down of one project.

**Portfolio page:** repos reporting, gate failing, open Critical/High, stale repos (no scan for 14 days), repos with tool problems; a sortable, filterable table with a trend line per repo.
**Repo page:** severity cards, "configuration that affects coverage" (tools turned off, waivers, reduced coverage, excluded paths), trend of Critical/High/Medium, tool coverage, filterable findings with fix hints, scan history with links to the CI run, other branches.

## Run it
```bash
scripts/platform-up.sh --host <address people will use>     # dashboard :8090 and SonarQube :9000
```
Credentials are generated once into `~/.secscan-platform/platform.env` (mode 600): `DASHBOARD_PASSWORD` (login `secscan`) and `DASHBOARD_INGEST_TOKEN` (what CI uses). There are **no default credentials**: the server refuses to start without them. Data lives in the `mckesson-sonar_dashboard_data` Docker volume (SQLite); back it up like any volume.

Stop/start: `cd docker && docker compose --env-file ../versions.env --profile dashboard down|up -d`. Logs: `docker logs mckesson-sonar-dashboard-1`.

## How scans get there
CI publishes automatically at the end of every scan when `SEC_DASHBOARD_URL` is set and the CI secret `SECSCAN_DASHBOARD_TOKEN` exists: see [integrations.md](integrations.md). Repo, branch, commit and the CI run link are detected from GitHub Actions, Jenkins, Azure DevOps or local git. `secscan publish` re-sends the latest report by hand. The dashboard keeps the last 100 scans per repo and branch.

The dashboard stores findings (rule, file and line, title, fix hint, severity; secrets are already redacted by the scanners) and the summary, **not** the raw tool output. Anyone who can log in can see them, so treat the login like access to the vulnerability list.

## Security of the dashboard itself
- Viewing needs the password (HTTP basic auth, failed attempts throttled); publishing needs the ingest token (constant-time compare, 8 MB limit).
- All data is HTML-escaped, a strict Content-Security-Policy is sent, links from CI are accepted only as http(s).
- **It speaks plain HTTP.** On an untrusted network the password and token travel in clear text. Do one of: restrict the port to company IP ranges in the security group, or put a TLS reverse proxy in front. Minimal Caddy example (`Caddyfile`): `secscan.example.com { reverse_proxy 127.0.0.1:8090 }` and then set `DASHBOARD_BIND=127.0.0.1`.
- Rotate by editing `platform.env` and re-running `scripts/platform-up.sh`, then updating the CI secrets.
- SonarQube: run `scripts/sonar-bootstrap.sh` once so the default `admin/admin` is replaced before the port is opened.

## Limits
Latest-per-repo view, no per-user accounts or roles (one shared viewer login), no alerting (use the CI gate for that), findings beyond 1500 per scan are cut (the CI artifact has all). Add a real identity provider in front (reverse proxy with SSO) if you need per-user access.
