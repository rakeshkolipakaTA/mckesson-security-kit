# Central dashboard

One page that shows every repository's latest security scan, from all tools (gitleaks, Semgrep, Trivy, Bandit, pip-audit, npm audit, ESLint, ZAP, agent checks, red team ...), not only SonarQube's. SonarQube stays the place for code-quality drill-down of one project.

**Portfolio page:** repos reporting, gate failing, open Critical/High, stale repos (no scan for 14 days), repos with tool problems; a sortable, filterable table with a trend line per repo.
**Repo page:** severity cards, "configuration that affects coverage" (tools turned off, waivers, reduced coverage, excluded paths), trend of Critical/High/Medium, tool coverage, filterable findings with fix hints, scan history with links to the CI run, other branches.

## Run it
```bash
scripts/platform-up.sh --host <address people will use>     # dashboard :8090 and SonarQube :9000
```
Credentials are generated once into `~/.warden-platform/platform.env` (mode 600): `DASHBOARD_PASSWORD` (login `warden`) and `DASHBOARD_INGEST_TOKEN` (what CI uses). There are **no default credentials**: the server refuses to start without them. Data lives in the `mckesson-sonar_dashboard_data` Docker volume (SQLite); back it up like any volume.

Stop/start: `cd docker && docker compose --env-file ../versions.env --profile dashboard down|up -d`. Logs: `docker logs mckesson-sonar-dashboard-1`.

## How scans get there
CI publishes automatically at the end of every scan when `SEC_DASHBOARD_URL` is set and the CI secret `WARDEN_DASHBOARD_TOKEN` exists: see [integrations.md](integrations.md). Repo, branch, commit and the CI run link are detected from GitHub Actions, Jenkins, Azure DevOps or local git. `warden publish` re-sends the latest report by hand. The dashboard keeps the last 100 scans per repo and branch.

The dashboard stores findings (rule, file and line, title, fix hint, severity; secrets are already redacted by the scanners) and the summary, **not** the raw tool output. Anyone who can log in can see them, so treat the login like access to the vulnerability list.

## Security of the dashboard itself
- Viewing needs the password (HTTP basic auth, failed attempts throttled); publishing needs the ingest token (constant-time compare, 8 MB limit).
- All data is HTML-escaped, a strict Content-Security-Policy is sent, links from CI are accepted only as http(s).
- **It speaks plain HTTP.** On an untrusted network the password and token travel in clear text. Do one of: restrict the port to company IP ranges in the security group, or put a TLS reverse proxy in front. Minimal Caddy example (`Caddyfile`): `warden.example.com { reverse_proxy 127.0.0.1:8090 }` and then set `DASHBOARD_BIND=127.0.0.1`.
- Rotate by editing `platform.env` and re-running `scripts/platform-up.sh`, then updating the CI secrets.
- SonarQube: run `scripts/sonar-bootstrap.sh` once so the default `admin/admin` is replaced before the port is opened.

## Remediation SLA tracking
The dashboard keeps the age of every open finding: the clock starts when it **first saw** that finding (matched by the finding's stable fingerprint, per repo and branch) and stops when a later scan no longer contains it, or when an approved exception applies. The allowed age per severity comes with every scan from the central `policy.json` (`sla_days`: Critical 3, High 14, Medium 60, Low 90). A finding older than that is **overdue**.

- **Portfolio:** tiles *Findings past SLA* and *Repos with SLA breached*, plus sortable *Past SLA* and *Oldest (d)* columns with an "SLA breached" badge.
- **Repo page:** a *Remediation SLA* table (open / past SLA / oldest per severity) and an *Age (d)* column on every finding; overdue ages are highlighted.
- **Machine access:** `GET /api/overdue?repo=<name>&branch=<branch>` (Bearer ingest token, or the viewer login) returns the overdue fingerprints; `warden tickets` uses it.
- **Limits:** the clock starts at the first scan the dashboard saw, so a repo onboarded today starts all its existing findings at day 0 (use `warden baseline` for legacy ones). A scan whose finding list was cut (over 1500) never marks findings as fixed. Without a dashboard URL there is no SLA tracking: SLAs are then only a number in the policy.

## Alerts (optional)
Set `DASHBOARD_ALERT_WEBHOOK` to a Slack or Microsoft Teams incoming-webhook URL (any endpoint that accepts `{"text": "..."}` works) in `~/.warden-platform/platform.env`, then re-run `scripts/platform-up.sh`. The dashboard posts one short message per scan when something **new** happens on the main branch(es):

| Event | When |
|---|---|
| Gate flipped | the previous scan passed and this one fails |
| New Critical finding | a finding at or above `DASHBOARD_ALERT_MIN` (`critical` default, or `high`) that was not in the previous scan |
| SLA newly breached | a finding just went past its SLA |
| Repo stale | no scan for `STALE_DAYS` (default 14); checked hourly |

Each event is sent once (de-duplicated by finding and scan date). The first scan of a repo is its baseline and raises no "new finding" alert. Feature branches are silent unless `DASHBOARD_ALERT_BRANCHES=*`. The message holds the repo, branch, counts and rule ids, never finding text or file contents; set `DASHBOARD_PUBLIC_URL` to add a link. Delivery runs in the background with a 5 second timeout and a failing webhook never affects scanning or ingest. Tested against a local mock receiver, not against a real Slack or Teams workspace.

## Tickets
`warden tickets` turns findings into tickets so they have an owner and a due date: GitHub issues, Jira issues, Azure DevOps work items.
```bash
warden tickets                       # dry run: shows what would be created and what already exists
warden tickets --apply               # create them (GitHub by default)
warden tickets --target jira --apply
warden tickets --target all --dashboard https://dash.example --apply   # also ticket overdue findings
```
- **Which findings:** Critical and High (`--min-severity critical` for fewer), not excepted, and either **new** (not in the baseline) or **overdue** (needs `--dashboard` and the CI secret `WARDEN_DASHBOARD_TOKEN`); `--include-existing` adds the baseline too.
- **Grouping:** one ticket per package and manifest for dependency CVEs ("Upgrade pillow in requirements.txt (4 findings)"), one per rule and file for everything else.
- **No duplicates:** every ticket carries a label `warden-gk-<id>` derived from the group; a re-run finds it and creates nothing, including when you closed it. If the lookup fails, nothing is created (a delayed ticket beats a duplicate).
- **Safe by default:** dry run unless `--apply`; at most 20 tickets per target per run (`--max-issues`); a pause between API calls and retries on rate limits; credential-like strings are scrubbed from the text again; `http://` is refused except to localhost.
- **Credentials** (CI secrets, never files): GitHub `GITHUB_TOKEN` with `issues: write` and `--repo owner/name` (or `GITHUB_REPOSITORY`, set by Actions); Jira `JIRA_URL`, `JIRA_USER`, `JIRA_TOKEN`, `JIRA_PROJECT` (optional `JIRA_ISSUE_TYPE`, default Bug); Azure DevOps `AZDO_ORG_URL`, `AZDO_PROJECT`, `AZDO_TOKEN` (a PAT with Work Items read and write).
- **Tested** against local mock servers that imitate the three APIs (create, de-duplicate, auth headers, throttling, lookup failure) and a real dashboard instance for the overdue case. Not tested against real GitHub, Jira or Azure DevOps tenants: try `--target ... ` as a dry run first and check one ticket.

## Limits
Latest-per-repo view, no per-user accounts or roles (one shared viewer login), alerts only via a chat webhook (no email or paging), findings beyond 1500 per scan are cut (the CI artifact has all). Add a real identity provider in front (reverse proxy with SSO) if you need per-user access.
