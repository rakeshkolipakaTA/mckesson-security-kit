# Platform team: one-time setup

Teams onboard themselves ([GETTING-STARTED.md](GETTING-STARTED.md)); you provide the shared pieces. Nothing here is needed to start in report-only mode with the core tools.

## 1. Publish the framework
Create the repo **`mckesson-security-kit`** from this folder. Tag a release (`v1`). Teams get it by `git clone`; the GitHub reusable workflow is consumed as `uses: rakeshkolipakaTA/mckesson-security-kit/.github/workflows/security-scan-reusable.yml@v1` (replace `<ORG>` in that file once). Keep the repo readable by all engineers (or provide `FRAMEWORK_TOKEN`).
Upgrade policy: bump versions in `versions.env`, run `scripts/selftest.sh` and `scripts/test-onboarding.sh`, tag `v1.x`, announce. Teams upgrade with `warden init <repo>`.

## 2. Runners / agents
Docker, bash, python3 >= 3.8, ~8 GB disk for images, outbound HTTPS to the hosts printed by `warden doctor` (ghcr.io, registry-1.docker.io, pypi.org, registry.npmjs.org, semgrep.dev, mirror.gcr.io). Behind a proxy/firewall: allow those hosts or mirror them; offline Semgrep rules via `SEC_SEMGREP_RULES`, Trivy DB via `TRIVY_DB_REPOSITORY`.
Speed: pre-pull/bake images on self-hosted runners (`warden pull`) or push the two small scanner images (`mckesson-scanner:1`, `mckesson-scanner-node:1`, built from `docker/scanner*`) to your registry.

## 3. SonarQube (optional)
`make sonar-up` for a local test instance; for a shared server deploy `docker/docker-compose.yml` behind your auth/ingress (host `vm.max_map_count >= 262144`). `scripts/sonar-bootstrap.sh` sets the admin password and creates a token. Give teams `SONAR_HOST_URL` and a CI secret token each. Community Build has no PR decoration or taint analysis; those need a paid edition. See [sonar-setup.md](sonar-setup.md).

## 4. Dependency-Check database (Java teams)
Request a free NVD API key, run `NVD_API_KEY=... scripts/depcheck-update.sh` nightly on one runner. Teams use `SEC_DEPCHECK=1 SEC_DEPCHECK_NOUPDATE=1`. (The database volume must be on the runner that scans; for ephemeral runners, publish the DB as an artifact/volume snapshot.)

## 5. Policy and governance
- Severity gates and SLAs live in `configs/policies/policy.json` and **cannot** be overridden by a project; agree them with McKesson security (values are proposals).
- Require CODEOWNERS review on `.security/`; recommend branch protection with the **security-scan** check required once a team enforces.
- Secret handling: scanner tokens only in CI secret stores, least privilege; reports are confidential (may contain code paths and secret metadata).

## 6. Visibility
Each run writes `summary.json`. To aggregate across repos, collect them (artifact download or a shared folder) into `reports/<repo>/<run>/` and run `scripts/aggregate.py` for `dashboard.md`. A real dashboard is a later phase.

## 7. AI agents
- **Model/endpoint registry**: you own `configs/agentic/approved-models.json` (the shipped content is an *example*). Projects cannot override it. Review requests to add models, pin versions, and keep the approved endpoint list (data residency) current.
- **Red-team access**: QA agents need two test users and a token mechanism for the harness; run red teaming only in QA/UAT with the owner's approval (the probes are real attacks).
- **LLM-driven tools** (DeepTeam/promptfoo): provide an approved attacker/judge model endpoint; keep telemetry opted out. See [agentic-redteam.md](agentic-redteam.md).
- **Not provided, needed for the full control framework**: a code-execution sandbox runtime, a vault/rotation service, an IdP/token-exchange service, write-once audit storage, runtime detection (Datadog/Sentinel). See the Gap notes in [agentic-security.md](agentic-security.md).
