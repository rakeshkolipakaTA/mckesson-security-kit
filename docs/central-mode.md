# Central mode — install once, scan any repo

## 1. Prerequisites
Docker 24+ with Compose, Python 3.8+ (stdlib only), outbound HTTPS to: Docker Hub / ghcr.io (images), `mirror.gcr.io` or `ghcr.io` (Trivy DB), `pypi.org` + `osv.dev`/PyPI advisory API (pip-audit), `nvd.nist.gov` (Dependency-Check only). In a locked-down network, mirror these and set the proxy / registry accordingly (see troubleshooting).

## 2. Install
```bash
git clone <mckesson-security-kit> && cd mckesson-security-kit   # this folder
make build-scanner        # builds warden-scanner:1 (Bandit + pip-audit, versions from versions.env)
make sonar-up             # optional; SonarQube at http://localhost:9000 (bound to localhost)
```
Tool versions live only in `versions.env`; images are pinned (digests for Sonar).

## 3. First-time SonarQube setup
```bash
export SONAR_ADMIN_PASSWORD='<12+ chars, upper, lower, digit, special>'
scripts/sonar-bootstrap.sh        # changes the default admin password, prints SONAR_HOST_URL / SONAR_TOKEN exports
```
Store the token in your secret manager / CI secret. Never commit it. Details: [sonar-setup.md](sonar-setup.md).

## 4. Scan
(Developers use `warden` inside their repo; this is the platform-team/central form. Settings can come from the repo's `.security/config.env` too.)
```bash
scripts/scan.sh /path/to/repo                                # report-only (pilot)
scripts/scan.sh /path/to/repo --gate pr --enforce            # PR gate
scripts/scan.sh /path/to/repo --gate release --enforce --sonar
scripts/scan.sh /path/to/repo --image myapp:1.2 --enforce    # + Trivy image scan
scripts/scan.sh /path/to/repo --sec-dir /central/project-config/<repo>   # keep overrides outside the repo
make dashboard
```
The repo is mounted read-only; nothing is written to it. Reports: `reports/<repo>/<timestamp>/{summary.md,summary.json,findings.json,raw/}`.

## 5. Project settings and overrides (optional)
A directory with any of: `config.env`, `bandit.yaml`, `gitleaks.toml`, `trivy.yaml`, `eslint.config.mjs`, `exceptions.json`, `baseline.json` (the severity policy cannot be overridden). Default `<repo>/.security/`, or `--sec-dir`. See `examples/project-config/claude-cost-kit/`.

## 6. Running from CI
GitHub: use the reusable workflow ([ci-github-actions.md](ci-github-actions.md) option B).
The central host can be a Jenkins agent / runner with Docker: check out the framework once on the agent, and call `scan.sh "$WORKSPACE" --gate pr --enforce --sonar` from each pipeline. Pass `SONAR_HOST_URL` and `SONAR_TOKEN` from the CI secret store.
