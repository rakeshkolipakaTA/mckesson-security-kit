# SonarQube setup
1. `make sonar-up` (Community Build + Postgres, localhost:9000). For a shared server run `scripts/platform-up.sh --host <address>` (SonarQube + dashboard, see [dashboard.md](dashboard.md)); put TLS/SSO in front for anything beyond a trusted network, with `vm.max_map_count>=262144` on the host.
2. `SONAR_ADMIN_PASSWORD=... scripts/sonar-bootstrap.sh` → change admin password, get a token.
3. Projects are created on first analysis; the key defaults to `warden-<repo-name>` (`--sonar-key` to override).
4. `scripts/scan.sh <repo> --sonar` (needs the URL: `SONAR_HOST_URL`, or `SEC_SONAR_HOST_URL` in `configs/central.env` / `config.env`; and the secret `SONAR_TOKEN`). Where each value goes for GitHub / Jenkins / Azure: [integrations.md](integrations.md). Issues and the quality-gate status are pulled via API into the common report.
5. Per-repo config template: `configs/sonar/sonar-project.properties.template`. Exclusions default to venv/build/dist/node_modules.
Notes: Community Build has no branch/PR analysis or PR decoration; that needs a paid edition. Sonar severities are mapped BLOCKER→CRITICAL, CRITICAL→HIGH, MAJOR→MEDIUM, MINOR→LOW.
