# Per-project mode: a self-contained kit inside each repo (the default for developers)

The step-by-step guide is [GETTING-STARTED.md](GETTING-STARTED.md). This page is the reference.

```bash
warden init [repo] [--ci github|jenkins|azure|all|none] [--preset starter|standard|strict] [--thin]
cd /path/to/repo && .security/warden doctor && .security/warden scan
```

Two ways the engine reaches a repo:

| | **Vendored** (the default) | **Thin** (`warden init --thin`) |
|---|---|---|
| In the repo | config, CI files, launcher **and `.security/kit/` (the whole engine)** | config, CI files, launcher, `warden.lock` (version pin) |
| Teammates / CI need | Docker only. Nothing is fetched from our repository or package index | Docker, Python 3, access to the package source; the launcher installs the pinned version once into `~/.cache/warden/<version>` |
| Upgrade | re-run `warden init` from a newer Warden and review the diff (a big diff) | `pip install --upgrade ...` then `warden upgrade` (a small diff: the pin), or follow the newest release automatically |
| Use when | the default; required when GitHub Actions may not pull from our repository, and for offline / air-gapped build agents | you trust our repository as a source and want new checks to arrive without a diff |

## Self-contained repo (the default): no access to our repository needed
Plain **`warden init`** (from the installed `warden` or a checkout of the framework) copies everything the scan needs into the repo; commit `.security/` and `.github/`. A client that does not allow GitHub Actions to pull anything from our repository or package index needs nothing else:

| Copied into the repo | Used for |
|---|---|
| `.security/kit/scripts/` | the scan, the gate, the GitHub report (`ci-report`), publishing to DefectDojo / Dependency-Track / Wiz, ticket and credential helpers, the AI-agent checks and probes |
| `.security/kit/configs/`, `agentic/` | tool configs, the severity policy, the Semgrep agent rules, the agentsec library |
| `.security/kit/docker/` | the two scanner image recipes, built on the runner (or pushed once to the client's own registry) |
| `.security/warden` | the launcher that runs everything from `.security/kit` |
| `.github/workflows/security-scan.yml` | the workflow: it runs `.security/warden` and uses only GitHub's own `checkout` and `upload-artifact` actions (pinned by commit), never our repository |

Roughly 650 KB, with no copy of the scanners themselves. What still needs the network from the runner, and how to avoid it:

| The runner still fetches | Avoid it with |
|---|---|
| Scanner base images and tools (Docker Hub, ghcr.io, PyPI, npm) | A client registry or mirror: push the built scanner images once, or `warden pull` on a self-hosted runner. Hosts: [platform-setup.md](platform-setup.md) |
| Semgrep rules (semgrep.dev) | `warden rules fetch` once, then `SEC_SEMGREP_RULES=.security/semgrep-rules`: [offline-and-blocked-networks.md](offline-and-blocked-networks.md) |
| Vulnerability databases (Trivy, pip-audit, npm audit) | `TRIVY_DB_REPOSITORY` for a mirror; the others need their own registries |

To update the engine, re-run `warden init <repo>` from a newer version and review the diff in a pull request. Protect `.security/` and `.github/` with CODEOWNERS, because the engine now lives in the repo. Tested: a vendored repo ran a real scan and the GitHub report step; `scripts/test-onboarding.sh` checks that every script the engine calls is inside `.security/kit`.

## What `init` adds
| Path | Owner | Purpose |
|---|---|---|
| `.security/warden` | generated | The command (launcher in thin mode): `doctor`, `scan`, `gate`, `quick`, `baseline`, `open`, `config`, `disable`, `hook`, ... |
| `.security/warden.lock` | generated, commit it | The pinned warden version (and where to install it from) |
| `.security/kit/` | generated, vendored mode only | Pinned scripts, configs, scanner Dockerfiles, `versions.env` |
| `.security/config.env` | **you** | The settings: preset, per-tool switches, targets, excluded paths (see [configuration.md](configuration.md)). Created once |
| `.security/exceptions.json`, `baseline.json` | you | Time-boxed finding exceptions and tool waivers / existing findings |
| `.security/bandit.yaml`, `gitleaks.toml`, `trivy.yaml`, `eslint.config.mjs` | optional | Override a tool's central config (same name wins). The severity policy is **not** overridable |
| `.security/ci/` | copy once | Pipeline templates: GitHub (PR, release, DAST), Jenkins, Azure DevOps, CODEOWNERS, pre-commit, PR template |
| `.github/workflows/security-scan.yml` | you | Added when GitHub Actions applies (report-only) |
| `.security/reports/` | git-ignored | Output |

## Upgrading
Thin (`--thin`): install the newer warden, then `warden upgrade` in the repo. It bumps `warden.lock` and refreshes generated files, and never touches your config, exceptions or baseline. Review the diff in a PR.
Vendored (default): re-run `warden init <repo>` from a newer Warden and review the diff.

## Taking it out
`warden disable --until DATE --reason "..."` pauses scanning (90 days at most, resumes by itself). `warden uninstall` removes what `init` added and keeps your config, exceptions and baseline (`--purge` removes those too); `warden reinstall` starts fresh.

**Supply-chain note:** in thin mode (`--thin`) the version pin lives in the repo, so a pull request could change it. Protect `.security/` and `.github/` with CODEOWNERS (the generated `CODEOWNERS.snippet` does this) and prefer the org-level required workflow for repos that need a stronger guarantee.

## Central vs per-project
| | Central ([central-mode.md](central-mode.md)) | Per-project (this page) |
|---|---|---|
| Install | Once on a host/runner | Per repo (generated, committed) |
| Upgrades | One place | Re-run `init` per repo |
| Best for | Platform team scanning many repos; GitHub reusable workflow | Teams owning their pipeline; no dependency on a central host |
Both give identical findings (verified) and the same gate.
