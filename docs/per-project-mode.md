# Per-project mode: a self-contained kit inside each repo (the default for developers)

The step-by-step guide is [GETTING-STARTED.md](GETTING-STARTED.md). This page is the reference.

```bash
warden init [repo] [--ci github|jenkins|azure|all|none] [--preset starter|standard|strict] [--vendor]
cd /path/to/repo && .security/warden doctor && .security/warden scan
```

Two ways the engine reaches a repo:

| | **Thin** (default when installed with pip) | **Vendored** (`--vendor`; default from a framework checkout) |
|---|---|---|
| In the repo | config, CI files, launcher, `warden.lock` (version pin) | all of that plus `.security/kit/` (the whole engine) |
| Teammates / CI need | Docker, Python 3, access to the package source; the launcher installs the pinned version once into `~/.cache/warden/<version>` | Docker only |
| Upgrade | `pip install --upgrade ...` then `warden upgrade` (a small diff: the pin) | re-run `init` from a newer checkout (a big diff) |
| Use when | normal repos | offline / air-gapped build agents |

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
Thin: install the newer warden, then `warden upgrade` in the repo. It bumps `warden.lock` and refreshes generated files, and never touches your config, exceptions or baseline. Review the diff in a PR.
Vendored: re-run `warden init <repo> --vendor` from a newer checkout.

## Taking it out
`warden disable --until DATE --reason "..."` pauses scanning (90 days at most, resumes by itself). `warden uninstall` removes what `init` added and keeps your config, exceptions and baseline (`--purge` removes those too); `warden reinstall` starts fresh.

**Supply-chain note:** in thin mode the version pin lives in the repo, so a pull request could change it. Protect `.security/` and `.github/` with CODEOWNERS (the generated `CODEOWNERS.snippet` does this) and prefer the org-level required workflow for repos that need a stronger guarantee.

## Central vs per-project
| | Central ([central-mode.md](central-mode.md)) | Per-project (this page) |
|---|---|---|
| Install | Once on a host/runner | Per repo (generated, committed) |
| Upgrades | One place | Re-run `init` per repo |
| Best for | Platform team scanning many repos; GitHub reusable workflow | Teams owning their pipeline; no dependency on a central host |
Both give identical findings (verified) and the same gate.
