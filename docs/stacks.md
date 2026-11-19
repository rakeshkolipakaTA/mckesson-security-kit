# What runs for each stack

`SEC_PROFILE=auto` detects stacks from your files; one repo can have several (e.g. a Python API plus a React front end).

| Always (every repo) | gitleaks (secrets), Trivy (dependency CVEs, secrets, Dockerfile/IaC), Semgrep (code analysis) |
|---|---|
| **python** | + Bandit (code), pip-audit (dependencies of **every** `requirements*.txt` in the repo, plus root `pyproject.toml`/`setup.py`) |
| **node** | + ESLint security rules (`.js .jsx .ts .tsx .mjs`), `npm audit` per `package-lock.json` |
| **java** | Semgrep Java rules + Trivy on `pom.xml`/`build.gradle`; add Dependency-Check with `SEC_DEPCHECK=1` (see below) |
| **agent** (AI agents, auto-detected from agent/LLM frameworks or MCP config) | + 16 agent Semgrep rules, inventory/registry scan (`agent-scan`), model-file scan; dynamic: `secscan redteam`. See [agentic-security.md](agentic-security.md) |
| **model files** (any repo with `.pkl .pt .pth .bin .ckpt .h5 .joblib .npy .keras`) | `modelscan` |
| **Dockerfile** | Trivy checks the Dockerfile automatically; add `SEC_IMAGE=name:tag` (CI) to scan the built image |
| **optional** | SonarQube (`SEC_SONAR=1`), ZAP DAST (`--zap-url`, QA only) |

## Python
- Pin your dependencies (`pkg==x.y.z`); pip-audit audits what you list *and* what they pull in.
- If your pins conflict, pip cannot resolve them and the report shows **Reduced coverage**; only the pinned lines are audited. Fix the conflict.
- Tests are excluded from Bandit/Semgrep (`tests/`, `test/`). Override in `.security/bandit.yaml`.

## Node / JavaScript / TypeScript
- **Commit `package-lock.json`.** Without it `npm audit` can only audit freshly resolved versions (reported as reduced coverage).
- yarn / pnpm repos: dependencies are covered by Trivy only (npm audit needs a `package-lock.json`).
- ESLint uses the central security config (`configs/eslint/eslint.config.mjs`) regardless of your own ESLint setup. Override with `.security/eslint.config.mjs`.
- The scan never runs `npm audit fix` or changes your files.

## Java
- Trivy reads `pom.xml` (direct dependencies), Semgrep checks the code (SQL injection, deserialization, weak hashes ...).
- OWASP Dependency-Check adds deeper analysis. It needs the NVD database: the platform team prepares it once (`scripts/depcheck-update.sh`, needs an `NVD_API_KEY`); you set `SEC_DEPCHECK=1` and `SEC_DEPCHECK_NOUPDATE=1`. **Not yet validated end to end** (see status.md).
- Gradle: Trivy covers `gradle.lockfile` only; commit a lockfile (`./gradlew dependencies --write-locks`).

## Monorepos
Everything under the repo is scanned (build, `node_modules`, venvs, `.git`, `target`, `dist` are skipped). Findings are tracked per manifest file, so the same vulnerable package in two folders is two findings.

## What is NOT covered in v1
Go, .NET, PHP, Ruby dependency audits (Trivy still reads their lockfiles); authenticated DAST; POST-body DAST; license compliance; Terraform/Kubernetes manifest policies beyond Trivy's built-in checks.
