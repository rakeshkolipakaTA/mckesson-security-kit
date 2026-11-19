# End-to-end test: intentionally vulnerable FastAPI app

`examples/fastapi-sample/` is a small FastAPI service with planted weaknesses, a Dockerfile and old pinned dependencies.
`scripts/e2e-fastapi.sh` builds it, runs it on an isolated Docker network and scans it with every layer of the framework
(gitleaks, Trivy fs + image, Semgrep, Bandit, pip-audit, SonarQube if configured, ZAP full scan).
Only run DAST against apps you own or are authorised to test: local fixtures, QA/UAT, never production.

## Result: planted vs detected (final v1 run, 2026-11-18; line numbers checked exactly)
| Planted weakness | Static tools | DAST (ZAP) |
|---|---|---|
| SQL injection `GET /items/{id}` (L33) | Bandit B608 (M), Semgrep formatted-sql-query (M) + sqlalchemy-execute-raw-query (M). **Sonar CE missed** | **missed** (path parameter; also missed in `api` mode) |
| Command injection `POST /run` | Bandit B602 (H), Semgrep (H), Sonar S7487 | not exercised (POST body) |
| Unsafe `pickle.loads` `POST /load` | Bandit B301, Semgrep (H) | not exercised |
| Unsafe `yaml.load` `POST /yaml` | Bandit B506, Semgrep (H), Sonar S930 | not exercised |
| SSRF + `verify=False` `GET /fetch` | Bandit B501, Semgrep ssrf/disabled-cert (H), Sonar S4830 | not in the full-scan seeds |
| Path traversal `GET /file` | **missed by all** | **missed** |
| Reflected XSS `GET /greet` | **missed by all** | **found** (reflected + DOM) in `full` mode only |
| MD5 `GET /hash` | Bandit B324, Semgrep, Sonar | n/a |
| Hardcoded secret key / DB password | Bandit B105 (LOW), Sonar S2068 | n/a |
| Fake GitHub token, fake AWS key | gitleaks + Trivy + Semgrep + Sonar, merged into one finding each (CRITICAL) | n/a |
| Wildcard CORS + credentials | Semgrep wildcard-cors (M) | **found** (ZAP 40040) |
| Vulnerable pins (PyYAML 5.3.1, requests 2.25.0, fastapi 0.65.2 ...) | pip-audit + Trivy, merged | n/a |
| Dockerfile: root user, `ADD`, secrets in `ENV`, no HEALTHCHECK, old base | Trivy DS-0002/0005/0026/0031, Sonar docker rules, Semgrep missing-user, gitleaks | n/a |
| Image: OS and Python packages in `python:3.9-slim` | Trivy image (hundreds of OS-package CVEs) | n/a |

## What this tells us
1. **Secrets, dependencies, Dockerfile and image checks are reliable** and overlap usefully; the same GitHub token reported by four tools is one finding.
2. **Several code scanners are better than one.** Bandit and Semgrep both caught the SQL injection; Semgrep alone caught the wildcard CORS and the SSRF/TLS-verification pair; Sonar Community Build missed the SQL injection (no taint analysis; that is a paid-edition feature).
3. **Two classic web bugs slipped past every static tool: path traversal and reflected XSS.** ZAP found the XSS (in `full` mode) but not the traversal. Static analysis alone, or DAST alone, would have missed something.
4. **ZAP modes differ a lot.** `baseline` finds almost nothing on a pure API (no pages to crawl). `api` mode (OpenAPI import) ran the injection rules but only sends example values and found none of the planted bugs. `full` mode with explicit seed URLs found XSS and CORS. It still missed the SQL injection in a URL path segment and path traversal.
5. **A DAST "PASS" is not evidence of safety**, and neither is "no findings". Treat DAST as a supplement to code analysis and code review. For real services give ZAP authenticated sessions, request bodies and realistic parameters (ZAP automation plans), QA only.
6. POST-body endpoints are not exercised by the simple seed-URL mode.

## Correction note
An earlier version of this page said no tool caught the SQL injection. That was wrong: it came from looking up the wrong source line (L32, the `def`, instead of L33). Bandit B608 and Semgrep did flag it. The matrix above is generated from exact line matches.

## Run it
```bash
scripts/e2e-fastapi.sh        # add SONAR_HOST_URL / SONAR_TOKEN to include SonarQube; ~6 min; leaves nothing running
```
Reports: `reports/fastapi-sample/e2e-*/summary.html`.
