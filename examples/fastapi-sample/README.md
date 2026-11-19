# fastapi-sample (TEST FIXTURE - intentionally vulnerable)
A small FastAPI app used to exercise every scanner layer: SAST, SCA, secrets, Dockerfile/image, DAST.
**Never deploy.** All credentials are fake. Run only on a local Docker network (see docs/fastapi-e2e.md).

| Endpoint | Planted weakness | Expected detector |
|---|---|---|
| `GET /items/{id}` | SQL injection (string-built query) | Bandit B608, Sonar, ZAP active |
| `POST /run` | command injection (`shell=True`) | Bandit B602 |
| `POST /load` | unsafe `pickle.loads` | Bandit B301 |
| `POST /yaml` | `yaml.load` without safe loader | Bandit B506, vulnerable PyYAML |
| `GET /fetch` | SSRF + `verify=False` | Bandit B501, Sonar |
| `GET /file` | path traversal | Sonar, ZAP active |
| `GET /greet` | reflected XSS | ZAP active |
| `GET /hash` | MD5 | Bandit B324 |
| module level | hardcoded secrets, wildcard CORS with credentials | gitleaks, Trivy, Sonar |
| `requirements.txt` | old pinned packages with known CVEs | pip-audit, Trivy |
| `Dockerfile` | root user, old base image, `ADD`, secret in `ENV`, no HEALTHCHECK | Trivy config/image |
