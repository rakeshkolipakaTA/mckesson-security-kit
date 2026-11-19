# Fixing common findings (cookbook)

Find your finding's rule id in the report, then jump to the section. Each has the *why* and a before/after.

## Secrets
**Rules:** `github-pat`, `aws-access-key-id`, `generic-api-key`, `npm-access-token`, Trivy `DS-0031` (secrets in Dockerfile ENV), Bandit `B105/B106/B107`, Sonar `S2068/S6689`.
1. **Rotate the secret first.** If it was ever committed, assume it is public (even in a private repo, clones and CI logs spread it). Removing it from the code does not un-leak it.
2. Move it out of code: environment variable or secret manager (Key Vault, GitHub/Azure/Jenkins secrets).
   ```python
   # before                                   # after
   DB_PASSWORD = "Pa55w0rd"                   DB_PASSWORD = os.environ["DB_PASSWORD"]
   ```
3. Dockerfile: never `ENV SECRET=...` or `ARG` secrets. Pass at runtime (`docker run -e`, Kubernetes secret), or use BuildKit `--mount=type=secret`.
4. Dummy values in tests: allowlist them in `.security/gitleaks.toml` (see `examples/project-config/claude-cost-kit/gitleaks.toml`) instead of exceptions.
5. Cleaning git history is optional after rotation (`git filter-repo`); ask your security contact.

## Vulnerable dependencies (CVE / GHSA rows)
The **Fix** text shows the version to move to. Python: edit `requirements.txt` (`requests==2.32.3`), reinstall, run tests. Node: `npm install pkg@x.y.z` or `npm update`, commit `package-lock.json`. Java: bump the version in `pom.xml`.
- Upgrade the *parent* package when the vulnerable one is transitive (`npm ls <pkg>`, `pip show <pkg>`).
- Many rows for one package: upgrading it clears them all.
- No fix available: add a time-boxed exception with a note on mitigation ([exceptions-and-baseline.md](exceptions-and-baseline.md)).
- "Reduced coverage" for a requirements file: your pins conflict (`pip install -r` would fail). Resolve the conflict; consider `pip-compile` to generate a consistent lock file.
- Node without a lockfile: commit `package-lock.json` so the audit checks what you actually deploy.

## SQL injection
**Rules:** Bandit `B608`, Semgrep `formatted-sql-query`, `sqlalchemy-execute-raw-query`, `jdbc-sqli`, `formatted-sql-string`.
```python
# before                                                  # after (parameters, never string building)
db.execute("SELECT * FROM t WHERE id = %s" % item_id)     db.execute("SELECT * FROM t WHERE id = ?", (item_id,))      # sqlite
cur.execute(f"... WHERE name = '{name}'")                 cur.execute("... WHERE name = %s", (name,))                 # psycopg2
```
```java
// before: stmt.executeQuery("... WHERE name = '" + name + "'");
PreparedStatement ps = c.prepareStatement("... WHERE name = ?"); ps.setString(1, name);
```
Table/column names cannot be parameters: validate them against an allow-list.

## Command injection
**Rules:** Bandit `B602/B605`, Semgrep `subprocess-shell-true`, `subprocess-injection`, `detect-child-process`.
```python
subprocess.call(cmd, shell=True)                      # before
subprocess.run(["ls", "-l", directory], check=True)   # after: list form, no shell
```
```js
exec("ls " + dir)                    // before
execFile("ls", ["-l", dir])          // after
```
Never build a shell string from user input; validate against an allow-list when you must.

## Unsafe deserialization / YAML
**Rules:** Bandit `B301`, `B506`, Semgrep `avoid-pickle`, `avoid-insecure-deserialization`. Never `pickle.loads` data you did not create; use JSON. `yaml.load(x)` -> `yaml.safe_load(x)`. Java `ObjectInputStream`: use JSON or an allow-list filter.

## Cross-site scripting (XSS), DOM and reflected
**Rules:** ZAP `40012/40026`, ESLint `no-unsanitized/*`, Semgrep `raw-html-format`, `direct-response-write`.
```js
el.innerHTML = userHtml;                 // before
el.textContent = userText;               // after (or sanitize with DOMPurify if HTML is required)
res.send("<h1>Hello " + name + "</h1>")  // before: use a template engine that escapes, or escape-html
```
React escapes by default; avoid `dangerouslySetInnerHTML`. FastAPI/Flask: render with Jinja2 autoescape instead of f-string HTML.

## Path traversal, SSRF, weak crypto
- **Path traversal** (`open(BASE + name)`): `p = (Path(BASE) / name).resolve(); assert p.is_relative_to(Path(BASE).resolve())`.
- **SSRF** (`requests.get(user_url)`): allow-list hosts/schemes; block private/metadata IP ranges. **`verify=False`**: remove it; fix the CA bundle instead.
- **MD5/SHA1** (`B324`, `use-of-md5`): use SHA-256 for integrity; for passwords use `bcrypt`/`argon2`, never a plain hash.
- **`eval`** (`no-eval`, `eval-detected`): parse data with `JSON.parse`/`ast.literal_eval` instead.
- **Regex from user input** (`detect-non-literal-regexp`): escape it, or avoid user-supplied patterns (ReDoS).

## CORS, security headers (ZAP)
- **CORS `*` with credentials**: list the exact origins you trust.
  ```python
  app.add_middleware(CORSMiddleware, allow_origins=["https://app.example.com"], allow_credentials=True)
  ```
- Missing headers (CSP, `X-Content-Type-Options`, `X-Frame-Options`, HSTS): add them in one middleware or at the gateway. Quick win: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Content-Security-Policy: default-src 'self'`.

## Dockerfile and image
| Rule | Fix |
|---|---|
| `DS-0002` / `missing-user` (runs as root) | `RUN useradd -r app && chown -R app /app` then `USER app` |
| `DS-0005` / `S7029` (`ADD`) | Use `COPY` (`ADD` fetches URLs and unpacks archives implicitly) |
| `DS-0026` (no HEALTHCHECK) | `HEALTHCHECK CMD curl -f http://localhost:8000/health || exit 1` |
| `DS-0029` (`apt-get` without `--no-install-recommends`) | `apt-get install -y --no-install-recommends ...` |
| `DS-0031` (secrets in ENV) | See Secrets above |
| Hundreds of OS-package CVEs in the image | Rebuild on a current, smaller base (`python:3.12-slim`, `node:22-alpine`, distroless), pin it, and rebuild regularly. Old tags (`python:3.9`) keep accumulating CVEs |
| `FROM node:14` / EOL runtimes | Move to a supported runtime version |

## Not sure? Is it a false positive?
Read the rule's explanation (search the rule id), check whether the flagged input is really user-controlled. If it is safe, record **why** in an exception with an expiry ([exceptions-and-baseline.md](exceptions-and-baseline.md)); do not delete the check.
