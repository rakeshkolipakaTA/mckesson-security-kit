# 5. Dynamic testing (DAST): can the running application be attacked from outside?

## What it protects against
Some problems only show when the app runs: missing security headers, cookies without `Secure`, error pages that leak internals, a server that answers on plain HTTP, a debug endpoint left open, an API that crashes on odd input, a page that reflects input as script. Dynamic testing behaves like an attacker with a browser or a script: it sends requests to a **running QA system** and looks at the answers.

**Only point these at systems you own, in QA or UAT, with a dedicated test account. Never production.** Active scans create and change data.

## Checks

| Check | What it does | What it finds | Severity | Stage |
|---|---|---|---|---|
| **OWASP ZAP baseline** | Passive: crawls and watches responses, sends no attacks | Missing security headers, insecure cookies, information disclosure | by alert risk | post-deploy QA |
| **OWASP ZAP API scan** | Imports your OpenAPI spec and probes every operation | Issues on documented endpoints | by alert risk | post-deploy QA |
| **OWASP ZAP full (active) scan** | Actively attacks the seeded URLs | Reflected and DOM XSS, CORS problems, error disclosure, injection | by alert risk | post-deploy QA |
| **ZAP logged in** (`SEC_ZAP_AUTH`) | Signs in as a test user first, so ZAP also tests what is **behind** the login | Everything above on the authenticated area. Login types: basic, cookie, JSON login, HTML form (with CSRF), OAuth2 client credentials, OAuth2 password grant (SSO token flows) | by alert risk | post-deploy QA |
| **Schemathesis API fuzzing** | Generates many valid and invalid requests from the OpenAPI spec, with bodies | Server errors (HTTP 5xx), operations that ignore authentication, responses that break the schema. It found the 500s on the SQL injection, deserialisation, SSRF and traversal endpoints of the sample app | by finding type | post-deploy QA |
| **Exposure scan** (`SEC_EXPOSURE_TARGETS`) | Safe requests only (GET, TCP connect, TLS handshake) to hosts you list | See the table below | per rule | post-deploy and scheduled |

### Exposure scan rules

| Area | Rules (id) | Severity |
|---|---|---|
| TLS | Certificate expired (`EXP-TLS-EXPIRED`), expiring soon (`EXP-TLS-EXPIRING`), obsolete protocol (`EXP-TLS-PROTOCOL`), certificate not trusted or wrong host name (`EXP-TLS-CERT`) | High, Medium, High, High |
| Transport | Served over plain HTTP (`EXP-HTTP`), port 80 serves content instead of redirecting (`EXP-NO-REDIRECT`) | Medium |
| Headers | HSTS missing (`EXP-HDR-HSTS`), clickjacking protection missing (`EXP-HDR-XFO`), `X-Content-Type-Options` and Content-Security-Policy missing (`EXP-HDR-XCTO`, `EXP-HDR-CSP`), server version banner (`EXP-BANNER`) | Medium, Low, Low, Low |
| CORS | Reflects any origin with credentials (`EXP-CORS-REFLECT`), wildcard with credentials (`EXP-CORS-WILDCARD`), open to every origin (`EXP-CORS-OPEN`) | High, High, Low |
| Sensitive paths (High) | `/.git/HEAD` (source and history downloadable), `/.env`, Spring `/actuator/env` and `/actuator/heapdump`, Go `/debug/pprof/`, `/phpinfo.php`, backup archives and database dumps (`/backup.zip`, `/dump.sql`) (`EXP-GIT`, `EXP-ENV`, `EXP-ACTUATOR-ENV`, `EXP-HEAPDUMP`, `EXP-PPROF`, `EXP-PHPINFO`, `EXP-BACKUP`) | High |
| Sensitive paths (Medium and Low) | Spring `/actuator` index, Apache `/server-status`, Prometheus `/metrics` and OpenTelemetry `/v1/traces`, `/v1/metrics` open without authentication (`EXP-ACTUATOR`, `EXP-SERVERSTATUS`, `EXP-METRICS`, `EXP-OTLP`: Medium); public API specification and Swagger/ReDoc pages (`EXP-APIDOCS`: Low) | Medium / Low |
| Open ports | Docker API 2375, etcd 2379, Redis 6379, PostgreSQL 5432, MySQL 3306, MongoDB 27017, Elasticsearch 9200, Memcached 11211 (High); Kibana 5601, Consul 8500, OTLP 4317/4318, Prometheus 9090, node_exporter 9100, RabbitMQ management 15672 (Medium) (`EXP-PORT-<n>`) | High / Medium |

A result means "reachable from where the scanner runs", so run it from a network position an attacker would have.

## How it protects
* **A failed login stops the scan.** If ZAP cannot sign in, Warden does not run an anonymous scan that would look clean while the authenticated area was never tested. The report shows ZAP as "did not complete".
* **Credentials never touch git.** Usernames, passwords and tokens come from CI secrets, a file path, a local store outside the repo or a hidden prompt. They are never printed, never written to reports, and tokens are masked in GitHub Actions logs. Details: [../zap-authentication.md](../zap-authentication.md).
* **Safe by default.** The exposure scan and API fuzz use a few dozen requests, identify themselves with a User-Agent, and avoid false path findings on "catch-all" apps. ZAP defaults to report-only, since DAST results need a human to triage.
* **Setting a target switches the check on** (`SEC_ZAP_URL`, `SEC_API_SPEC`, `SEC_EXPOSURE_TARGETS`); with no target nothing runs and nothing is sent.

```ini
SEC_ZAP_URL=https://qa.example.com/
SEC_ZAP_AUTH=login-json            # see docs/zap-authentication.md for the other login types
SEC_API_SPEC=https://qa.example.com/openapi.json
SEC_EXPOSURE_TARGETS=https://qa.example.com
```

## Limits (important)
* **DAST is not a penetration test.** On the sample app ZAP's API scan sent example values only and found none of the planted bugs; the full scan missed SQL injection and path traversal there (no request bodies). Schemathesis did find the failing endpoints.
* Interactive browser SSO with MFA (SAML, redirect-based OpenID Connect) is **not** automated. Token-based SSO flows are. The guide describes a headless-browser step that is **not** part of Warden and is untested.
* Tokens expire (often an hour); a long full scan can outlive one.
* Broken access control that needs two users and business knowledge (user A reading user B's data on your own endpoints) is not found by generic scans. Test it by hand or with the red-team probes for agents.
* Status: **Verified** for ZAP baseline, logged-in scans (against a mock app and identity provider and a real ZAP container; not against real Entra ID or Okta), Schemathesis and the exposure scan. ZAP API and full scans are **verified (partial)**.
