# Logged-in ZAP scans: login types, SSO, and how to keep test credentials safe

A scan of a login page finds little. To test what is **behind** the login, ZAP and the API fuzzer must be signed in as a **test user**. Warden does the login for you, keeps the result in memory, and gives ZAP one header (a token or session cookie) for every request.

Only run this against QA/UAT systems you own, with a dedicated test account. Never production.

## 1. Pick the login type
Set `SEC_ZAP_AUTH` in `.security/config.env` (non-secret) and give the secrets separately (section 3).

| `SEC_ZAP_AUTH` | Use it when | Settings (config.env, not secret) | Secrets |
|---|---|---|---|
| *(not set)* + `ZAP_AUTH_TOKEN` | You already have a token | | `ZAP_AUTH_TOKEN` |
| *(not set)* + `ZAP_AUTH_HEADER` | API key in a header | | `ZAP_AUTH_HEADER` = `X-Api-Key: value` |
| `basic` | HTTP Basic auth | | `ZAP_AUTH_USER`, `ZAP_AUTH_PASSWORD` |
| `cookie` | You have a session cookie | | `ZAP_AUTH_COOKIE` = `name=value; name2=value2` |
| `login-json` | A REST login returns a token (most SPAs and APIs) | `SEC_ZAP_LOGIN_URL`, `SEC_ZAP_USER_FIELD` (default `username`), `SEC_ZAP_PASSWORD_FIELD` (default `password`), `SEC_ZAP_TOKEN_PATH` (default `access_token`; `data.token` for nested; empty = use cookies) | `ZAP_AUTH_USER`, `ZAP_AUTH_PASSWORD` |
| `form` | A classic HTML login form with a session cookie | `SEC_ZAP_LOGIN_URL` (where the form posts), `SEC_ZAP_LOGIN_PAGE` (page to open first), `SEC_ZAP_USER_FIELD`, `SEC_ZAP_PASSWORD_FIELD`, `SEC_ZAP_CSRF_FIELD` (hidden anti-forgery input), `SEC_ZAP_LOGIN_EXTRA` (`a=b&c=d`) | `ZAP_AUTH_USER`, `ZAP_AUTH_PASSWORD` |
| `oauth2-client` | **SSO, machine login** (OpenID Connect / OAuth2 client credentials) | `SEC_ZAP_LOGIN_URL` (the token endpoint), `SEC_ZAP_OAUTH_SCOPE`, `SEC_ZAP_OAUTH_AUDIENCE`, `SEC_ZAP_OAUTH_CLIENT_AUTH` (`basic` default or `body`) | `ZAP_OAUTH_CLIENT_ID`, `ZAP_OAUTH_CLIENT_SECRET` |
| `oauth2-password` | **SSO, test user** with the password grant (non-production tenant only) | same as above | `ZAP_OAUTH_CLIENT_ID`, `ZAP_OAUTH_CLIENT_SECRET`, `ZAP_AUTH_USER`, `ZAP_AUTH_PASSWORD` |

Example (`.security/config.env`, safe to commit):
```ini
SEC_ZAP_URL=https://qa.example.com/
SEC_ZAP_AUTH=login-json
SEC_ZAP_LOGIN_URL=https://qa.example.com/api/login
SEC_ZAP_TOKEN_PATH=data.token
```
Settings with spaces or special characters (a logged-in/out text such as `SEC_ZAP_LOGGED_IN_REGEX`, `SEC_ZAP_LOGGED_OUT_REGEX`, `SEC_ZAP_TOKEN_PREFIX`, `SEC_ZAP_LOGIN_EXTRA_JSON`) go in the workflow's `env:` instead of config.env.

**A failed login stops the scan.** If the login does not work, ZAP is **not** run and the report shows ZAP as "did not complete". An anonymous scan would look clean when it is not. Warden never prints the password or the token; in GitHub Actions the obtained token is also masked in the log.

For a form login, set `SEC_ZAP_LOGGED_OUT_REGEX` (for example `Invalid credentials`) or `SEC_ZAP_LOGGED_IN_REGEX` (for example `Welcome`) so a wrong password cannot pass for a login. Without either, Warden still requires the login to set or change a cookie.

## 2. Can it do SSO?
**Yes for the token-based SSO flows, which is how most enterprise APIs work. Not for interactive browser SSO with MFA out of the box.**

| Your situation | Possible? | How |
|---|---|---|
| API or app protected by an OpenID Connect / OAuth2 identity provider (Entra ID / Azure AD, Okta, Keycloak, Auth0, Ping) | **Yes** | Register a **scanner client** in the **non-production** tenant (client credentials). Use `oauth2-client`. The token endpoint goes in `SEC_ZAP_LOGIN_URL`. |
| Same, but the API needs a user identity, not just an app | **Yes** (non-prod) | Create a dedicated test user and enable the password grant for the test client. Use `oauth2-password`. Many tenants block this grant or require MFA; then use the next row. |
| Interactive SSO: SAML, or OpenID Connect through the browser, with a redirect, consent screen or MFA | **Not directly** | ZAP cannot click through an identity provider. Add a workflow step **before** the scan that signs a dedicated test user in with a headless browser (Playwright), captures the access token or the session cookie, and passes it as `ZAP_AUTH_TOKEN` or `ZAP_AUTH_COOKIE`. Ask your identity team for a test user that is exempt from MFA, or a TOTP secret you can use in the script. See the example below. This step is not part of Warden and is untested here. |
| Scan the single-page app UI behind SSO | Partly | ZAP crawls with the cookie or token you give it. A single-page app that keeps its token in browser storage is easier to test through its API (`oauth2-*` + `--zap-mode api`) than through the UI. |

Typical endpoints (check your tenant's documentation):

| Provider | `SEC_ZAP_LOGIN_URL` (token endpoint) | `SEC_ZAP_OAUTH_SCOPE` / audience |
|---|---|---|
| Microsoft Entra ID | `https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token` | scope `api://<api-app-id>/.default` |
| Okta | `https://<org>.okta.com/oauth2/<server-id>/v1/token` | scope of your API |
| Keycloak | `https://<host>/realms/<realm>/protocol/openid-connect/token` | client scope |
| Auth0 | `https://<tenant>.auth0.com/oauth/token` | `SEC_ZAP_OAUTH_AUDIENCE=<api identifier>`, `SEC_ZAP_OAUTH_CLIENT_AUTH=body` |

What to ask your identity team for: a scanner **client** (and, if needed, a test **user**) in the **QA tenant only**, least privilege, no production access, secrets stored as in section 3, and an expiry/rotation date. Tokens usually live about an hour: long active scans (`--zap-mode full`) may outlive them, so scan fewer URLs at a time or ask for a longer-lived token for the scanner client.

Browser step, GitHub Actions (example, adapt and test on your tenant):
```yaml
      - name: Sign the test user in through SSO (headless browser)
        env:
          SSO_USER: ${{ secrets.ZAP_AUTH_USER }}
          SSO_PASSWORD: ${{ secrets.ZAP_AUTH_PASSWORD }}
        run: |
          pip install playwright && playwright install --with-deps chromium
          python .security/sso_login.py > "$RUNNER_TEMP/cookie.txt"     # your script: prints "name=value; name2=value2"
          echo "::add-mask::$(cat "$RUNNER_TEMP/cookie.txt")"
          echo "ZAP_AUTH_COOKIE=$(cat "$RUNNER_TEMP/cookie.txt")" >> "$GITHUB_ENV"
      - run: .security/warden scan --zap-url "$QA_URL"
```

## 3. Where the usernames, passwords and tokens live (never in git)
Warden reads secrets **only from the environment**, a file, or a prompt. They are never read from `config.env` and never written to a report. A secret written into `config.env` is refused with a message and gitleaks flags it anyway.

| Where you run it | How to give the secrets | Effort |
|---|---|---|
| **GitHub Actions** | Repository or **Environment** secrets (Settings > Secrets and variables > Actions). Put QA secrets in an Environment named `qa` and add `environment: qa` to the job: they are only released to that job, and you can require a reviewer. Pass them in the step's `env:` (examples below). | 2 minutes |
| **Your laptop** | `warden creds set ZAP_AUTH_USER` and `warden creds set ZAP_AUTH_PASSWORD` (typed hidden). Stored in `~/.config/warden/credentials.env` (mode 600, **outside any repo**; it refuses a path inside a git repository). `warden creds list` shows names only; `warden creds delete NAME` removes one. Use `--profile qa` / `--profile uat` (or `SEC_CREDENTIALS_PROFILE=qa`) to keep environments apart. | 1 minute, once |
| **Prompt** | Run `warden scan` in a terminal with `SEC_ZAP_AUTH` set and nothing stored: Warden asks for what is missing (password typed hidden) and keeps it in memory only. In CI it never asks. | nothing to set up |
| **Docker / Kubernetes / Jenkins file credentials** | Give a file path instead of the value: `ZAP_AUTH_PASSWORD_FILE=/run/secrets/zap_pw` (works for every secret name). | nothing to install |
| **A secret manager** (HashiCorp Vault, Azure Key Vault, AWS Secrets Manager, 1Password) | Fetch in a step before the scan and export to the environment (examples below). Warden does not need to know which manager you use. | 5 minutes |

Order of precedence: environment variable (or CI secret) > `NAME_FILE` > the local credentials file > prompt.

GitHub Actions, secrets from GitHub:
```yaml
  zap:
    environment: qa
    steps:
      - uses: actions/checkout@<pinned sha>
        with: { persist-credentials: false }
      - name: ZAP (logged in as the test user)
        env:
          QA_URL: ${{ vars.QA_URL }}
          ZAP_AUTH_USER: ${{ secrets.ZAP_AUTH_USER }}
          ZAP_AUTH_PASSWORD: ${{ secrets.ZAP_AUTH_PASSWORD }}
        run: .security/warden scan --zap-url "$QA_URL"
```
OAuth2 / SSO client: use `ZAP_OAUTH_CLIENT_ID` and `ZAP_OAUTH_CLIENT_SECRET` instead.

From a secret manager (add `::add-mask::` so the value cannot appear in logs):
```yaml
      - name: Fetch the test credentials from Azure Key Vault     # after azure/login (OIDC, no stored key)
        run: |
          pw="$(az keyvault secret show --vault-name my-qa-vault --name zap-test-password --query value -o tsv)"
          echo "::add-mask::$pw"; echo "ZAP_AUTH_PASSWORD=$pw" >> "$GITHUB_ENV"
      - name: Fetch from AWS Secrets Manager                      # after aws-actions/configure-aws-credentials (OIDC)
        run: |
          pw="$(aws secretsmanager get-secret-value --secret-id qa/zap-test-password --query SecretString --output text)"
          echo "::add-mask::$pw"; echo "ZAP_AUTH_PASSWORD=$pw" >> "$GITHUB_ENV"
      - name: Fetch from HashiCorp Vault                          # needs a runner that can reach Vault
        run: |
          pw="$(vault kv get -field=password secret/qa/zap-test)"
          echo "::add-mask::$pw"; echo "ZAP_AUTH_PASSWORD=$pw" >> "$GITHUB_ENV"
```
Jenkins: bind a *Username with password* or *Secret text* credential with `withCredentials` and set the same variable names. Azure DevOps: use a variable group linked to Key Vault and map the secrets to environment variables of the step.

## 4. Good habits for test accounts
- One **dedicated** account per environment, used only by the scanner. Never a person's account, never a production account.
- Least privilege: just enough to reach the pages and APIs under test. Active scans create and change data, so use test data.
- Rotate on a schedule and when someone leaves. Put an expiry date on the account.
- Restrict who can read the secrets (GitHub Environments with required reviewers, vault policies).
- If a credential is ever committed by mistake, treat it as leaked: **rotate it first**, then remove it from history.
