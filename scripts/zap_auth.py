#!/usr/bin/env python3
"""Get the login header for an authenticated ZAP / API scan (standard library only).

  zap_auth.py --mode bearer|header|basic|cookie|login-json|form|oauth2-client|oauth2-password

Prints ONE line, "Header-Name: value", on stdout; scan.sh hands it to ZAP, which adds it to every request. Problems go to stderr
with exit 1: a scan that was meant to be authenticated must never silently run as an anonymous one. Secrets only ever come from
the environment (CI secrets), are never written to a file, and are never printed except as that one header line.

Non-secret settings (config.env or env)            Secrets (CI secrets, environment only)
  SEC_ZAP_LOGIN_URL        login endpoint / token endpoint   ZAP_AUTH_TOKEN                bearer: "Authorization: Bearer <t>"
  SEC_ZAP_LOGIN_PAGE       form: page to GET first (cookies / CSRF)  ZAP_AUTH_HEADER      header: "Name: value" (API key ...)
  SEC_ZAP_USER_FIELD / SEC_ZAP_PASSWORD_FIELD  field names    ZAP_AUTH_USER, ZAP_AUTH_PASSWORD   basic / login-json / form / oauth2-password
  SEC_ZAP_CSRF_FIELD       form: hidden input to copy        ZAP_AUTH_COOKIE               cookie: "name=value; name2=value2"
  SEC_ZAP_LOGIN_EXTRA      extra form fields "a=b&c=d"       ZAP_OAUTH_CLIENT_ID, ZAP_OAUTH_CLIENT_SECRET   oauth2-*
  SEC_ZAP_LOGIN_EXTRA_JSON extra JSON fields (login-json)
  SEC_ZAP_TOKEN_PATH       login-json: where the token is in the reply, e.g. access_token or data.token (empty = use cookies)
  SEC_ZAP_TOKEN_PREFIX     default "Bearer "
  SEC_ZAP_LOGGED_IN_REGEX / SEC_ZAP_LOGGED_OUT_REGEX   form: text that proves / disproves a successful login
  SEC_ZAP_OAUTH_SCOPE, SEC_ZAP_OAUTH_AUDIENCE, SEC_ZAP_OAUTH_CLIENT_AUTH=basic|body
  SEC_ZAP_AUTH_INSECURE=1  accept a self-signed certificate on the login host    SEC_ZAP_AUTH_ALLOW_HTTP=1  allow credentials over plain http

Any secret above can also be given as NAME_FILE=/path/to/file (the file holds the value), and --prompt asks for missing ones in a terminal.
"""
import argparse
import base64
import http.cookiejar
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

MODES = ["bearer", "header", "basic", "cookie", "login-json", "form", "oauth2-client", "oauth2-password"]
HEADER_NAME = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")


class AuthError(Exception):
    pass


def env(name, default=""):
    """A setting from the environment. NAME_FILE=/path reads the value from a file instead (Docker / Kubernetes secrets, Jenkins file credentials)."""
    v = os.environ.get(name)
    if v is not None and (v != "" or not os.environ.get(name + "_FILE")):   # set (even to empty: "no token path" means cookies) wins over the default
        return v
    path = os.environ.get(name + "_FILE")
    if path:
        try:
            with open(path, encoding="utf-8") as f:
                return f.read().strip("\r\n")
        except OSError as e:
            raise AuthError(f"{name}_FILE could not be read: {e.strerror}")
    return default


NEEDS = {   # what each mode needs from the secret side: (name, hidden?)
    "bearer": [("ZAP_AUTH_TOKEN", True)], "header": [("ZAP_AUTH_HEADER", True)], "cookie": [("ZAP_AUTH_COOKIE", True)],
    "basic": [("ZAP_AUTH_USER", False), ("ZAP_AUTH_PASSWORD", True)], "login-json": [("ZAP_AUTH_USER", False), ("ZAP_AUTH_PASSWORD", True)],
    "form": [("ZAP_AUTH_USER", False), ("ZAP_AUTH_PASSWORD", True)],
    "oauth2-client": [("ZAP_OAUTH_CLIENT_ID", False), ("ZAP_OAUTH_CLIENT_SECRET", True)],
    "oauth2-password": [("ZAP_OAUTH_CLIENT_ID", False), ("ZAP_OAUTH_CLIENT_SECRET", True), ("ZAP_AUTH_USER", False), ("ZAP_AUTH_PASSWORD", True)],
}


def prompt_missing(mode):
    """Ask for credentials that are not set (interactive use only). Typed secrets are hidden, kept only in this process, never saved."""
    import getpass
    for name, hidden in NEEDS.get(mode, []):
        if env(name) or (name == "ZAP_OAUTH_CLIENT_SECRET" and mode.startswith("oauth2")):   # a public client has no secret: Enter leaves it empty
            continue
        try:
            val = getpass.getpass(f"{name}: ", stream=sys.stderr) if hidden else (print(f"{name}: ", end="", file=sys.stderr, flush=True) or sys.stdin.readline().rstrip("\r\n"))
        except (EOFError, KeyboardInterrupt):
            raise AuthError(f"no value given for {name}")
        if val:
            os.environ[name] = val


def need(name):
    v = env(name)
    if not v:
        raise AuthError(f"{name} is not set")
    return v


def header_line(name, value):
    if not HEADER_NAME.match(name):
        raise AuthError("the header name is not valid")
    if "\r" in value or "\n" in value or not value.strip():
        raise AuthError("the header value is empty or contains a line break")
    return f"{name}: {value}"


def check_url(url):
    u = urllib.parse.urlparse(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise AuthError(f"not a usable URL: {url!r}")
    loopback = u.hostname in ("localhost", "127.0.0.1", "::1")
    if u.scheme == "http" and not loopback and env("SEC_ZAP_AUTH_ALLOW_HTTP") != "1":
        raise AuthError("refusing to send credentials over plain http; use https or set SEC_ZAP_AUTH_ALLOW_HTTP=1 for a throw-away QA host")
    return url


def opener():
    jar = http.cookiejar.CookieJar()
    ctx = ssl.create_default_context()
    if env("SEC_ZAP_AUTH_INSECURE") == "1":
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), urllib.request.HTTPSHandler(context=ctx)), jar


def call(op, url, data=None, headers=None):
    req = urllib.request.Request(check_url(url), data=data, headers=headers or {}, method="POST" if data is not None else "GET")
    try:
        with op.open(req, timeout=25) as r:
            return r.status, r.read(2_000_000).decode("utf-8", "replace"), r.geturl()
    except urllib.error.HTTPError as e:
        return e.code, e.read(200_000).decode("utf-8", "replace"), url
    except (urllib.error.URLError, OSError) as e:
        raise AuthError(f"could not reach {urllib.parse.urlparse(url).netloc}: {getattr(e, 'reason', e)}")


def dig(obj, path):
    for part in path.split("."):
        if isinstance(obj, dict) and part in obj:
            obj = obj[part]
        elif isinstance(obj, list) and part.isdigit() and int(part) < len(obj):
            obj = obj[int(part)]
        else:
            return None
    return obj


def cookie_header(jar):
    pairs = [f"{c.name}={c.value}" for c in jar]
    if not pairs:
        raise AuthError("the login did not return any session cookie")
    return header_line("Cookie", "; ".join(pairs))


def oauth_error(body):
    try:
        d = json.loads(body)
        return ": ".join(str(d[k]) for k in ("error", "error_description") if d.get(k))[:300]
    except ValueError:
        return ""


# ---------- modes ----------
def m_bearer():
    return header_line("Authorization", f"Bearer {need('ZAP_AUTH_TOKEN')}")


def m_header():
    raw = need("ZAP_AUTH_HEADER")
    if ":" not in raw:
        raise AuthError('ZAP_AUTH_HEADER must look like "Name: value"')
    n, v = raw.split(":", 1)
    return header_line(n.strip(), v.strip())


def m_basic():
    tok = base64.b64encode(f"{need('ZAP_AUTH_USER')}:{need('ZAP_AUTH_PASSWORD')}".encode()).decode()
    return header_line("Authorization", f"Basic {tok}")


def m_cookie():
    return header_line("Cookie", need("ZAP_AUTH_COOKIE"))


def m_login_json():
    url = need("SEC_ZAP_LOGIN_URL")
    body = {env("SEC_ZAP_USER_FIELD", "username"): need("ZAP_AUTH_USER"), env("SEC_ZAP_PASSWORD_FIELD", "password"): need("ZAP_AUTH_PASSWORD")}
    if env("SEC_ZAP_LOGIN_EXTRA_JSON"):
        try:
            extra = json.loads(env("SEC_ZAP_LOGIN_EXTRA_JSON"))
        except ValueError:
            raise AuthError("SEC_ZAP_LOGIN_EXTRA_JSON is not valid JSON")
        body.update(extra if isinstance(extra, dict) else {})
    op, jar = opener()
    st, text, _ = call(op, url, json.dumps(body).encode(), {"Content-Type": "application/json", "Accept": "application/json"})
    if st >= 400:
        raise AuthError(f"login failed: HTTP {st}")
    path = env("SEC_ZAP_TOKEN_PATH", "access_token")
    if not path:
        return cookie_header(jar)
    try:
        tok = dig(json.loads(text), path)
    except ValueError:
        tok = None
    if not isinstance(tok, str) or not tok:
        raise AuthError(f"login worked but no token was found at '{path}' in the reply (set SEC_ZAP_TOKEN_PATH, or empty to use cookies)")
    return header_line("Authorization", env("SEC_ZAP_TOKEN_PREFIX", "Bearer ") + tok)


def m_form():
    url = need("SEC_ZAP_LOGIN_URL")
    fields = {env("SEC_ZAP_USER_FIELD", "username"): need("ZAP_AUTH_USER"), env("SEC_ZAP_PASSWORD_FIELD", "password"): need("ZAP_AUTH_PASSWORD")}
    for k, v in urllib.parse.parse_qsl(env("SEC_ZAP_LOGIN_EXTRA")):
        fields[k] = v
    op, jar = opener()
    csrf = env("SEC_ZAP_CSRF_FIELD")
    page = env("SEC_ZAP_LOGIN_PAGE") or (url if csrf else "")
    if page:
        st, html, _ = call(op, page)
        if csrf:
            n = re.escape(csrf)
            m = re.search(rf"<input[^>]*name=[\"']{n}[\"'][^>]*value=[\"']([^\"']*)", html, re.I) or re.search(rf"<input[^>]*value=[\"']([^\"']*)[\"'][^>]*name=[\"']{n}[\"']", html, re.I)
            if not m:
                raise AuthError(f"the CSRF field '{csrf}' was not found on {page}")
            fields[csrf] = m.group(1)
    before = {(c.name, c.value) for c in jar}      # cookies that exist BEFORE logging in (CSRF / anonymous session): they prove nothing
    st, text, final = call(op, url, urllib.parse.urlencode(fields).encode(), {"Content-Type": "application/x-www-form-urlencoded"})
    if st >= 400:
        raise AuthError(f"login failed: HTTP {st}")
    seen = text + " " + final
    if env("SEC_ZAP_LOGGED_OUT_REGEX") and re.search(env("SEC_ZAP_LOGGED_OUT_REGEX"), seen):
        raise AuthError("login failed: the 'logged out' text was found in the reply (wrong username or password?)")
    if env("SEC_ZAP_LOGGED_IN_REGEX") and not re.search(env("SEC_ZAP_LOGGED_IN_REGEX"), seen):
        raise AuthError("login not confirmed: the 'logged in' text was not found in the reply")
    if not ({(c.name, c.value) for c in jar} - before):
        raise AuthError("the login did not set or change any cookie, so no session was started (wrong username or password? "
                        "Set SEC_ZAP_LOGGED_OUT_REGEX / SEC_ZAP_LOGGED_IN_REGEX to confirm; a login that keeps its token in browser storage needs login-json instead)")
    return cookie_header(jar)


def m_oauth(grant):
    url = need("SEC_ZAP_LOGIN_URL")
    cid, secret = need("ZAP_OAUTH_CLIENT_ID"), env("ZAP_OAUTH_CLIENT_SECRET")
    form = {"grant_type": grant}
    if grant == "password":
        form["username"], form["password"] = need("ZAP_AUTH_USER"), need("ZAP_AUTH_PASSWORD")
    for key, name in (("scope", "SEC_ZAP_OAUTH_SCOPE"), ("audience", "SEC_ZAP_OAUTH_AUDIENCE")):
        if env(name):
            form[key] = env(name)
    headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
    if env("SEC_ZAP_OAUTH_CLIENT_AUTH", "basic") == "basic" and secret:
        headers["Authorization"] = "Basic " + base64.b64encode(f"{urllib.parse.quote(cid, safe='')}:{urllib.parse.quote(secret, safe='')}".encode()).decode()
    else:
        form["client_id"] = cid
        if secret:
            form["client_secret"] = secret
    op, _ = opener()
    st, text, _ = call(op, url, urllib.parse.urlencode(form).encode(), headers)
    if st >= 400:
        raise AuthError(f"the identity provider refused the request: HTTP {st} {oauth_error(text)}".strip())
    try:
        d = json.loads(text)
    except ValueError:
        d = {}
    tok = d.get("access_token") if isinstance(d, dict) else None
    if not isinstance(tok, str) or not tok:
        raise AuthError("the identity provider answered without an access_token")
    kind = d.get("token_type") if isinstance(d.get("token_type"), str) and d["token_type"].isalpha() else "Bearer"
    return header_line("Authorization", f"{kind[:1].upper()}{kind[1:]} {tok}")


def run(mode):
    if mode == "oauth2-client":
        return m_oauth("client_credentials")
    if mode == "oauth2-password":
        return m_oauth("password")
    return {"bearer": m_bearer, "header": m_header, "basic": m_basic, "cookie": m_cookie, "login-json": m_login_json, "form": m_form}[mode]()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True)
    ap.add_argument("--prompt", action="store_true", help="ask for credentials that are not set (terminal use)")
    a = ap.parse_args()
    if a.mode not in MODES:
        print(f"zap_auth: unknown SEC_ZAP_AUTH '{a.mode}' (use one of: {', '.join(MODES)})", file=sys.stderr)
        return 2
    try:
        if a.prompt:
            prompt_missing(a.mode)
        print(run(a.mode))
        return 0
    except AuthError as e:
        print(f"zap_auth: {a.mode}: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
