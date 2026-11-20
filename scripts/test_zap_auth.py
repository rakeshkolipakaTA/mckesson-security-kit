"""Tests for scripts/zap_auth.py (the login types for authenticated ZAP scans) against a mock app and a mock identity provider.
Run: python3 -I scripts/test_zap_auth.py"""
import base64, json, os, re, subprocess, sys, threading, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "zap_auth.py")
CSRF = "csrf-abc-123"


class App(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def send(self, code, body="", ctype="text/html", headers=()):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(b)))
        for k, v in headers: self.send_header(k, v)
        self.end_headers(); self.wfile.write(b)

    def read(self):
        n = int(self.headers.get("Content-Length") or 0); return self.rfile.read(n).decode()

    def do_GET(self):
        if self.path == "/login-page":   # value before name on purpose in the second input: both attribute orders must work
            return self.send(200, f'<form><input type="hidden" name="_csrf" value="{CSRF}"><input value="x" name="other"></form>', headers=[("Set-Cookie", "pre=1; Path=/")])
        if self.path == "/login-page2":
            return self.send(200, f'<form><input value="{CSRF}" type="hidden" name="_csrf"></form>', headers=[("Set-Cookie", "pre=1; Path=/")])
        if self.path == "/home":
            return self.send(200, "Welcome back" if "sessionid=SESS42" in (self.headers.get("Cookie") or "") else "Please log in")
        self.send(404, "no")

    def do_POST(self):
        body = self.read(); ct = self.headers.get("Content-Type", "")
        if self.path == "/form-login":
            f = dict(urllib.parse.parse_qsl(body))
            if f.get("_csrf") == CSRF and "pre=1" in (self.headers.get("Cookie") or "") and f.get("username") == "tester" and f.get("password") == "S3cret!pw":
                return self.send(302, "", headers=[("Set-Cookie", "sessionid=SESS42; Path=/"), ("Location", "/home")])
            return self.send(200, "Invalid credentials")
        if self.path == "/api/login":
            d = json.loads(body)
            if d.get("username") == "tester" and d.get("password") == "S3cret!pw" and d.get("tenant", "t1") == "t1":
                return self.send(200, json.dumps({"data": {"token": "JWT-123", "list": ["a"]}}), "application/json", [("Set-Cookie", "api=1; Path=/")])
            return self.send(401, json.dumps({"error": "bad"}), "application/json")
        if self.path == "/token":
            f = dict(urllib.parse.parse_qsl(body)); auth = self.headers.get("Authorization", "")
            cid, sec = f.get("client_id"), f.get("client_secret")
            if auth.startswith("Basic "):
                cid, _, sec = base64.b64decode(auth[6:]).decode().partition(":")
                cid, sec = urllib.parse.unquote(cid), urllib.parse.unquote(sec)
            if (cid, sec) != ("scanner", "cl1ent/secret+x"):
                return self.send(401, json.dumps({"error": "invalid_client", "error_description": "bad client", "secret_echo": sec}), "application/json")
            if f.get("grant_type") == "client_credentials":
                return self.send(200, json.dumps({"access_token": "CC-TOKEN", "token_type": "bearer", "scope": f.get("scope", "")}), "application/json")
            if f.get("grant_type") == "password" and (f.get("username"), f.get("password")) == ("tester", "S3cret!pw"):
                return self.send(200, json.dumps({"access_token": "PW-TOKEN", "token_type": "Bearer"}), "application/json")
            return self.send(400, json.dumps({"error": "invalid_grant"}), "application/json")
        self.send(404, "no")


srv = ThreadingHTTPServer(("127.0.0.1", 0), App)
threading.Thread(target=srv.serve_forever, daemon=True).start()
U = "http://127.0.0.1:%d" % srv.server_address[1]
GOOD = {"ZAP_AUTH_USER": "tester", "ZAP_AUTH_PASSWORD": "S3cret!pw"}


def run(mode, _stdin=None, _args=(), **env):
    e = {k: v for k, v in os.environ.items() if not k.startswith(("ZAP_", "SEC_ZAP"))}
    e.update(env)
    p = subprocess.run([sys.executable, "-I", SCRIPT, "--mode", mode, *_args], capture_output=True, text=True, env=e, timeout=60,
                       input=_stdin, start_new_session=True)   # no controlling terminal: getpass falls back to stdin, which is what the test feeds
    return p.returncode, p.stdout.strip(), p.stderr.strip()


def t_bearer_and_header_and_cookie():
    assert run("bearer", ZAP_AUTH_TOKEN="tok")[1:2] == ("Authorization: Bearer tok",)
    assert run("header", ZAP_AUTH_HEADER="X-Api-Key:  k1 ")[1] == "X-Api-Key: k1"
    assert run("cookie", ZAP_AUTH_COOKIE="a=1; b=2")[1] == "Cookie: a=1; b=2"


def t_basic_username_password():
    rc, out, _ = run("basic", **GOOD)
    assert rc == 0 and out == "Authorization: Basic " + base64.b64encode(b"tester:S3cret!pw").decode()


def t_json_login_returns_the_token_from_a_nested_path():
    rc, out, err = run("login-json", SEC_ZAP_LOGIN_URL=U + "/api/login", SEC_ZAP_TOKEN_PATH="data.token", **GOOD)
    assert rc == 0 and out == "Authorization: Bearer JWT-123", (out, err)


def t_json_login_custom_fields_prefix_extra_and_cookie_mode():
    rc, out, _ = run("login-json", SEC_ZAP_LOGIN_URL=U + "/api/login", SEC_ZAP_TOKEN_PATH="data.token", SEC_ZAP_TOKEN_PREFIX="JWT ", SEC_ZAP_LOGIN_EXTRA_JSON='{"tenant":"t1"}', **GOOD)
    assert out == "Authorization: JWT JWT-123"
    rc, out, _ = run("login-json", SEC_ZAP_LOGIN_URL=U + "/api/login", SEC_ZAP_TOKEN_PATH="", **GOOD)
    assert rc == 0 and out == "Cookie: api=1"
    assert run("login-json", SEC_ZAP_LOGIN_URL=U + "/api/login", SEC_ZAP_LOGIN_EXTRA_JSON='{"tenant":"other"}', **GOOD)[0] == 1


def t_json_login_wrong_password_fails_and_never_echoes_secrets():
    rc, out, err = run("login-json", SEC_ZAP_LOGIN_URL=U + "/api/login", ZAP_AUTH_USER="tester", ZAP_AUTH_PASSWORD="wrong-pw-xyz")
    assert rc == 1 and out == "" and "HTTP 401" in err and "wrong-pw-xyz" not in err


def t_json_login_missing_token_path_is_explained():
    rc, out, err = run("login-json", SEC_ZAP_LOGIN_URL=U + "/api/login", SEC_ZAP_TOKEN_PATH="nope.here", **GOOD)
    assert rc == 1 and "SEC_ZAP_TOKEN_PATH" in err


def t_form_login_with_csrf_both_attribute_orders():
    for page in ("/login-page", "/login-page2"):
        rc, out, err = run("form", SEC_ZAP_LOGIN_URL=U + "/form-login", SEC_ZAP_LOGIN_PAGE=U + page, SEC_ZAP_CSRF_FIELD="_csrf", SEC_ZAP_LOGGED_IN_REGEX="Welcome back", **GOOD)
        assert rc == 0 and "sessionid=SESS42" in out and out.startswith("Cookie: "), (page, out, err)


def t_form_login_wrong_password_is_detected_not_silently_anonymous():
    rc, out, err = run("form", SEC_ZAP_LOGIN_URL=U + "/form-login", SEC_ZAP_LOGIN_PAGE=U + "/login-page", SEC_ZAP_CSRF_FIELD="_csrf",
                       SEC_ZAP_LOGGED_OUT_REGEX="Invalid credentials", ZAP_AUTH_USER="tester", ZAP_AUTH_PASSWORD="nope")
    assert rc == 1 and "nope" not in err and out == ""
    rc, out, err = run("form", SEC_ZAP_LOGIN_URL=U + "/form-login", SEC_ZAP_LOGIN_PAGE=U + "/login-page", SEC_ZAP_CSRF_FIELD="_csrf", ZAP_AUTH_USER="tester", ZAP_AUTH_PASSWORD="nope")
    assert rc == 1 and "did not set or change any cookie" in err, err   # no regex configured: a login that starts no session must still fail


def t_form_login_missing_csrf_field_is_explained():
    rc, out, err = run("form", SEC_ZAP_LOGIN_URL=U + "/form-login", SEC_ZAP_LOGIN_PAGE=U + "/login-page", SEC_ZAP_CSRF_FIELD="token_that_is_not_there", **GOOD)
    assert rc == 1 and "token_that_is_not_there" in err


def t_oauth2_client_credentials_basic_and_body_auth_with_special_characters():
    base = dict(SEC_ZAP_LOGIN_URL=U + "/token", ZAP_OAUTH_CLIENT_ID="scanner", ZAP_OAUTH_CLIENT_SECRET="cl1ent/secret+x")
    rc, out, err = run("oauth2-client", SEC_ZAP_OAUTH_SCOPE="api://x/.default", **base)
    assert rc == 0 and out == "Authorization: Bearer CC-TOKEN", (out, err)
    rc, out, _ = run("oauth2-client", SEC_ZAP_OAUTH_CLIENT_AUTH="body", **base)
    assert rc == 0 and out == "Authorization: Bearer CC-TOKEN"


def t_oauth2_password_grant_for_a_test_user():
    rc, out, err = run("oauth2-password", SEC_ZAP_LOGIN_URL=U + "/token", ZAP_OAUTH_CLIENT_ID="scanner", ZAP_OAUTH_CLIENT_SECRET="cl1ent/secret+x", **GOOD)
    assert rc == 0 and out == "Authorization: Bearer PW-TOKEN", (out, err)
    rc, out, err = run("oauth2-password", SEC_ZAP_LOGIN_URL=U + "/token", ZAP_OAUTH_CLIENT_ID="scanner", ZAP_OAUTH_CLIENT_SECRET="cl1ent/secret+x", ZAP_AUTH_USER="tester", ZAP_AUTH_PASSWORD="bad")
    assert rc == 1 and "invalid_grant" in err and "bad" not in err.replace("invalid_grant", "")


def t_idp_errors_show_the_idp_reason_but_never_the_secret():
    rc, out, err = run("oauth2-client", SEC_ZAP_LOGIN_URL=U + "/token", ZAP_OAUTH_CLIENT_ID="scanner", ZAP_OAUTH_CLIENT_SECRET="WRONG-SECRET-VALUE")
    assert rc == 1 and "invalid_client" in err and "WRONG-SECRET-VALUE" not in err


def t_plain_http_to_a_non_loopback_host_is_refused_for_credentials():
    rc, out, err = run("basic", **GOOD)   # basic needs no request: allowed
    assert rc == 0
    rc, out, err = run("login-json", SEC_ZAP_LOGIN_URL="http://qa.internal.example/api/login", **GOOD)
    assert rc == 1 and "plain http" in err and "SEC_ZAP_AUTH_ALLOW_HTTP" in err


def t_header_injection_and_bad_input_are_rejected():
    assert run("header", ZAP_AUTH_HEADER="X-A: v\r\nX-Evil: 1")[0] == 1
    assert run("header", ZAP_AUTH_HEADER="Bad Name: v")[0] == 1
    assert run("header", ZAP_AUTH_HEADER="novalue")[0] == 1
    assert run("bearer", ZAP_AUTH_TOKEN="a\nb")[0] == 1
    assert run("bearer")[0] == 1 and run("basic", ZAP_AUTH_USER="u")[0] == 1
    assert run("nonsense")[0] == 2
    assert run("form", SEC_ZAP_LOGIN_URL="file:///etc/passwd", **GOOD)[0] == 1


def t_secrets_can_come_from_files_for_docker_kubernetes_and_jenkins():
    import tempfile
    d = tempfile.mkdtemp(); pw = os.path.join(d, "pw"); us = os.path.join(d, "us")
    open(pw, "w").write("S3cret!pw\n"); open(us, "w").write("tester\n")
    rc, out, err = run("login-json", SEC_ZAP_LOGIN_URL=U + "/api/login", SEC_ZAP_TOKEN_PATH="data.token", ZAP_AUTH_USER_FILE=us, ZAP_AUTH_PASSWORD_FILE=pw)
    assert rc == 0 and out == "Authorization: Bearer JWT-123", (out, err)
    assert run("bearer", ZAP_AUTH_TOKEN_FILE=pw)[1] == "Authorization: Bearer S3cret!pw"
    assert run("bearer", ZAP_AUTH_TOKEN_FILE=os.path.join(d, "missing"))[0] == 1
    assert run("bearer", ZAP_AUTH_TOKEN="direct", ZAP_AUTH_TOKEN_FILE=pw)[1] == "Authorization: Bearer direct", "a plain variable wins over the file"


def t_prompt_asks_only_for_what_is_missing_and_hides_nothing_in_output():
    rc, out, err = run("basic", _stdin="tester\nS3cret!pw\n", _args=("--prompt",))
    assert rc == 0 and out == "Authorization: Basic " + base64.b64encode(b"tester:S3cret!pw").decode(), (out, err)
    assert "ZAP_AUTH_USER" in err and "ZAP_AUTH_PASSWORD" in err
    rc, out, err = run("basic", _stdin="S3cret!pw\n", _args=("--prompt",), ZAP_AUTH_USER="tester")   # the user name is already set: only the password is asked
    assert rc == 0 and "ZAP_AUTH_USER" not in err and "ZAP_AUTH_PASSWORD" in err
    rc, out, err = run("basic", _stdin="", _args=("--prompt",))
    assert rc == 1 and out == ""
    assert run("basic", _stdin="x\n")[0] == 1, "without --prompt (CI) nothing is ever asked"


def t_unreachable_login_host_fails_clearly():
    rc, out, err = run("login-json", SEC_ZAP_LOGIN_URL="http://127.0.0.1:9/login", **GOOD)
    assert rc == 1 and "could not reach" in err


TESTS = [(n, f) for n, f in sorted(globals().items()) if n.startswith("t_") and callable(f)]
ok = 0
for n, f in TESTS:
    try:
        f(); ok += 1; print("  PASS ", n[2:])
    except Exception as e:
        import traceback; print("  FAIL ", n[2:], repr(e)); traceback.print_exc(limit=3)
print("%d/%d passed" % (ok, len(TESTS)))
sys.exit(0 if ok == len(TESTS) else 1)
