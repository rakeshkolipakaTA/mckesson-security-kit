"""Tests for the helper scripts behind the newer checks: api_fuzz_report, exposure, repo_posture (local mock servers, no network).
Run: python3 -I scripts/test_tools.py"""
import http.server, json, os, subprocess, sys, tempfile, threading
HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable


def run(script, *args, env=None):
    return subprocess.run([PY, "-I", os.path.join(HERE, script), *args], capture_output=True, text=True, env=dict(os.environ, **(env or {})))


def serve(handler):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


# ---------------------------------------------------------------- api_fuzz_report
def test_api_fuzz_report_from_a_real_schemathesis_junit():
    out = os.path.join(tempfile.mkdtemp(), "o.json")
    r = run("api_fuzz_report.py", "--junit", os.path.join(HERE, "testdata", "schemathesis.xml"), "--spec", "http://x/openapi.json", "--out", out)
    assert r.returncode == 0, r.stderr
    d = json.load(open(out))
    ops = {f["location"] for f in d["findings"]}
    assert {"GET /items/{item_id}", "POST /load", "GET /fetch", "GET /file"} <= ops and all(f["severity"] == "MEDIUM" and f["rule"] == "API-FUZZ-5XX" for f in d["findings"])
    assert d["operations"] == 9


def test_api_fuzz_report_fails_closed_without_a_report_and_redacts_auth_headers():
    out = os.path.join(tempfile.mkdtemp(), "o.json")
    assert run("api_fuzz_report.py", "--junit", "/nonexistent.xml", "--out", out).returncode == 1 and not os.path.exists(out)
    x = os.path.join(tempfile.mkdtemp(), "j.xml")
    open(x, "w").write('<testsuites><testsuite><testcase name="GET /a"><failure message="m">- Server error\n\nReproduce with: \n\n    curl -X GET -H \'Authorization: Bearer SECRET123\' http://h/a</failure></testcase></testsuite></testsuites>')
    assert run("api_fuzz_report.py", "--junit", x, "--out", out).returncode == 0
    assert "SECRET123" not in open(out).read()
    open(x, "w").write("<testsuites></testsuites>")
    assert run("api_fuzz_report.py", "--junit", x, "--out", out + "2").returncode == 1


# ---------------------------------------------------------------- exposure
class Exposed(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def do_GET(self):
        o = self.headers.get("Origin")
        routes = {"/": (200, "text/html", "<html>hi</html>"), "/.git/HEAD": (200, "text/plain", "ref: refs/heads/main\n"),
                  "/.env": (200, "text/plain", "DB_PASSWORD=hunter2\nAPI_TOKEN=abc\n"), "/metrics": (200, "text/plain", "# HELP up\n# TYPE up gauge\nup 1\n"),
                  "/docs": (200, "text/html", "<html>swagger-ui</html>")}
        code, ctype, body = routes.get(self.path, (404, "text/plain", "nope"))
        self.send_response(code); self.send_header("Content-Type", ctype); self.send_header("Server", "nginx/1.18.0")
        if o:
            self.send_header("Access-Control-Allow-Origin", o); self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers(); self.wfile.write(body.encode())


def test_exposure_finds_planted_problems():
    srv, port = serve(Exposed)
    out = os.path.join(tempfile.mkdtemp(), "e.json")
    r = run("exposure.py", "--targets", f"http://127.0.0.1:{port}", "--out", out, "--no-ports")
    assert r.returncode == 0, r.stderr
    rules = {f["rule"] for f in json.load(open(out))["findings"]}
    assert {"EXP-HTTP", "EXP-GIT", "EXP-ENV", "EXP-METRICS", "EXP-APIDOCS", "EXP-CORS-REFLECT", "EXP-BANNER", "EXP-HDR-CSP"} <= rules, rules
    srv.shutdown()


class SpaCatchAll(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def do_GET(self):  # single-page app: every path returns the same HTML with 200
        self.send_response(200); self.send_header("Content-Type", "text/html"); self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"); self.end_headers(); self.wfile.write(b"<html>app</html>")


def test_exposure_does_not_cry_wolf_on_a_catch_all_app():
    srv, port = serve(SpaCatchAll)
    out = os.path.join(tempfile.mkdtemp(), "e.json")
    run("exposure.py", "--targets", f"http://127.0.0.1:{port}", "--out", out, "--no-ports")
    rules = {f["rule"] for f in json.load(open(out))["findings"]}
    assert rules <= {"EXP-HTTP", "EXP-BANNER"}, rules   # only transport/banner notes: no .git/.env/metrics/docs false positives
    srv.shutdown()


def test_exposure_reports_an_unreachable_target_as_info_and_detects_open_ports():
    out = os.path.join(tempfile.mkdtemp(), "e.json")
    run("exposure.py", "--targets", "http://127.0.0.1:9", "--out", out, "--no-ports")
    assert [f["severity"] for f in json.load(open(out))["findings"]] == ["INFO"]
    import socket
    s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(1); port = s.getsockname()[1]
    srv, hport = serve(SpaCatchAll)
    sys.path.insert(0, HERE)
    import exposure
    old = dict(exposure.PORTS); exposure.PORTS.clear(); exposure.PORTS[port] = ("Redis", "HIGH")
    res = []
    exposure.check_target(f"http://127.0.0.1:{hport}", 3, True, res)
    exposure.PORTS.clear(); exposure.PORTS.update(old); s.close(); srv.shutdown()
    assert any(f["rule"] == f"EXP-PORT-{port}" and f["severity"] == "HIGH" for f in res)


# ---------------------------------------------------------------- repo_posture
def github_mock(unprotected=True):
    class G(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a): pass

        def do_GET(self):
            p = self.path
            def send(code, body=None):
                self.send_response(code); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(json.dumps(body).encode() if body is not None else b"")
            if self.headers.get("Authorization") != "Bearer tok":
                return send(401, {})
            if p == "/repos/o/r":
                return send(200, {"default_branch": "main", "security_and_analysis": {"secret_scanning": {"status": "disabled"}, "secret_scanning_push_protection": {"status": "enabled"}}})
            if p.endswith("/protection"):
                return send(404, {}) if unprotected else send(200, {"required_pull_request_reviews": {}, "required_status_checks": {}, "allow_force_pushes": {"enabled": True}, "enforce_admins": {"enabled": False}})
            if "/rules/branches/" in p:
                return send(200, [])
            if "/contents/" in p:
                return send(404, {})
            if p.endswith("vulnerability-alerts"):
                return send(404, {})
            if p.endswith("/actions/permissions/workflow"):
                return send(200, {"default_workflow_permissions": "write", "can_approve_pull_request_reviews": True})
            send(404, {})
    return G


def test_repo_posture_flags_unprotected_repo_with_open_settings():
    srv, port = serve(github_mock(True))
    out = os.path.join(tempfile.mkdtemp(), "r.json")
    r = run("repo_posture.py", "--repo", "o/r", "--out", out, env={"GITHUB_TOKEN": "tok", "GITHUB_API_URL": f"http://127.0.0.1:{port}"})
    assert r.returncode == 0, r.stderr
    rules = {f["rule"]: f["severity"] for f in json.load(open(out))["findings"]}
    assert rules["REPO-UNPROTECTED"] == "HIGH" and rules["REPO-SECRET-SCANNING"] == "MEDIUM" and rules["REPO-NO-CODEOWNERS"] == "MEDIUM" and rules["REPO-WORKFLOW-WRITE"] == "MEDIUM" and rules["REPO-NO-ALERTS"] == "MEDIUM"
    assert "REPO-PUSH-PROTECTION" not in rules
    srv.shutdown()


def test_repo_posture_weak_protection_and_failure_modes():
    srv, port = serve(github_mock(False))
    out = os.path.join(tempfile.mkdtemp(), "r.json")
    run("repo_posture.py", "--repo", "o/r", "--out", out, env={"GITHUB_TOKEN": "tok", "GITHUB_API_URL": f"http://127.0.0.1:{port}"})
    rules = {f["rule"]: f["severity"] for f in json.load(open(out))["findings"]}
    assert rules["REPO-FORCE-PUSH"] == "HIGH" and rules["REPO-ADMIN-BYPASS"] == "LOW" and "REPO-UNPROTECTED" not in rules
    bad = run("repo_posture.py", "--repo", "o/r", "--out", out + "2", env={"GITHUB_TOKEN": "wrong", "GITHUB_API_URL": f"http://127.0.0.1:{port}"})
    assert bad.returncode == 1 and not os.path.exists(out + "2")                # a failed check is a tool error, never a pass
    assert run("repo_posture.py", "--out", out + "3", env={"GITHUB_TOKEN": "", "GH_TOKEN": "", "GITHUB_REPOSITORY": ""}).returncode == 1
    srv.shutdown()


if __name__ == "__main__":
    n = fail = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            n += 1
            try:
                fn(); print("  PASS ", name)
            except Exception as e:
                fail += 1; print("  FAIL ", name, repr(e)[:300])
    print(f"{n - fail}/{n} passed"); sys.exit(1 if fail else 0)
