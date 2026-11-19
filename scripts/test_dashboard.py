"""Dashboard + publisher tests (no Docker, no network beyond localhost). Run: python3 -I scripts/test_dashboard.py"""
import base64, json, os, subprocess, sys, tempfile, threading, urllib.error, urllib.request
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "dashboard"))
import server as S
from http.server import ThreadingHTTPServer

PW, TOK = "correct-horse-battery", "t" * 32
C = dict(user="secscan", password=PW, token=TOK, db=os.path.join(tempfile.mkdtemp(), "d.db"), stale=14, keep=3, sonar="http://sonar.example:9000")
S.db(C["db"]).close()
S.H.log_message = lambda *a, **k: None
srv = ThreadingHTTPServer(("127.0.0.1", 0), S.H); srv.c = C
threading.Thread(target=srv.serve_forever, daemon=True).start()
BASE = f"http://127.0.0.1:{srv.server_address[1]}"
AUTH = "Basic " + base64.b64encode(f"secscan:{PW}".encode()).decode()


def call(path, method="GET", data=None, headers=None):
    req = urllib.request.Request(BASE + path, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode(), r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), e.headers


def summary(**kw):
    s = {"target": "app", "date": "2026-11-19T10:00:00", "gate": "pr", "mode": "report-only", "result": "FAIL", "counts": {"CRITICAL": 2, "HIGH": 5, "MEDIUM": 3, "LOW": 1, "INFO": 0},
         "new_counts": {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 0, "LOW": 0, "INFO": 0}, "tool_status": {"gitleaks": "ok", "semgrep": "ok", "npm-audit": "invalid"},
         "by_tool": {"semgrep": 3}, "preset": "starter", "tools_not_run": {"bandit": "turned off"}, "degraded_manifests": ["frontend/package.json (no lockfile)"]}
    s.update(kw); return s


def post(payload, token=TOK, raw=None):
    body = raw if raw is not None else json.dumps(payload).encode()
    return call("/api/ingest", "POST", body, {"Authorization": f"Bearer {token}", "Content-Type": "application/json"})


F = [{"severity": "CRITICAL", "tool": "semgrep", "rule": "r1", "location": "a.py:3", "title": "<script>alert(1)</script> bad", "fix": "", "new": True}]


def test_health_open_everything_else_needs_login():
    assert call("/health")[0] == 200
    assert call("/")[0] == 401 and call("/api/repos")[0] == 401
    assert call("/", headers={"Authorization": "Basic " + base64.b64encode(b"secscan:wrong").decode()})[0] == 401


def test_ingest_requires_the_token():
    assert post({"summary": summary()}, token="nope")[0] == 401
    assert post({"summary": summary()}, token="")[0] == 401


def test_ingest_and_views():
    assert post({"repo": "acme/shop", "branch": "main", "commit": "abcdef1234567", "run_url": "https://ci.example/run/1", "summary": summary(), "findings": F})[0] == 200
    code, body, h = call("/", headers={"Authorization": AUTH})
    assert code == 200 and "acme/shop" in body and "SonarQube" in body
    code, body, _ = call("/repo/acme/shop", headers={"Authorization": AUTH})
    assert code == 200 and "bandit</b> did not run" in body and "no lockfile" in body and "npm-audit" in body
    assert "<script>alert(1)</script>" not in body and "&lt;script&gt;alert(1)&lt;/script&gt;" in body        # escaped
    rows = [x for x in json.loads(call("/api/repos", headers={"Authorization": AUTH})[1]) if x["repo"] == "acme/shop"]
    assert rows and rows[0]["crit"] == 2 and rows[0]["tools_ok"] == 2 and rows[0]["tools_total"] == 3


def test_security_headers_and_csp():
    _, _, h = call("/", headers={"Authorization": AUTH})
    assert "default-src 'none'" in h["Content-Security-Policy"] and h["X-Frame-Options"] == "DENY" and h["Cache-Control"] == "no-store"


def test_hostile_input():
    assert post({"repo": "<img src=x onerror=alert(1)>", "summary": summary()})[0] == 400
    assert post({"repo": "ok/repo", "branch": "<b>x</b>", "run_url": "javascript:alert(1)", "summary": summary(), "findings": []})[0] == 200
    _, body, _ = call("/repo/ok/repo", headers={"Authorization": AUTH})
    assert "javascript:alert" not in body and "&lt;b&gt;x&lt;/b&gt;" in body
    assert post(None, raw=b"{not json")[0] == 400
    assert post({"summary": {"nope": 1}})[0] == 400
    try:
        assert post(None, raw=b"x" * (S.MAX_BODY + 10))[0] in (413, 400)
    except (urllib.error.URLError, ConnectionError):
        pass                                          # server hung up on the oversized upload: also a rejection
    assert call("/repo/does/not/exist", headers={"Authorization": AUTH})[0] == 404


def test_history_is_pruned_and_trend_drawn():
    for i in range(5):
        post({"repo": "acme/hist", "branch": "main", "summary": summary(counts={"CRITICAL": i, "HIGH": i, "MEDIUM": 1, "LOW": 0, "INFO": 0})})
    con = S.db(C["db"]); n = con.execute("SELECT COUNT(*) FROM scans WHERE repo='acme/hist'").fetchone()[0]; con.close()
    assert n == 3                                     # KEEP_SCANS=3
    assert "<polyline" in call("/repo/acme/hist", headers={"Authorization": AUTH})[1]


def test_main_branch_preferred_on_the_portfolio():
    post({"repo": "acme/br", "branch": "main", "summary": summary(counts={"CRITICAL": 9, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0})})
    post({"repo": "acme/br", "branch": "feature-x", "summary": summary(counts={"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0})})
    r = [x for x in json.loads(call("/api/repos", headers={"Authorization": AUTH})[1]) if x["repo"] == "acme/br"][0]
    assert r["branch"] == "main" and r["crit"] == 9


def test_publisher_end_to_end_and_never_breaks_a_build():
    rep = tempfile.mkdtemp()
    json.dump(summary(target="pub-app"), open(rep + "/summary.json", "w")); json.dump([dict(F[0], severity="HIGH")], open(rep + "/findings.json", "w"))
    env = dict(os.environ, SECSCAN_DASHBOARD_TOKEN=TOK, GITHUB_ACTIONS="true", GITHUB_REPOSITORY="acme/published", GITHUB_REF_NAME="main", GITHUB_SHA="deadbeef", GITHUB_RUN_ID="42")
    r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "publish.py"), "--report", rep, "--url", BASE], env=env, capture_output=True, text=True)
    assert r.returncode == 0 and "published acme/published" in r.stdout, r.stderr
    assert "actions/runs/42" in call("/repo/acme/published", headers={"Authorization": AUTH})[1]
    r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "publish.py"), "--report", rep, "--url", "http://127.0.0.1:9"], env=env, capture_output=True, text=True)
    assert r.returncode == 0 and "could not reach" in r.stderr                      # a dead dashboard is a warning only
    r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "publish.py"), "--report", rep, "--url", "http://127.0.0.1:9", "--strict"], env=env, capture_output=True, text=True)
    assert r.returncode == 1
    r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "publish.py"), "--report", rep, "--url", BASE], env=dict(env, SECSCAN_DASHBOARD_TOKEN="", CI="true"), capture_output=True, text=True)
    assert r.returncode == 0 and "SECSCAN_DASHBOARD_TOKEN is not set" in r.stderr


def test_failed_logins_are_throttled():
    S.FAILS.clear()
    bad = {"Authorization": "Basic " + base64.b64encode(b"x:y").decode()}
    codes = [call("/", headers=bad)[0] for _ in range(12)]
    assert codes[-1] == 429 and codes[0] == 401
    S.FAILS.clear()


def test_refuses_to_start_without_credentials():
    r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "..", "dashboard", "server.py")], env={"PATH": os.environ["PATH"]}, capture_output=True, text=True)
    assert r.returncode != 0 and "no default credentials" in r.stderr


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
