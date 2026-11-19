"""Dashboard + publisher tests (no Docker, no network beyond localhost). Run: python3 -I scripts/test_dashboard.py"""
import base64, datetime as dt, json, os, sqlite3, subprocess, sys, tempfile, threading, urllib.error, urllib.request
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "dashboard"))
import server as S
from http.server import ThreadingHTTPServer

PW, TOK = "correct-horse-battery", "t" * 32
C = dict(user="warden", password=PW, token=TOK, db=os.path.join(tempfile.mkdtemp(), "d.db"), stale=14, keep=3, sonar="http://sonar.example:9000")
S.db(C["db"]).close()
S.H.log_message = lambda *a, **k: None
srv = ThreadingHTTPServer(("127.0.0.1", 0), S.H); srv.c = C
threading.Thread(target=srv.serve_forever, daemon=True).start()
BASE = f"http://127.0.0.1:{srv.server_address[1]}"
AUTH = "Basic " + base64.b64encode(f"warden:{PW}".encode()).decode()


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
    assert call("/", headers={"Authorization": "Basic " + base64.b64encode(b"warden:wrong").decode()})[0] == 401


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
    env = dict(os.environ, WARDEN_DASHBOARD_TOKEN=TOK, GITHUB_ACTIONS="true", GITHUB_REPOSITORY="acme/published", GITHUB_REF_NAME="main", GITHUB_SHA="deadbeef", GITHUB_RUN_ID="42")
    r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "publish.py"), "--report", rep, "--url", BASE], env=env, capture_output=True, text=True)
    assert r.returncode == 0 and "published acme/published" in r.stdout, r.stderr
    assert "actions/runs/42" in call("/repo/acme/published", headers={"Authorization": AUTH})[1]
    r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "publish.py"), "--report", rep, "--url", "http://127.0.0.1:9"], env=env, capture_output=True, text=True)
    assert r.returncode == 0 and "could not reach" in r.stderr                      # a dead dashboard is a warning only
    r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "publish.py"), "--report", rep, "--url", "http://127.0.0.1:9", "--strict"], env=env, capture_output=True, text=True)
    assert r.returncode == 1
    r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "publish.py"), "--report", rep, "--url", BASE], env=dict(env, WARDEN_DASHBOARD_TOKEN="", CI="true"), capture_output=True, text=True)
    assert r.returncode == 0 and "WARDEN_DASHBOARD_TOKEN is not set" in r.stderr


# ---------------------------------------------------------------- SLA tracking
def fnd(fp, sev, rule="r", excepted=""):
    return {"severity": sev, "tool": "semgrep", "rule": rule, "location": f"{rule}.py:1", "title": f"{rule} issue", "fix": "", "new": True, "excepted": excepted, "fingerprint": fp}


def sla_scan(repo, findings, result="FAIL", branch="main", total=None, **kw):
    sm = summary(result=result, sla_days={"CRITICAL": 3, "HIGH": 14, "MEDIUM": 60, "LOW": 90}, **kw)
    p = {"repo": repo, "branch": branch, "summary": sm, "findings": findings}
    if total is not None:
        p["findings_total"] = total
    return post(p)


def backdate(repo, fp, days):
    con = sqlite3.connect(C["db"])
    con.execute("UPDATE finding_age SET first_seen=? WHERE repo=? AND fp=?", ((dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)).isoformat(timespec="seconds"), repo, fp))
    con.commit(); con.close()


def overdue(repo, token=TOK, branch="main"):
    code, body, _ = call(f"/api/overdue?repo={repo}&branch={branch}", headers={"Authorization": f"Bearer {token}"})
    return code, (json.loads(body) if code == 200 else None)


def test_sla_overdue_is_tracked_per_finding_and_shown():
    assert sla_scan("sla/app", [fnd("aaaa1111", "CRITICAL", "c1"), fnd("bbbb2222", "HIGH", "h1"), fnd("cccc3333", "MEDIUM", "m1")])[0] == 200
    assert overdue("sla/app")[1] == []                                   # nothing is old yet
    backdate("sla/app", "aaaa1111", 10); backdate("sla/app", "bbbb2222", 10); backdate("sla/app", "cccc3333", 10)
    code, items = overdue("sla/app")
    assert code == 200 and [i["fingerprint"] for i in items] == ["aaaa1111"]     # Critical (3d) is overdue; High (14d) and Medium (60d) are not
    assert items[0]["age_days"] == 10 and items[0]["sla_days"] == 3
    _, page, _ = call("/repo/sla/app", headers={"Authorization": AUTH})
    assert "SLA breached" in page and "Remediation SLA" in page and "Age (d)" in page
    _, home, _ = call("/", headers={"Authorization": AUTH})
    assert "SLA breached" in home and "Findings past SLA" in home and "Past SLA" in home


def test_sla_clock_survives_rescans_and_stops_when_fixed():
    sla_scan("sla/clock", [fnd("dddd4444", "CRITICAL")]); backdate("sla/clock", "dddd4444", 5)
    sla_scan("sla/clock", [fnd("dddd4444", "CRITICAL")])                 # same finding again: first-seen must not reset
    assert [i["age_days"] for i in overdue("sla/clock")[1]] == [5]
    sla_scan("sla/clock", [])                                            # fixed
    assert overdue("sla/clock")[1] == []


def test_excepted_findings_and_truncated_lists_are_handled():
    sla_scan("sla/exc", [fnd("eeee5555", "CRITICAL", excepted="approved until 2099")]); backdate("sla/exc", "eeee5555", 30)
    assert overdue("sla/exc")[1] == []                                   # an approved exception stops the clock
    sla_scan("sla/trunc", [fnd("ffff6666", "CRITICAL"), fnd("gggg7777", "HIGH")]); backdate("sla/trunc", "ffff6666", 9)
    sla_scan("sla/trunc", [fnd("gggg7777", "HIGH")], total=S.MAX_FINDINGS + 500)   # list was cut: ffff6666 must NOT be treated as fixed
    assert [i["fingerprint"] for i in overdue("sla/trunc")[1]] == ["ffff6666"]


def test_overdue_api_auth_and_validation():
    sla_scan("sla/api", [fnd("hhhh8888", "LOW")])
    assert call("/api/overdue?repo=sla/api")[0] == 401
    assert overdue("sla/api", token="nope")[0] == 401
    assert call("/api/overdue?repo=sla/api", headers={"Authorization": AUTH})[0] == 200          # viewer login also works
    assert call("/api/overdue", headers={"Authorization": AUTH})[0] == 400
    assert overdue("no/such-repo")[0] == 404


def test_scan_sla_days_override_the_default_and_bad_values_are_ignored():
    sm = summary(sla_days={"CRITICAL": 1, "HIGH": "x", "LOW": 999999})
    post({"repo": "sla/custom", "branch": "main", "summary": sm, "findings": [fnd("iiii9999", "CRITICAL")]}); backdate("sla/custom", "iiii9999", 2)
    assert [i["sla_days"] for i in overdue("sla/custom")[1]] == [1]
    assert S.sla_from(sm, C)["HIGH"] == 14 and S.sla_from(sm, C)["LOW"] == 90


# ---------------------------------------------------------------- alerts
class Receiver:
    def __init__(self):
        self.got = []
        outer = self

        class R(S.BaseHTTPRequestHandler):
            def do_POST(self):
                outer.got.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok")

            def log_message(self, *a): pass
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), R)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}/hook"


def _with_alerts(url, fn, **extra):
    old = {k: C.get(k) for k in ("webhook", "alert_min", "alert_branches", "public")}
    C.update(webhook=url, alert_min="critical", alert_branches=["main", "master"], public="https://dash.example", **extra)
    S.ALERT_ASYNC = False
    try:
        fn()
    finally:
        S.ALERT_ASYNC = True
        C.update(old)


def test_alerts_gate_flip_new_critical_sla_and_dedupe():
    rx = Receiver()
    def run():
        sla_scan("al/app", [fnd("al000001", "LOW")], result="PASS")
        assert rx.got == []                                                # first scan = baseline, no news
        sla_scan("al/app", [fnd("al000001", "LOW"), fnd("al000002", "CRITICAL", "sqli"), fnd("al000003", "HIGH", "h-only")], result="FAIL")
        msgs = [m["text"] for m in rx.got]
        assert len(msgs) == 1 and "gate FAIL (was PASS)" in msgs[0] and "1 new CRITICAL finding(s): sqli" in msgs[0], msgs
        assert "h-only" not in msgs[0] and "https://dash.example/repo/al/app" in msgs[0]     # HIGH is below the default threshold
        sla_scan("al/app", [fnd("al000001", "LOW"), fnd("al000002", "CRITICAL", "sqli"), fnd("al000003", "HIGH", "h-only")], result="FAIL")
        assert len(rx.got) == 1                                            # nothing new: de-duplicated
        backdate("al/app", "al000002", 6)
        sla_scan("al/app", [fnd("al000001", "LOW"), fnd("al000002", "CRITICAL", "sqli"), fnd("al000003", "HIGH", "h-only")], result="FAIL")
        assert len(rx.got) == 2 and "newly past SLA" in rx.got[1]["text"] and "Critical 3d" in rx.got[1]["text"]
        sla_scan("al/app", [fnd("al000001", "LOW"), fnd("al000002", "CRITICAL", "sqli"), fnd("al000003", "HIGH", "h-only")], result="FAIL")
        assert len(rx.got) == 2                                            # SLA breach is announced once
    _with_alerts(rx.url, run)


def test_alert_threshold_high_and_branch_filter():
    rx = Receiver()
    def run():
        C["alert_min"] = "high"                                            # _with_alerts restores it afterwards
        sla_scan("al/hi", [], result="PASS")
        sla_scan("al/hi", [fnd("hi000001", "HIGH", "hh")], result="PASS")
        assert len(rx.got) == 1 and "new HIGH finding(s): hh" in rx.got[0]["text"]
        sla_scan("al/hi", [], result="PASS", branch="feature-x"); sla_scan("al/hi", [fnd("hi000002", "CRITICAL")], result="FAIL", branch="feature-x")
        assert len(rx.got) == 1                                            # feature branches are silent by default
    _with_alerts(rx.url, run)


def test_alerts_never_break_ingest_and_bad_urls_are_ignored():
    def run():
        sla_scan("al/dead", [], result="PASS")
        code = sla_scan("al/dead", [fnd("de000001", "CRITICAL")], result="FAIL")[0]
        assert code == 200                                                 # unreachable receiver: ingest still succeeds
    _with_alerts("http://127.0.0.1:9/hook", run)
    rx = Receiver()
    def run2():
        sla_scan("al/ftp", [], result="PASS"); assert sla_scan("al/ftp", [fnd("ft000001", "CRITICAL")], result="FAIL")[0] == 200
    _with_alerts("ftp://example.com/x", run2)
    assert rx.got == []


def test_stale_repo_alert_is_sent_once_per_last_scan():
    rx = Receiver()
    def run():
        sla_scan("al/stale", [], result="PASS")
        con = sqlite3.connect(C["db"]); con.execute("UPDATE scans SET created=? WHERE repo='al/stale'", ((dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=40)).isoformat(timespec="seconds"),)); con.commit(); con.close()
        con = S.db(C["db"])
        try:
            n1 = S.check_stale(con, C); n2 = S.check_stale(con, C)
        finally:
            con.close()
        assert n1 >= 1 and n2 == 0
        assert any("al/stale" in m["text"] and "no scan for 40 days" in m["text"] for m in rx.got)
    _with_alerts(rx.url, run)


def test_failed_logins_are_throttled():
    S.FAILS.clear()
    bad = {"Authorization": "Basic " + base64.b64encode(b"x:y").decode()}
    codes = [call("/", headers=bad)[0] for _ in range(12)]
    assert codes[-1] == 429 and codes[0] == 401
    S.FAILS.clear()


def test_requests_without_credentials_are_not_counted_as_failed_logins():
    S.FAILS.clear()
    assert all(call("/")[0] == 401 for _ in range(25))                         # browsers and probes send no credentials first
    assert call("/", headers={"Authorization": AUTH})[0] == 200                # ...and nobody is locked out by that
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
