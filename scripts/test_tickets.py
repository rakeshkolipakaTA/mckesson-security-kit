"""Ticketing tests against local mock GitHub / Jira / Azure DevOps servers and a real dashboard instance. Run: python3 -I scripts/test_tickets.py"""
import base64, contextlib, io, json, os, re, sqlite3, sys, tempfile, threading, urllib.parse, datetime as dt
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.join(HERE, "..", "dashboard"))
import tickets as T
import server as S

STORE = {"github": [], "jira": [], "azure": [], "calls": [], "fail_lookup": False, "throttle_once": False}


class Mock(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _reply(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n)) if n else None

    def handle_any(self, method):
        u = urllib.parse.urlparse(self.path); q = urllib.parse.parse_qs(u.query); body = self._body()
        STORE["calls"].append((method, u.path, self.headers.get("Authorization", "")))
        if STORE["throttle_once"]:
            STORE["throttle_once"] = False
            self.send_response(429); self.send_header("Retry-After", "0"); self.send_header("Content-Length", "0"); self.end_headers(); return
        if u.path.startswith("/repos/"):                                   # GitHub
            if method == "GET":
                if STORE["fail_lookup"]:
                    return self._reply(500, {"message": "boom"})
                lab = q["labels"][0]
                return self._reply(200, [i for i in STORE["github"] if lab in i["labels"]])
            STORE["github"].append(dict(body, html_url="https://github.example/o/r/issues/%d" % (len(STORE["github"]) + 1)))
            return self._reply(201, STORE["github"][-1])
        if u.path.startswith("/rest/api/2/search"):                        # Jira
            lab = re.search(r'labels = "([^"]+)"', q["jql"][0]).group(1)
            return self._reply(200, {"issues": [{"key": i["key"]} for i in STORE["jira"] if lab in i["fields"]["labels"]]})
        if u.path == "/rest/api/2/issue":
            STORE["jira"].append(dict(body, key="SEC-%d" % (len(STORE["jira"]) + 1)))
            return self._reply(201, {"key": STORE["jira"][-1]["key"]})
        if u.path.endswith("/_apis/wit/wiql"):                             # Azure DevOps
            lab = re.search(r"CONTAINS '([^']+)'", body["query"]).group(1)
            return self._reply(200, {"workItems": [{"id": w["id"]} for w in STORE["azure"] if lab in w["tags"]]})
        if "/_apis/wit/workitems/" in u.path:
            f = {o["path"].split("/")[-1]: o["value"] for o in body}
            STORE["azure"].append({"id": len(STORE["azure"]) + 100, "tags": f["System.Tags"], "title": f["System.Title"], "desc": f["System.Description"]})
            return self._reply(200, {"id": STORE["azure"][-1]["id"]})
        self._reply(404, {})

    def do_GET(self): self.handle_any("GET")
    def do_POST(self): self.handle_any("POST")


srv = ThreadingHTTPServer(("127.0.0.1", 0), Mock)
threading.Thread(target=srv.serve_forever, daemon=True).start()
URL = "http://127.0.0.1:%d" % srv.server_address[1]
ENV = {"GITHUB_TOKEN": "ghp_fakefakefakefakefake", "GITHUB_API_URL": URL, "JIRA_URL": URL, "JIRA_USER": "bot@example.com", "JIRA_TOKEN": "jira-fake", "JIRA_PROJECT": "SEC",
       "AZDO_ORG_URL": URL, "AZDO_PROJECT": "My Project", "AZDO_TOKEN": "azdo-fake", "GITHUB_REPOSITORY": "o/r"}


def F(fp, sev, rule, loc, title="t", cat="SAST", new=True, **kw):
    d = {"fingerprint": fp, "severity": sev, "rule": rule, "location": loc, "path": loc.split(":")[0], "title": title, "category": cat, "new": new, "fix": None, "all_ids": []}
    d.update(kw); return d


FINDINGS = [
    F("fp000001", "CRITICAL", "CVE-2026-0001", "requirements.txt: pillow 11.3.0", "pillow overflow", "SCA", all_ids=["CVE-2026-0001"], fix="13.0.0"),
    F("fp000002", "HIGH", "CVE-2026-0002", "requirements.txt: pillow 11.3.0", "pillow other", "SCA", all_ids=["CVE-2026-0002"]),
    F("fp000003", "HIGH", "sqli", "app/db.py:10", "SQL injection with key ghp_abcdefghijklmnopqrstuvwxyz0123456789 inside"),
    F("fp000004", "HIGH", "old-one", "app/old.py:1", "in baseline", new=False),
    F("fp000005", "MEDIUM", "med", "app/m.py:1", "medium"),
    F("fp000006", "CRITICAL", "excepted", "app/x.py:1", "approved", excepted="until 2099"),
]


def report(findings=FINDINGS):
    d = tempfile.mkdtemp(); json.dump(findings, open(d + "/findings.json", "w")); return d


def run(args, env=None, findings=FINDINGS):
    for k in ("github", "jira", "azure"):
        pass
    old = dict(os.environ)
    os.environ.update(ENV); os.environ.update(env or {})
    out, err = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                rc = T.main(["--report", report(findings), "--delay", "0"] + args)
            except SystemExit as e:
                rc = e.code if isinstance(e.code, int) else 2; err.write(str(e.code))
    finally:
        os.environ.clear(); os.environ.update(old)
    return rc, out.getvalue(), err.getvalue()


def reset():
    STORE.update(github=[], jira=[], azure=[], calls=[], fail_lookup=False, throttle_once=False)


def test_selection_new_only_by_default_and_excepted_skipped():
    sel = T.select(FINDINGS, "high", False, set())
    assert {f["fingerprint"] for f in sel} == {"fp000001", "fp000002", "fp000003"}      # not the baseline one, not medium, not excepted
    assert {f["fingerprint"] for f in T.select(FINDINGS, "high", True, set())} == {"fp000001", "fp000002", "fp000003", "fp000004"}
    assert {f["fingerprint"] for f in T.select(FINDINGS, "critical", False, set())} == {"fp000001"}
    assert {f["fingerprint"] for f in T.select(FINDINGS, "high", False, {"fp000004"})} >= {"fp000004"}   # overdue pulls in a baseline finding


def test_grouping_per_package_and_per_rule_file():
    groups = T.build_groups(T.select(FINDINGS, "high", False, set()))
    assert len(groups) == 2
    pil = [g for g in groups if "pillow" in g["title"]][0]
    assert len(pil["items"]) == 2 and pil["severity"] == "CRITICAL" and "requirements.txt" in pil["title"]
    assert pil["label"].startswith("secscan-gk-") and len(pil["label"]) == len("secscan-gk-") + 12
    again = T.build_groups(T.select(FINDINGS, "high", False, set()))
    assert {g["label"] for g in again} == {g["label"] for g in groups}                    # stable ids: the basis of de-duplication


def test_tickets_never_contain_credential_like_text():
    g = [g for g in T.build_groups(T.select(FINDINGS, "high", False, set())) if "sqli" in g["title"]][0]
    body = T.body_for(g, dict(repo="o/r", branch="main", commit="abc", run=""))
    assert "ghp_abcdefghijklmnopqrstuvwxyz" not in body and "<redacted>" in body and "secscan:gk=" in body
    assert "<redacted>" in T.scrub("key AKIAABCDEFGHIJKLMNOP here") and "AKIAABCDEFGHIJKLMNOP" not in T.scrub("key AKIAABCDEFGHIJKLMNOP here")
    assert T.scrub("normal sentence about frontend/src/app/pages/page.ts") == "normal sentence about frontend/src/app/pages/page.ts"   # paths and prose survive


def test_dry_run_creates_nothing():
    reset()
    rc, out, _ = run([])
    assert rc == 0 and "would create" in out and "dry run" in out and STORE["github"] == []
    assert not [c for c in STORE["calls"] if c[0] == "POST"]                              # not a single write call


def test_github_apply_then_rerun_is_idempotent():
    reset()
    rc, out, _ = run(["--apply"])
    assert rc == 0 and len(STORE["github"]) == 2 and out.count("created") == 2
    first = STORE["github"][0]
    assert "secscan" in first["labels"] and any(l.startswith("secscan-gk-") for l in first["labels"]) and "severity:critical" in first["labels"]
    assert "secscan:gk=" in first["body"] and first["title"].startswith("[secscan] CRITICAL")
    rc, out, _ = run(["--apply"])
    assert rc == 0 and len(STORE["github"]) == 2 and out.count("exists") == 2             # no duplicates
    assert all(a == "Bearer " + ENV["GITHUB_TOKEN"] for m, p, a in STORE["calls"] if p.startswith("/repos/"))


def test_jira_and_azure_create_and_dedupe():
    reset()
    rc, out, _ = run(["--apply", "--target", "jira"])
    assert rc == 0 and len(STORE["jira"]) == 2 and STORE["jira"][0]["fields"]["project"]["key"] == "SEC" and "secscan" in STORE["jira"][0]["fields"]["labels"]
    assert "<!--" not in STORE["jira"][0]["fields"]["description"]
    want = "Basic " + base64.b64encode(b"bot@example.com:jira-fake").decode()
    assert all(a == want for m, p, a in STORE["calls"] if p.startswith("/rest/"))
    run(["--apply", "--target", "jira"]); assert len(STORE["jira"]) == 2
    rc, out, _ = run(["--apply", "--target", "azure"])
    assert rc == 0 and len(STORE["azure"]) == 2 and "secscan-gk-" in STORE["azure"][0]["tags"] and "&lt;" not in STORE["azure"][0]["desc"].replace("&lt;redacted&gt;", "")
    azauth = "Basic " + base64.b64encode(b":azdo-fake").decode()
    assert all(a == azauth for m, p, a in STORE["calls"] if "_apis" in p)
    run(["--apply", "--target", "azure"]); assert len(STORE["azure"]) == 2
    reset(); rc, out, _ = run(["--apply", "--target", "all"])
    assert rc == 0 and len(STORE["github"]) == 2 and len(STORE["jira"]) == 2 and len(STORE["azure"]) == 2


def test_max_issues_limit_and_retry_on_throttle():
    reset()
    rc, out, _ = run(["--apply", "--max-issues", "1"])
    assert len(STORE["github"]) == 1 and "skipped (limit 1)" in out
    reset(); STORE["throttle_once"] = True
    rc, out, _ = run(["--apply"])
    assert rc == 0 and len(STORE["github"]) == 2                                          # one 429 was retried


def test_lookup_failure_never_creates_duplicates_blindly():
    reset(); STORE["fail_lookup"] = True
    rc, out, _ = run(["--apply"])
    assert rc == 1 and STORE["github"] == [] and "lookup failed" in out


def test_credentials_and_transport_rules():
    reset()
    rc, _, err = run(["--apply"], env={"GITHUB_TOKEN": ""})
    assert rc == 2 and "credentials are missing" in err and STORE["github"] == []
    rc, _, err = run([], env={"GITHUB_API_URL": "http://api.example.com"})
    assert rc == 2 and "refusing to send a token over http" in err
    rc, _, err = run(["--allow-http", "--target", "github"], env={"GITHUB_API_URL": URL})
    assert rc == 0
    rc, _, err = run([], env={"GITHUB_REPOSITORY": "", "GITHUB_API_URL": URL}); assert rc == 2 and "--repo" in err
    assert T.main(["--report", "/nonexistent"]) == 2


def test_nothing_to_ticket_is_quiet_success():
    reset(); rc, out, _ = run(["--apply"], findings=[F("fp000009", "LOW", "low", "a.py:1")])
    assert rc == 0 and STORE["github"] == [] and "0 finding(s)" in out


def test_overdue_findings_from_the_dashboard_are_ticketed_even_when_in_baseline():
    reset()
    C = dict(user="u", password="correct-horse-battery", token="t" * 32, db=os.path.join(tempfile.mkdtemp(), "d.db"), stale=14, keep=5, sonar="", sla={"CRITICAL": 3, "HIGH": 14, "MEDIUM": 60, "LOW": 90}, webhook="")
    S.db(C["db"]).close()
    dash = ThreadingHTTPServer(("127.0.0.1", 0), S.H); dash.c = C
    S.H.log_message = lambda *a, **k: None
    threading.Thread(target=dash.serve_forever, daemon=True).start()
    durl = "http://127.0.0.1:%d" % dash.server_address[1]
    import urllib.request
    # the repo/branch tickets.py reports are what publish.ci_context finds: mimic them through the CI environment
    env = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "o/r", "GITHUB_REF_NAME": "main", "GITHUB_SHA": "abc", "GITHUB_RUN_ID": "1", "SECSCAN_DASHBOARD_TOKEN": C["token"]}
    summ = {"target": "r", "counts": {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 0, "LOW": 0, "INFO": 0}, "tool_status": {"semgrep": "ok"}, "result": "FAIL", "sla_days": {"CRITICAL": 3, "HIGH": 14, "MEDIUM": 60, "LOW": 90}}
    fl = [F("fp000004", "HIGH", "old-one", "app/old.py:1", new=False), F("fp000007", "HIGH", "fresh-baseline", "app/b.py:1", new=False)]
    req = urllib.request.Request(durl + "/api/ingest", data=json.dumps({"repo": "o/r", "branch": "main", "summary": summ, "findings": fl}).encode(), method="POST", headers={"Authorization": "Bearer " + C["token"], "Content-Type": "application/json"})
    urllib.request.urlopen(req).read()
    con = sqlite3.connect(C["db"]); con.execute("UPDATE finding_age SET first_seen=? WHERE fp='fp000004'", ((dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=20)).isoformat(timespec="seconds"),)); con.commit(); con.close()
    rc, out, _ = run(["--apply", "--dashboard", durl], env=env, findings=fl)
    assert rc == 0 and "1 overdue" in out and len(STORE["github"]) == 1 and "old-one" in STORE["github"][0]["title"], out
    assert "(overdue)" in STORE["github"][0]["body"]
    dash.shutdown()


if __name__ == "__main__":
    n = fail = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            n += 1
            try:
                fn(); print("  PASS ", name)
            except Exception as e:
                import traceback; fail += 1; print("  FAIL ", name, repr(e)[:300]); traceback.print_exc(limit=3)
    print(f"{n - fail}/{n} passed"); sys.exit(1 if fail else 0)
