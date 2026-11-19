"""Tests for `warden ci-report` (scripts/gh_report.py): annotations, job summary, pull request comment against a mock GitHub API.
Run: python3 -I scripts/test_gh_report.py"""
import contextlib, io, json, os, re, sys, tempfile, threading, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gh_report as G

ST = {"comments": [], "calls": [], "status": 200}


class Mock(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def reply(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    def go(self, method):
        u = urllib.parse.urlparse(self.path); q = urllib.parse.parse_qs(u.query)
        n = int(self.headers.get("Content-Length") or 0); body = json.loads(self.rfile.read(n)) if n else None
        ST["calls"].append((method, u.path, self.headers.get("Authorization", "")))
        if ST["status"] != 200:
            return self.reply(ST["status"], {"message": "nope"})
        if method == "GET":
            page, per = int(q["page"][0]), int(q["per_page"][0])
            return self.reply(200, ST["comments"][(page - 1) * per: page * per])
        if method == "POST":
            ST["comments"].append({"id": len(ST["comments"]) + 1, "body": body["body"], "user": {"type": "Bot"}}); return self.reply(201, ST["comments"][-1])
        if method == "PATCH":
            cid = int(u.path.rsplit("/", 1)[1])
            for c in ST["comments"]:
                if c["id"] == cid: c["body"] = body["body"]
            return self.reply(200, {})

    def do_GET(self): self.go("GET")
    def do_POST(self): self.go("POST")
    def do_PATCH(self): self.go("PATCH")


srv = ThreadingHTTPServer(("127.0.0.1", 0), Mock)
threading.Thread(target=srv.serve_forever, daemon=True).start()
URL = "http://127.0.0.1:%d" % srv.server_address[1]

W = tempfile.mkdtemp()
os.makedirs(os.path.join(W, "app")); open(os.path.join(W, "app", "main.py"), "w").write("x=1\n"); open(os.path.join(W, "req.txt"), "w").write("a\n")
F = lambda sev, rule, path, loc=None, title="t", tool="semgrep", new=True, fix=None: dict(tool=tool, tools=[tool], severity=sev, rule=rule, title=title, path=path, location=loc or path, new=new, fix=fix)
SUM = dict(mode="report-only", result="FAIL", blocking=3, counts=dict(CRITICAL=1, HIGH=2, MEDIUM=1, LOW=0), new_counts=dict(CRITICAL=1, HIGH=2, MEDIUM=1, LOW=0),
           tool_status=dict(gitleaks="ok", semgrep="ok"))


def report(summary=None, findings=None):
    d = tempfile.mkdtemp()
    json.dump(summary or SUM, open(os.path.join(d, "summary.json"), "w")); json.dump(findings if findings is not None else [], open(os.path.join(d, "findings.json"), "w"))
    open(os.path.join(d, "summary.md"), "w").write("# full\n@everyone <script>alert(1)</script>\n")
    return d


def run(rep, env=None, args=()):
    e = dict(env or {}); out = io.StringIO(); err = io.StringIO()
    old = dict(os.environ)
    for k in list(os.environ):
        if k.startswith(("GITHUB_", "WARDEN_", "SEC_")): del os.environ[k]
    os.environ.update(e)
    old_argv = sys.argv; sys.argv = ["x", "--report", rep, "--root", W, *args]
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = G.main()
    finally:
        sys.argv = old_argv; os.environ.clear(); os.environ.update(old)
    return rc, out.getvalue(), err.getvalue()


def pr_env(extra=None, number=7):
    ev = os.path.join(tempfile.mkdtemp(), "event.json"); json.dump({"pull_request": {"number": number, "head": {"sha": "headsha"}}}, open(ev, "w"))
    summ = os.path.join(tempfile.mkdtemp(), "sum.md")
    e = dict(GITHUB_EVENT_PATH=ev, GITHUB_REPOSITORY="o/r", GITHUB_SHA="mergesha", GITHUB_RUN_ID="42", GITHUB_TOKEN="ghp_fakefakefake", GITHUB_API_URL=URL, GITHUB_STEP_SUMMARY=summ)
    e.update(extra or {}); return e, summ


def reset(): ST.update(comments=[], calls=[], status=200)


def t_annotations_only_for_real_repo_files():
    f = [F("CRITICAL", "r1", "app/main.py", "app/main.py:3"), F("HIGH", "r2", "nope/missing.py"), F("HIGH", "r3", "img:tag (debian)", "img:tag (debian)"),
         F("HIGH", "r4", "../etc/passwd"), F("MEDIUM", "r5", "app/main.py", "app/main.py:1")]
    out = G.annotations(f, W, 10)
    assert len(out) == 1 and out[0].startswith("::error file=app/main.py,title=") and "line=3" in out[0], out


def t_annotation_limits_and_order():
    f = [F("HIGH", "h%d" % i, "app/main.py", "app/main.py:%d" % i) for i in range(30)] + [F("CRITICAL", "c%d" % i, "req.txt") for i in range(30)]
    out = G.annotations(f, W, 10)
    assert sum(o.startswith("::error") for o in out) == 10 and sum(o.startswith("::warning") for o in out) == 10 and len(out) == 20
    assert G.annotations(f, W, 3).__len__() == 6


def t_new_findings_come_before_old():
    f = [F("CRITICAL", "old%d" % i, "app/main.py", "app/main.py:%d" % i, new=False) for i in range(12)] + [F("CRITICAL", "fresh", "req.txt")]
    assert any("fresh" in o for o in G.annotations(f, W, 10))


def t_workflow_command_injection_is_escaped():
    f = [F("HIGH", "x", "app/main.py", "app/main.py:1", title="bad\n::set-output name=pwn::1\r%0A", fix="a,b:c")]
    out = G.annotations(f, W, 10)
    assert len(out) == 1 and "\n" not in out[0] and "\r" not in out[0] and "%250A" in out[0]
    assert G.wc_prop("a:b,c") == "a%3Ab%2Cc"


def t_untrusted_text_cannot_inject_markup_or_mentions():
    s = G.cell("[click](http://evil) <img src=x onerror=1> @octocat a|b `c`\nline2")
    assert "<" not in s and not re.search(r"(?<!\\)\]\(", s) and "\n" not in s and "@octocat" not in s and "a\\|b" in s


def t_verdicts_are_honest():
    assert G.verdict(dict(SUM, mode="report-only", result="FAIL"))[0] == "REPORT" and "not blocked" in G.verdict(dict(SUM))[1]
    assert G.verdict(dict(SUM, mode="enforce", result="FAIL"))[0] == "FAIL" and "blocked" in G.verdict(dict(SUM, mode="enforce"))[1]
    t, txt = G.verdict(dict(SUM, mode="enforce", result="PASS (with tool errors: trivy-fs=missing)"))
    assert t == "PASS" and "errors" in txt


def t_summary_shows_tools_that_did_not_run_and_links_files():
    s = dict(SUM, tool_status=dict(gitleaks="ok", semgrep="missing"))
    c = G.ctx(dict(GITHUB_REPOSITORY="o/r", GITHUB_SHA="abc", GITHUB_RUN_ID="9"))
    md = G.build_summary(s, [F("CRITICAL", "r1", "app/main.py", "app/main.py:3"), F("HIGH", "img", "Python")], c, report(s), W)
    assert "Did not complete" in md and "semgrep (missing)" in md and "not a clean result" in md
    assert "https://github.com/o/r/blob/abc/app/main.py#L3" in md and "blob/abc/Python" not in md      # a non-file location is not linked
    assert "<script>" not in md and "@everyone" not in md


def t_summary_written_and_exit_zero_even_without_findings():
    e, summ = pr_env()
    rc, out, err = run(report(findings=[]), e, ["--no-comment"])
    assert rc == 0 and "No Critical or High findings" in open(summ).read()


def t_missing_report_never_fails_the_build():
    rc, out, err = run(tempfile.mkdtemp(), {})
    assert rc == 0 and "no report found" in err


def t_comment_created_then_updated_not_duplicated():
    reset(); e, _ = pr_env(); r = report(findings=[F("CRITICAL", "r1", "app/main.py", "app/main.py:3")])
    rc, out, _ = run(r, e); assert rc == 0 and "created" in out and len(ST["comments"]) == 1
    rc, out, _ = run(r, e); assert "updated" in out and len(ST["comments"]) == 1
    assert ST["calls"][0][2] == "Bearer ghp_fakefakefake" and "Warden security scan" in ST["comments"][0]["body"] and G.MARK in ST["comments"][0]["body"]


def t_existing_comment_found_on_a_later_page():
    reset(); ST["comments"] = [{"id": i + 1, "body": "human %d" % i, "user": {"type": "User"}} for i in range(130)]
    ST["comments"].append({"id": 999, "body": G.MARK + "old", "user": {"type": "Bot"}})
    ST["comments"].extend({"id": 1000 + i, "body": "later", "user": {"type": "User"}} for i in range(5))
    e, _ = pr_env(); rc, out, _ = run(report(), e)
    assert "updated" in out and [c for c in ST["comments"] if c["id"] == 999][0]["body"] != G.MARK + "old"


def t_comment_from_a_human_quoting_the_marker_is_never_edited():
    reset(); ST["comments"] = [{"id": 1, "body": G.MARK + " pasted by a person", "user": {"type": "User"}}]
    e, _ = pr_env(); rc, out, _ = run(report(), e)
    assert "created" in out and ST["comments"][0]["body"].endswith("pasted by a person") and len(ST["comments"]) == 2


def t_fork_or_read_only_token_degrades_quietly():
    reset(); ST["status"] = 403; e, summ = pr_env(); rc, out, _ = run(report(findings=[F("CRITICAL", "r1", "req.txt")]), e)
    assert rc == 0 and "skipped" in out and "read-only" in out and os.path.getsize(summ) > 0 and "::error" in out


def t_no_comment_without_pr_token_or_when_switched_off():
    reset(); e, _ = pr_env(); del e["GITHUB_EVENT_PATH"]; rc, out, _ = run(report(), e); assert "not a pull request" in out and not ST["calls"]
    e, _ = pr_env(); del e["GITHUB_TOKEN"]; rc, out, _ = run(report(), e); assert "no GITHUB_TOKEN" in out and not ST["calls"]
    e, _ = pr_env({"WARDEN_PR_COMMENT": "off"}); rc, out, _ = run(report(), e); assert not ST["calls"]
    e, _ = pr_env(); rc, out, _ = run(report(), e, ["--no-comment"]); assert not ST["calls"]


def t_pr_number_from_ref_when_no_event_file():
    reset(); e, _ = pr_env(); del e["GITHUB_EVENT_PATH"]; e["GITHUB_REF"] = "refs/pull/12/merge"
    rc, out, _ = run(report(), e); assert "created" in out and "/issues/12/comments" in ST["calls"][0][1]


def t_big_reports_stay_under_github_limits():
    many = [F("HIGH", "r%d" % i, "app/main.py", "app/main.py:%d" % (i % 50), title="x" * 400) for i in range(5000)]
    c = G.ctx(dict(GITHUB_REPOSITORY="o/r", GITHUB_SHA="a", GITHUB_RUN_ID="1"))
    assert len(G.build_comment(SUM, many, c, W)) <= G.COMMENT_MAX and len(G.build_summary(SUM, many, c, report(), W)) <= G.SUMMARY_MAX
    assert len(G.annotations(many, W, 10)) <= 10


def t_secret_values_are_never_echoed():
    f = [F("CRITICAL", "github-pat", "app/main.py", "app/main.py:1", title="GitHub token", tool="gitleaks")]; f[0]["match"] = "ghp_REALSECRETVALUE123"; f[0]["secret"] = "ghp_REALSECRETVALUE123"
    c = G.ctx(dict(GITHUB_REPOSITORY="o/r", GITHUB_SHA="a", GITHUB_RUN_ID="1"))
    blob = "\n".join(G.annotations(f, W, 10)) + G.build_summary(SUM, f, c, report(), W) + G.build_comment(SUM, f, c, W)
    assert "REALSECRET" not in blob


TESTS = [(n, f) for n, f in sorted(globals().items()) if n.startswith("t_") and callable(f)]
ok = 0
for n, f in TESTS:
    try:
        f(); ok += 1; print("  PASS ", n[2:])
    except Exception as e:
        import traceback; print("  FAIL ", n[2:], repr(e)); traceback.print_exc(limit=3)
print("%d/%d passed" % (ok, len(TESTS)))
sys.exit(0 if ok == len(TESTS) else 1)
