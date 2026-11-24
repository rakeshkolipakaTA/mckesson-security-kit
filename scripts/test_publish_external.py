"""Tests for scripts/publish_external.py (DefectDojo + Dependency-Track publishing) against mock servers.
Run: python3 -I scripts/test_publish_external.py"""
import json, os, re, subprocess, sys, tempfile, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "publish_external.py")
DOJO_TOKEN, DT_KEY = "dojo-secret-token-123", "odt_dt-secret-key-456"
CALLS = []          # (server, method, path, headers, fields, files)
BEHAVE = {"dojo": 201, "dtrack": 200}


def parse_multipart(ctype, body):
    boundary = re.search(r"boundary=(.+)", ctype).group(1).encode()
    fields, files = {}, {}
    for part in body.split(b"--" + boundary):
        if b"Content-Disposition" not in part:
            continue
        head, _, data = part.partition(b"\r\n\r\n")
        data = data[:-2] if data.endswith(b"\r\n") else data
        name = re.search(rb'name="([^"]+)"', head).group(1).decode()
        if b"filename=" in head:
            files[name] = data
        else:
            fields[name] = data.decode()
    return fields, files


def make_server(kind):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass

        def send(self, code, obj):
            b = json.dumps(obj).encode()
            self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            fields, files = parse_multipart(self.headers.get("Content-Type", ""), body)
            CALLS.append((kind, "POST", self.path, dict(self.headers), fields, files))
            code = BEHAVE[kind]
            if kind == "dojo":
                if code != 201:
                    return self.send(code, {"detail": "nope"})
                z = {"total": {"total": 0, "active": 0}}
                return self.send(201, {"statistics": {"before": {"total": {"total": 0}}, "after": {"total": {"total": 3, "active": 3}},
                                                      "delta": {"created": {"total": {"total": 3}}, "closed": z, "reactivated": z, "untouched": z}}})
            if code not in (200, 202):
                return self.send(code, {"error": "nope"})
            return self.send(200, {"token": "tok-1"})

        def do_GET(self):
            CALLS.append((kind, "GET", self.path, dict(self.headers), {}, {}))
            if self.path.startswith("/api/v1/bom/token/"):
                return self.send(200, {"processing": False})
            if self.path.startswith("/api/v1/project/lookup"):
                return self.send(200, {"uuid": "u-1"})
            if self.path.startswith("/api/v1/metrics/project/"):
                return self.send(200, {"components": 12, "critical": 1, "high": 2, "medium": 3, "low": 4})
            self.send(404, {})
    s = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s, f"http://127.0.0.1:{s.server_address[1]}"


DOJO, DOJO_URL = make_server("dojo")
DT, DT_URL = make_server("dtrack")
FINDINGS = [
    {"tool": "gitleaks+semgrep", "category": "Secrets", "severity": "HIGH", "rule": "generic-api-key", "title": "Detected a Generic API Key", "location": "app/cfg.py:7",
     "path": "app/cfg.py", "fingerprint": "fp-aaa", "fix": "rotate it", "tools": ["gitleaks"], "all_ids": [], "new": True},
    {"tool": "trivy-fs", "category": "SCA", "severity": "CRITICAL", "rule": "CVE-2024-12345", "title": "pkg 1.0: remote code execution", "location": "requirements.txt",
     "path": "requirements.txt", "fingerprint": "fp-bbb", "fix": "upgrade to 1.2", "all_ids": ["GHSA-xxxx", "CVE-2024-12345"], "new": False},
    {"tool": "bandit", "category": "SAST", "severity": "LOW", "rule": "B101", "title": "assert used", "location": "x.py:3", "path": "x.py", "fingerprint": "fp-ccc", "excepted": True},
]


def report(sbom=True):
    d = tempfile.mkdtemp()
    json.dump(FINDINGS, open(os.path.join(d, "findings.json"), "w"))
    json.dump({"target": "x"}, open(os.path.join(d, "summary.json"), "w"))
    if sbom:
        open(os.path.join(d, "sbom.cdx.json"), "w").write('{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}')
    return d


def run(rep, branch="main", dojo=True, dtrack=True, extra_env=None, args=(), ci=True):
    env = {"PATH": os.environ["PATH"], "HOME": tempfile.mkdtemp()}
    if ci:
        env.update(GITHUB_ACTIONS="true", GITHUB_REPOSITORY="acme/shop", GITHUB_REF_NAME=branch, GITHUB_SHA="a" * 40, GITHUB_RUN_ID="777")
    if dojo:
        env.update(SEC_DEFECTDOJO_URL=DOJO_URL, DEFECTDOJO_TOKEN=DOJO_TOKEN)
    if dtrack:
        env.update(SEC_DTRACK_URL=DT_URL, DTRACK_API_KEY=DT_KEY)
    env.update(extra_env or {})
    del CALLS[:]
    p = subprocess.run([sys.executable, "-I", SCRIPT, "--report", rep, "--root", tempfile.mkdtemp(), *args], env=env, capture_output=True, text=True, timeout=60)
    return p.returncode, p.stdout, p.stderr


def calls(kind, method="POST"):
    return [c for c in CALLS if c[0] == kind and c[1] == method]


def t_defectdojo_gets_a_reimport_with_the_right_context():
    rc, out, err = run(report(), dtrack=False)
    assert rc == 0 and "defectdojo: published acme/shop (main)" in out and "new 3" in out, (out, err)
    (_, _, path, hdr, f, files), = calls("dojo")
    assert path == "/api/v2/reimport-scan/" and hdr["Authorization"] == f"Token {DOJO_TOKEN}"
    assert (f["product_name"], f["engagement_name"], f["product_type_name"], f["scan_type"]) == ("acme/shop", "main", "Warden", "Generic Findings Import")
    assert f["auto_create_context"] == "true" and f["close_old_findings"] == "true" and f["close_old_findings_product_scope"] == "false"
    assert f["commit_hash"] == "a" * 40 and f["build_id"] == "777" and f["test_title"] == "Warden scan"
    assert not calls("dtrack"), "Dependency-Track was not configured"


def t_findings_are_mapped_faithfully():
    run(report(), dtrack=False)
    items = json.loads(calls("dojo")[0][5]["file"])["findings"]
    a, b, c = items
    assert (a["severity"], a["file_path"], a["line"], a["unique_id_from_tool"], a["mitigation"]) == ("High", "app/cfg.py", 7, "fp-aaa", "rotate it")
    assert b["severity"] == "Critical" and b["cve"] == "CVE-2024-12345" and b["line"] == 0 and "baseline" in b["tags"]
    assert c["severity"] == "Low" and c["active"] is False and c["risk_accepted"] is True      # an approved exception is a risk acceptance, not an open finding
    assert a["active"] is True and "warden" in a["tags"] and "date" in a


def t_same_report_produces_identical_payload_so_a_reimport_matches():
    rep = report()
    run(rep, dtrack=False); first = calls("dojo")[0][5]["file"]
    run(rep, dtrack=False); second = calls("dojo")[0][5]["file"]
    assert first == second


def t_product_names_can_be_overridden():
    run(report(), dtrack=False, extra_env={"SEC_DEFECTDOJO_PRODUCT": "shop-api", "SEC_DEFECTDOJO_PRODUCT_TYPE": "Payments"})
    f = calls("dojo")[0][4]
    assert f["product_name"] == "shop-api" and f["product_type_name"] == "Payments"


def t_pull_request_branches_are_skipped_by_default_and_star_allows_them():
    rc, out, err = run(report(), branch="feature/x")
    assert rc == 0 and "skipped" in out and not CALLS, (out, CALLS)
    rc, out, err = run(report(), branch="feature/x", extra_env={"SEC_DEFECTDOJO_BRANCHES": "*", "SEC_DTRACK_BRANCHES": "feature/x"})
    assert rc == 0 and len(calls("dojo")) == 1 and calls("dtrack")[0][4]["projectVersion"] == "feature/x"


def t_dependency_track_gets_the_sbom_as_a_project_version():
    rc, out, err = run(report(), dojo=False)
    assert rc == 0 and "uploaded SBOM for acme/shop version main" in out and "components 12" in out and "critical 1 high 2" in out, (out, err)
    (_, _, path, hdr, f, files), = calls("dtrack")
    assert path == "/api/v1/bom" and hdr["X-Api-Key"] == DT_KEY
    assert (f["projectName"], f["projectVersion"], f["autoCreate"], f["isLatest"]) == ("acme/shop", "main", "true", "true")
    assert json.loads(files["bom"])["bomFormat"] == "CycloneDX"
    assert not calls("dojo")
    run(report(), dojo=False, branch="release", extra_env={"SEC_DTRACK_BRANCHES": "release", "SEC_DTRACK_PROJECT": "shop"})
    f = calls("dtrack")[0][4]
    assert f["projectName"] == "shop" and f["isLatest"] == "false"


def t_no_sbom_is_a_clear_skip_not_an_error():
    rc, out, err = run(report(sbom=False), dojo=False)
    assert rc == 0 and "no SBOM" in out and not CALLS


def t_both_tools_in_one_run():
    rc, out, err = run(report())
    assert rc == 0 and len(calls("dojo")) == 1 and len(calls("dtrack")) == 1


def t_server_errors_are_warnings_unless_strict():
    for kind, code, hint in (("dojo", 401, "token rejected"), ("dojo", 403, "may not create"), ("dtrack", 401, "API key rejected"), ("dtrack", 403, "BOM_UPLOAD")):
        BEHAVE[kind] = code
        try:
            rc, out, err = run(report(), dojo=(kind == "dojo"), dtrack=(kind == "dtrack"))
            assert rc == 0 and hint in err, (kind, code, err)
            rc, out, err = run(report(), dojo=(kind == "dojo"), dtrack=(kind == "dtrack"), args=("--strict",))
            assert rc == 1 and hint in err
        finally:
            BEHAVE.update(dojo=201, dtrack=200)


def t_unreachable_server_is_a_warning():
    rc, out, err = run(report(), extra_env={"SEC_DEFECTDOJO_URL": "http://127.0.0.1:9", "SEC_DTRACK_URL": "http://127.0.0.1:9"})
    assert rc == 0 and err.count("could not reach") == 2, err


def t_missing_secret_is_explained_and_nothing_is_sent():
    rc, out, err = run(report(), extra_env={"DEFECTDOJO_TOKEN": "", "DTRACK_API_KEY": ""})
    assert rc == 0 and "DEFECTDOJO_TOKEN is not set" in err and "DTRACK_API_KEY is not set" in err and not CALLS


def t_secrets_never_appear_in_output():
    for code in (201, 401):
        BEHAVE["dojo"] = code
        try:
            rc, out, err = run(report())
            assert DOJO_TOKEN not in out + err and DT_KEY not in out + err
        finally:
            BEHAVE["dojo"] = 201


def t_a_local_scan_does_not_publish_unless_asked():
    rc, out, err = run(report(), ci=False)
    assert rc == 0 and out == "" and not CALLS
    rc, out, err = run(report(), ci=False, args=("--strict",))
    assert rc == 0 and len(calls("dojo")) == 1       # `warden publish` passes --strict: a deliberate send, whatever the branch (not a git repo here -> "unknown")
    assert calls("dojo")[0][4]["engagement_name"] == "unknown"


def t_dry_run_contacts_nobody():
    rc, out, err = run(report(), args=("--dry-run",), extra_env={"DEFECTDOJO_TOKEN": "", "DTRACK_API_KEY": ""})
    assert rc == 0 and "dry run" in out and not CALLS


def t_bad_url_and_nothing_configured():
    rc, out, err = run(report(), extra_env={"SEC_DEFECTDOJO_URL": "ftp://x"}, args=("--strict",))
    assert rc == 1 and "must start with http" in err
    rc, out, err = run(report(), dojo=False, dtrack=False, args=("--strict",))
    assert rc == 1 and "nothing to publish" in err


def wiz_report(kinds=("dir", "iac", "image")):
    d = report(sbom=False)
    for k in kinds:
        open(os.path.join(d, f"wizcli-{k}.json"), "w").write(json.dumps({"scan": k}))
    return d


def t_wiz_results_are_imported_with_defectdojos_own_wiz_parsers():
    rc, out, err = run(wiz_report(), dtrack=False, args=("--only", "wiz"))
    assert rc == 0, (out, err)
    got = {c[4]["scan_type"]: (c[4]["test_title"], c[4]["product_name"], c[4]["engagement_name"], json.loads(c[5]["file"])) for c in calls("dojo")}
    assert set(got) == {"Wizcli Dir Scan", "Wizcli IaC Scan", "Wizcli Img Scan"}, got.keys()
    assert got["Wizcli IaC Scan"][:3] == ("Wiz CLI iac scan", "acme/shop", "main") and got["Wizcli Img Scan"][3] == {"scan": "image"}   # the file is sent unchanged
    assert all(c[3]["Authorization"] == f"Token {DOJO_TOKEN}" and c[4]["close_old_findings"] == "true" for c in calls("dojo"))
    assert not calls("dtrack")


def t_wiz_import_only_sends_the_scans_that_ran_and_respects_branches():
    rc, out, err = run(wiz_report(("dir",)), dtrack=False, args=("--only", "wiz"))
    assert [c[4]["scan_type"] for c in calls("dojo")] == ["Wizcli Dir Scan"]
    rc, out, err = run(wiz_report(), dtrack=False, args=("--only", "wiz"), branch="feature/x")
    assert rc == 0 and "skipped" in out and not CALLS
    rc, out, err = run(report(sbom=False), dtrack=False, args=("--only", "wiz"))
    assert rc == 0 and "no Wiz CLI results" in out and not CALLS


def t_wiz_import_failures_and_dry_run():
    rc, out, err = run(wiz_report(), dtrack=False, args=("--only", "wiz", "--dry-run"))
    assert rc == 0 and out.count("dry run") == 3 and not CALLS
    rc, out, err = run(wiz_report(), dtrack=False, args=("--only", "wiz"), extra_env={"DEFECTDOJO_TOKEN": ""})
    assert "DEFECTDOJO_TOKEN is not set" in err and not CALLS
    BEHAVE["dojo"] = 401
    try:
        rc, out, err = run(wiz_report(), dtrack=False, args=("--only", "wiz", "--strict"))
        assert rc == 1 and err.count("token rejected") == 3 and DOJO_TOKEN not in out + err
    finally:
        BEHAVE["dojo"] = 201


TESTS = [(n, f) for n, f in sorted(globals().items()) if n.startswith("t_") and callable(f)]
ok = 0
for n, f in TESTS:
    try:
        f(); ok += 1; print("  PASS ", n[2:])
    except Exception as e:
        import traceback; print("  FAIL ", n[2:], repr(e)); traceback.print_exc(limit=3)
print("%d/%d passed" % (ok, len(TESTS)))
sys.exit(0 if ok == len(TESTS) else 1)
