"""Tests for scripts/wiz_scan.py and `warden wiz` with a STAND-IN wizcli (records how it is called, writes JSON). They prove Warden's side:
no licence = nothing runs, correct commands, secrets never printed, policy failures vs errors, enforcement, safe install. They do NOT prove that
the real wizcli accepts these flags: that needs a Wiz tenant (docs/integrations/wiz.md).
Run: python3 -I scripts/test_wiz_scan.py"""
import hashlib, json, os, shutil, subprocess, sys, tempfile, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "wiz_scan.py")
ROOT = os.path.abspath(os.path.join(HERE, ".."))
CID, SEC = "svc-client-id-123", "sup3r-secret-wiz-456"
STUB = '''#!/usr/bin/env python3
import json, os, sys
a = sys.argv[1:]
open(os.environ["STUB_LOG"], "a").write(json.dumps({"args": a, "cwd": os.getcwd()}) + "\\n")
if os.environ.get("STUB_ECHO"):
    print("leak check: client secret is " + a[a.index("--secret") + 1] if "--secret" in a else "scan output mentions " + os.environ["STUB_ECHO"])
if a[0] == "auth":
    sys.exit(1 if os.environ.get("STUB_AUTH_FAIL") else 0)
kind = a[0]
out = a[a.index("-o") + 1].rsplit(",", 1)[0]
mode = os.environ.get("STUB_MODE", "pass")
if mode == "error":
    sys.stderr.write("boom: cannot reach Wiz\\n"); sys.exit(3)
open(out, "w").write(json.dumps({"scan": kind, "result": "ok"}))
sys.exit(1 if mode == "policy" else 0)
'''


def stub_dir():
    d = tempfile.mkdtemp()
    p = os.path.join(d, "wizcli")
    open(p, "w").write(STUB)
    os.chmod(p, 0o755)
    return p, os.path.join(d, "calls.log")


def run(extra_env=None, args=(), creds=True, cli=True):
    p, log = stub_dir()
    out = tempfile.mkdtemp()
    env = {"PATH": "/usr/bin:/bin", "HOME": tempfile.mkdtemp(), "STUB_LOG": log, "XDG_CACHE_HOME": tempfile.mkdtemp()}
    if creds:
        env.update(WIZ_CLIENT_ID=CID, WIZ_CLIENT_SECRET=SEC)
    if cli:
        env["SEC_WIZCLI"] = p
    env.update(extra_env or {})
    r = subprocess.run([sys.executable, "-I", SCRIPT, "--root", tempfile.mkdtemp(), "--out", out, *args], env=env, capture_output=True, text=True, timeout=60)
    calls = [json.loads(l) for l in open(log)] if os.path.exists(log) else []
    return r.returncode, r.stdout, r.stderr, calls, out


def t_no_licence_means_nothing_runs():
    rc, so, se, calls, out = run(creds=False)
    assert rc == 0 and "skipped" in so and not calls and not os.listdir(out)
    rc, so, se, calls, _ = run(creds=False, args=("--strict",))
    assert rc == 2 and not calls


def t_only_one_half_of_the_credentials_is_not_a_licence():
    rc, so, se, calls, _ = run(creds=False, extra_env={"WIZ_CLIENT_ID": CID})
    assert rc == 0 and "skipped" in so and not calls


def t_signs_in_then_scans_the_code_and_the_iac_files():
    rc, so, se, calls, out = run()
    assert rc == 0, (so, se)
    assert calls[0]["args"] == ["auth", "--id", CID, "--secret", SEC]
    kinds = [c["args"][0] for c in calls[1:]]
    assert kinds == ["dir", "iac"], kinds
    d = calls[1]["args"]
    assert d[:4] == ["dir", "scan", "--path", "./"] and d[4] == "-o" and d[5] == os.path.join(out, "wizcli-dir.json") + ",json"
    assert json.load(open(os.path.join(out, "wizcli-iac.json")))["scan"] == "iac"
    s = json.load(open(os.path.join(out, "wiz-summary.json")))["scans"]
    assert [x["status"] for x in s] == ["passed", "passed"]


def t_image_scan_needs_an_image():
    rc, so, se, calls, out = run(args=("--scans", "dir,image", "--image", "acme/shop:1.2"))
    assert rc == 0 and [c["args"][0] for c in calls[1:]] == ["dir", "docker"]
    assert calls[2]["args"][:4] == ["docker", "scan", "--image", "acme/shop:1.2"]
    rc, so, se, calls, out = run(args=("--scans", "image"))
    assert rc == 0 and "no image is set" in se and [c["args"][0] for c in calls[1:]] == []


def t_secrets_never_appear_in_output():
    rc, so, se, calls, out = run(extra_env={"STUB_ECHO": SEC})
    assert SEC not in so + se and CID not in so + se and "***" in so, (so, se)
    rc, so, se, calls, out = run(extra_env={"STUB_AUTH_FAIL": "1", "STUB_ECHO": SEC})
    assert SEC not in so + se


def t_policy_failure_is_reported_but_only_blocks_when_enforcing():
    env = {"STUB_MODE": "policy"}
    rc, so, se, calls, out = run(extra_env=env)
    assert rc == 0 and "policy-failed" in so and "Report-only" in so
    assert json.load(open(os.path.join(out, "wiz-summary.json")))["scans"][0]["status"] == "policy-failed"
    assert run(extra_env=env, args=("--enforce",))[0] == 1
    assert run(extra_env={**env, "SEC_WIZ_ENFORCE": "1"})[0] == 1


def t_a_scan_that_could_not_run_is_an_error_not_a_pass():
    env = {"STUB_MODE": "error"}
    rc, so, se, calls, out = run(extra_env=env)
    assert rc == 0 and "did not run" in se and "boom" in se
    assert json.load(open(os.path.join(out, "wiz-summary.json")))["scans"][0]["status"] == "error"
    assert run(extra_env=env, args=("--enforce",))[0] == 1          # fail closed when enforcing


def t_sign_in_failure_is_explained_and_nothing_is_scanned():
    rc, so, se, calls, out = run(extra_env={"STUB_AUTH_FAIL": "1"})
    assert rc == 0 and "sign-in failed" in se and [c["args"][0] for c in calls] == ["auth"]
    assert run(extra_env={"STUB_AUTH_FAIL": "1"}, args=("--enforce",))[0] == 1


def t_policy_name_is_passed_through():
    rc, so, se, calls, out = run(extra_env={"SEC_WIZ_POLICY": "My Policy"})
    assert calls[1]["args"][-2:] == ["--policy", "My Policy"]


def t_secrets_can_come_from_files():
    d = tempfile.mkdtemp()
    open(os.path.join(d, "id"), "w").write(CID + "\n"); open(os.path.join(d, "sec"), "w").write(SEC + "\n")
    rc, so, se, calls, out = run(creds=False, extra_env={"WIZ_CLIENT_ID_FILE": os.path.join(d, "id"), "WIZ_CLIENT_SECRET_FILE": os.path.join(d, "sec")})
    assert rc == 0 and calls[0]["args"] == ["auth", "--id", CID, "--secret", SEC]


def t_missing_wizcli_is_explained():
    rc, so, se, calls, out = run(cli=False)
    assert rc == 0 and "not installed" in se and "--install" in se
    assert run(cli=False, args=("--enforce",))[0] == 2
    assert run(extra_env={"SEC_WIZCLI": "/nonexistent/wizcli"})[0] == 0


def t_unknown_scan_kind_is_rejected():
    assert run(args=("--scans", "dir,ftp"))[0] == 2


def t_install_checks_the_hash_and_the_url():
    payload = b"#!/bin/sh\necho fake wizcli\n"
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            self.send_response(200); self.send_header("Content-Length", str(len(payload))); self.end_headers(); self.wfile.write(payload)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}/wizcli"
    cache = tempfile.mkdtemp()
    base = {"XDG_CACHE_HOME": cache, "SEC_WIZCLI_URL": url}
    bad = run(cli=False, args=("--install",), extra_env={**base, "SEC_WIZCLI_SHA256": "0" * 64})
    assert "does not match" in bad[2] and not os.path.exists(os.path.join(cache, "warden", "wizcli", "wizcli"))
    ok = run(cli=False, args=("--install",), extra_env={**base, "SEC_WIZCLI_SHA256": hashlib.sha256(payload).hexdigest()})
    inst = os.path.join(cache, "warden", "wizcli", "wizcli")
    assert "installed wizcli" in ok[1] and os.access(inst, os.X_OK) and open(inst, "rb").read() == payload
    unpinned = run(cli=False, args=("--install",), extra_env={"XDG_CACHE_HOME": tempfile.mkdtemp(), "SEC_WIZCLI_URL": url})
    assert "not verified" in unpinned[2]
    insecure = run(cli=False, args=("--install",), extra_env={"SEC_WIZCLI_URL": "http://downloads.example.com/wizcli"})
    assert "must be https" in insecure[2]
    srv.shutdown()


def t_warden_wiz_runs_through_the_scan_script_and_config_secrets_are_refused():
    repo = tempfile.mkdtemp()
    os.makedirs(os.path.join(repo, ".security"))
    open(os.path.join(repo, ".security", "config.env"), "w").write("SEC_WIZ_SCANS=dir\nWIZ_CLIENT_SECRET=do-not-put-this-here\n")
    p, log = stub_dir()
    env = {"PATH": "/usr/bin:/bin", "HOME": tempfile.mkdtemp(), "STUB_LOG": log, "SEC_WIZCLI": p, "WIZ_CLIENT_ID": CID, "WIZ_CLIENT_SECRET": SEC, "WARDEN_WIZ_ARGS": ""}
    r = subprocess.run([os.path.join(ROOT, "scripts", "scan.sh"), repo, "--wiz"], env=env, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert "looks like a SECRET and was ignored" in r.stderr and "do-not-put-this-here" not in r.stdout + r.stderr
    calls = [json.loads(l) for l in open(log)]
    assert [c["args"][0] for c in calls] == ["auth", "dir"], calls          # SEC_WIZ_SCANS=dir came from config.env
    assert os.path.exists(os.path.join(repo, ".security", "reports", "wiz", "wizcli-dir.json"))
    assert SEC not in r.stdout + r.stderr


TESTS = [(n, f) for n, f in sorted(globals().items()) if n.startswith("t_") and callable(f)]
ok = 0
for n, f in TESTS:
    try:
        f(); ok += 1; print("  PASS ", n[2:])
    except Exception as e:
        import traceback; print("  FAIL ", n[2:], repr(e)); traceback.print_exc(limit=3)
print("%d/%d passed" % (ok, len(TESTS)))
sys.exit(0 if ok == len(TESTS) else 1)
