"""Tests for scripts/semgrep_rules.py (download Semgrep packs for offline scans) against a local server.
Run: python3 -I scripts/test_semgrep_rules.py"""
import os, subprocess, sys, tempfile, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "semgrep_rules.py")
PACKS = {"/c/p/good": "rules:\n- id: a.one\n  message: x\n- id: a.two\n  message: y\n", "/c/p/html": "<html>login</html>"}


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = PACKS.get(self.path)
        self.send_response(200 if body else 404); self.end_headers()
        self.wfile.write((body or "nope").encode())

    def log_message(self, *a):
        pass


srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
BASE = f"http://127.0.0.1:{srv.server_port}/c/"
FAILS = 0


def run(out, *packs, base=BASE):
    env = dict(os.environ, WARDEN_RULES_BASE=base)
    return subprocess.run([sys.executable, "-I", SCRIPT, "--out", out, *packs], env=env, capture_output=True, text=True)


def check(name, ok):
    global FAILS
    print(("  PASS  " if ok else "  FAIL  ") + name)
    FAILS += 0 if ok else 1


with tempfile.TemporaryDirectory() as t:
    out = os.path.join(t, "rules")
    r = run(out, "p/good")
    check("a good pack is saved and counted", r.returncode == 0 and "p/good: 2 rules" in r.stdout and os.path.isfile(os.path.join(out, "p_good.yml")))
    check("a README with the date and licence note is written", "Semgrep Rules License" in open(os.path.join(out, "README.txt")).read())
    out2 = os.path.join(t, "r2")
    r = run(out2, "p/good", "p/html")
    check("an answer that is not a rule file fails the run", r.returncode == 1 and "not a Semgrep rule file" in r.stderr)
    check("...and no README is written for an incomplete folder", not os.path.exists(os.path.join(out2, "README.txt")))
    r = run(os.path.join(t, "r3"), "p/missing")
    check("a pack the server does not have fails the run", r.returncode == 1)
    r = run(os.path.join(t, "r4"), "p/good", base="http://127.0.0.1:9/c/")
    check("an unreachable server fails clearly (exit 1)", r.returncode == 1 and "FAILED p/good" in r.stderr)
    r = run(os.path.join(t, "r5"), "../evil", "p/ok;rm")
    check("invalid pack names are refused (exit 2) before any download", r.returncode == 2 and not os.path.exists(os.path.join(t, "r5")))

print(f"semgrep_rules test: {'ok' if not FAILS else str(FAILS) + ' failed'}")
sys.exit(1 if FAILS else 0)
