#!/usr/bin/env python3
"""Run Wiz CLI (wizcli) scans on the repository, when a Wiz licence is available. Standard library only.  Run it with `warden wiz`.

  wiz_scan.py --root <repo> --out <dir> [--scans dir,iac,image] [--image NAME:TAG] [--install] [--enforce] [--strict]

Needs a Wiz licence: a Wiz service account, as the CI secrets WIZ_CLIENT_ID and WIZ_CLIENT_SECRET (or ..._FILE paths).
Without them nothing runs and nothing is sent (exit 0), so the same pipeline works with or without a licence. --strict makes that an error.

Settings (not secret; config.env or environment):
  SEC_WIZ_SCANS     dir,iac (default) | add image. dir = code and dependencies, iac = Terraform / Kubernetes / ARM files, image = a built image
  SEC_WIZ_ENFORCE   1 = exit non-zero when a Wiz policy fails (default: report-only, like the starter preset)
  SEC_WIZ_POLICY    optional: name of a Wiz policy to use (passed as --policy; policies are defined in the Wiz portal). Set it in the workflow env if the name has spaces
  SEC_IMAGE         image to scan with the image scan (needs the Docker daemon)
  SEC_WIZCLI        path to wizcli (default: wizcli on PATH, then Warden's cache)
  SEC_WIZCLI_URL    where --install downloads wizcli (default https://downloads.wiz.io/wizcli/latest/wizcli-linux-amd64). Pin a version for repeatable builds
  SEC_WIZCLI_SHA256 expected SHA-256 of that download: --install refuses a file that does not match

Results: Wiz shows them in its own portal. Each scan also writes JSON to <out>/wizcli-<kind>.json, which `warden publish` imports into DefectDojo with
DefectDojo's own Wiz parsers. This tool is not tested against a real Wiz tenant (see docs/integrations/wiz.md): the wizcli flags follow Wiz's published usage,
check them with `wizcli dir scan --help` on the version you install."""
import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import urllib.parse
import urllib.request

KINDS = {"dir": ("dir", "--path"), "iac": ("iac", "--path"), "image": ("docker", "--image")}
DEFAULT_URL = "https://downloads.wiz.io/wizcli/latest/wizcli-linux-amd64"


def secret(name):
    """A secret from the environment or from NAME_FILE (a file path, as Docker / Kubernetes / Jenkins mount secrets)."""
    v = os.environ.get(name, "")
    if v:
        return v
    f = os.environ.get(name + "_FILE", "")
    if f:
        try:
            return open(f).read().strip()
        except OSError:
            return ""
    return ""


def cache_path():
    return os.path.join(os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache"), "warden", "wizcli", "wizcli")


def find_cli():
    p = os.environ.get("SEC_WIZCLI", "")
    if p:
        return p if os.access(p, os.X_OK) else ""
    return shutil.which("wizcli") or (cache_path() if os.access(cache_path(), os.X_OK) else "")


def install():
    url = os.environ.get("SEC_WIZCLI_URL") or DEFAULT_URL
    host = urllib.parse.urlparse(url).hostname or ""
    if not url.startswith("https://") and host not in ("localhost", "127.0.0.1"):
        print(f"wiz: SEC_WIZCLI_URL must be https:// ({url})", file=sys.stderr)
        return ""
    want = (os.environ.get("SEC_WIZCLI_SHA256") or "").strip().lower()
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "warden-wiz"}), timeout=120) as r:
            data = r.read()
    except Exception as e:
        print(f"wiz: could not download wizcli from {url}: {e}", file=sys.stderr)
        return ""
    got = hashlib.sha256(data).hexdigest()
    if want and got != want:
        print(f"wiz: the download does not match SEC_WIZCLI_SHA256 (got {got}); not installing", file=sys.stderr)
        return ""
    if not want:
        print(f"wiz: note: no SEC_WIZCLI_SHA256 set, so this download is not verified (sha256 of what was fetched: {got}). Pin the version and the hash for repeatable builds", file=sys.stderr)
    dest = cache_path()
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    tmp = dest + ".part"
    open(tmp, "wb").write(data)
    os.chmod(tmp, os.stat(tmp).st_mode | stat.S_IXUSR)
    os.replace(tmp, dest)
    print(f"wiz: installed wizcli to {dest}")
    return dest


def redact(text, *secrets):
    for s in secrets:
        if s:
            text = text.replace(s, "***")
    return text


def run_cli(cli, args, cwd, cid, sec):
    p = subprocess.run([cli, *args], cwd=cwd, capture_output=True, text=True, timeout=1800)
    return p.returncode, redact(p.stdout, cid, sec), redact(p.stderr, cid, sec)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=".")
    ap.add_argument("--out", required=True)
    ap.add_argument("--scans", default=os.environ.get("SEC_WIZ_SCANS") or "dir,iac")
    ap.add_argument("--image", default=os.environ.get("SEC_IMAGE", ""))
    ap.add_argument("--install", action="store_true", help="download wizcli if it is not installed")
    ap.add_argument("--enforce", action="store_true", default=os.environ.get("SEC_WIZ_ENFORCE") in ("1", "true", "on", "yes"))
    ap.add_argument("--strict", action="store_true", help="a missing licence or wizcli is an error")
    a = ap.parse_args()
    cid, sec = secret("WIZ_CLIENT_ID"), secret("WIZ_CLIENT_SECRET")
    if not (cid and sec):
        print("wiz: skipped: no Wiz licence credentials (set the CI secrets WIZ_CLIENT_ID and WIZ_CLIENT_SECRET; see docs/integrations/wiz.md)")
        return 2 if a.strict else 0
    cli = find_cli()
    if not cli and a.install:
        cli = install()
    if not cli:
        print("wiz: wizcli is not installed. Run `warden wiz --install`, or install it from Wiz and set SEC_WIZCLI (docs/integrations/wiz.md)", file=sys.stderr)
        return 2 if (a.strict or a.enforce) else 0
    kinds = [k.strip() for k in a.scans.split(",") if k.strip()]
    bad = [k for k in kinds if k not in KINDS]
    if bad:
        print(f"wiz: unknown scan kind {bad} (use dir, iac, image)", file=sys.stderr)
        return 2
    if "image" in kinds and not a.image:
        print("wiz: the image scan was asked for but no image is set (SEC_IMAGE=name:tag or --image): skipping it", file=sys.stderr)
        kinds.remove("image")
    root, out = os.path.abspath(a.root), os.path.abspath(a.out)
    os.makedirs(out, exist_ok=True)
    # the documented way to sign in: the service account id and secret. They are redacted from everything printed below
    rc, so, se = run_cli(cli, ["auth", "--id", cid, "--secret", sec], root, cid, sec)
    if rc != 0:
        print(f"wiz: sign-in failed (exit {rc}): is the service account valid for your Wiz tenant?\n{(se or so).strip()[:400]}", file=sys.stderr)
        return 1 if a.enforce else 0
    results, worst = [], 0
    for k in kinds:
        sub, flag = KINDS[k]
        target = a.image if k == "image" else "./"
        jf = os.path.join(out, f"wizcli-{k}.json")
        if os.path.exists(jf):
            os.remove(jf)
        args = [sub, "scan", flag, target, "-o", f"{jf},json"]
        if os.environ.get("SEC_WIZ_POLICY"):
            args += ["--policy", os.environ["SEC_WIZ_POLICY"]]
        rc, so, se = run_cli(cli, args, root, cid, sec)
        if so.strip():
            print(so.rstrip()[-6000:])
        have_json = os.path.isfile(jf) and os.path.getsize(jf) > 0
        # wizcli exits non-zero both when a policy fails and when it cannot run; a result file means it ran
        status = "passed" if rc == 0 else ("policy-failed" if have_json else "error")
        if status == "error":
            print(f"wiz: {k} scan did not run (exit {rc}): {se.strip()[:400]}", file=sys.stderr)
        worst = max(worst, {"passed": 0, "policy-failed": 1, "error": 2}[status])
        results.append({"scan": k, "status": status, "exit_code": rc, "json": jf if have_json else None})
        print(f"wiz: {k} scan {status}" + (f" (results: {jf})" if have_json else ""))
    json.dump({"scans": results}, open(os.path.join(out, "wiz-summary.json"), "w"), indent=1)
    if worst == 1 and not a.enforce:
        print("wiz: a Wiz policy failed. Report-only mode: not failing the build (SEC_WIZ_ENFORCE=1 or --enforce to block).")
    return 1 if (a.enforce and worst) else 0


if __name__ == "__main__":
    sys.exit(main())
