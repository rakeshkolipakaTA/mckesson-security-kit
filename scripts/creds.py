#!/usr/bin/env python3
"""Local test-credential store for Warden (standard library only). For YOUR machine; CI uses CI secrets instead.

  creds.py set NAME [--stdin] [--profile P]   store one credential (typed hidden, or one line from stdin)
  creds.py list [--profile P]                 names only, never values
  creds.py delete NAME [--profile P]
  creds.py path [--profile P]                 where the file lives

The file is outside your repository (default ~/.config/warden/credentials.env, mode 600; profile P: credentials.P.env) so it cannot be
committed by accident, and it refuses to live inside a git working tree. Environment variables and CI secrets always win over it.
Only the names Warden knows are accepted.
"""
import argparse
import getpass
import os
import re
import subprocess
import sys
import tempfile

ALLOWED = re.compile(r"^(ZAP_AUTH_(USER|PASSWORD|TOKEN|HEADER|COOKIE)|ZAP_OAUTH_CLIENT_(ID|SECRET)|API_TEST_TOKEN|REDTEAM_TOKEN|SONAR_TOKEN|WARDEN_DASHBOARD_TOKEN)$")


def file_for(profile):
    base = os.environ.get("WARDEN_CREDENTIALS_FILE")
    if base and not profile:
        return os.path.abspath(os.path.expanduser(base))
    if profile and not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", profile):
        sys.exit("creds: a profile name may only contain letters, digits, - and _")
    cfg = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(cfg, "warden", f"credentials.{profile}.env" if profile else "credentials.env")


def read(path):
    out = {}
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.rstrip("\r\n")
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    out[k] = v
    except FileNotFoundError:
        pass
    return out


def inside_git(path):
    d = os.path.dirname(path)
    while d and not os.path.isdir(d):
        d = os.path.dirname(d)
    try:
        r = subprocess.run(["git", "-C", d or ".", "rev-parse", "--is-inside-work-tree"], capture_output=True, text=True, timeout=10)
        return r.returncode == 0 and r.stdout.strip() == "true"
    except (OSError, subprocess.TimeoutExpired):
        return False


def write(path, data):
    if inside_git(path):
        sys.exit(f"creds: {path} is inside a git working tree: refusing, so a credential can never be committed. Use the default location or set WARDEN_CREDENTIALS_FILE.")
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".creds-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("# Warden test credentials (mode 600). Do not commit, do not share.\n")
            for k in sorted(data):
                f.write(f"{k}={data[k]}\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("action", choices=["set", "list", "delete", "path"])
    ap.add_argument("name", nargs="?")
    ap.add_argument("--stdin", action="store_true")
    ap.add_argument("--profile", default=os.environ.get("SEC_CREDENTIALS_PROFILE", ""))
    a = ap.parse_args()
    path = file_for(a.profile)
    if a.action == "path":
        print(path)
        return 0
    data = read(path)
    if a.action == "list":
        if not data:
            print(f"no credentials stored ({path})")
        for k in sorted(data):
            print(f"{k}  (set, {len(data[k])} characters)")
        return 0
    if not a.name or not ALLOWED.match(a.name):
        sys.exit("creds: NAME must be one of ZAP_AUTH_USER, ZAP_AUTH_PASSWORD, ZAP_AUTH_TOKEN, ZAP_AUTH_HEADER, ZAP_AUTH_COOKIE, ZAP_OAUTH_CLIENT_ID, "
                 "ZAP_OAUTH_CLIENT_SECRET, API_TEST_TOKEN, REDTEAM_TOKEN, SONAR_TOKEN, WARDEN_DASHBOARD_TOKEN")
    if a.action == "delete":
        if data.pop(a.name, None) is None:
            print(f"{a.name} was not stored")
            return 0
        write(path, data)
        print(f"deleted {a.name}")
        return 0
    val = sys.stdin.readline().rstrip("\r\n") if a.stdin else getpass.getpass(f"{a.name} (hidden): ")
    if not val or "\n" in val or "\r" in val:
        sys.exit("creds: empty value, nothing stored")
    data[a.name] = val
    write(path, data)
    print(f"stored {a.name} in {path} (mode 600)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
