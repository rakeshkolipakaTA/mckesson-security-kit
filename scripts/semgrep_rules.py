#!/usr/bin/env python3
"""Download the Semgrep rule packs a repository uses into a folder, so scans can run without reaching semgrep.dev.

  warden rules fetch [DIR]      (DIR defaults to .security/semgrep-rules)
  python3 semgrep_rules.py --out DIR p/default p/python ...

Run it once on a machine that can reach semgrep.dev, commit the folder (or put it on the runner / an internal artifact store) and set
SEC_SEMGREP_RULES=<folder> in .security/config.env. Standard library only. Nothing is sent to semgrep.dev except the pack names."""
import argparse
import datetime
import os
import re
import sys
import urllib.error
import urllib.request

BASE = os.environ.get("WARDEN_RULES_BASE", "https://semgrep.dev/c/")   # override only for tests / an internal mirror
PACK = re.compile(r"^[pr]/[A-Za-z0-9._-]+$")


def fetch(pack, timeout=60):
    req = urllib.request.Request(BASE + pack, headers={"User-Agent": "warden-rules-fetch"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True)
    ap.add_argument("packs", nargs="+")
    a = ap.parse_args(argv)
    bad = [p for p in a.packs if not PACK.match(p)]
    if bad:
        print("invalid pack name(s): " + ", ".join(bad) + " (expected p/name)", file=sys.stderr)
        return 2
    os.makedirs(a.out, exist_ok=True)
    got, failed, total = [], [], 0
    for pack in dict.fromkeys(a.packs):
        try:
            text = fetch(pack)
        except (urllib.error.URLError, OSError, ValueError) as e:
            failed.append(pack)
            print(f"  FAILED {pack}: {getattr(e, 'reason', e)}", file=sys.stderr)
            continue
        if not text.lstrip().startswith("rules:"):
            failed.append(pack)
            print(f"  FAILED {pack}: the answer is not a Semgrep rule file", file=sys.stderr)
            continue
        n = len(re.findall(r"^- id: ", text, re.M))
        with open(os.path.join(a.out, pack.replace("/", "_") + ".yml"), "w", encoding="utf-8") as f:
            f.write(text)
        got.append(pack)
        total += n
        print(f"  {pack}: {n} rules")
    if failed:
        print(f"{len(failed)} pack(s) could not be downloaded; the folder is incomplete: {', '.join(failed)}", file=sys.stderr)
        return 1
    with open(os.path.join(a.out, "README.txt"), "w", encoding="utf-8") as f:
        f.write(f"Semgrep rule packs downloaded by 'warden rules fetch' on {datetime.date.today()}.\n"
                f"Packs: {', '.join(got)}\n"
                "Refresh with 'warden rules fetch' (the rules change over time). These rules belong to Semgrep and are published under the\n"
                "Semgrep Rules License: keep them in your own repositories or storage for internal use and check the licence before sharing them.\n")
    shown = os.path.relpath(a.out)
    shown = a.out if shown.startswith("..") else shown
    print(f"wrote {total} rules from {len(got)} packs to {shown}")
    print(f"next: warden config set SEC_SEMGREP_RULES {shown}   (then commit the folder and .security/config.env)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
