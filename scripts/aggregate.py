#!/usr/bin/env python3
"""Central visibility (plan section 12): roll the latest summary.json of every scanned repo into reports/dashboard.md.
Usage: scripts/aggregate.py [reports-dir]   (default: <framework>/reports)"""
import glob, json, os, sys

base = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..", "reports")
rows = []
for repo_dir in sorted(glob.glob(os.path.join(base, "*", ""))):
    runs = sorted(glob.glob(os.path.join(repo_dir, "*", "summary.json")))
    if not runs:
        continue
    s = json.load(open(runs[-1]))
    tools = s["tool_status"]
    rows.append((os.path.basename(repo_dir.rstrip("/")), s, sum(1 for v in tools.values() if v == "ok"), len(tools)))
L = ["# Security posture dashboard", "", f"Repos scanned: **{len(rows)}**  ·  gate failing: **{sum(1 for r in rows if r[1]['result'].startswith('FAIL'))}**", "",
     "| Repo | Last scan | Result | Crit | High | Med | Low | New Crit+High | Tools ok | Exceptions |", "|---|---|---|---|---|---|---|---|---|---|"]
for name, s, ok, n in rows:
    c, nc = s["counts"], s["new_counts"]
    L.append(f"| {name} | {s['date'][:16]} | {s['result'].split(' ')[0]} | {c['CRITICAL']} | {c['HIGH']} | {c['MEDIUM']} | {c['LOW']} | "
             f"{nc['CRITICAL'] + nc['HIGH']} | {ok}/{n} | {s['exceptions_applied']} |")
out = os.path.join(base, "dashboard.md")
open(out, "w").write("\n".join(L) + "\n")
print("\n".join(L)); print(f"\nwritten {out}")
