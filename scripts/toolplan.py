#!/usr/bin/env python3
"""Decide which scanners run, and why. Used by scan.sh (and `secscan config show`). Standard library only.

  toolplan.py preset  --policy P --preset NAME            -> prints "<enforce> <gate>" defaults of that preset
  toolplan.py plan    --policy P --preset NAME --profiles python,node --modes bandit=off,sonar=on ...
                      [--exceptions F] [--image X] [--zap-url X] [--redteam-url X] [--model-files] [--partial]
                      -> JSON {tools:{name:{run,reason,mode}}, waivers:[...], errors:[...]}

Tool modes: auto = run when the stack/target fits, on = always run, off = never run.
Tools the central policy lists as *required* ignore `off` unless a valid, unexpired waiver exists in exceptions.json
(--partial = an intentionally incomplete local run such as `secscan quick`: required tools may be skipped).
"""
import argparse
import datetime as dt
import json
import os
import sys

ORDER = ["gitleaks", "gitleaks-history", "semgrep", "trivy-fs", "sbom", "bandit", "pip-audit", "npm-audit", "eslint", "workflow-scan", "agent-scan", "modelscan",
         "k8s-posture", "trivy-image", "dependency-check", "sonarqube", "zap", "api-fuzz", "exposure", "repo-posture", "redteam"]
CONFIG_NAME = {"gitleaks": "SEC_GITLEAKS", "semgrep": "SEC_SEMGREP", "trivy-fs": "SEC_TRIVY", "bandit": "SEC_BANDIT",
               "pip-audit": "SEC_PIP_AUDIT", "npm-audit": "SEC_NPM_AUDIT", "eslint": "SEC_ESLINT", "agent-scan": "SEC_AGENT_SCAN",
               "modelscan": "SEC_MODELSCAN", "trivy-image": "SEC_TRIVY_IMAGE", "dependency-check": "SEC_DEPCHECK",
               "sonarqube": "SEC_SONAR", "zap": "SEC_ZAP", "redteam": "SEC_REDTEAM", "gitleaks-history": "SEC_GITLEAKS_HISTORY", "sbom": "SEC_SBOM",
               "workflow-scan": "SEC_WORKFLOW_SCAN", "k8s-posture": "SEC_K8S_POSTURE", "api-fuzz": "SEC_API_FUZZ", "exposure": "SEC_EXPOSURE", "repo-posture": "SEC_REPO_POSTURE"}
# short names accepted in --modes / the legacy SEC_SKIP list
ALIAS = {"trivy": "trivy-fs", "sonar": "sonarqube", "depcheck": "dependency-check", "image": "trivy-image", "history": "gitleaks-history",
         "workflows": "workflow-scan", "k8s": "k8s-posture", "fuzz": "api-fuzz", "posture": "repo-posture"}
VALUE = {"auto": "auto", "on": "on", "off": "off", "1": "on", "0": "off", "true": "on", "false": "off", "yes": "on", "no": "off"}


def canon(name):
    name = ALIAS.get(name, name)
    return name if name in ORDER else None


def load_waivers(path):
    """Valid unexpired tool waivers {tool: entry}, plus problems found."""
    waivers, errors = {}, []
    if not path or not os.path.exists(path):
        return waivers, errors
    today = dt.date.today().isoformat()
    try:
        entries = json.load(open(path))
    except (OSError, ValueError) as ex:
        return waivers, [f"{path}: cannot read ({ex})"]
    for e in entries if isinstance(entries, list) else []:
        if not isinstance(e, dict) or "tool" not in e:
            continue
        t = canon(str(e["tool"]))
        if not t:
            errors.append(f"waiver for unknown tool '{e['tool']}' ignored")
        elif not (e.get("reason") and e.get("approved_by") and e.get("expires")):
            errors.append(f"waiver for {t} needs reason, approved_by and expires: ignored")
        elif str(e["expires"]) < today:
            errors.append(f"waiver for {t} expired on {e['expires']}: ignored")
        else:
            waivers[t] = e
    return waivers, errors


def required_set(policy, profiles):
    r = policy.get("required_tools", {})
    req = set(r.get("always", []))
    for p in profiles:
        req |= set(r.get("by_profile", {}).get(p, []))
    return req, set(r.get("when_present", []))


def fits(tool, a):
    """(applicable, why-not) for `auto` mode."""
    pr = set(a.profiles)
    if tool in ("gitleaks", "semgrep", "trivy-fs"):
        return True, ""
    if tool in ("bandit", "pip-audit"):
        return "python" in pr, "not a Python project"
    if tool in ("npm-audit", "eslint"):
        return "node" in pr, "not a Node project"
    if tool == "agent-scan":
        return "agent" in pr, "no AI agent code detected"
    if tool == "modelscan":
        return a.model_files, "no serialized model files found"
    if tool == "trivy-image":
        return bool(a.image), "no image to scan (set SEC_IMAGE)"
    if tool == "dependency-check":
        return "java" in pr, "not a Java project"
    if tool == "sonarqube":
        return bool(os.environ.get("SONAR_HOST_URL") and os.environ.get("SONAR_TOKEN")), "SONAR_HOST_URL / SONAR_TOKEN not set"
    if tool == "zap":
        return bool(a.zap_url), "no QA URL (set SEC_ZAP_URL)"
    if tool == "redteam":
        return bool(a.redteam_url), "no QA agent URL (set SEC_REDTEAM_URL)"
    facts = set(a.facts)
    if tool == "gitleaks-history":
        return "git" in facts, "not a git checkout (a worktree or an export has no history to scan)"
    if tool == "sbom":
        return True, ""
    if tool == "workflow-scan":
        return "workflows" in facts, "no GitHub Actions workflows"
    if tool == "k8s-posture":
        return "k8s" in facts, "no Kubernetes manifests found"
    if tool == "api-fuzz":
        return bool(a.api_spec), "no OpenAPI spec URL (set SEC_API_SPEC)"
    if tool == "exposure":
        return bool(a.exposure_targets), "no targets (set SEC_EXPOSURE_TARGETS)"
    if tool == "repo-posture":
        return "ghrepo" in facts, "no GitHub repository / GITHUB_TOKEN (the check reads repository settings through the API)"
    return True, ""


def preset_defaults(policy, name):
    presets = policy.get("presets", {})
    if name not in presets or name.startswith("_"):
        raise SystemExit(f"SEC_PRESET must be one of: {', '.join(k for k in presets if not k.startswith('_'))}")
    return presets[name]


def plan(a):
    policy = json.load(open(a.policy))
    pre = preset_defaults(policy, a.preset)
    preset_tools = {canon(k): v for k, v in pre.get("tools", {}).items() if canon(k)}
    modes = {t: VALUE[preset_tools.get(t, "auto")] for t in ORDER}
    errors = []
    explicit = set()  # tools the team itself switched (config.env / env / flags), as opposed to preset defaults
    for item in filter(None, a.modes.split(",")):
        k, _, v = item.partition("=")
        t = canon(k)
        if not t or v not in VALUE:
            errors.append(f"ignored setting '{item}'")
            continue
        modes[t] = VALUE[v]
        explicit.add(t)
    waivers, werr = load_waivers(a.exceptions)
    errors += werr
    required, when_present = required_set(policy, a.profiles)
    out = {}
    for t in ORDER:
        mode = modes[t]
        ok, why_not = fits(t, a)
        is_req = t in required or (t in when_present and ok)
        if mode == "off":
            if t in waivers:
                out[t] = dict(run=False, mode=mode, reason=f"turned off, waived by {waivers[t]['approved_by']} until {waivers[t]['expires']}: {waivers[t]['reason']}")
            elif is_req and not a.partial:
                out[t] = dict(run=True, mode=mode, forced=True, reason="REQUIRED by policy: 'off' is ignored. To waive it add a time-boxed entry to .security/exceptions.json")
            else:
                out[t] = dict(run=False, mode=mode, reason="turned off" + (" (partial local run)" if is_req else ""))
        elif mode == "on":
            out[t] = dict(run=True, mode=mode, reason="turned on")
        else:
            out[t] = dict(run=ok, mode=mode, reason=("applies to this project" if ok else why_not))
        out[t]["explicit"] = t in explicit
        if out[t]["run"] and t in ("trivy-image", "zap", "redteam", "sonarqube", "api-fuzz", "exposure", "repo-posture", "gitleaks-history", "workflow-scan", "k8s-posture") and mode == "on" and not fits(t, a)[0]:
            errors.append(f"{CONFIG_NAME[t]}=on but {why_not}")
    return dict(tools=out, waivers=[dict(tool=t, **{k: e[k] for k in ("reason", "approved_by", "expires")}) for t, e in waivers.items()],
                errors=errors, preset=a.preset)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["preset", "plan"])
    ap.add_argument("--policy", required=True)
    ap.add_argument("--preset", default="starter")
    ap.add_argument("--profiles", default="")
    ap.add_argument("--modes", default="", help="comma list tool=auto|on|off (explicit user settings)")
    ap.add_argument("--exceptions")
    ap.add_argument("--image", default="")
    ap.add_argument("--zap-url", default="")
    ap.add_argument("--redteam-url", default="")
    ap.add_argument("--model-files", action="store_true")
    ap.add_argument("--facts", default="", help="comma list of detected facts: git,workflows,k8s,ghrepo")
    ap.add_argument("--api-spec", default="")
    ap.add_argument("--exposure-targets", default="")
    ap.add_argument("--partial", action="store_true")
    a = ap.parse_args()
    a.profiles = [p for p in a.profiles.split(",") if p]
    a.facts = [x for x in a.facts.split(",") if x]
    if a.cmd == "preset":
        p = preset_defaults(json.load(open(a.policy)), a.preset)
        print(p["enforce"], p["gate"])
        return 0
    print(json.dumps(plan(a)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
