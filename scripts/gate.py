#!/usr/bin/env python3
"""Normalize scanner output, apply the McKesson security gate, write summary reports.

Reads raw tool reports from <out>/raw/, writes <out>/findings.json, summary.json, summary.md.
Exit code: 0 = pass (or report-only), 1 = gate failed (only with --enforce), 2 = usage/IO error.

Stdlib only so it runs identically in central mode, the per-project kit and CI.
"""
import argparse
import csv
import fnmatch
import glob
import datetime as dt
import hashlib
import html as htmlmod
import json
import os
import re
import sys
from urllib.parse import urlparse

SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SONAR_SEV = {"BLOCKER": "CRITICAL", "CRITICAL": "HIGH", "MAJOR": "MEDIUM", "MINOR": "LOW", "INFO": "INFO"}
# Which raw report belongs to which logical tool/category
AGENT_INVENTORY = {}   # filled from agent-scan.json; shown in the reports
REDTEAM_SUMMARY = {}
AUDITED_LOCKS = set()  # lockfiles audited by npm-audit (Trivy's duplicate findings for them are dropped)
SBOM_INFO = {}  # components found by the SBOM step
DEGRADED = []  # manifests audited in pinned-only mode (dependency resolution failed)
TOOL_CATEGORY = {"gitleaks-history": "Secrets (git history)", "sbom": "SBOM", "workflow-scan": "CI/CD security", "api-fuzz": "API fuzzing", "exposure": "Exposure / TLS", "repo-posture": "Repo posture", "k8s-posture": "Kubernetes posture", "agent-scan": "Agentic governance", "redteam": "AI red team", "modelscan": "Model files (P6)", "semgrep": "SAST", "eslint": "SAST", "npm-audit": "SCA", "bandit": "SAST", "sonarqube": "SAST", "pip-audit": "SCA", "dependency-check": "SCA",
                 "zap": "DAST", "trivy-fs": "SCA/Container/IaC", "trivy-image": "Container", "gitleaks": "Secrets"}


def load(path):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except json.JSONDecodeError:
        return "INVALID"


def rel(path, root):
    path = path or ""
    for prefix in (root.rstrip("/") + "/", "/src/"):
        if prefix and path.startswith(prefix):
            return path[len(prefix):]
    return path[2:] if path.startswith("./") else path


def fp(*parts):
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:16]


def norm_sev(s, policy):
    s = (s or "").upper()
    s = {"MODERATE": "MEDIUM", "ERROR": "HIGH", "WARNING": "MEDIUM"}.get(s, s)
    if s in SEV:
        return s
    return policy["unknown_severity_as"]


def src_hash(root, path, start, end=None):
    """Hash of the flagged source lines, so a finding keeps its identity when code above it moves (some tools hide the code)."""
    try:
        base = os.path.realpath(root)
        full = os.path.realpath(os.path.join(base, path))
        if not full.startswith(base + os.sep):
            return None
        lines = open(full, errors="ignore").read().splitlines()
        seg = " ".join(x.strip() for x in lines[max(start - 1, 0):(end or start)])
        return hashlib.sha256(seg.encode()).hexdigest()[:10]
    except (OSError, TypeError):
        return None


def f_semgrep(d, policy, root):
    out = []
    smap = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
    for r in d.get("results", []):
        path = rel(r["path"], root)
        line, end = r["start"]["line"], r["end"]["line"]
        extra = r.get("extra", {})
        cid = r["check_id"]
        is_secret = "secret" in cid.lower() or "detected-" in cid.lower()
        sev = smap.get(extra.get("severity"), policy["unknown_severity_as"])
        cap = policy.get("semgrep_severity_cap", {}).get(cid)
        if cap and SEV.index(cap) > SEV.index(sev):
            sev = cap
        f = dict(tool="semgrep", category="Secrets" if is_secret else "SAST", severity=sev,
                 rule=".".join(cid.split(".")[-2:]), title=(extra.get("message") or "")[:160].replace("\n", " "),
                 location=f"{path}:{line}", path=path,
                 fingerprint=fp("semgrep", cid, path, src_hash(root, path, line, end) or line), fix=None)
        if is_secret:
            f["dkey"] = ("secret", path, line)
        out.append(f)
    return out


ESLINT_HIGH = {"security/detect-eval-with-expression", "security/detect-child-process", "no-eval", "no-implied-eval", "no-new-func",
               "no-unsanitized/method", "no-unsanitized/property", "security/detect-unsafe-regex", "security/detect-buffer-noassert"}


def f_eslint(d, policy, root):
    out = []
    high = set(policy.get("eslint_high_rules", ESLINT_HIGH))
    for fl in d:
        path = rel(fl["filePath"], root)
        for m in fl.get("messages", []):
            if m.get("fatal") or not m.get("ruleId"):  # parse errors are not findings
                continue
            sev = "HIGH" if m["ruleId"] in high else ("MEDIUM" if m.get("severity") == 2 else "LOW")
            out.append(dict(tool="eslint", category="SAST", severity=sev, rule=m["ruleId"], title=m["message"][:160],
                            location=f"{path}:{m['line']}", path=path,
                            fingerprint=fp("eslint", m["ruleId"], path, src_hash(root, path, m["line"], m.get("endLine")) or m["line"]), fix=None))
    return out


def f_npmaudit(d, policy, root, manifest=""):
    out = []
    for name, v in (d.get("vulnerabilities") or {}).items():
        fa = v.get("fixAvailable")
        fix = (f"upgrade {fa['name']} to {fa['version']}" + (" (major)" if fa.get("isSemVerMajor") else "")) if isinstance(fa, dict) else ("npm audit fix" if fa else None)
        for via in v.get("via", []):
            if not isinstance(via, dict):  # a string = vulnerable only through another package, reported under that package
                continue
            url = via.get("url") or ""
            ghsa = url.rsplit("/", 1)[-1] if "ghsa-" in url.lower() else None
            vname = via.get("name") or name
            ids = sorted({x for x in (ghsa, f"npm:{via.get('source')}") if x})
            out.append(dict(tool="npm-audit", category="SCA", severity=norm_sev(via.get("severity"), policy),
                            ids=ids, scope=(manifest, vname.lower()), rule=ghsa or f"npm:{via.get('source')}",
                            title=f"{vname} {v.get('range', '')}: {(via.get('title') or '')[:140]}",
                            location=f"{manifest}: {vname}", path=manifest,
                            fingerprint=fp("npm-audit", ids[0] if ids else "", vname, manifest), fix=fix))
    return out


def f_agentscan(d, policy, root):
    AGENT_INVENTORY.clear()
    AGENT_INVENTORY.update(d.get("inventory", {}))
    out = []
    for f in d.get("findings", []):
        path, line = f["path"], f.get("line") or 1
        x = dict(tool="agent-scan", category="Agentic", severity=norm_sev(f["severity"], policy), rule=f["rule"], title=f["title"][:200],
                 location=f"{path}:{line}", path=path, fix=f.get("fix"), domain=f.get("domain"), owasp=f.get("owasp"),
                 fingerprint=fp("agent-scan", f["rule"], path, f["title"]))
        if f.get("dkey"):
            x["dkey"] = tuple(f["dkey"])
        out.append(x)
    return out


def f_redteam(d, policy, root):
    REDTEAM_SUMMARY.clear()
    REDTEAM_SUMMARY.update(d.get("summary", {}))
    out = []
    for r in d.get("results", []):
        if r.get("skipped") or r.get("passed"):
            continue
        loc = r.get("location") or "agent"
        out.append(dict(tool="redteam", category="AI red team", severity=norm_sev(r["severity"], policy), rule=r["id"],
                        title=f"{r['title']}: {r.get('evidence', '')}"[:220], location=loc, path=loc,
                        fingerprint=fp("redteam", r["id"], loc, r["title"]), fix=r.get("fix"), domain=r.get("domain"), owasp=r.get("owasp")))
    return out


def f_modelscan(d, policy, root):
    out = []
    for i in d.get("issues", []):
        path = rel(i.get("source", ""), root)
        out.append(dict(tool="modelscan", category="Model files", severity=norm_sev(i.get("severity"), policy), rule=f"modelscan:{i.get('operator', '')}",
                        title=f"{path}: {i.get('description', '')}"[:200], location=path, path=path,
                        fingerprint=fp("modelscan", i.get("operator"), i.get("module"), path),
                        fix="Do not load this file. Use safetensors / weights_only loading and obtain models only from verified, hash-pinned sources."))
    return out


def f_bandit(d, policy, root):
    out = []
    for r in d.get("results", []):
        path = rel(r["filename"], root)
        if r["test_id"] in ("B105", "B106", "B107"):  # message quotes the literal secret value - never copy it into reports
            r = dict(r, issue_text="Possible hardcoded password (value redacted)")
        code_hash = hashlib.sha256((r.get("code") or "").strip().encode()).hexdigest()[:10]
        out.append(dict(tool="bandit", category="SAST", severity=norm_sev(r["issue_severity"], policy),
                        rule=r["test_id"], title=r["issue_text"], location=f"{path}:{r['line_number']}",
                        path=path, fingerprint=fp("bandit", r["test_id"], path, code_hash),
                        fix=None, confidence=r.get("issue_confidence")))
    return out


def f_pipaudit(d, policy, root, manifest=""):
    out = []
    for dep in d.get("dependencies", []):
        for v in dep.get("vulns", []):
            out.append(dict(tool="pip-audit", category="SCA", severity=norm_sev(None, policy), severity_assumed=True,  # pip-audit has no severity
                            ids=sorted({v["id"], *v.get("aliases", [])}), scope=(manifest, dep["name"].lower().replace("_", "-")), rule=v["id"], title=f"{dep['name']} {dep.get('version')}: {(v.get('description') or '')[:140]}",
                            location=f"{manifest or 'deps'}: {dep['name']} {dep.get('version')}", path=manifest or dep["name"],
                            fingerprint=fp("pip-audit", v["id"], dep["name"], manifest),
                            fix=", ".join(v.get("fix_versions") or []) or None))
    return out


def license_sev(name, policy):
    """Central licence policy: deny -> HIGH, review -> MEDIUM, unknown -> LOW, permissive -> not reported (None)."""
    lp = policy.get("license_policy") or {}
    n = (name or "").strip()
    if not n or n.upper() in ("UNKNOWN", "NOASSERTION"):
        return lp.get("unknown_severity", "LOW")
    for sev, key in (("HIGH", "deny"), ("MEDIUM", "review")):
        if any(fnmatch.fnmatch(n.lower(), pat.lower()) for pat in lp.get(key, [])):
            return sev
    return None


def f_trivy(d, policy, root, tool):
    out = []
    for res in d.get("Results", []) or []:
        target = rel(res.get("Target", ""), root)
        for v in res.get("Vulnerabilities") or []:
            out.append(dict(tool=tool, category="SCA", severity=norm_sev(v.get("Severity"), policy),
                            ids=[v["VulnerabilityID"]], scope=(target, v["PkgName"].lower().replace("_", "-")),
                            rule=v["VulnerabilityID"], title=f"{v['PkgName']} {v.get('InstalledVersion')}: {v.get('Title', '')}",
                            location=f"{target}: {v['PkgName']} {v.get('InstalledVersion')}", path=target,
                            fingerprint=fp(tool, v["VulnerabilityID"], v["PkgName"], target),
                            fix=v.get("FixedVersion")))
        for s in res.get("Secrets") or []:
            out.append(dict(tool=tool, category="Secrets", severity=norm_sev(s.get("Severity"), policy),
                            dkey=("secret", target, s.get("StartLine")), rule=s["RuleID"], title=s.get("Title", "secret"), location=f"{target}:{s.get('StartLine')}",
                            path=target, fingerprint=fp(tool, s["RuleID"], target, s.get("StartLine")), fix=None))
        for lic in res.get("Licenses") or []:
            sev = license_sev(lic.get("Name"), policy)
            if sev is None:
                continue
            pkg = lic.get("PkgName") or lic.get("FilePath") or ""
            out.append(dict(tool=tool, category="License", severity=sev, rule=f"license:{lic.get('Name') or 'unknown'}",
                            title=f"{pkg}: licence {lic.get('Name') or 'unknown'} needs {'removal' if sev == 'HIGH' else 'a legal review' if sev == 'MEDIUM' else 'identification'}",
                            location=f"{target}: {pkg}", path=target, fingerprint=fp(tool, "license", lic.get("Name"), pkg, target),
                            fix="Replace the dependency, or get the licence approved by legal"))
        for m in res.get("Misconfigurations") or []:
            if m.get("Status") != "FAIL":
                continue
            out.append(dict(tool=tool, category="IaC/Config", severity=norm_sev(m.get("Severity"), policy),
                            rule=m["ID"], title=m.get("Title", ""), location=target, path=target,
                            fingerprint=fp(tool, m["ID"], target), fix=m.get("Resolution")))
    return out


def f_gitleaks(d, policy, root):
    out = []
    for r in d or []:
        path = rel(r.get("File"), root)
        out.append(dict(tool="gitleaks", category="Secrets", severity=norm_sev(policy["secret_severity"], policy),
                        dkey=("secret", path, r.get("StartLine")), rule=r["RuleID"], title=r.get("Description", "secret"), location=f"{path}:{r.get('StartLine')}",
                        path=path, fingerprint=fp("gitleaks", r["RuleID"], path, r.get("Secret", "")[:4], r.get("StartLine")),
                        fix=None))
    return out


def f_cis(d, tool, policy):
    """Trivy compliance summary (CIS Docker benchmark): one advisory finding per failed control, capped at MEDIUM (Trivy's own DS-* checks stay authoritative)."""
    out = []
    for c in d.get("SummaryControls") or []:
        if not c.get("TotalFail"):
            continue
        sev = "MEDIUM" if str(c.get("Severity", "")).upper() in ("CRITICAL", "HIGH", "MEDIUM") else "LOW"
        out.append(dict(tool=tool, category="Container", severity=sev, rule=f"CIS-DOCKER-{c.get('ID')}", title=f"CIS Docker benchmark {c.get('ID')}: {c.get('Name')}",
                        location=f"image (control {c.get('ID')})", path="image", fingerprint=fp(tool, "cis", c.get("ID")), fix="See the CIS Docker Benchmark remediation for this control"))
    return out


def f_gitleaks_history(d, policy, root):
    """Secrets found in past commits, grouped per (rule, file): one finding says how many commits, since when."""
    groups = {}
    for r in d or []:
        groups.setdefault((r["RuleID"], rel(r.get("File"), root)), []).append(r)
    out = []
    for (rule, path), rs in groups.items():
        rs.sort(key=lambda r: r.get("Date") or "")
        first = rs[0]
        when = (first.get("Date") or "")[:10]
        out.append(dict(tool="gitleaks-history", category="Secrets", severity=norm_sev(policy["secret_severity"], policy), rule=rule,
                        title=f"{first.get('Description', 'secret')} in git history: {len(rs)} commit(s), first {(first.get('Commit') or '')[:8]} on {when}. Rotate it: deleting the file does not remove it from history",
                        location=f"{path} (history)", path=path, age_hint=when,
                        fingerprint=fp("gitleaks-history", rule, path), fix="Revoke/rotate the credential; then remove it from history only if policy requires it"))
    return out


ZIZMOR_SEV = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW", "INFORMATIONAL": "INFO", "UNKNOWN": "MEDIUM"}


def f_zizmor(d, policy, root):
    out = []
    for x in d:
        det = x.get("determinations") or {}
        sev = ZIZMOR_SEV.get(str(det.get("severity", "")).upper(), policy["unknown_severity_as"])
        for loc in (x.get("locations") or [{}])[:1]:
            key = ((loc.get("symbolic") or {}).get("key") or {}).get("Local") or {}
            path = rel(key.get("verbatim_path") or key.get("given_path") or key.get("prefix") or "", root)
            row = (((loc.get("concrete") or {}).get("location") or {}).get("start_point") or {}).get("row")
            line = (row + 1) if isinstance(row, int) else ""
            out.append(dict(tool="workflow-scan", category="CI/CD", severity=sev, rule=x.get("ident", "zizmor"),
                            title=(x.get("desc") or "")[:200], location=f"{path}:{line}" if line else path, path=path,
                            fingerprint=fp("workflow-scan", x.get("ident"), path, line), fix=x.get("url")))
    return out


KUBESCAPE_SEV = {"CRITICAL": "HIGH", "HIGH": "MEDIUM", "MEDIUM": "LOW", "LOW": "LOW"}  # advisory: one level below Trivy's authoritative checks


def f_kubescape(d, policy, root):
    src = {}
    for r in d.get("resources", []):
        s = r.get("source") or {}
        src[r["resourceID"]] = rel(os.path.join(s.get("path", ""), s.get("relativePath", "")), root)
    ctl = d.get("summaryDetails", {}).get("controls", {})
    out = []
    for res in d.get("results", []):
        rid = res["resourceID"]
        name = rid.rsplit("/", 2)[-2:] if "/" in rid else [rid]
        for c in res.get("controls", []):
            if (c.get("status") or {}).get("status") != "failed":
                continue
            path = src.get(rid, "")
            sev = KUBESCAPE_SEV.get(str(c.get("severity", "")).upper(), "LOW")
            out.append(dict(tool="k8s-posture", category="Kubernetes", severity=sev, rule=c["controlID"],
                            title=f"{c.get('name', '')} ({'/'.join(name)})", location=f"{path}: {'/'.join(name)}", path=path,
                            fingerprint=fp("k8s-posture", c["controlID"], rid), fix=(ctl.get(c["controlID"], {}) or {}).get("remediation") or "see https://hub.armosec.io/docs/" + c["controlID"].lower()))
    return out


def f_simple(d, tool, category, policy):
    """Tools of ours that write {"findings": [{severity, rule, title, location, fix}]} (exposure, repo-posture, ...)."""
    out = []
    for x in d.get("findings", []):
        out.append(dict(tool=tool, category=category, severity=norm_sev(x.get("severity"), policy), rule=x.get("rule", tool), title=str(x.get("title", ""))[:300],
                        location=str(x.get("location", "")), path=str(x.get("path") or x.get("location", "")).split(" ")[0],
                        fingerprint=fp(tool, x.get("rule"), x.get("location")), fix=x.get("fix")))
    return out


def f_sbom(d):
    comps = d.get("components") or []
    SBOM_INFO.clear()
    SBOM_INFO.update(components=len(comps), by_type={t: sum(1 for c in comps if c.get("type") == t) for t in sorted({c.get("type") for c in comps if c.get("type")})},
                     with_license=sum(1 for c in comps if c.get("licenses")), format=d.get("bomFormat", "CycloneDX"), spec=d.get("specVersion", ""))
    return []


def f_depcheck(d, policy, root):
    out = []
    for dep in d.get("dependencies", []):
        for v in dep.get("vulnerabilities", []) or []:
            out.append(dict(tool="dependency-check", category="SCA", severity=norm_sev(v.get("severity"), policy),
                            rule=v["name"], title=f"{dep.get('fileName')}: {(v.get('description') or '')[:140]}",
                            location=dep.get("fileName", ""), path=dep.get("fileName", ""),
                            fingerprint=fp("dependency-check", v["name"], dep.get("fileName")), fix=None))
    return out


ZAP_RISK = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}  # ZAP has no Critical level


def f_zap(d, policy, root):
    out = []
    for site in d.get("site", []):
        for a in site.get("alerts", []):
            sev = ZAP_RISK.get(str(a.get("riskcode")), policy["unknown_severity_as"])
            uris = sorted({(i.get("method", "GET"), i.get("uri", "").split("?")[0]) for i in a.get("instances", [])}) or [("", site.get("@name", ""))]
            for method, uri in uris:
                path = urlparse(uri).path or "/"
                out.append(dict(tool="zap", category="DAST", severity=sev, rule=f"ZAP-{a.get('pluginid')}",
                                title=f"{a.get('name') or a.get('alert')} ({a.get('confidence', '')} confidence)",
                                location=f"{method} {path}", path=path,
                                fingerprint=fp("zap", a.get("pluginid"), method, path), fix=(a.get("solution") or "")[:140] or None))
    return out


def f_sonar(d, policy, root):
    out = []
    for i in d.get("issues", []):
        path = i.get("component", "").split(":", 1)[-1]
        sev = SONAR_SEV.get(i.get("severity"), policy["unknown_severity_as"])
        dk = ("secret", path, i.get("line")) if i["rule"].startswith("secrets:") else None
        out.append(dict(tool="sonarqube", category="SAST", severity=sev, dkey=dk, rule=i["rule"], title=i["message"],
                        location=f"{path}:{i.get('line', '')}", path=path,
                        fingerprint=fp("sonarqube", i["rule"], path, i.get("hash", i.get("line"))), fix=None,
                        sonar_type=i.get("type")))
    return out


def collect(raw_dir, tools, policy, root):
    """Return (findings, tool_status). tool_status: ok / missing / invalid per expected tool."""
    parsers = {
        "bandit": lambda d: f_bandit(d, policy, root),
        "trivy-fs": lambda d: f_trivy(d, policy, root, "trivy-fs"),
        "trivy-image": lambda d: f_trivy(d, policy, root, "trivy-image"),
        "gitleaks": lambda d: f_gitleaks(d, policy, root),
        "dependency-check": lambda d: f_depcheck(d, policy, root),
        "sonarqube": lambda d: f_sonar(d, policy, root),
        "semgrep": lambda d: f_semgrep(d, policy, root) if isinstance(d, dict) and "results" in d else None,
        "eslint": lambda d: f_eslint(d, policy, root) if isinstance(d, list) else None,
        "agent-scan": lambda d: f_agentscan(d, policy, root) if isinstance(d, dict) and "findings" in d else None,
        "redteam": lambda d: f_redteam(d, policy, root) if isinstance(d, dict) and "results" in d else None,
        "modelscan": lambda d: f_modelscan(d, policy, root) if isinstance(d, dict) and "issues" in d else None,
        "gitleaks-history": lambda d: f_gitleaks_history(d, policy, root) if isinstance(d, list) else None,
        "sbom": lambda d: f_sbom(d) if isinstance(d, dict) and "components" in d else None,
        "exposure": lambda d: f_simple(d, "exposure", "Exposure", policy) if isinstance(d, dict) and "findings" in d else None,
        "repo-posture": lambda d: f_simple(d, "repo-posture", "Repo posture", policy) if isinstance(d, dict) and "findings" in d else None,
        "workflow-scan": lambda d: f_zizmor(d, policy, root) if isinstance(d, list) else None,
        "api-fuzz": lambda d: f_simple(d, "api-fuzz", "API fuzzing", policy) if isinstance(d, dict) and "findings" in d else None,
        "k8s-posture": lambda d: f_kubescape(d, policy, root) if isinstance(d, dict) and "results" in d and "summaryDetails" in d else None,
    }
    findings, status = [], {}
    DEGRADED.clear()
    AUDITED_LOCKS.clear()
    SBOM_INFO.clear()
    for t in tools:
        if t == "pip-audit":  # one report per manifest, see raw/pip-audit.manifests
            files = sorted(glob.glob(os.path.join(raw_dir, "pip-audit-*.json"))) or sorted(glob.glob(os.path.join(raw_dir, "pip-audit.json")))
            mp = load(os.path.join(raw_dir, "pip-audit.manifests")) if os.path.exists(os.path.join(raw_dir, "pip-audit.manifests")) else {}
            mp = mp if isinstance(mp, dict) else {}
            status[t] = "ok" if files else "missing"
            for fpath in files:
                d = load(fpath)
                if not isinstance(d, dict) or "dependencies" not in d:  # (an empty audit of a non-empty manifest is prevented in scan.sh)
                    status[t] = "invalid"
                    continue
                mf = mp.get(os.path.basename(fpath), "")
                if mf.endswith("|degraded"):
                    mf = mf[: -len("|degraded")]
                    DEGRADED.append(f"{mf} (pip could not resolve the pins: only pinned versions audited, no transitive dependencies)")
                findings += f_pipaudit(d, policy, root, mf)
            continue
        if t == "npm-audit":  # one report per lockfile, see raw/npm-audit.manifests
            files = sorted(glob.glob(os.path.join(raw_dir, "npm-audit-*.json")))
            mpf = os.path.join(raw_dir, "npm-audit.manifests")
            mp = load(mpf) if os.path.exists(mpf) else {}
            mp = mp if isinstance(mp, dict) else {}
            status[t] = "ok" if files else "missing"
            for fpath in files:
                d = load(fpath)
                if not isinstance(d, dict) or "vulnerabilities" not in d:
                    status[t] = "invalid"
                    continue
                mf = mp.get(os.path.basename(fpath), "")
                if mf.endswith("|nolock"):
                    mf = mf[: -len("|nolock")]
                    DEGRADED.append(f"{mf} (no lockfile committed: audited versions were freshly resolved, not what you deploy; commit package-lock.json)")
                else:
                    AUDITED_LOCKS.add(mf)
                findings += f_npmaudit(d, policy, root, mf)
            continue
        if t == "zap":  # zap.json (baseline/api) or zap-<n>.json (one per seed in full mode)
            files = sorted(glob.glob(os.path.join(raw_dir, "zap*.json")))
            status[t] = "ok" if files else "missing"
            for fpath in files:
                d = load(fpath)
                if not isinstance(d, dict) or "site" not in d:
                    status[t] = "invalid"
                    continue
                findings += f_zap(d, policy, root)
            continue
        if t not in parsers:
            status[t] = "unknown-tool"
            continue
        d = load(os.path.join(raw_dir, f"{t}.json"))
        if d is None:
            status[t] = "missing"
        elif d == "INVALID" or (t == "sonarqube" and not isinstance(d, dict) or (t == "sonarqube" and "issues" not in d)):
            status[t] = "invalid"
        else:
            res = parsers[t](d)
            if res is None:
                status[t] = "invalid"
            else:
                status[t] = "ok"
                findings += res
    if "trivy-image" in tools:
        cis = load(os.path.join(raw_dir, "trivy-image-cis.json"))
        if isinstance(cis, dict) and "SummaryControls" in cis:
            findings += f_cis(cis, "trivy-image", policy)
    if "gitleaks-history" in tools:
        note = os.path.join(raw_dir, "gitleaks-history.note")
        if os.path.exists(note):
            DEGRADED.append(open(note).read().strip())
        # a secret that is still in the working tree is already reported by gitleaks: keep only history-only (deleted) ones
        live = {(f["rule"], f["path"]) for f in findings if f["tool"] == "gitleaks"}
        findings = [f for f in findings if not (f["tool"] == "gitleaks-history" and (f["rule"], f["path"]) in live)]
    if AUDITED_LOCKS:
        findings = [f for f in findings if not (f["tool"] == "trivy-fs" and f["category"] == "SCA" and f["path"] in AUDITED_LOCKS)]
    return findings, status


def dedupe(findings):
    """Merge the same issue reported by several tools (same package+CVE, same secret location).
    Highest severity wins, except a tool-assumed severity (pip-audit) never overrides a real one."""
    # SCA: the same vulnerability is known under several ids (CVE-, GHSA-, PYSEC-) and tools list them in arbitrary order.
    # Cluster findings of the same (manifest, package) that share ANY id; the cluster key is its smallest id (deterministic).
    clusters = {}
    for f in findings:
        if "ids" not in f:
            continue
        groups = clusters.setdefault(f["scope"], [])
        hit = [g for g in groups if g["ids"] & set(f["ids"])]
        new = {"ids": set(f["ids"])}
        for g in hit:
            new["ids"] |= g["ids"]
            groups.remove(g)
        groups.append(new)
    for f in findings:
        if "ids" in f:
            cl = next(g for g in clusters[f["scope"]] if g["ids"] & set(f["ids"]))
            f["all_ids"] = sorted(cl["ids"])
            f["dkey"] = ("sca", *f["scope"], min(cl["ids"], key=lambda i: (not i.startswith("CVE-"), i)))
    merged, order = {}, []
    for f in findings:
        k = f.pop("dkey", None) or ("raw", f["fingerprint"])
        if k not in merged:
            merged[k] = dict(f, tools=[f["tool"]])
            order.append(k)
            continue
        m = merged[k]
        if f["tool"] not in m["tools"]:
            m["tools"].append(f["tool"])
        if m.get("severity_assumed") and not f.get("severity_assumed"):
            m["severity"], m["severity_assumed"] = f["severity"], False
        elif not f.get("severity_assumed") and SEV.index(f["severity"]) < SEV.index(m["severity"]):
            m["severity"] = f["severity"]
        m["fix"] = m.get("fix") or f.get("fix")
        m["all_ids"] = sorted(set(m.get("all_ids", [])) | set(f.get("all_ids", [])))
        if f["tool"] == "trivy-fs" or f["tool"] == "trivy-image":  # trivy has richer titles/CVE ids
            m["rule"], m["title"] = f["rule"], f["title"]
    out = []
    for k in order:
        m = merged[k]
        if k[0] != "raw":
            m["fingerprint"] = fp(*k)  # stable across tools -> baseline survives a tool being added/removed
        m["tool"] = "+".join(m["tools"])
        # every identity this finding is known by, so a baseline/exception made with one alias still matches
        m["fps"] = [m["fingerprint"]] + ([fp("sca", *k[1:3], i) for i in m["all_ids"]] if k[0] == "sca" else [])
        for tmp in ("ids", "scope"):
            m.pop(tmp, None)
        out.append(m)
    return out


def apply_exceptions(findings, path):
    """Exceptions: list of {fingerprint|rule+path, reason, approved_by, expires(YYYY-MM-DD)}. Expired ones are ignored."""
    if not path or not os.path.exists(path):
        return findings, []
    today = dt.date.today().isoformat()
    ex = json.load(open(path))
    active, expired = [], []
    for e in ex:
        if "tool" in e:  # tool waiver (see toolplan.py), not a finding exception
            continue
        if not e.get("reason") or not e.get("approved_by") or not e.get("expires"):
            raise SystemExit(f"exception entry missing reason/approved_by/expires: {e}")
        (active if e["expires"] >= today else expired).append(e)
    kept = []
    for f in findings:
        hit = next((e for e in active if e.get("fingerprint") in f["fps"]
                    or (e.get("rule") == f["rule"] and e.get("path") in (None, f["path"]))), None)
        if hit:
            f["excepted"] = hit["reason"]
        kept.append(f)
    return kept, expired


def apply_exclusions(findings, patterns):
    """SEC_EXCLUDE_PATHS: drop code/secret findings under these globs. Dependency CVEs are never excluded (that would hide real risk)."""
    if not patterns:
        return findings, 0
    def hit(path):
        path = path or ""
        return any(fnmatch.fnmatch(path, p) or path.startswith(p.rstrip("/") + "/") for p in patterns)
    kept = [f for f in findings if not (hit(f.get("path")) and not (f.get("category") or "").startswith("SCA") and not f.get("all_ids"))]
    return kept, len(findings) - len(kept)


def load_baseline(path):
    """{fingerprint: 'YYYY-MM-DD' | None}. The old format (a plain list) has no dates, so its findings never age."""
    if not path or not os.path.exists(path):
        return None
    raw = json.load(open(path))
    return {k: v for k, v in raw.items()} if isinstance(raw, dict) else {k: None for k in raw}


def evaluate(findings, gate, baseline, sla_days=None):
    """Blocking findings. New findings block per gate.block_new; baselined ones per block_existing, or - once older than the SLA for
    their severity - per block_overdue (the baseline stops being a free pass: that is how the SLA is enforced)."""
    blocking = []
    today = dt.date.today()
    sla_days = sla_days or {}
    if baseline is not None and not isinstance(baseline, dict):
        baseline = {k: None for k in baseline}
    for f in findings:
        if f.get("excepted"):
            continue
        is_new = baseline is None or not any(x in baseline for x in f["fps"])
        f["new"] = is_new
        sevs = gate["block_new"] if is_new else gate["block_existing"]
        if not is_new:
            dates = [baseline[x] for x in f["fps"] if baseline.get(x)]
            if dates:
                f["age_days"] = (today - dt.date.fromisoformat(min(dates))).days
                limit = sla_days.get(f["severity"])
                if limit is not None and f["age_days"] > limit:
                    f["overdue"] = True
                    if f["severity"] in gate.get("block_overdue", []):
                        sevs = list(sevs) + [f["severity"]]
        if f["severity"] in sevs:
            blocking.append(f)
    return blocking


def assign_controls(findings, cw):
    """Crosswalk: tag every finding with the architectural controls it evidences (configs/compliance/crosswalk.json)."""
    rules = [(fld, re.compile(rx), ctrls) for fld, rx, ctrls in (cw or {}).get("rules", [])]
    for f in findings:
        hit = set()
        for fld, rx, ctrls in rules:
            if rx.search(str(f.get(fld, ""))):
                hit.update(ctrls)
        f["controls"] = sorted(hit)
    return findings


def crosswalk_summary(findings, cw):
    out = {}
    for f in findings:
        if f.get("excepted"):
            continue
        for c in f.get("controls", []):
            d = out.setdefault(c, {s: 0 for s in SEV})
            d[f["severity"]] += 1
    ctrl = (cw or {}).get("controls", {})
    return [dict(control=c, name=ctrl.get(c, {}).get("name", c), standards={k: v for k, v in ctrl.get(c, {}).items() if k not in ("name", "pillar")}, counts=n, total=sum(n.values()))
            for c, n in sorted(out.items())]


def counts(findings):
    c = {s: 0 for s in SEV}
    for f in findings:
        if not f.get("excepted"):
            c[f["severity"]] += 1
    return c


def write_md(path, summary, findings, blocking):
    L = [f"# Security scan summary — {summary['target']}", "",
         f"- Date: {summary['date']}", f"- Gate: **{summary['gate']}** ({summary['mode']})",
         f"- Result: **{summary['result']}**", ""]
    L += ["## Tool coverage", "", "| Tool | Category | Status |", "|---|---|---|"]
    for t, s in summary["tool_status"].items():
        L.append(f"| {t} | {TOOL_CATEGORY.get(t, '')} | {s} |")
    L += ["", "## Findings by severity", "", "| Severity | Open | New (vs baseline) |", "|---|---|---|"]
    for s in SEV:
        L.append(f"| {s} | {summary['counts'][s]} | {summary['new_counts'][s]} |")
    L += ["", "## Findings by tool", "", "| Tool | Count |", "|---|---|"]
    for t, n in summary["by_tool"].items():
        L.append(f"| {t} | {n} |")
    if blocking:
        L += ["", "## Blocking findings", "", "| Sev | Tool | Rule | Location | Title |", "|---|---|---|---|---|"]
        for f in sorted(blocking, key=lambda x: SEV.index(x["severity"])):
            L.append(f"| {f['severity']} | {f['tool']} | {f['rule']} | `{f['location']}` | {f['title'][:100]} |")
    inv = summary.get("agent_inventory") or {}
    if inv:
        L += ["", "## Agent inventory", "",
              f"- Frameworks: {', '.join(inv.get('frameworks', [])) or 'none detected'}",
              f"- Models: {', '.join(sorted({m['id'] + ('' if m['approved'] else ' (NOT registered)') for m in inv.get('models', [])})) or 'none found'}",
              f"- LLM endpoints: {', '.join(sorted({e['host'] + ('' if e['approved'] else ' (NOT approved)') for e in inv.get('endpoints', [])})) or 'none found'}",
              f"- Tools: {', '.join(t['name'] + ('[' + ','.join(t['capabilities']) + ']' if t['capabilities'] else '') for t in inv.get('tools', [])) or 'none found (only decorator-registered tools are detected)'}",
              f"- MCP servers: {', '.join(m['name'] for m in inv.get('mcp_servers', [])) or 'none'}"]
    rt = summary.get("redteam") or {}
    if rt:
        L += ["", "## AI red team", "", f"Target {rt.get('target', '')}: {rt.get('failed', 0)} failed, {rt.get('passed', 0)} passed, {len(rt.get('skipped', []))} skipped"
              + ("".join(f"\n- skipped {s['id']}: {s['why']}" for s in rt.get("skipped", [])))]
    if summary.get("degraded_manifests"):
        L += ["", "## Reduced coverage", "", "These dependency manifests were only partly audited:", ""] + [f"- `{m}`" for m in summary["degraded_manifests"]]
    if summary.get("tools_not_run") or summary.get("tool_waivers") or summary.get("tools_forced") or summary.get("excluded_by_path"):
        L += ["", "## Configuration that affects coverage", ""]
        L += [f"- not run: **{t}** ({r})" for t, r in summary.get("tools_not_run", {}).items()]
        L += [f"- waiver in use: **{w['tool']}** until {w['expires']}, approved by {w['approved_by']}: {w['reason']}" for w in summary.get("tool_waivers", [])]
        L += [f"- {t} is required by policy, so it ran although it was set to off" for t in summary.get("tools_forced", [])]
        if summary.get("excluded_by_path"):
            L += [f"- {summary['excluded_by_path']} code finding(s) left out by SEC_EXCLUDE_PATHS ({', '.join(summary.get('exclude_paths', []))})"]
    if summary.get("sonar_quality_gate_failures"):
        L += ["", "## SonarQube quality gate", ""] + [f"- {q}" for q in summary["sonar_quality_gate_failures"]]
    if summary.get("overdue"):
        L += ["", "## Past their remediation deadline", "", f"{summary['overdue']} baselined finding(s) are older than the SLA for their severity ("
              + ", ".join(f"{k}: {v}" for k, v in summary["overdue_by_severity"].items()) + "). Baselined Critical/High findings block again once overdue; fix them or record a time-boxed exception."]
    if summary.get("sbom"):
        sb = summary["sbom"]
        L += ["", "## Software bill of materials", "", f"{sb.get('components', 0)} components ({sb.get('format')} {sb.get('spec')}), {sb.get('with_license', 0)} with licence data. File: `sbom.cdx.json` (CycloneDX)."]
    if summary.get("crosswalk"):
        L += ["", "## Compliance view (which control each finding evidences)", "", "| Control | Findings | Critical | High | NIST AI RMF | OWASP LLM | EU AI Act |", "|---|---|---|---|---|---|---|"]
        for x in summary["crosswalk"]:
            st = x["standards"]
            L.append(f"| {x['control']} {x['name']} | {x['total']} | {x['counts']['CRITICAL']} | {x['counts']['HIGH']} | {st.get('NIST AI RMF', '')} | {st.get('OWASP LLM Top 10', '')} | {st.get('EU AI Act', '')} |")
        L.append("\nFull per-finding mapping: `crosswalk.csv`. Heuristic mapping, not a compliance verdict.")
    if summary["expired_exceptions"]:
        L += ["", "## Expired exceptions (no longer applied)", ""] + [f"- {e.get('rule') or e.get('fingerprint')}: {e['reason']} (expired {e['expires']})" for e in summary["expired_exceptions"]]
    open(path, "w").write("\n".join(L) + "\n")


def write_sarif(path, findings):
    """SARIF 2.1.0 for GitHub code scanning / Azure DevOps. Source-code findings only (DAST URLs and image layers have no repo file)."""
    skip_tools = {"zap", "trivy-image", "redteam"}
    rules, results = {}, []
    for f in findings:
        if set(f["tools"]) <= skip_tools:
            continue
        rid = f"{f['tool'].split('+')[0]}/{f['rule']}"
        rules.setdefault(rid, {"id": rid, "shortDescription": {"text": f["title"][:100] or rid}})
        loc = f["location"]
        line = None
        if ":" in loc and loc.rsplit(":", 1)[-1].isdigit():
            line = int(loc.rsplit(":", 1)[-1])
        region = {"startLine": line} if line else {"startLine": 1}
        res = {"ruleId": rid, "level": {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning"}.get(f["severity"], "note"),
               "message": {"text": f"[{f['severity']}] {f['title']}" + (f" Fix: {f['fix']}" if f.get("fix") else "")},
               "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["path"]}, "region": region}}],
               "partialFingerprints": {"warden/v1": f["fingerprint"]}}
        if f.get("excepted"):
            res["suppressions"] = [{"kind": "external", "justification": f["excepted"]}]
        results.append(res)
    sarif = {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
             "runs": [{"tool": {"driver": {"name": "warden-kit", "informationUri": "https://example.invalid/warden", "rules": list(rules.values())}},
                       "results": results}]}
    json.dump(sarif, open(path, "w"), indent=1)


def write_html(path, summary, findings, blocking):
    e = htmlmod.escape
    blocking_ids = {id(f) for f in blocking}
    rows = []
    for f in sorted(findings, key=lambda x: (SEV.index(x["severity"]), x["tool"], x["location"])):
        cls = "blk" if id(f) in blocking_ids else ("exc" if f.get("excepted") else "")
        rows.append(f'<tr class="{cls}" data-sev="{f["severity"]}" data-tool="{e(f["tool"])}"><td><span class="sev {f["severity"]}">{f["severity"]}</span></td>'
                    f'<td>{e(f["tool"])}</td><td>{e(f["rule"])}</td><td><code>{e(f["location"])}</code></td><td>{e(f["title"])}'
                    + (f'<div class="fix">Fix: {e(f["fix"])}</div>' if f.get("fix") else "")
                    + (f'<div class="fix">Exception: {e(f["excepted"])}</div>' if f.get("excepted") else "") + "</td></tr>")
    cov = "".join(f'<tr><td>{e(t)}</td><td>{e(TOOL_CATEGORY.get(t, ""))}</td><td class="{"ok" if s == "ok" else "bad"}">{e(s)}</td></tr>' for t, s in summary["tool_status"].items())
    cards = "".join(f'<div class="card {s}"><b>{summary["counts"][s]}</b><span>{s}</span><small>{summary["new_counts"][s]} new</small></div>' for s in SEV)
    cfg_notes = [f"{t} not run: {r}" for t, r in summary.get("tools_not_run", {}).items()] + [f"{t} is required by policy: ran although set to off" for t in summary.get("tools_forced", [])] \
        + ([f"{summary['excluded_by_path']} code finding(s) left out by SEC_EXCLUDE_PATHS"] if summary.get("excluded_by_path") else [])
    notes = "".join(f"<li>{e(m)}</li>" for m in list(summary.get("degraded_manifests", [])) + cfg_notes)
    qg = "".join(f"<li>{e(m)}</li>" for m in summary.get("sonar_quality_gate_failures", []))
    res_cls = "pass" if summary["result"].startswith("PASS") else "fail"
    inv, rt = summary.get("agent_inventory") or {}, summary.get("redteam") or {}
    agent_html = ""
    if inv:
        agent_html += "<h3>Agent inventory</h3><ul>" + "".join(f"<li>{e(k)}: {e(v)}</li>" for k, v in (
            ("Frameworks", ", ".join(inv.get("frameworks", [])) or "none detected"),
            ("Models", ", ".join(sorted({m["id"] + ("" if m["approved"] else " (NOT registered)") for m in inv.get("models", [])})) or "none found"),
            ("LLM endpoints", ", ".join(sorted({x["host"] + ("" if x["approved"] else " (NOT approved)") for x in inv.get("endpoints", [])})) or "none found"),
            ("Tools", ", ".join(x["name"] for x in inv.get("tools", [])) or "none found"),
            ("MCP servers", ", ".join(x["name"] for x in inv.get("mcp_servers", [])) or "none"))) + "</ul>"
    if rt:
        agent_html += f"<h3>AI red team</h3><p>{e(str(rt.get('target', '')))}: <b>{rt.get('failed', 0)}</b> probes failed, {rt.get('passed', 0)} passed, {len(rt.get('skipped', []))} skipped.</p>"
    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security scan - {e(summary['target'])}</title><style>
:root{{--bg:#fff;--fg:#1d2433;--mut:#5b6678;--line:#dfe3ea;--card:#f6f8fb;--crit:#a3122a;--high:#d9480f;--med:#b7791f;--low:#2b6cb0;--info:#6b7280;--ok:#1a7f4b}}
@media (prefers-color-scheme:dark){{:root{{--bg:#12161f;--fg:#e6e9ef;--mut:#9aa4b5;--line:#2b3342;--card:#1a202c;--crit:#ff6b81;--high:#ff9a5c;--med:#f0c15a;--low:#6cb2ff;--info:#9aa4b5;--ok:#4cc38a}}}}
body{{font:14px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg);margin:0;padding:24px;max-width:1200px;margin:auto}}
h1{{font-size:20px;margin:0 0 4px}} .sub{{color:var(--mut);margin-bottom:16px}}
.result{{display:inline-block;padding:4px 12px;border-radius:6px;font-weight:600;color:#fff}} .result.pass{{background:var(--ok)}} .result.fail{{background:var(--crit)}}
.cards{{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}} .card{{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 16px;min-width:90px;display:flex;flex-direction:column}}
.card b{{font-size:24px}} .card small{{color:var(--mut)}} .card.CRITICAL b{{color:var(--crit)}} .card.HIGH b{{color:var(--high)}} .card.MEDIUM b{{color:var(--med)}} .card.LOW b{{color:var(--low)}}
table{{border-collapse:collapse;width:100%;margin:8px 0 24px}} th,td{{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}} th{{color:var(--mut);font-weight:600}}
tr.blk td:first-child{{border-left:4px solid var(--crit)}} tr.exc{{opacity:.6}} .sev{{font-weight:700;font-size:12px}} .sev.CRITICAL{{color:var(--crit)}} .sev.HIGH{{color:var(--high)}} .sev.MEDIUM{{color:var(--med)}} .sev.LOW{{color:var(--low)}} .sev.INFO{{color:var(--info)}}
.ok{{color:var(--ok)}} .bad{{color:var(--crit);font-weight:700}} .fix{{color:var(--mut);font-size:12px}} code{{font-size:12px;word-break:break-all}} select{{padding:4px;margin-right:8px;background:var(--card);color:var(--fg);border:1px solid var(--line)}}
</style></head><body>
<h1>Security scan: {e(summary['target'])}</h1>
<div class="sub">{e(summary['date'])} &middot; gate <b>{e(summary['gate'])}</b> ({e(summary['mode'])}) &middot; baseline {'used' if summary['baseline_used'] else 'not used (all findings count as new)'}</div>
<span class="result {res_cls}">{e(summary['result'])}</span>
<div class="cards">{cards}</div>
{('<h3>Reduced coverage</h3><ul>' + notes + '</ul>') if notes else ''}{('<h3>SonarQube quality gate</h3><ul>' + qg + '</ul>') if qg else ''}
{agent_html}<h3>Tools</h3><table><tr><th>Tool</th><th>Type</th><th>Status</th></tr>{cov}</table>
<h3>Findings ({len(findings)})</h3>
<div>Severity <select id="fs"><option value="">all</option>{''.join(f'<option>{s}</option>' for s in SEV)}</select>
Tool <select id="ft"><option value="">all</option>{''.join(f'<option>{e(t)}</option>' for t in sorted({x for f in findings for x in f['tools']}))}</select>
<label><input type="checkbox" id="fb"> blocking only</label></div>
<table id="t"><tr><th>Severity</th><th>Tool</th><th>Rule</th><th>Where</th><th>What</th></tr>{''.join(rows)}</table>
<p class="sub">Highlighted rows block the gate. Never publish this report: it can contain code paths and metadata about secrets.</p>
<script>
const s=document.getElementById('fs'),t=document.getElementById('ft'),b=document.getElementById('fb');
function f(){{document.querySelectorAll('#t tr[data-sev]').forEach(r=>{{r.style.display=((!s.value||r.dataset.sev===s.value)&&(!t.value||r.dataset.tool.split('+').includes(t.value))&&(!b.checked||r.classList.contains('blk')))?'':'none'}})}}
s.onchange=t.onchange=b.onchange=f;
</script></body></html>"""
    open(path, "w").write(doc)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True, help="report dir containing raw/")
    ap.add_argument("--tools", required=True, help="comma list of tools expected to have run")
    ap.add_argument("--policy", required=True)
    ap.add_argument("--gate", choices=["pr", "release"], default="pr")
    ap.add_argument("--enforce", action="store_true", help="exit 1 when the gate fails (default: report-only)")
    ap.add_argument("--baseline", help="baseline.json (list of fingerprints); findings in it are 'existing'")
    ap.add_argument("--write-baseline", help="write current fingerprints to this file and exit 0")
    ap.add_argument("--exceptions", help="exceptions.json")
    ap.add_argument("--root", default="/src", help="path prefix to strip from reported file paths")
    ap.add_argument("--target", default="repo")
    ap.add_argument("--crosswalk", help="crosswalk.json (control -> standards, finding -> control rules)")
    ap.add_argument("--plan", help="plan.json written by toolplan.py (which tools ran / were skipped and why)")
    ap.add_argument("--exclude", default="", help="comma list of path globs (SEC_EXCLUDE_PATHS)")
    a = ap.parse_args()

    policy = json.load(open(a.policy))
    findings, status = collect(os.path.join(a.out, "raw"), a.tools.split(","), policy, a.root)
    findings = dedupe(findings)
    findings, expired = apply_exceptions(findings, a.exceptions)
    findings, excluded = apply_exclusions(findings, [p for p in a.exclude.split(",") if p])
    plan = load(a.plan) if a.plan else None
    plan = plan if isinstance(plan, dict) else {}

    if a.write_baseline:
        old = load_baseline(a.write_baseline) or load_baseline(a.baseline) or {}
        today = dt.date.today().isoformat()
        fps = {x: old.get(x) or today for f in findings for x in f["fps"]}  # a finding keeps the date it was first recorded
        json.dump(dict(sorted(fps.items())), open(a.write_baseline, "w"), indent=1)
        print(f"baseline written: {len(fps)} fingerprints (dated; findings older than their SLA block again) -> {a.write_baseline}")
        return 0

    qg = load(os.path.join(a.out, "raw", "sonarqube-qualitygate.json"))
    qg_fail = []
    if isinstance(qg, dict) and qg.get("projectStatus", {}).get("status") == "ERROR":
        qg_fail = [f"SonarQube quality gate: {c['metricKey']} {c.get('actualValue')} vs {c.get('comparator')} {c.get('errorThreshold')}"
                   for c in qg["projectStatus"].get("conditions", []) if c.get("status") == "ERROR"] or ["SonarQube quality gate: ERROR"]
    baseline = load_baseline(a.baseline)
    blocking = evaluate(findings, policy["gates"][a.gate], baseline, policy.get("sla_days"))
    cw = load(a.crosswalk) if a.crosswalk else None
    cw = cw if isinstance(cw, dict) else {}
    assign_controls(findings, cw)
    xwalk = crosswalk_summary(findings, cw)
    overdue = [f for f in findings if f.get("overdue") and not f.get("excepted")]
    bad_tools = {t: s for t, s in status.items() if s != "ok"}
    failed = bool(blocking) or bool(qg_fail) or (a.enforce and bool(bad_tools))  # fail closed: a broken scanner must not look like a pass
    result = "FAIL" if failed else "PASS"
    if bad_tools:
        result += " (with tool errors: " + ", ".join(f"{t}={s}" for t, s in bad_tools.items()) + ")"
    new = [f for f in findings if f.get("new") and not f.get("excepted")]
    by_tool = {}
    for f in findings:
        for t in f["tools"]:
            by_tool[t] = by_tool.get(t, 0) + 1
    summary = dict(target=a.target, date=dt.datetime.now().isoformat(timespec="seconds"), gate=a.gate,
                   mode="enforce" if a.enforce else "report-only", result=result, blocking=len(blocking),
                   counts=counts(findings), new_counts=counts(new), by_tool=by_tool, tool_status=status,
                   baseline_used=baseline is not None, exceptions_applied=sum(1 for f in findings if f.get("excepted")),
                   expired_exceptions=expired, sonar_quality_gate_failures=qg_fail, degraded_manifests=list(DEGRADED),
                   agent_inventory=dict(AGENT_INVENTORY), redteam=dict(REDTEAM_SUMMARY), sbom=dict(SBOM_INFO), crosswalk=xwalk,
                   overdue=len(overdue), overdue_by_severity={s: sum(1 for f in overdue if f["severity"] == s) for s in SEV if any(f["severity"] == s for f in overdue)},
                   preset=plan.get("preset"), excluded_by_path=excluded, exclude_paths=[p for p in a.exclude.split(",") if p],
                   tools_not_run={t: v["reason"] for t, v in plan.get("tools", {}).items() if not v["run"] and v["mode"] == "off" and v.get("explicit")},
                   tools_forced=[t for t, v in plan.get("tools", {}).items() if v.get("forced")], tool_waivers=plan.get("waivers", []))
    json.dump(findings, open(os.path.join(a.out, "findings.json"), "w"), indent=1)
    json.dump(summary, open(os.path.join(a.out, "summary.json"), "w"), indent=1)
    with open(os.path.join(a.out, "crosswalk.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["severity", "tool", "rule", "location", "controls", "age_days", "overdue"])
        for f in findings:
            w.writerow([f["severity"], f["tool"], f["rule"], f["location"], " ".join(f.get("controls", [])), f.get("age_days", ""), "yes" if f.get("overdue") else ""])
    write_md(os.path.join(a.out, "summary.md"), summary, findings, blocking)
    write_html(os.path.join(a.out, "summary.html"), summary, findings, blocking)
    write_sarif(os.path.join(a.out, "results.sarif"), findings)

    print(f"\n== Security gate [{a.gate}, {summary['mode']}] for {a.target}: {result}")
    print("   open: " + "  ".join(f"{s}={n}" for s, n in summary["counts"].items()))
    for f in sorted(blocking, key=lambda x: SEV.index(x["severity"]))[:15]:
        print(f"   BLOCK {f['severity']:8} {f['tool']:12} {f['rule']:20} {f['location']}")
    if len(blocking) > 15:
        print(f"   ... and {len(blocking) - 15} more (see {a.out}/summary.md)")
    for q in qg_fail:
        print(f"   BLOCK {q}")
    for m in DEGRADED:
        print(f"   NOTE reduced coverage: {m}")
    if bad_tools:
        print(f"   WARNING tool problems: {bad_tools}")
    return 1 if (failed and a.enforce) else 0


if __name__ == "__main__":
    sys.exit(main())
