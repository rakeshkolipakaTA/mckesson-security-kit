#!/usr/bin/env python3
"""Turn a Schemathesis JUnit report into findings (raw/api-fuzz.json). Standard library only.
  api_fuzz_report.py --junit st.xml --spec http://host/openapi.json --out api-fuzz.json
Exit 1 (and no output file) when the JUnit file is missing or empty, so a fuzzer that did not run is a tool error, never a pass."""
import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET

RULES = [  # (substring in the failure text, severity, rule, short title, fix)
    ("Server error", "MEDIUM", "API-FUZZ-5XX", "server error (HTTP 5xx) on crafted input", "Validate and reject bad input with a 4xx; never let it reach an unhandled exception (possible injection or crash)"),
    ("ignored_auth", "HIGH", "API-FUZZ-AUTH", "operation works without valid authentication although the spec declares it", "Enforce authentication on every operation"),
    ("accepts requests without", "HIGH", "API-FUZZ-AUTH", "operation works without valid authentication although the spec declares it", "Enforce authentication on every operation"),
    ("API accepted", "LOW", "API-FUZZ-NEGATIVE", "invalid data was accepted instead of rejected", "Validate request bodies and parameters against the schema"),
    ("Response violates schema", "LOW", "API-FUZZ-SCHEMA", "response does not match the documented schema", "Fix the response or the documentation"),
    ("Undocumented HTTP status code", "LOW", "API-FUZZ-STATUS", "undocumented HTTP status code returned", "Document the status code or fix the behaviour"),
    ("Missing Content-Type", "LOW", "API-FUZZ-HEADERS", "response has a missing or malformed Content-Type", "Always send a correct Content-Type"),
]
SECRET_HDR = re.compile(r"(-H\s+'?(?:Authorization|Cookie|X-Api-Key|X-Auth[\w-]*)\s*:)[^'\n]*'?", re.I)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--junit", required=True)
    ap.add_argument("--spec", default="")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    try:
        root = ET.parse(a.junit).getroot()
    except (OSError, ET.ParseError) as ex:
        print(f"api-fuzz: no usable JUnit report ({ex})", file=sys.stderr)
        return 1
    cases = list(root.iter("testcase"))
    if not cases:
        print("api-fuzz: the report holds no test cases (spec unreachable or empty?)", file=sys.stderr)
        return 1
    findings = {}
    for tc in cases:
        op = tc.get("name", "")
        for e in list(tc.findall("failure")) + list(tc.findall("error")):
            text = (e.text or "") + " " + (e.get("message") or "")
            repro = re.search(r"Reproduce with:\s*\n*\s*(curl[^\n]*)", text)
            curl = SECRET_HDR.sub(r"\1 <redacted>'", repro.group(1)) if repro else ""
            hit = [r for r in RULES if r[0] in text] or [("", "LOW", "API-FUZZ-OTHER", "check failed on crafted input", "See the Schemathesis output")]
            sev, rule, title, fix = hit[0][1:]
            for h in hit[1:]:
                if ["CRITICAL", "HIGH", "MEDIUM", "LOW"].index(h[1]) < ["CRITICAL", "HIGH", "MEDIUM", "LOW"].index(sev):
                    sev, rule, title, fix = h[1:]
            findings.setdefault((op, rule), dict(severity=sev, rule=rule, title=f"{op}: {title}" + (f". Reproduce: {curl[:200]}" if curl else ""), location=op, path=op.split(" ")[-1], fix=fix))
    json.dump({"spec": a.spec, "operations": len(cases), "findings": list(findings.values())}, open(a.out, "w"), indent=1)
    print(f"api-fuzz: {len(cases)} operation(s) tested, {len(findings)} finding(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
