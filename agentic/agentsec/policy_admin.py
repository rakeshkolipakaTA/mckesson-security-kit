"""P1/P8 Policy administration point (PAP): validate, version, enable/disable and change-log the policies the PDP enforces.

  store = PolicyStore("policy.json", audit=AuditLog("audit.jsonl"))
  pdp = PDP(store)                                   # every decision uses store.effective(): validated and minus disabled tools/agents
  store.put(new_policy, actor="alice", reason="add send_email tool")      # validated, versioned, atomic, audited
  store.disable("support-bot", tool="send_email", actor="oncall", reason="incident 123")   # kill switch for one tool (or a whole agent)
CLI:  python -m agentsec.policy_admin validate FILE | show FILE | disable FILE AGENT [TOOL] --actor A --reason R | enable ...

Fail-closed: a missing, corrupt or invalid policy file makes effective() raise, and the PDP turns that into deny. Disabling is always safe.
Limits: a JSON file with a hash chain of changes, not an access-controlled admin service. Protect the file/API with your own
authentication and approvals (who may call put/disable is YOUR decision), and keep the audit log somewhere an admin cannot rewrite.
Standard library only.
"""
import copy
import hashlib
import hmac
import json
import os
import re
import sys
import tempfile
import time

KNOWN_ARG_RULES = {"max_len": int, "enum": list, "regex": str}
KNOWN_COND_OPS = {"equals", "in", "not_in", "max", "min"}
_NAME = re.compile(r"^[A-Za-z0-9_.:-]{1,100}$")


class PolicyInvalid(ValueError):
    def __init__(self, errors):
        super().__init__("policy is invalid: " + "; ".join(errors[:6]) + (f" (+{len(errors) - 6} more)" if len(errors) > 6 else ""))
        self.errors = errors


def validate_policy(policy):
    """Return a list of error strings (empty = valid). Unknown keys are errors: a typo in a security policy should not pass silently."""
    e = []
    if not isinstance(policy, dict):
        return ["policy must be a JSON object"]
    for k in policy:
        if k not in ("agents", "_comment"):
            e.append(f"unknown top-level key {k!r}")
    agents = policy.get("agents")
    if not isinstance(agents, dict):
        return e + ["'agents' must be an object"]
    for aid, a in agents.items():
        w = f"agent {aid!r}"
        if not _NAME.match(str(aid)):
            e.append(f"{w}: bad name")
        if not isinstance(a, dict):
            e.append(f"{w}: must be an object")
            continue
        for k in a:
            if k not in ("allow_roles", "tools", "_comment"):
                e.append(f"{w}: unknown key {k!r}")
        roles = a.get("allow_roles")
        if not (isinstance(roles, list) and roles and all(isinstance(r, str) and r for r in roles)):
            e.append(f"{w}: allow_roles must be a non-empty list of role names")
        tools = a.get("tools", {})
        if not isinstance(tools, dict):
            e.append(f"{w}: tools must be an object")
            continue
        for tid, t in tools.items():
            tw = f"{w} tool {tid!r}"
            if not isinstance(t, dict):
                e.append(f"{tw}: must be an object")
                continue
            for k in t:
                if k not in ("scopes", "approval", "args", "strict_args", "conditions", "_comment"):
                    e.append(f"{tw}: unknown key {k!r}")
            sc = t.get("scopes", [])
            if not (isinstance(sc, list) and all(isinstance(x, str) for x in sc)):
                e.append(f"{tw}: scopes must be a list of strings")
            elif not sc:
                e.append(f"{tw}: scopes is empty: a tool should require at least one scope (least privilege)")
            for k in ("approval", "strict_args"):
                if k in t and not isinstance(t[k], bool):
                    e.append(f"{tw}: {k} must be true or false")
            for an, rule in (t.get("args") or {}).items():
                if not isinstance(rule, dict):
                    e.append(f"{tw} arg {an!r}: rule must be an object")
                    continue
                for rk, rv in rule.items():
                    if rk not in KNOWN_ARG_RULES:
                        e.append(f"{tw} arg {an!r}: unknown rule {rk!r}")
                    elif not isinstance(rv, KNOWN_ARG_RULES[rk]) or isinstance(rv, bool):
                        e.append(f"{tw} arg {an!r}: {rk} has the wrong type")
                if isinstance(rule.get("regex"), str):
                    try:
                        re.compile(rule["regex"])
                    except re.error:
                        e.append(f"{tw} arg {an!r}: regex does not compile")
            for c in t.get("conditions", []) or []:
                if not (isinstance(c, dict) and isinstance(c.get("attr"), str)):
                    e.append(f"{tw}: each condition needs an 'attr'")
                    continue
                ops = set(c) - {"attr"}
                if not ops or not ops <= KNOWN_COND_OPS:
                    e.append(f"{tw}: condition on {c.get('attr')!r} needs one or more of {sorted(KNOWN_COND_OPS)}")
    return e


def _canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


class PolicyStore:
    """File format: {"version": n, "updated": ts, "updated_by": who, "digest": sha256(policy), "policy": {...}, "disabled": {"agent": ["tool"|"*"]}}."""

    def __init__(self, path, *, audit=None, create=False):
        self.path, self.audit = path, audit
        if not os.path.exists(path):
            if not create:
                raise FileNotFoundError(path)
            self._write({"version": 0, "updated": time.time(), "updated_by": "init", "policy": {"agents": {}}, "disabled": {}}, None, "init", "create")

    # -- reading
    def _read(self):
        with open(self.path, "r", encoding="utf-8") as f:
            doc = json.load(f)
        if not isinstance(doc, dict) or "policy" not in doc:
            raise PolicyInvalid(["not a policy store file (no 'policy')"])
        errs = validate_policy(doc["policy"])
        if errs:
            raise PolicyInvalid(errs)
        if doc.get("digest") and not hmac.compare_digest(str(doc["digest"]), hashlib.sha256(_canon(doc["policy"]).encode()).hexdigest()):
            raise PolicyInvalid(["policy content does not match its recorded digest (edited outside the store?)"])
        return doc

    def document(self):
        return self._read()

    @property
    def version(self):
        return self._read().get("version", 0)

    def effective(self):
        """The policy the PDP should enforce: validated, with disabled agents/tools removed. Raises on any problem (PDP then denies)."""
        doc = self._read()
        pol = copy.deepcopy(doc["policy"])
        for agent, tools in (doc.get("disabled") or {}).items():
            if agent not in pol.get("agents", {}):
                continue
            if "*" in tools:
                del pol["agents"][agent]
            else:
                for t in tools:
                    pol["agents"][agent].get("tools", {}).pop(t, None)
        return pol

    # -- writing
    def _write(self, doc, actor, reason, action):
        doc["digest"] = hashlib.sha256(_canon(doc["policy"]).encode()).hexdigest()
        d = os.path.dirname(os.path.abspath(self.path))
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".policy-")
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(doc, out, indent=2, sort_keys=True)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(tmp, 0o640)
        os.replace(tmp, self.path)
        if self.audit is not None:
            self.audit.record(actor=actor or "unknown", agent="policy-store", action=f"policy:{action}", resource=os.path.basename(self.path),
                              decision="applied", details={"version": doc.get("version"), "digest": doc["digest"], "reason": reason})

    def put(self, policy, *, actor, reason):
        """Replace the policy. Validated first; an invalid policy is rejected and the file is untouched."""
        if not actor or not reason:
            raise PolicyInvalid(["actor and reason are required for every change"])
        errs = validate_policy(policy)
        if errs:
            raise PolicyInvalid(errs)
        try:
            cur = self._read()
        except (FileNotFoundError, PolicyInvalid, ValueError):
            cur = {"version": 0, "disabled": {}}
        doc = {"version": cur.get("version", 0) + 1, "updated": round(time.time(), 3), "updated_by": actor, "policy": policy, "disabled": cur.get("disabled", {})}
        self._write(doc, actor, reason, "put")
        return doc["version"]

    def _toggle(self, agent, tool, actor, reason, disable):
        if not actor or not reason:
            raise PolicyInvalid(["actor and reason are required for every change"])
        doc = self._read()
        if agent not in doc["policy"].get("agents", {}):
            raise PolicyInvalid([f"unknown agent {agent!r}"])
        if tool not in (None, "*") and tool not in doc["policy"]["agents"][agent].get("tools", {}):
            raise PolicyInvalid([f"unknown tool {tool!r} for agent {agent!r}"])
        key = tool or "*"
        lst = set(doc.get("disabled", {}).get(agent, []))
        lst.add(key) if disable else lst.discard(key)
        doc.setdefault("disabled", {})
        if lst:
            doc["disabled"][agent] = sorted(lst)
        else:
            doc["disabled"].pop(agent, None)
        doc["version"] = doc.get("version", 0) + 1
        doc["updated"], doc["updated_by"] = round(time.time(), 3), actor
        self._write(doc, actor, reason, "disable" if disable else "enable")
        return doc["version"]

    def disable(self, agent, tool=None, *, actor, reason):
        return self._toggle(agent, tool, actor, reason, True)

    def enable(self, agent, tool=None, *, actor, reason):
        return self._toggle(agent, tool, actor, reason, False)


def _main(argv):
    import argparse
    ap = argparse.ArgumentParser(prog="python -m agentsec.policy_admin", description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate", help="check a policy (or policy-store) file; exit 1 if invalid")
    v.add_argument("file")
    s = sub.add_parser("show", help="summarise a policy store")
    s.add_argument("file")
    for n in ("disable", "enable"):
        d = sub.add_parser(n)
        d.add_argument("file")
        d.add_argument("agent")
        d.add_argument("tool", nargs="?")
        d.add_argument("--actor", required=True)
        d.add_argument("--reason", required=True)
        d.add_argument("--audit", help="audit log path to record the change in")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "validate":
            doc = json.load(open(a.file))
            pol = doc["policy"] if isinstance(doc, dict) and "policy" in doc else doc
            errs = validate_policy(pol)
            for x in errs:
                print("ERROR:", x)
            n_agents = len(pol.get("agents", {})) if isinstance(pol, dict) and isinstance(pol.get("agents"), dict) else 0
            print(f"{'INVALID' if errs else 'valid'}: {a.file} ({n_agents} agent(s), {len(errs)} error(s))")
            return 1 if errs else 0
        if a.cmd == "show":
            st = PolicyStore(a.file)
            doc = st.document()
            print(f"version {doc.get('version')} updated by {doc.get('updated_by')} at {doc.get('updated')} digest {doc['digest'][:12]}")
            for aid, ag in doc["policy"]["agents"].items():
                dis = doc.get("disabled", {}).get(aid, [])
                print(f"  agent {aid}: roles={ag.get('allow_roles')} tools={sorted(ag.get('tools', {}))} disabled={dis or '-'}")
            return 0
        audit = None
        if a.audit:
            from .audit import AuditLog
            audit = AuditLog(a.audit)
        st = PolicyStore(a.file, audit=audit)
        ver = (st.disable if a.cmd == "disable" else st.enable)(a.agent, a.tool, actor=a.actor, reason=a.reason)
        print(f"{a.cmd}d {a.agent}{'/' + a.tool if a.tool else ''}: now version {ver}")
        return 0
    except (PolicyInvalid, FileNotFoundError, ValueError) as e:
        print("ERROR:", e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
