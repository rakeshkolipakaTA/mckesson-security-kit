"""P1/P8 Policy decision (PDP) and enforcement (PEP) for agent tool calls, default-deny and fail-closed.
Policy shape (JSON/dict):
  {"agents": {"support-bot": {"allow_roles": ["user", "admin"],
      "tools": {"search_docs": {"scopes": ["docs:read"], "args": {"query": {"max_len": 500}}},
                "send_email":  {"scopes": ["mail:send"], "approval": true, "args": {"to": {"regex": "^[^@]+@example\\\\.com$"}}}}}}}
The PDP only decides; the PEP calls the tool (or not), asks a human when the policy says `approval`, and writes every decision to the audit log.

PIP (policy information point): pass `context=[provider, ...]` (objects with `.attributes(principal, agent_id, tool, args) -> dict`, or plain callables)
to feed attributes (risk score, business hours, device posture, ticket state ...) into decisions. A tool may then carry `conditions`:
  "conditions": [{"attr": "risk_score", "max": 0.7}, {"attr": "device", "in": ["managed"]}, {"attr": "business_hours", "equals": true}]
A provider that raises, or an attribute that is missing, DENIES (indeterminate is deny).
PAP (policy administration point): see policy_admin.PolicyStore: pass a store as `policy` and every decision uses its current, validated, enabled policy."""
import re
import uuid
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Principal:
    id: str
    roles: tuple = ()
    tenant: str = None
    scopes: tuple = field(default_factory=tuple)


class PolicyDenied(PermissionError):
    pass


class ApprovalRequired(PermissionError):
    def __init__(self, request_id, tool):
        super().__init__(f"human approval required for {tool}")
        self.request_id, self.tool = request_id, tool


@dataclass(frozen=True)
class PDecision:
    effect: str          # permit | deny
    reason: str = ""
    approval: bool = False


class ContextProvider:
    """PIP base class: override attributes(). A plain callable with the same signature works too."""

    def attributes(self, principal, agent_id, tool, args):
        raise NotImplementedError


def _cond_ok(cond, ctx):
    a = cond["attr"]
    if a not in ctx:
        raise KeyError(f"attribute {a!r} is not available")
    v = ctx[a]
    if "equals" in cond and v != cond["equals"]:
        return False
    if "in" in cond and v not in cond["in"]:
        return False
    if "not_in" in cond and v in cond["not_in"]:
        return False
    if "max" in cond and not v <= cond["max"]:
        return False
    if "min" in cond and not v >= cond["min"]:
        return False
    return True


class PDP:
    def __init__(self, policy, context=None):
        self.policy = policy                  # a dict, or a policy_admin.PolicyStore (anything with .effective())
        self.providers = list(context or [])

    def _policy(self):
        eff = getattr(self.policy, "effective", None)
        return eff() if callable(eff) else self.policy

    def _context(self, principal, agent_id, tool, args):
        ctx = {}
        for p in self.providers:
            got = p.attributes(principal, agent_id, tool, args) if hasattr(p, "attributes") else p(principal, agent_id, tool, args)
            if not isinstance(got, dict):
                raise TypeError("a context provider must return a dict")
            ctx.update(got)
        return ctx

    def decide(self, principal, agent_id, tool, args=None):
        try:
            return self._decide(principal, agent_id, tool, args or {})
        except Exception as e:  # noqa: BLE001 - indeterminate means deny
            return PDecision("deny", f"policy error ({type(e).__name__}): indeterminate is deny")

    def _decide(self, principal, agent_id, tool, args):
        agent = self._policy().get("agents", {}).get(agent_id)
        if not agent:
            return PDecision("deny", f"agent {agent_id!r} is not registered")
        if not set(principal.roles) & set(agent.get("allow_roles", [])):
            return PDecision("deny", "caller role may not use this agent")
        t = agent.get("tools", {}).get(tool)
        if t is None:
            return PDecision("deny", f"tool {tool!r} is not allowed for this agent")
        missing = set(t.get("scopes", [])) - set(principal.scopes)
        if missing:
            return PDecision("deny", f"missing scopes: {sorted(missing)}")
        for name, rule in t.get("args", {}).items():
            v = args.get(name)
            if v is None:
                continue
            if "max_len" in rule and len(str(v)) > rule["max_len"]:
                return PDecision("deny", f"argument {name} too long")
            if "enum" in rule and v not in rule["enum"]:
                return PDecision("deny", f"argument {name} not in allowed values")
            if "regex" in rule and not re.fullmatch(rule["regex"], str(v)):
                return PDecision("deny", f"argument {name} does not match the allowed pattern")
        unknown = set(args) - set(t.get("args", {})) if t.get("strict_args") else set()
        if unknown:
            return PDecision("deny", f"unexpected arguments: {sorted(unknown)}")
        conds = t.get("conditions") or []
        if conds:
            ctx = self._context(principal, agent_id, tool, args)     # a failing provider raises -> deny in decide()
            for c in conds:
                if not _cond_ok(c, ctx):
                    return PDecision("deny", f"condition on {c['attr']!r} not met")
        return PDecision("permit", "", bool(t.get("approval")))


class PEP:
    def __init__(self, pdp, audit=None, approver=None):
        self.pdp, self.audit, self.approver = pdp, audit, approver

    def _log(self, principal, agent_id, tool, decision, details):
        if self.audit:
            self.audit.record(actor=principal.id, agent=agent_id, action=f"tool:{tool}", resource=tool, decision=decision, details=details)

    def call(self, principal, agent_id, tool, fn, **args):
        d = self.pdp.decide(principal, agent_id, tool, args)
        if d.effect != "permit":
            self._log(principal, agent_id, tool, "deny", {"reason": d.reason, "args": args})
            raise PolicyDenied(d.reason)
        if d.approval:
            rid = uuid.uuid4().hex[:12]
            approved = False
            if self.approver is not None:
                try:
                    approved = self.approver(principal, agent_id, tool, args) is True   # only an explicit True is a yes
                except Exception:  # noqa: BLE001
                    approved = False
            if not approved:
                self._log(principal, agent_id, tool, "pending_approval", {"request_id": rid, "args": args})
                raise ApprovalRequired(rid, tool)
            self._log(principal, agent_id, tool, "approved", {"request_id": rid})
        self._log(principal, agent_id, tool, "permit", {"args": args})
        return fn(**args)


def require_owner(principal, resource_owner, resource_tenant=None):
    """Object-level authorisation. Cross-tenant access is always denied; other users' objects need the admin role."""
    if resource_tenant is not None and principal.tenant != resource_tenant:
        raise PolicyDenied("cross-tenant access denied")
    if principal.id != resource_owner and "admin" not in principal.roles:
        raise PolicyDenied("not the owner of this resource")
