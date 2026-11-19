"""agentsec: reference runtime controls for enterprise agentic applications (standard library only).

Maps to the control framework in the Agentic Security presentation:
  P1 policy.py (PDP/PEP, least privilege, ownership)   broker.py (agent identity, scoped short-lived tokens)
  P2 limits.py (budgets, DoS)                          guard.py (fail-closed guardrails)
  P3 paths.py, untrusted.py (trusted I/O, RAG data)    P4 egress.py (SSRF / egress control)
  P5 pii.py (secrets/PII masking in logs)              P8 audit.py (tamper-evident audit), policy.py approval (human in the loop)
These are building blocks and reference implementations: review them, then wire them to your IdP, vault, gateway and SIEM.
"""
from .audit import AuditLog, verify_chain
from .broker import CredentialBroker, TokenError
from .egress import EgressViolation, safe_fetch, validate_url
from .guard import Decision, enforce
from .limits import Budget, BudgetExceeded, RateLimiter
from .paths import PathViolation, safe_path
from .pii import redact, redact_obj
from .policy import PDP, PEP, ApprovalRequired, PolicyDenied, Principal, require_owner
from .untrusted import detect_injection, make_canary, wrap_untrusted

__all__ = ["AuditLog", "verify_chain", "CredentialBroker", "TokenError", "EgressViolation", "safe_fetch", "validate_url", "Decision", "enforce",
           "Budget", "BudgetExceeded", "RateLimiter", "PathViolation", "safe_path", "redact", "redact_obj", "PDP", "PEP", "ApprovalRequired", "PolicyDenied",
           "Principal", "require_owner", "detect_injection", "make_canary", "wrap_untrusted"]
