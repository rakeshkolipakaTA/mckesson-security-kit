"""P1 Agent identity & credential broker (REFERENCE IMPLEMENTATION / test double).
Every agent is a distinct principal; tools receive short-lived tokens that are scoped to ONE audience and a few scopes and name
the human the agent acts for. A tool never sees the user's own session token or a long-lived key. In production issue these from your
IdP / token-exchange service and vault; keep the same claims and checks."""
import base64
import hashlib
import hmac
import json
import time


class TokenError(PermissionError):
    pass


def _b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class CredentialBroker:
    def __init__(self, secret, *, max_ttl=900):
        if not secret or len(secret) < 16:
            raise ValueError("broker secret must be at least 16 bytes (load it from a vault, never from source)")
        self._k = secret.encode() if isinstance(secret, str) else secret
        self.max_ttl = max_ttl

    def issue(self, *, agent_id, on_behalf_of, audience, scopes, ttl=300, extra=None):
        now = int(time.time())
        claims = {"sub": agent_id, "act": on_behalf_of, "aud": audience, "scp": sorted(scopes), "iat": now, "exp": now + min(int(ttl), self.max_ttl)}
        claims.update({k: v for k, v in (extra or {}).items() if k not in claims})   # e.g. roles, tenant; reserved claims cannot be overridden
        p = _b64(json.dumps(claims, sort_keys=True).encode())
        return f"v1.{p}.{_b64(hmac.new(self._k, p.encode(), hashlib.sha256).digest())}"

    def verify(self, token, *, audience, scope=None):
        try:
            ver, p, sig = token.split(".")
        except (ValueError, AttributeError):
            raise TokenError("malformed token") from None
        if ver != "v1" or not hmac.compare_digest(sig, _b64(hmac.new(self._k, p.encode(), hashlib.sha256).digest())):  # constant time
            raise TokenError("bad signature")
        c = json.loads(_unb64(p))
        if c["exp"] < time.time():
            raise TokenError("token expired")
        if c["aud"] != audience:
            raise TokenError("token not issued for this audience")
        if scope and scope not in c["scp"]:
            raise TokenError(f"missing scope {scope}")
        return c
