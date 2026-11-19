"""P8 Immutable audit & non-repudiation: append-only JSON-lines log where every record carries the hash of the previous one
(optionally an HMAC, so an attacker without the key cannot recompute the chain after editing). Detects edits, deletions and reordering.
Ship the records to write-once storage / your SIEM as well: a file on the same host is evidence, not a vault."""
import hashlib
import hmac
import json
import os
import threading
import time

from .pii import redact_obj

_GENESIS = "0" * 64


def _digest(prev, rec, key):
    body = prev + json.dumps(rec, sort_keys=True, separators=(",", ":"))
    return hmac.new(key, body.encode(), hashlib.sha256).hexdigest() if key else hashlib.sha256(body.encode()).hexdigest()


class AuditLog:
    def __init__(self, path, *, key=None, redact=True):
        self.path, self.key, self.redact = path, (key.encode() if isinstance(key, str) else key), redact
        self._lock = threading.Lock()
        self._prev = _GENESIS
        if os.path.exists(path):
            with open(path, "rb") as f:
                last = None
                for last in f:
                    pass
                if last:
                    self._prev = json.loads(last)["hash"]

    def record(self, *, actor, agent, action, resource="", decision="", details=None):
        rec = {"ts": round(time.time(), 3), "actor": actor, "agent": agent, "action": action, "resource": resource,
               "decision": decision, "details": redact_obj(details or {}) if self.redact else (details or {})}
        with self._lock:
            rec["prev"] = self._prev
            rec["hash"] = _digest(self._prev, {k: v for k, v in rec.items() if k not in ("prev", "hash")}, self.key)
            with open(self.path, "a") as f:
                f.write(json.dumps(rec, sort_keys=True) + "\n")
                f.flush()
                os.fsync(f.fileno())
            self._prev = rec["hash"]
        return rec


def verify_chain(path, *, key=None):
    """Return (ok, records_checked, first_bad_index_or_None)."""
    key = key.encode() if isinstance(key, str) else key
    prev, n = _GENESIS, 0
    with open(path) as f:
        for i, line in enumerate(f):
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                return False, n, i
            body = {k: v for k, v in rec.items() if k not in ("prev", "hash")}
            if rec.get("prev") != prev or not hmac.compare_digest(rec.get("hash", ""), _digest(prev, body, key)):
                return False, n, i
            prev, n = rec["hash"], n + 1
    return True, n, None
