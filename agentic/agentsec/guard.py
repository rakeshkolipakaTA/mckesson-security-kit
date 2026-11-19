"""P2/P3 Deterministic, FAIL-CLOSED guardrails. Control flow is decided by code, never by the model: a guard that raises, times out
or returns something other than an explicit allow means BLOCK."""
import concurrent.futures
from dataclasses import dataclass

_pool = concurrent.futures.ThreadPoolExecutor(max_workers=8, thread_name_prefix="agentsec-guard")


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str = ""
    guard: str = ""


def _run_one(check, text, timeout):
    name = getattr(check, "__name__", repr(check))
    fut = _pool.submit(check, text)
    try:
        res = fut.result(timeout=timeout)
    except concurrent.futures.TimeoutError:
        fut.cancel()
        return Decision(False, "guard timed out (fail-closed)", name)
    except Exception as e:  # noqa: BLE001 - any failure of a guard is a block
        return Decision(False, f"guard error: {type(e).__name__} (fail-closed)", name)
    if res is True:
        return Decision(True, "", name)
    if isinstance(res, Decision):
        return Decision(res.allowed is True, res.reason, res.guard or name)
    if isinstance(res, tuple) and len(res) == 2 and res[0] is True:
        return Decision(True, str(res[1]), name)
    if isinstance(res, tuple) and len(res) == 2:
        return Decision(False, str(res[1]), name)
    return Decision(False, "guard returned a non-boolean result (fail-closed)", name)  # None / False / anything else


def enforce(text, checks, *, timeout=2.0):
    """Run every check; the first block wins. Empty `checks` is a block (a misconfigured pipeline must not mean 'no guard')."""
    if not checks:
        return Decision(False, "no guardrails configured (fail-closed)")
    for c in checks:
        d = _run_one(c, text, timeout)
        if not d.allowed:
            return d
    return Decision(True)
