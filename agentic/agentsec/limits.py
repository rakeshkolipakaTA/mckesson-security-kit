"""P2 Resilience: bound what one request/agent run may consume (steps, tool calls, wall-clock, output size)."""
import time


class BudgetExceeded(RuntimeError):
    pass


class Budget:
    def __init__(self, *, max_steps=10, max_tool_calls=20, max_seconds=60.0, max_output_bytes=200_000):
        self.max_steps, self.max_tool_calls, self.max_seconds, self.max_output_bytes = max_steps, max_tool_calls, max_seconds, max_output_bytes
        self.steps = self.tool_calls = self.output_bytes = 0
        self._t0 = time.monotonic()

    def _time(self):
        if time.monotonic() - self._t0 > self.max_seconds:
            raise BudgetExceeded("time budget exceeded")

    def step(self):
        self.steps += 1
        if self.steps > self.max_steps:
            raise BudgetExceeded("step budget exceeded")
        self._time()

    def tool_call(self):
        self.tool_calls += 1
        if self.tool_calls > self.max_tool_calls:
            raise BudgetExceeded("tool-call budget exceeded")
        self._time()

    def output(self, data):
        self.output_bytes += len(data if isinstance(data, (bytes, str)) else repr(data))
        if self.output_bytes > self.max_output_bytes:
            raise BudgetExceeded("output budget exceeded")


class RateLimiter:
    """Sliding-window limiter per key (user/agent/IP). `allow(key)` is False once max_events happened in the last per_seconds."""
    def __init__(self, max_events=30, per_seconds=10.0):
        import threading
        from collections import defaultdict, deque
        self.max_events, self.per_seconds = max_events, per_seconds
        self._ev, self._lock = defaultdict(deque), threading.Lock()

    def allow(self, key):
        now = time.monotonic()
        with self._lock:
            q = self._ev[key]
            while q and now - q[0] > self.per_seconds:
                q.popleft()
            if len(q) >= self.max_events:
                return False
            q.append(now)
            return True
