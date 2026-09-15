"""
Minimal in-process sliding-window rate limiter (NFR-5).
Good enough for a single-process demo; the improvement plan calls out
swapping this for a shared Redis-backed limiter in production (multi-process
deployments each get their own counters otherwise).
"""
import threading
import time
from collections import defaultdict, deque


class RateLimiter:
    def __init__(self) -> None:
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def is_allowed(self, key: str, max_requests: int, window_seconds: int) -> bool:
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and q[0] <= now - window_seconds:
                q.popleft()
            if len(q) >= max_requests:
                return False
            q.append(now)
            return True


rate_limiter = RateLimiter()
