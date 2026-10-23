"""Sliding-window rate limiter (in memory, one process)."""
import threading
import time
from collections import defaultdict, deque
from typing import Optional


class RateLimiter:
    def __init__(self, max_attempts: int, window_seconds: int):
        self.max = max_attempts
        self.window = window_seconds
        self._hits = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, now: Optional[float] = None) -> bool:
        """Record an attempt for key. Returns False once the limit is exceeded."""
        now = time.time() if now is None else now
        with self._lock:
            hits = self._hits[key]
            while hits and hits[0] <= now - self.window:
                hits.popleft()
            if len(hits) >= self.max:
                return False
            hits.append(now)
            return True