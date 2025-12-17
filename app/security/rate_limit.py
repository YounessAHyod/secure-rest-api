import time
from collections import defaultdict, deque


class SimpleRateLimiter:
    """
    In-memory sliding-window rate limiter.
    Good for local/dev; not suitable for multi-instance production.
    """

    def __init__(self, max_attempts: int, window_seconds: int):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.attempts = defaultdict(deque)

    def is_allowed(self, key: str) -> bool:
        now = time.time()
        q = self.attempts[key]

        # drop old timestamps
        while q and (now - q[0]) > self.window_seconds:
            q.popleft()

        if len(q) >= self.max_attempts:
            return False

        q.append(now)
        return True


# 5 attempts per 60 seconds
login_limiter = SimpleRateLimiter(max_attempts=5, window_seconds=60)
