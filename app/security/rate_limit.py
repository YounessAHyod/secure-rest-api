from collections import defaultdict
from time import time

from fastapi import HTTPException, status


class SimpleRateLimiter:


    def __init__(self, limit: int, window_seconds: int):
        self.limit = limit
        self.window = window_seconds
        self.attempts = defaultdict(list)

    def check(self, key: str) -> None:
        now = time()
        window_start = now - self.window

        # only timestamps in the current window
        self.attempts[key] = [t for t in self.attempts[key] if t > window_start]

        if len(self.attempts[key]) >= self.limit:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests",
            )

        self.attempts[key].append(now)

login_ip_limiter = SimpleRateLimiter(limit=20, window_seconds=60)
login_target_limiter = SimpleRateLimiter(limit=10, window_seconds=60)
