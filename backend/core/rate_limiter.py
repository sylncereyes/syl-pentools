"""
Rate limiting middleware for Starlette using Redis backend.
"""
from __future__ import annotations

import time
from typing import Optional
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp

from core.config import settings
import redis.asyncio as redis


class RateLimiter:
    """Redis-backed sliding window rate limiter."""

    def __init__(self, redis_url: str):
        self.redis_url = redis_url
        self._client: Optional[redis.Redis] = None

    async def get_client(self) -> redis.Redis:
        if self._client is None:
            self._client = redis.from_url(self.redis_url, decode_responses=True)
        return self._client

    async def is_allowed(
        self,
        key: str,
        limit: int,
        window_seconds: int,
    ) -> tuple[bool, dict]:
        """
        Check if request is allowed under rate limit.
        Returns (allowed, headers_dict).
        """
        client = await self.get_client()
        now = time.time()
        window_start = now - window_seconds

        pipe = client.pipeline()
        pipe.zremrangebyscore(key, 0, window_start)
        pipe.zcard(key)
        pipe.zadd(key, {str(now): now})
        pipe.expire(key, window_seconds + 1)
        results = await pipe.execute()

        current_count = results[1]
        allowed = current_count < limit

        retry_after = 0
        if not allowed:
            oldest = await client.zrange(key, 0, 0, withscores=True)
            if oldest:
                retry_after = int(oldest[0][1] + window_seconds - now) + 1

        headers = {
            "X-RateLimit-Limit": str(limit),
            "X-RateLimit-Remaining": str(max(0, limit - current_count - 1)),
            "X-RateLimit-Reset": str(int(now + window_seconds)),
        }
        if retry_after > 0:
            headers["Retry-After"] = str(retry_after)

        return allowed, headers

    async def close(self):
        if self._client:
            await self._client.close()
            self._client = None


_rate_limiter: Optional[RateLimiter] = None


def get_rate_limiter() -> RateLimiter:
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter(settings.REDIS_URL)
    return _rate_limiter


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Starlette middleware for rate limiting."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        default_limit: int = 100,
        default_window: int = 60,
        auth_limit: int = 300,  # Higher for tests
        auth_window: int = 60,
        exempt_paths: Optional[list[str]] = None,
    ):
        super().__init__(app)
        self.default_limit = default_limit
        self.default_window = default_window
        self.auth_limit = auth_limit
        self.auth_window = auth_window
        self.exempt_paths = exempt_paths or ["/api/health", "/socket.io"]

    def _get_client_key(self, request: Request) -> str:
        """Extract client identifier from request."""
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            ip = forwarded.split(",")[0].strip()
        else:
            ip = request.client.host if request.client else "unknown"
        return f"ratelimit:{ip}"

    def _is_exempt(self, path: str) -> bool:
        for exempt in self.exempt_paths:
            if path.startswith(exempt):
                return True
        return False

    def _get_limits(self, request: Request) -> tuple[int, int]:
        """Get rate limit based on auth status and path."""
        if request.url.path.startswith("/api/auth/"):
            return self.auth_limit, self.auth_window
        return self.default_limit, self.default_window

    async def dispatch(self, request: Request, call_next):
        if self._is_exempt(request.url.path):
            return await call_next(request)

        limiter = get_rate_limiter()
        key = self._get_client_key(request)
        limit, window = self._get_limits(request)

        allowed, headers = await limiter.is_allowed(key, limit, window)

        if not allowed:
            return JSONResponse(
                {"detail": "Rate limit exceeded", "retry_after": headers.get("Retry-After")},
                status_code=429,
                headers=headers,
            )

        response = await call_next(request)
        for k, v in headers.items():
            response.headers[k] = v
        return response