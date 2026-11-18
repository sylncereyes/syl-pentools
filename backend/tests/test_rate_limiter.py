"""
Rate limiter tests (unit + integration).
"""
from __future__ import annotations

import pytest
import time
from httpx import AsyncClient


class TestRateLimiterUnit:
    """Unit tests for rate limiter logic."""

    @pytest.mark.asyncio
    async def test_sliding_window(self):
        """Test sliding window algorithm allows burst then blocks."""
        from core.rate_limiter import RateLimiter
        from core.config import settings

        limiter = RateLimiter(settings.REDIS_URL)
        key = f"test:ratelimit:{int(time.time())}"

        try:
            # Allow up to 5 requests in 10 seconds
            for i in range(5):
                allowed, _ = await limiter.is_allowed(key, 5, 10)
                assert allowed, f"Request {i+1} should be allowed"

            # 6th request should be denied
            allowed, headers = await limiter.is_allowed(key, 5, 10)
            assert not allowed, "6th request should be denied"
            assert "Retry-After" in headers
        finally:
            await limiter.close()

    @pytest.mark.asyncio
    async def test_window_expiry(self):
        """Test that window expires and allows new requests."""
        from core.rate_limiter import RateLimiter
        from core.config import settings

        limiter = RateLimiter(settings.REDIS_URL)
        key = f"test:ratelimit:expiry:{int(time.time())}"

        try:
            # Use very short window
            for i in range(3):
                allowed, _ = await limiter.is_allowed(key, 3, 1)
                assert allowed

            # Wait for window to expire
            time.sleep(1.5)

            # Should be allowed again
            allowed, _ = await limiter.is_allowed(key, 3, 1)
            assert allowed
        finally:
            await limiter.close()


class TestRateLimiterIntegration:
    """Integration tests against running API server."""

    @pytest.mark.asyncio
    async def test_health_endpoint_exempt(self, api_client: AsyncClient):
        """Health endpoint should be exempt from rate limiting."""
        for _ in range(5):
            response = await api_client.get("/api/health")
            assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_auth_endpoints_exempt(self, api_client: AsyncClient):
        """Auth endpoints are exempt from rate limiting."""
        response = await api_client.post(
            "/api/auth/login",
            json={"email": "nonexistent@example.com", "password": "wrong"},
        )
        assert response.status_code == 401
        # Auth endpoints exempt - no rate limit headers expected

    @pytest.mark.asyncio
    async def test_general_endpoint_rate_limit(self, auth_api_client: AsyncClient):
        """General endpoints have default rate limit."""
        response = await auth_api_client.get("/api/workspace")
        assert response.status_code == 200
        assert "X-RateLimit-Limit" in response.headers

    @pytest.mark.asyncio
    async def test_rate_limit_headers_present(self, auth_api_client: AsyncClient):
        """Rate limit headers should be present on all responses."""
        response = await auth_api_client.get("/api/workspace")
        assert response.status_code == 200
        assert "X-RateLimit-Limit" in response.headers
        assert "X-RateLimit-Remaining" in response.headers
        assert "X-RateLimit-Reset" in response.headers