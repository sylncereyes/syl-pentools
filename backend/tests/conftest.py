"""
Pytest configuration and fixtures.
"""
from __future__ import annotations

import asyncio
import os
import sys
from typing import AsyncGenerator, Generator

import pytest
import pytest_asyncio
from httpx import AsyncClient

# Ensure backend is in path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core.auth import hash_password, create_token_pair
from core.rate_limiter import RateLimiter
from models.user import User, UserRole
from core.config import settings


@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def test_user():
    """Create a test user object (not persisted)."""
    user = User(
        id="00000000-0000-0000-0000-000000000001",
        email="test@example.com",
        hashed_password=hash_password("password123"),
        full_name="Test User",
        role=UserRole.OWNER,
        is_active=True,
        is_verified=True,
    )
    return user


@pytest.fixture
async def auth_headers(test_user) -> dict[str, str]:
    """Create auth headers for test user."""
    tokens = create_token_pair(str(test_user.id), test_user.email, test_user.role.value)
    return {"Authorization": f"Bearer {tokens['access_token']}"}


# Integration tests against running server (requires API on localhost:8000)
@pytest.fixture(scope="session")
def api_base_url() -> str:
    """Base URL for integration tests."""
    return os.environ.get("TEST_API_URL", "http://localhost:8000")


@pytest.fixture
async def api_client(api_base_url: str) -> AsyncGenerator[AsyncClient, None]:
    """HTTP client for integration tests against running server."""
    async with AsyncClient(base_url=api_base_url, timeout=30.0) as client:
        yield client


@pytest.fixture
async def auth_api_client(api_base_url: str) -> AsyncGenerator[AsyncClient, None]:
    """Authenticated client for integration tests."""
    async with AsyncClient(base_url=api_base_url, timeout=30.0) as client:
        # Login with test user
        resp = await client.post(
            "/api/auth/login",
            json={"email": "test@example.com", "password": "password123"},
        )
        if resp.status_code == 200:
            token = resp.json()["access_token"]
            client.headers["Authorization"] = f"Bearer {token}"
        yield client