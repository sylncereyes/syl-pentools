"""
Authentication tests (unit + integration).
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient


class TestAuthUnit:
    """Unit tests for auth functions."""

    @pytest.mark.asyncio
    async def test_create_token_pair(self):
        """Test token pair creation."""
        from core.auth import create_token_pair
        from models.user import UserRole
        tokens = create_token_pair("user-id", "test@example.com", UserRole.OWNER)
        assert "access_token" in tokens
        assert "refresh_token" in tokens
        assert tokens["token_type"] == "bearer"

    @pytest.mark.asyncio
    async def test_hash_and_verify_password(self):
        """Test password hashing and verification."""
        from core.auth import hash_password, verify_password
        password = "testpassword123"
        hashed = hash_password(password)
        assert verify_password(password, hashed)
        assert not verify_password("wrong", hashed)


class TestAuthIntegration:
    """Integration tests against running API server."""

    @pytest.mark.asyncio
    async def test_login(self, api_client: AsyncClient):
        """Test user login."""
        response = await api_client.post(
            "/api/auth/login",
            json={"email": "test@example.com", "password": "password123"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data

    @pytest.mark.asyncio
    async def test_login_wrong_password(self, api_client: AsyncClient):
        """Test login with wrong password fails."""
        response = await api_client.post(
            "/api/auth/login",
            json={"email": "test@example.com", "password": "wrongpassword"},
        )
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_me(self, auth_api_client: AsyncClient):
        """Test getting current user info."""
        response = await auth_api_client.get("/api/auth/me")
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == "test@example.com"

    @pytest.mark.asyncio
    async def test_me_unauthorized(self, api_client: AsyncClient):
        """Test getting user info without auth fails."""
        response = await api_client.get("/api/auth/me")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_refresh_token(self, api_client: AsyncClient):
        """Test refreshing access token."""
        login_resp = await api_client.post(
            "/api/auth/login",
            json={"email": "test@example.com", "password": "password123"},
        )
        refresh_token = login_resp.json()["refresh_token"]

        response = await api_client.post(
            "/api/auth/refresh",
            json={"refresh_token": refresh_token},
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data

    @pytest.mark.asyncio
    async def test_logout(self, auth_api_client: AsyncClient):
        """Test logout."""
        response = await auth_api_client.post("/api/auth/logout")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_register_new_user(self, api_client: AsyncClient):
        """Test registering a new user."""
        import uuid
        email = f"test{uuid.uuid4().hex[:8]}@example.com"
        response = await api_client.post(
            "/api/auth/register",
            json={"email": email, "password": "password123", "full_name": "Test User"},
        )
        assert response.status_code in (200, 201)  # API returns 200
        data = response.json()
        assert data["user"]["email"] == email