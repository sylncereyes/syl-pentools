"""
API endpoint integration tests against running server.
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient


class TestAssetsIntegration:
    """Test asset endpoints against running server."""

    @pytest.mark.asyncio
    async def test_list_assets(self, auth_api_client: AsyncClient):
        """List assets."""
        response = await auth_api_client.get("/api/assets")
        assert response.status_code == 200
        assert isinstance(response.json(), list)

    @pytest.mark.asyncio
    async def test_create_asset(self, auth_api_client: AsyncClient):
        """Create a new asset."""
        import uuid
        target = f"test{uuid.uuid4().hex[:8]}.com"
        response = await auth_api_client.post(
            "/api/assets",
            json={"target": target, "type": "hostname"},
        )
        assert response.status_code == 201
        data = response.json()
        assert data["target"] == target
        assert data["type"] == "hostname"
        assert "id" in data

    @pytest.mark.asyncio
    async def test_import_assets(self, auth_api_client: AsyncClient):
        """Import assets from text."""
        import uuid
        targets = "\n".join([f"import{uuid.uuid4().hex[:8]}.com" for _ in range(3)])
        response = await auth_api_client.post(
            "/api/assets/import",
            json={"targets": targets, "type": "hostname"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["count"] == 3
        assert len(data["created"]) == 3


class TestScansIntegration:
    """Test scan endpoints against running server."""

    @pytest.mark.asyncio
    async def test_list_scans(self, auth_api_client: AsyncClient):
        """List scans."""
        response = await auth_api_client.get("/api/scans")
        assert response.status_code == 200
        assert isinstance(response.json(), list)

    @pytest.mark.asyncio
    async def test_create_scan(self, auth_api_client: AsyncClient):
        """Create a new scan."""
        import uuid
        target = f"scan{uuid.uuid4().hex[:8]}.test"
        response = await auth_api_client.post(
            "/api/scans",
            json={"target": target, "scan_type": "port", "intensity": "normal"},
        )
        # May fail due to concurrent limit, accept 201 or 400
        assert response.status_code in (201, 400)
        if response.status_code == 201:
            data = response.json()
            assert data["target"] == target
            assert data["type"] == "port"
            assert data["status"] == "pending"
            assert "id" in data


class TestFindingsIntegration:
    """Test finding endpoints against running server."""

    @pytest.mark.asyncio
    async def test_list_findings(self, auth_api_client: AsyncClient):
        """List findings."""
        response = await auth_api_client.get("/api/findings")
        assert response.status_code == 200
        assert isinstance(response.json(), list)

    @pytest.mark.asyncio
    async def test_create_finding(self, auth_api_client: AsyncClient):
        """Create a manual finding."""
        # First create an asset
        import uuid
        target = f"find{uuid.uuid4().hex[:8]}.com"
        asset_resp = await auth_api_client.post("/api/assets", json={"target": target, "type": "hostname"})
        asset_id = asset_resp.json()["id"]

        response = await auth_api_client.post(
            "/api/findings",
            json={
                "title": "Test Finding",
                "severity": "high",
                "asset_id": asset_id,
                "description": "Test description",
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["title"] == "Test Finding"
        assert data["severity"] == "high"
        assert data["source_scanner"] == "manual"


class TestWorkspaceIntegration:
    """Test workspace endpoints against running server."""

    @pytest.mark.asyncio
    async def test_get_workspace(self, auth_api_client: AsyncClient):
        """Get current workspace info."""
        response = await auth_api_client.get("/api/workspace")
        assert response.status_code == 200
        data = response.json()
        assert "id" in data
        assert "name" in data

    @pytest.mark.asyncio
    async def test_workspace_usage(self, auth_api_client: AsyncClient):
        """Get workspace usage stats."""
        response = await auth_api_client.get("/api/workspace/usage")
        assert response.status_code == 200
        data = response.json()
        assert "plan" in data
        assert "assets" in data
        assert "used" in data["assets"]
        assert "limit" in data["assets"]


class TestDashboardIntegration:
    """Test dashboard analytics against running server."""

    @pytest.mark.asyncio
    async def test_dashboard_analytics(self, auth_api_client: AsyncClient):
        """Get dashboard analytics."""
        response = await auth_api_client.get("/api/dashboard/analytics?days=7")
        assert response.status_code == 200
        data = response.json()
        assert "scans_total" in data
        assert "open_findings" in data
        assert "scans_by_day" in data


class TestReportsIntegration:
    """Test report endpoints against running server."""

    @pytest.mark.asyncio
    async def test_list_reports(self, auth_api_client: AsyncClient):
        """List reports."""
        response = await auth_api_client.get("/api/reports")
        assert response.status_code == 200
        assert isinstance(response.json(), list)

    @pytest.mark.asyncio
    async def test_list_report_templates(self, auth_api_client: AsyncClient):
        """List report templates."""
        response = await auth_api_client.get("/api/report-templates")
        assert response.status_code == 200
        assert isinstance(response.json(), list)


class TestScheduledScansIntegration:
    """Test scheduled scan endpoints against running server."""

    @pytest.mark.asyncio
    async def test_list_scheduled_scans(self, auth_api_client: AsyncClient):
        """List scheduled scans."""
        response = await auth_api_client.get("/api/scheduled-scans")
        assert response.status_code == 200
        assert isinstance(response.json(), list)

    @pytest.mark.asyncio
    async def test_create_scheduled_scan(self, auth_api_client: AsyncClient):
        """Create a scheduled scan."""
        response = await auth_api_client.post(
            "/api/scheduled-scans",
            json={
                "name": "Daily Scan",
                "target": "example.com",
                "scan_type": "port",
                "frequency": "daily",
                "start_time": "02:00",
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "Daily Scan"
        assert data["frequency"] == "daily"


class TestAttackSurfaceIntegration:
    """Test attack surface endpoints against running server."""

    @pytest.mark.asyncio
    async def test_attack_surface(self, auth_api_client: AsyncClient):
        """Get attack surface."""
        response = await auth_api_client.get("/api/attack-surface")
        assert response.status_code == 200
        data = response.json()
        assert "summary" in data
        assert "rows" in data
        assert isinstance(data["rows"], list)


class TestRobotsIntegration:
    """Test robot endpoints against running server."""

    @pytest.mark.asyncio
    async def test_list_robots(self, auth_api_client: AsyncClient):
        """List robots."""
        response = await auth_api_client.get("/api/robots")
        assert response.status_code == 200
        assert isinstance(response.json(), list)


class TestIntegrationsIntegration:
    """Test integration endpoints against running server."""

    @pytest.mark.asyncio
    async def test_list_integrations(self, auth_api_client: AsyncClient):
        """List integrations."""
        response = await auth_api_client.get("/api/integrations")
        assert response.status_code == 200
        assert isinstance(response.json(), list)


class TestTeamIntegration:
    """Test team endpoints against running server."""

    @pytest.mark.asyncio
    async def test_list_team_members(self, auth_api_client: AsyncClient):
        """List team members."""
        response = await auth_api_client.get("/api/team/members")
        assert response.status_code == 200
        data = response.json()
        assert "members" in data
        assert isinstance(data["members"], list)
        assert len(data["members"]) >= 1  # At least the owner


class TestAPIKeysIntegration:
    """Test API key endpoints against running server."""

    @pytest.mark.asyncio
    async def test_list_api_keys(self, auth_api_client: AsyncClient):
        """List API keys."""
        response = await auth_api_client.get("/api/api-keys")
        assert response.status_code == 200
        assert isinstance(response.json(), list)

    @pytest.mark.asyncio
    async def test_create_api_key(self, auth_api_client: AsyncClient):
        """Create an API key."""
        response = await auth_api_client.post(
            "/api/api-keys",
            json={"name": "Test Key", "scopes": ["read", "write"]},
        )
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "Test Key"
        assert "key" in data  # Only shown once


class TestBootstrapIntegration:
    """Test bootstrap endpoint against running server."""

    @pytest.mark.asyncio
    async def test_bootstrap(self, auth_api_client: AsyncClient):
        """Test bootstrap endpoint."""
        response = await auth_api_client.get("/api/bootstrap")
        assert response.status_code == 200
        data = response.json()
        assert "workspace" in data
        assert "assets" in data
        assert "scans" in data
        assert isinstance(data["scans"], list)