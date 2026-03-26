import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock
from httpx import AsyncClient, ASGITransport

from app.main import app
from app import es_client as es_client_module
from app.auth import require_auth


@pytest.fixture(autouse=True)
def mock_auth():
    """Bypass authentication for all tests — simulates a logged-in superuser."""
    app.dependency_overrides[require_auth] = lambda: {"sub": "testuser", "indices": None}
    yield
    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac


@pytest.fixture
def mock_es(monkeypatch):
    """Return a mock AsyncElasticsearch that can be configured per test."""
    mock = MagicMock()
    mock.cat = MagicMock()
    mock.cat.indices = AsyncMock()
    mock.search = AsyncMock()
    mock.close = AsyncMock()
    monkeypatch.setattr(es_client_module, "_client", mock)
    return mock
