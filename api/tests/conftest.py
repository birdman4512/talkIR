import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock
from httpx import AsyncClient, ASGITransport

from app.main import app
from app import es_client as es_client_module


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
