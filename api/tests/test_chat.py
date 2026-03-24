import json
import pytest
from unittest.mock import AsyncMock, patch, MagicMock


def _make_es_search_response(hits: list[dict]) -> dict:
    return {
        "hits": {
            "total": {"value": len(hits)},
            "hits": [{"_source": h, "_score": 1.0} for h in hits],
        }
    }


@pytest.mark.asyncio
async def test_chat_streams_sse(client, mock_es):
    mock_es.search.return_value = _make_es_search_response([
        {"event_type": "login_failure", "user": "admin", "src_ip": "10.0.0.1"}
    ])

    # Fake Ollama SSE chunks
    chunks = [
        json.dumps({"message": {"content": "This "}, "done": False}),
        json.dumps({"message": {"content": "looks "}, "done": False}),
        json.dumps({"message": {"content": "suspicious."}, "done": True}),
    ]

    async def fake_aiter_lines():
        for c in chunks:
            yield c

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.aiter_lines = fake_aiter_lines

    mock_stream_cm = MagicMock()
    mock_stream_cm.__aenter__ = AsyncMock(return_value=mock_response)
    mock_stream_cm.__aexit__ = AsyncMock(return_value=False)

    mock_client_cm = MagicMock()
    mock_client_cm.__aenter__ = AsyncMock(return_value=MagicMock(stream=MagicMock(return_value=mock_stream_cm)))
    mock_client_cm.__aexit__ = AsyncMock(return_value=False)

    with patch("app.routes.chat.httpx.AsyncClient", return_value=mock_client_cm):
        resp = await client.post(
            "/api/chat",
            json={"query": "Are there brute force attempts?", "indices": ["auth-2024.01.01"]},
        )

    assert resp.status_code == 200
    assert "text/event-stream" in resp.headers["content-type"]
    body = resp.text
    assert "data:" in body


@pytest.mark.asyncio
async def test_chat_invalid_query_too_short(client, mock_es):
    resp = await client.post("/api/chat", json={"query": "", "indices": []})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_health(client):
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}
