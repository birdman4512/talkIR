import json
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from app.routes.chat import _smart_search


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
async def test_chat_smart_query_streams_generated_eql_and_evidence_summary(client, mock_es):
    async def fake_smart_search(provider, model, indices, query, max_results):
        yield ("debug_query_prompt", "sys", query)
        yield ("result", [{"@timestamp": "2024-01-01T00:00:00Z", "event_type": "login", "src_ip": "1.2.3.4"}],
               {"query": {"term": {"src_ip": "1.2.3.4"}}}, None)

    async def fake_convert(provider, model, query_body, indices):
        return [{"query_index": 1, "language": "eql", "query": 'any where src_ip == "1.2.3.4"'}]

    async def fake_stream_ollama(model, messages):
        yield ("content", "I saw it once.", False, {})
        yield ("content", "", True, {"tokens": 4})

    with patch("app.routes.chat._smart_search", fake_smart_search), \
         patch("app.routes.chat._convert_query_artifacts_to_kibana_queries", fake_convert), \
         patch("app.routes.chat._stream_ollama", fake_stream_ollama):
        resp = await client.post(
            "/api/chat",
            json={"query": "When have I seen 1.2.3.4 before?", "indices": ["auth-*"], "smart_query": True},
        )

    assert resp.status_code == 200
    body = resp.text
    assert "generated_query" in body
    assert "generated_eql" in body
    assert 'any where src_ip == \\"1.2.3.4\\"' in body
    assert "evidence_summary" in body
    assert "First seen: 2024-01-01T00:00:00Z" in body


@pytest.mark.asyncio
async def test_health(client):
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_eql_route_uses_deterministic_fallback_without_llm(client):
    with patch("app.routes.chat._llm_complete", new=AsyncMock(side_effect=AssertionError("LLM should not be called"))):
        resp = await client.post(
            "/api/eql",
            json={
                "query_body": {
                    "query": {"term": {"source.ip": "1.2.3.4"}},
                    "size": 5,
                },
                "indices": ["auth-*"],
            },
        )

    assert resp.status_code == 200
    assert resp.json()["language"] == "esql"
    assert resp.json()["query"] == 'FROM auth-* | WHERE source.ip == "1.2.3.4" | LIMIT 5'


@pytest.mark.asyncio
async def test_chat_streams_zero_result_hint_for_rdpauth_destination_ip(client):
    async def fake_smart_search(provider, model, indices, query, max_results):
        yield ("result", [], {"query": {"exists": {"field": "destination.ip"}}, "_source": ["destination.ip"], "size": 20}, None)

    async def fake_convert(provider, model, query_body, indices):
        return [{"query_index": 1, "language": "esql", "query": "FROM windows.eventlogs.rdpauth-* | WHERE destination.ip IS NOT NULL | KEEP destination.ip | LIMIT 20"}]

    async def fake_stream_ollama(model, messages):
        yield ("content", "No destination IPs were found.", False, {})
        yield ("content", "", True, {"tokens": 6})

    with patch("app.routes.chat._smart_search", fake_smart_search), \
         patch("app.routes.chat._convert_query_artifacts_to_kibana_queries", fake_convert), \
         patch("app.routes.chat._stream_ollama", fake_stream_ollama):
        resp = await client.post(
            "/api/chat",
            json={"query": "Give me a list of destination IP addresses", "indices": ["windows.eventlogs.rdpauth-*"], "smart_query": True},
        )

    assert resp.status_code == 200
    body = resp.text
    assert "RDPAuth events in this dataset do not populate destination.* fields" in body


@pytest.mark.asyncio
async def test_chat_streams_clarification_and_stops_before_analysis(client):
    async def fake_smart_search(provider, model, indices, query, max_results):
        yield (
            "clarification",
            {
                "message": "I’m not fully sure which ip field to use for this question. I found: ClientIP (ip), ServerIP (ip). Which one should I search?",
                "role": "ip",
                "options": ["ClientIP", "ServerIP"],
            },
        )

    async def fake_stream_ollama(model, messages):
        raise AssertionError("analysis should not run when clarification is required")

    with patch("app.routes.chat._smart_search", fake_smart_search), \
         patch("app.routes.chat._stream_ollama", fake_stream_ollama):
        resp = await client.post(
            "/api/chat",
            json={"query": "Give me a list of IP addresses and how many times they appear", "indices": ["custom.logs-*"], "smart_query": True},
        )

    assert resp.status_code == 200
    body = resp.text
    assert "clarification_needed" in body
    assert "ClientIP" in body
    assert "ServerIP" in body
    assert "evidence_summary" not in body


@pytest.mark.asyncio
async def test_smart_search_rescues_bad_indicator_query_with_fast_path():
    async def fake_get_mapping_fields(es, indices):
        return (
            "source.ip (ip), destination.ip (ip), @timestamp (date), process.name (keyword)",
            {
                "source.ip": "ip",
                "destination.ip": "ip",
                "@timestamp": "date",
                "process.name": "keyword",
            },
        )

    async def fake_run_query(es, target, body, max_results):
        if body == {"query": {"term": {"IpAddress": "::1"}}, "_source": ["@timestamp"], "size": 5}:
            return []
        assert body["query"]["bool"]["minimum_should_match"] == 1
        return [
            {
                "@timestamp": "2024-01-01T00:00:00Z",
                "source": {"ip": "::1"},
                "process": {"name": "netstat.exe"},
            }
        ]

    events = []
    with patch("app.routes.chat.get_es_client", return_value=object()), \
         patch("app.routes.chat._get_mapping_fields", fake_get_mapping_fields), \
         patch("app.routes.chat._llm_complete", new=AsyncMock(return_value='{"query":{"term":{"IpAddress":"::1"}},"_source":["@timestamp"],"size":5}')), \
         patch("app.routes.chat._run_query", new=AsyncMock(side_effect=fake_run_query)), \
         patch("app.routes.chat._keyword_search", new=AsyncMock(return_value=[])):
        async for item in _smart_search(
            "openai",
            "gpt-test",
            ["windows.network.netstatenriched_netstat-*"],
            "When have I seen ::1 before and what was it doing?",
            5,
        ):
            events.append(item)

    result = [item for item in events if item[0] == "result"][-1]
    assert result[2]["query"]["bool"]["minimum_should_match"] == 1
    assert result[1][0]["source"]["ip"] == "::1"
    assert "built-in indicator hunt" in result[3]


@pytest.mark.asyncio
async def test_smart_search_uses_semantic_failed_login_planner():
    async def fake_get_mapping_fields(es, indices):
        return (
            "user.name (keyword), event.code (keyword), source.ip (ip)",
            {
                "user.name": "keyword",
                "event.code": "keyword",
                "source.ip": "ip",
            },
        )

    async def fake_run_query(es, target, body, max_results):
        assert body["aggs"]["by_account"]["terms"]["field"] == "user.name"
        return [{"by_account": "admin", "count": 3, "by_source_ip": "1.2.3.4"}]

    events = []
    with patch("app.routes.chat.get_es_client", return_value=object()), \
         patch("app.routes.chat._get_mapping_fields", fake_get_mapping_fields), \
         patch("app.routes.chat._run_query", new=AsyncMock(side_effect=fake_run_query)), \
         patch("app.routes.chat._keyword_search", new=AsyncMock(return_value=[])):
        async for item in _smart_search(
            "openai",
            "gpt-test",
            ["windows.eventlogs.evtx-*"],
            "Tell me about what accounts failed logins",
            10,
        ):
            events.append(item)

    result = [item for item in events if item[0] == "result"][-1]
    assert result[1][0]["by_account"] == "admin"
    assert "failed-login account summary" in result[3]


@pytest.mark.asyncio
async def test_smart_search_requests_clarification_for_ambiguous_generic_ip_question():
    async def fake_get_mapping_fields(es, indices):
        return (
            "ClientIP (ip), ServerIP (ip), @timestamp (date)",
            {
                "ClientIP": "ip",
                "ServerIP": "ip",
                "@timestamp": "date",
            },
            {
                "ClientIP": "192.168.1.10",
                "ServerIP": "192.168.1.20",
            },
        )

    events = []
    with patch("app.routes.chat.get_es_client", return_value=object()), \
         patch("app.routes.chat._get_mapping_fields", fake_get_mapping_fields):
        async for item in _smart_search(
            "openai",
            "gpt-test",
            ["custom.logs-*"],
            "Give me a list of IP addresses and how many times they appear",
            10,
        ):
            events.append(item)

    clarification = [item for item in events if item[0] == "clarification"][-1]
    assert clarification[1]["role"] == "ip"
    assert "ClientIP" in clarification[1]["options"]
    assert "ServerIP" in clarification[1]["options"]
