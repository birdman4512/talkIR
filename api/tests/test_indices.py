import pytest
from elasticsearch import ConnectionError as ESConnectionError


@pytest.mark.asyncio
async def test_list_indices_groups_dated_indices(client, mock_es):
    mock_es.cat.indices.return_value = [
        {"index": "auth-2024.01.01",  "docs.count": "100", "store.size": "1mb"},
        {"index": "auth-2024.01.02",  "docs.count": "50",  "store.size": "500kb"},
        {"index": "firewall-2024.01.01", "docs.count": "200", "store.size": "2mb"},
    ]

    resp = await client.get("/api/indices")
    assert resp.status_code == 200
    data = {i["name"]: i for i in resp.json()}

    assert "auth-*" in data
    assert data["auth-*"]["doc_count"] == 150   # 100 + 50 combined
    assert "firewall-*" in data
    assert data["firewall-*"]["doc_count"] == 200
    # individual dated names should not appear
    assert "auth-2024.01.01" not in data


@pytest.mark.asyncio
async def test_list_indices_filters_internal(client, mock_es):
    mock_es.cat.indices.return_value = [
        {"index": "auth-2024.01.01",  "docs.count": "100", "store.size": "1mb"},
        {"index": ".kibana",           "docs.count": "50",  "store.size": "200kb"},
        {"index": ".security-7",       "docs.count": "10",  "store.size": "50kb"},
    ]

    resp = await client.get("/api/indices")
    assert resp.status_code == 200
    names = [i["name"] for i in resp.json()]
    assert "auth-*" in names
    assert ".kibana" not in names
    assert ".security-7" not in names


@pytest.mark.asyncio
async def test_list_indices_returns_sorted(client, mock_es):
    mock_es.cat.indices.return_value = [
        {"index": "windows-2024.01.01", "docs.count": "5", "store.size": "1mb"},
        {"index": "auth-2024.01.01",    "docs.count": "5", "store.size": "1mb"},
    ]

    resp = await client.get("/api/indices")
    names = [i["name"] for i in resp.json()]
    assert names == sorted(names)


@pytest.mark.asyncio
async def test_list_indices_es_error_returns_502(client, mock_es):
    mock_es.cat.indices.side_effect = ESConnectionError("timeout")

    resp = await client.get("/api/indices")
    assert resp.status_code == 502
