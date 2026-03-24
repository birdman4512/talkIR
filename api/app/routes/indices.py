import re
from fastapi import APIRouter, HTTPException
from ..es_client import get_es_client
from ..models import IndexInfo

router = APIRouter()

# Matches the Logstash-style date suffix added by Fluent Bit: -YYYY.MM.DD
_DATE_SUFFIX = re.compile(r'-\d{4}\.\d{2}\.\d{2}$')


def _group_indices(raw: list[dict]) -> list[IndexInfo]:
    """
    Group date-suffixed indices into wildcard data views.

    e.g.  auth-2024.01.01  +  auth-2024.01.02  →  auth-*  (combined doc count)
          myindex  (no date suffix)              →  myindex (unchanged)
    """
    groups: dict[str, dict] = {}

    for idx in raw:
        name = idx.get("index", "")
        if name.startswith("."):
            continue

        doc_count = int(idx.get("docs.count") or 0)

        if _DATE_SUFFIX.search(name):
            base    = _DATE_SUFFIX.sub("", name)
            pattern = base + "-*"
        else:
            base    = name
            pattern = name

        if pattern not in groups:
            groups[pattern] = {"name": pattern, "doc_count": 0}
        groups[pattern]["doc_count"] += doc_count

    return sorted(
        [IndexInfo(name=g["name"], doc_count=g["doc_count"], store_size="") for g in groups.values()],
        key=lambda x: x.name,
    )


@router.get("/indices", response_model=list[IndexInfo])
async def list_indices():
    try:
        es = get_es_client()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Elasticsearch error: {exc}") from exc
    try:
        resp = await es.cat.indices(format="json", h="index,docs.count,store.size")
        return _group_indices(resp)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Elasticsearch error: {exc}") from exc
