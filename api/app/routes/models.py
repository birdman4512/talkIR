import json
import re
import httpx
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from ..auth import require_auth
from ..config import settings

router = APIRouter()

# Matches valid Ollama model names, e.g. "llama3.2:3b", "deepseek-r1:7b"
_MODEL_RE = re.compile(r'^[\w][\w.\-:/]{0,99}$')

CATALOGUE = [
    {"name": "llama3.2:1b",      "size": "1.3 GB", "ram": 1.3, "speed": "fast",   "low_mem": True,  "tags": ["fast"],               "desc": "Minimal footprint — quick triage on memory-constrained systems"},
    {"name": "deepseek-r1:1.5b", "size": "1.1 GB", "ram": 1.1, "speed": "fast",   "low_mem": True,  "tags": ["thinking", "fast"],    "desc": "Thinking model that fits in low memory — shows reasoning chain"},
    {"name": "llama3.2:3b",      "size": "2.0 GB", "ram": 2.0, "speed": "fast",   "low_mem": False, "tags": ["fast"],               "desc": "Best default choice — fast responses, reliable query generation"},
    {"name": "mistral:7b",       "size": "4.4 GB", "ram": 4.4, "speed": "medium", "low_mem": False, "tags": [],                     "desc": "Solid all-rounder, good at following structured instructions"},
    {"name": "qwen2.5:7b",       "size": "4.4 GB", "ram": 4.4, "speed": "medium", "low_mem": False, "tags": ["structured"],         "desc": "Best for tables, counts, and aggregation queries"},
    {"name": "llama3.1:8b",      "size": "4.9 GB", "ram": 4.9, "speed": "medium", "low_mem": False, "tags": ["reasoning"],          "desc": "Strong reasoning and multi-step analysis"},
    {"name": "gemma2:9b",        "size": "5.5 GB", "ram": 5.5, "speed": "slow",   "low_mem": False, "tags": ["reasoning"],          "desc": "High quality output, strong at nuanced security analysis"},
    {"name": "deepseek-r1:7b",   "size": "4.7 GB", "ram": 4.7, "speed": "slow",   "low_mem": False, "tags": ["thinking"],           "desc": "Full thinking model — shows step-by-step reasoning chain"},
    {"name": "deepseek-r1:8b",   "size": "4.9 GB", "ram": 4.9, "speed": "slow",   "low_mem": False, "tags": ["thinking"],           "desc": "Best reasoning quality — recommended for complex investigations"},
]


async def _get_installed() -> set[str]:
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{settings.ollama_host}/api/tags")
            resp.raise_for_status()
            return {m["name"] for m in resp.json().get("models", [])}
    except Exception:
        return set()


@router.get("/models")
async def list_models(_: dict = Depends(require_auth)):
    """Return names of installed models."""
    installed = await _get_installed()
    return sorted(installed)


@router.get("/models/catalogue")
async def model_catalogue(_: dict = Depends(require_auth)):
    """Return curated model list with installed status."""
    installed = await _get_installed()
    return [
        {**m, "installed": m["name"] in installed}
        for m in CATALOGUE
    ]


class PullRequest(BaseModel):
    model: str = Field(..., pattern=_MODEL_RE.pattern)


@router.delete("/models/{model:path}")
async def delete_model(model: str, _: dict = Depends(require_auth)):
    """Delete a model from Ollama."""
    if not _MODEL_RE.match(model):
        raise HTTPException(status_code=400, detail="Invalid model name")
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.delete(
                f"{settings.ollama_host}/api/delete",
                json={"model": model},
            )
            if resp.status_code not in (200, 404):
                raise HTTPException(status_code=502, detail=f"Ollama returned {resp.status_code}")
            return {"deleted": model}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@router.post("/models/pull")
async def pull_model(req: PullRequest, _: dict = Depends(require_auth)):
    """Stream Ollama pull progress as SSE."""
    async def stream():
        try:
            async with httpx.AsyncClient(timeout=3600.0) as client:
                async with client.stream(
                    "POST",
                    f"{settings.ollama_host}/api/pull",
                    json={"name": req.model, "stream": True},
                ) as response:
                    async for line in response.aiter_lines():
                        if line:
                            yield f"data: {line}\n\n"
        except Exception as exc:
            yield f'data: {{"error": {json.dumps(str(exc))}}}\n\n'

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
