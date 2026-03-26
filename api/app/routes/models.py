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
    {"name": "llama3.2:3b",      "size": "2.0 GB", "desc": "Fast, basic analysis"},
    {"name": "mistral:7b",        "size": "4.4 GB", "desc": "Good balance of speed and quality"},
    {"name": "llama3.1:8b",       "size": "4.9 GB", "desc": "Strong reasoning"},
    {"name": "qwen2.5:7b",        "size": "4.4 GB", "desc": "Best structured output (lists, tables)"},
    {"name": "gemma2:9b",         "size": "5.5 GB", "desc": "Strong reasoning, high quality"},
    {"name": "deepseek-r1:7b",    "size": "4.7 GB", "desc": "Shows reasoning chain (think block)"},
    {"name": "deepseek-r1:8b",    "size": "4.9 GB", "desc": "Best reasoning with think block"},
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
    model: str = Field(..., pattern=r'^[\w][\w.\-:/]{0,99}$')


@router.delete("/models/{model:path}")
async def delete_model(model: str, _: dict = Depends(require_auth)):
    """Delete a model from Ollama."""
    if not _MODEL_RE.match(model):
        raise HTTPException(status_code=400, detail="Invalid model name")
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.delete(
                f"{settings.ollama_host}/api/delete",
                json={"name": model},
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
            yield f'data: {{"error": "{exc}"}}\n\n'

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
