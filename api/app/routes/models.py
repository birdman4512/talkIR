import httpx
from fastapi import APIRouter
from ..config import settings

router = APIRouter()


@router.get("/models")
async def list_models():
    """Return models available in the local Ollama instance."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{settings.ollama_host}/api/tags")
            resp.raise_for_status()
            data = resp.json()
            return [m["name"] for m in data.get("models", [])]
    except Exception:
        return []
