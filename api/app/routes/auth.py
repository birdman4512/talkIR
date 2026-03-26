import httpx
from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel

from ..auth import create_token, require_auth
from ..config import settings
from .indices import _group_indices

router = APIRouter()


class LoginRequest(BaseModel):
    username: str
    password: str
    remember: bool = False


async def _es_auth_and_indices(username: str, password: str) -> list[str]:
    """
    Verify credentials against ES /_security/_authenticate.
    Return the list of index patterns visible to this user (ES enforces RBAC).
    """
    try:
        async with httpx.AsyncClient(verify=settings.es_ca_cert_path, timeout=10.0) as client:
            auth_resp = await client.get(
                f"{settings.es_host}/_security/_authenticate",
                auth=(username, password),
            )
            if auth_resp.status_code == 401:
                raise HTTPException(status_code=401, detail="Invalid username or password")
            if not auth_resp.is_success:
                raise HTTPException(status_code=502, detail="Elasticsearch authentication unavailable")

            # Fetch only the indices this user can see — ES silently filters by their privileges
            idx_resp = await client.get(
                f"{settings.es_host}/_cat/indices?h=index,docs.count,store.size&format=json",
                auth=(username, password),
            )
            if not idx_resp.is_success:
                return []

            grouped = _group_indices(idx_resp.json())
            return [idx.name for idx in grouped]

    except HTTPException:
        raise
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Elasticsearch timed out")
    except Exception:
        raise HTTPException(status_code=502, detail="Authentication service unavailable")


@router.post("/auth/login")
async def login(req: LoginRequest, response: Response):
    allowed_indices = await _es_auth_and_indices(req.username, req.password)
    token = create_token(req.username, allowed_indices, req.remember)

    max_age = 60 * 60 * 24 * 30 if req.remember else 60 * 60 * 8
    response.set_cookie(
        key="session",
        value=token,
        httponly=True,
        samesite="strict",
        max_age=max_age,
    )
    return {"username": req.username, "allowed_indices": allowed_indices}


@router.post("/auth/logout")
async def logout(response: Response):
    response.delete_cookie("session", samesite="strict")
    return {"ok": True}


@router.get("/auth/me")
async def me(user: dict = Depends(require_auth)):
    return {"username": user["sub"], "allowed_indices": user.get("indices", [])}
