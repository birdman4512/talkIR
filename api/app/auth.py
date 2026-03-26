import jwt
from datetime import datetime, timedelta, timezone
from fastapi import Depends, HTTPException, Request

from .config import settings

_ALGORITHM = "HS256"
_SHORT_TTL  = timedelta(hours=8)
_LONG_TTL   = timedelta(days=30)


def create_token(username: str, allowed_indices: list[str], remember: bool) -> str:
    expire = datetime.now(timezone.utc) + (_LONG_TTL if remember else _SHORT_TTL)
    payload = {"sub": username, "indices": allowed_indices, "exp": expire}
    return jwt.encode(payload, settings.jwt_secret, algorithm=_ALGORITHM)


def _decode(token: str) -> dict:
    try:
        return jwt.decode(token, settings.jwt_secret, algorithms=[_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Session expired — please log in again")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid session")


def require_auth(request: Request) -> dict:
    """FastAPI dependency — returns JWT payload or raises 401."""
    token = request.cookies.get("session")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return _decode(token)
