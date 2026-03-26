from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI

from .config import settings
from .es_client import close_es_client
from .auth import require_auth
from .routes import auth, chat, indices, models


@asynccontextmanager
async def lifespan(app: FastAPI):
    if len(settings.jwt_secret) < 32:
        raise RuntimeError(
            "JWT_SECRET must be at least 32 characters — set it in .env"
        )
    yield
    await close_es_client()


app = FastAPI(
    title="TalkIR API",
    description="Chat with your security logs via Elasticsearch + LLM",
    version="1.0.0",
    lifespan=lifespan,
)

app.include_router(auth.router, prefix="/api")
app.include_router(indices.router, prefix="/api")
app.include_router(chat.router, prefix="/api")
app.include_router(models.router, prefix="/api")


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/api/info")
async def info(_: dict = Depends(require_auth)):
    return {"model": settings.ollama_model}
