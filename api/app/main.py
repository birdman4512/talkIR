from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .es_client import close_es_client
from .auth import require_auth
from .routes import auth, chat, indices, models


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    await close_es_client()


app = FastAPI(
    title="TalkIR API",
    description="Chat with your security logs via Elasticsearch + LLM",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
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
