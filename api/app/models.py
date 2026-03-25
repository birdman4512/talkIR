from pydantic import BaseModel, Field
from typing import Optional


class ChatRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=2000)
    indices: list[str] = Field(default_factory=list)
    max_results: int = Field(default=15, ge=1, le=10000)
    conversation_history: list[dict] = Field(default_factory=list)
    model: Optional[str] = None
    provider: str = "ollama"  # ollama | claude | openai
    smart_query: bool = False


class IndexInfo(BaseModel):
    name: str
    doc_count: int
    store_size: str
