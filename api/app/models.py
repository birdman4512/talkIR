from pydantic import BaseModel, Field
from typing import Optional


class Message(BaseModel):
    role: str = Field(..., pattern=r'^(user|assistant|system)$')
    content: str = Field(..., max_length=10000)


class ChatRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=2000)
    indices: list[str] = Field(default_factory=list)
    max_results: int = Field(default=15, ge=1, le=10000)
    conversation_history: list[Message] = Field(default_factory=list)
    model: Optional[str] = None
    provider: str = "ollama"  # ollama | claude | openai
    smart_query: bool = False
    threat_intel: bool = False
    persona: str = "security"


class IndexInfo(BaseModel):
    name: str
    doc_count: int


class EqlRequest(BaseModel):
    query_body: dict
    indices: list[str] = Field(default_factory=list)
    model: Optional[str] = None
    provider: str = "ollama"
