import json
import httpx
from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from ..es_client import get_es_client
from ..models import ChatRequest
from ..config import settings

router = APIRouter()

SYSTEM_PROMPT = """You are an expert cybersecurity analyst and threat hunter with deep knowledge of:
- SIEM log analysis, anomaly detection, and behavioural baselining
- Attack patterns and TTPs mapped to the MITRE ATT&CK framework
- Common log formats: Windows Event Logs, Syslog, CEF, LEEF, JSON security events
- Indicators of Compromise (IoCs): IPs, hashes, domains, registry keys, file paths
- Incident response, digital forensics, and root-cause analysis
- Common attack chains: phishing → lateral movement → data exfiltration

When analysing security events:
1. Lead with the most critical findings (severity: CRITICAL > HIGH > MEDIUM > LOW > INFO)
2. Map observed behaviour to MITRE ATT&CK technique IDs (e.g. T1078 - Valid Accounts)
3. Highlight IoCs clearly so they can be actioned
4. Explain *why* something is suspicious, not just that it is
5. Recommend concrete next steps for investigation or remediation
6. If the data is insufficient to draw a conclusion, say so clearly

You will be given raw log events retrieved from Elasticsearch. Analyse them carefully and answer the user's question."""


async def _search_context(indices: list[str], query: str, max_results: int) -> list[dict]:
    try:
        es = get_es_client()
    except Exception:
        return []
    if not indices:
        try:
            resp = await es.cat.indices(format="json", h="index")
            indices = [i["index"] for i in resp if not i["index"].startswith(".")]
        except Exception:
            return []
    if not indices:
        return []
    try:
        result = await es.search(
            index=",".join(indices[:20]),
            body={
                "query": {
                    "multi_match": {
                        "query": query,
                        "fields": ["*"],
                        "type": "best_fields",
                        "fuzziness": "AUTO",
                    }
                },
                "size": max_results,
                "_source": True,
                "sort": [{"_score": "desc"}],
            },
        )
        return [hit["_source"] for hit in result["hits"]["hits"]]
    except Exception:
        return []


def _build_context_block(events: list[dict]) -> str:
    if not events:
        return "\n\n[No matching log events found in Elasticsearch for this query.]\n"
    lines = [f"\n\n--- {len(events)} log event(s) retrieved from Elasticsearch ---\n"]
    for i, event in enumerate(events, 1):
        lines.append(f"\n[Event {i}]\n{json.dumps(event, indent=2)}\n")
    return "".join(lines)


def _partial_tag_suffix(buf: str, tag: str) -> str:
    for i in range(min(len(tag) - 1, len(buf)), 0, -1):
        if buf.endswith(tag[:i]):
            return tag[:i]
    return ""


async def _stream_ollama(model: str, messages: list[dict]):
    """Yield (thinking|content, text, done, stats) tuples from Ollama."""
    async with httpx.AsyncClient(timeout=600.0) as client:
        async with client.stream(
            "POST",
            f"{settings.ollama_host}/api/chat",
            json={"model": model, "messages": messages, "stream": True},
        ) as response:
            if response.status_code != 200:
                body = await response.aread()
                yield ("error", body.decode(), False, {})
                return

            in_think = False
            buf = ""

            async for line in response.aiter_lines():
                if not line:
                    continue
                try:
                    chunk = json.loads(line)
                except json.JSONDecodeError:
                    continue

                content = chunk.get("message", {}).get("content", "")
                done = chunk.get("done", False)

                if content:
                    buf += content
                    while buf:
                        if not in_think:
                            idx = buf.find("<think>")
                            if idx == -1:
                                hold = _partial_tag_suffix(buf, "<think>")
                                emit, buf = buf[: len(buf) - len(hold)], hold
                                if emit:
                                    yield ("content", emit, False, {})
                                break
                            else:
                                if idx > 0:
                                    yield ("content", buf[:idx], False, {})
                                buf = buf[idx + len("<think>"):]
                                in_think = True
                        else:
                            idx = buf.find("</think>")
                            if idx == -1:
                                hold = _partial_tag_suffix(buf, "</think>")
                                emit, buf = buf[: len(buf) - len(hold)], hold
                                if emit:
                                    yield ("thinking", emit, False, {})
                                break
                            else:
                                if idx > 0:
                                    yield ("thinking", buf[:idx], False, {})
                                buf = buf[idx + len("</think>"):]
                                in_think = False

                if done:
                    if buf:
                        key = "thinking" if in_think else "content"
                        yield (key, buf, False, {})
                    stats = {}
                    eval_count = chunk.get("eval_count", 0)
                    eval_dur   = chunk.get("eval_duration", 0)
                    total_dur  = chunk.get("total_duration", 0)
                    if eval_count and eval_dur:
                        stats["tokens"]         = eval_count
                        stats["tokens_per_sec"] = round(eval_count / (eval_dur / 1e9), 1)
                    if total_dur:
                        stats["duration_sec"] = round(total_dur / 1e9, 1)
                    yield ("content", "", True, stats)
                    break


async def _stream_claude(model: str, messages: list[dict]):
    """Yield (thinking|content, text, done, stats) tuples from Anthropic Claude."""
    if not settings.anthropic_api_key:
        yield ("error", "ANTHROPIC_API_KEY is not set in .env", False, {})
        return

    # Split system message out — Claude API takes it separately
    system = next((m["content"] for m in messages if m["role"] == "system"), "")
    non_system = [m for m in messages if m["role"] != "system"]

    async with httpx.AsyncClient(timeout=600.0) as client:
        async with client.stream(
            "POST",
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": settings.anthropic_api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": model,
                "max_tokens": 8096,
                "system": system,
                "messages": non_system,
                "stream": True,
            },
        ) as response:
            if response.status_code != 200:
                body = await response.aread()
                yield ("error", body.decode(), False, {})
                return

            input_tokens = 0
            output_tokens = 0

            async for line in response.aiter_lines():
                if not line.startswith("data:"):
                    continue
                raw = line[5:].strip()
                if not raw:
                    continue
                try:
                    event = json.loads(raw)
                except json.JSONDecodeError:
                    continue

                etype = event.get("type", "")
                if etype == "content_block_delta":
                    delta = event.get("delta", {})
                    if delta.get("type") == "text_delta":
                        yield ("content", delta.get("text", ""), False, {})
                elif etype == "message_start":
                    usage = event.get("message", {}).get("usage", {})
                    input_tokens = usage.get("input_tokens", 0)
                elif etype == "message_delta":
                    usage = event.get("usage", {})
                    output_tokens = usage.get("output_tokens", 0)
                elif etype == "message_stop":
                    stats = {"tokens": output_tokens}
                    if input_tokens:
                        stats["input_tokens"] = input_tokens
                    yield ("content", "", True, stats)
                    break
                elif etype == "error":
                    yield ("error", event.get("error", {}).get("message", "Claude error"), False, {})
                    return


async def _stream_openai(model: str, messages: list[dict]):
    """Yield (thinking|content, text, done, stats) tuples from OpenAI."""
    if not settings.openai_api_key:
        yield ("error", "OPENAI_API_KEY is not set in .env", False, {})
        return

    async with httpx.AsyncClient(timeout=600.0) as client:
        async with client.stream(
            "POST",
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {settings.openai_api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": model,
                "messages": messages,
                "stream": True,
                "stream_options": {"include_usage": True},
            },
        ) as response:
            if response.status_code != 200:
                body = await response.aread()
                yield ("error", body.decode(), False, {})
                return

            output_tokens = 0

            async for line in response.aiter_lines():
                if not line.startswith("data:"):
                    continue
                raw = line[5:].strip()
                if raw == "[DONE]":
                    yield ("content", "", True, {"tokens": output_tokens})
                    break
                try:
                    chunk = json.loads(raw)
                except json.JSONDecodeError:
                    continue

                usage = chunk.get("usage")
                if usage:
                    output_tokens = usage.get("completion_tokens", 0)

                choices = chunk.get("choices", [])
                if choices:
                    delta = choices[0].get("delta", {})
                    text = delta.get("content") or ""
                    if text:
                        yield ("content", text, False, {})


@router.post("/chat")
async def chat(req: ChatRequest):
    provider = req.provider or "ollama"
    model    = req.model or settings.ollama_model

    async def stream_response():
        yield f"data: {json.dumps({'status': 'searching', 'indices': len(req.indices)})}\n\n"

        events = await _search_context(req.indices, req.query, req.max_results)

        yield f"data: {json.dumps({'status': 'found', 'count': len(events)})}\n\n"

        if events:
            yield f"data: {json.dumps({'context': events})}\n\n"

        context_block = _build_context_block(events)
        messages: list[dict] = [{"role": "system", "content": SYSTEM_PROMPT}]
        if req.conversation_history:
            messages.extend(req.conversation_history[-20:])
        messages.append({"role": "user", "content": req.query + context_block})

        try:
            if provider == "claude":
                stream = _stream_claude(model, messages)
            elif provider == "openai":
                stream = _stream_openai(model, messages)
            else:
                stream = _stream_ollama(model, messages)

            async for kind, text, done, stats in stream:
                if kind == "error":
                    yield f"data: {json.dumps({'error': text})}\n\n"
                    return
                elif kind == "thinking":
                    yield f"data: {json.dumps({'thinking': text})}\n\n"
                else:
                    yield f"data: {json.dumps({'content': text, 'done': done, 'stats': stats})}\n\n"
                    if done:
                        break

        except httpx.TimeoutException:
            yield f"data: {json.dumps({'error': 'LLM request timed out — try a smaller model or fewer results'})}\n\n"
        except Exception as exc:
            yield f"data: {json.dumps({'error': str(exc)})}\n\n"

    return StreamingResponse(
        stream_response(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
