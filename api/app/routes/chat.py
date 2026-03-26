import json
import re
import httpx
from string import Template
from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse

from ..auth import require_auth
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

QUERY_GEN_PROMPT = Template("""Generate an Elasticsearch Query DSL JSON body for this security log query.

Output ONLY a valid JSON object — no markdown, no explanation.

Rules:
- Must have a "query" key. Max size: $max_results.
- Use only exact field names from the list below. No wildcards as field names.
- No join queries (has_child, has_parent, nested) — documents are flat.
- The "query" value must contain EXACTLY ONE top-level key (e.g. "bool", "match", "term", "exists"). NEVER put two query types as sibling keys.
- To combine conditions use bool.must / bool.should / bool.filter arrays.
- For "list/show/summarise/relationship" queries: use match_all + _source with relevant fields.
- Do not invent specific values unless the user names them.

Fields ($indices): $fields

Example — "users signing in from 1.2.3.4":
{"query":{"bool":{"must":[{"term":{"IpAddress":"1.2.3.4"}},{"exists":{"field":"UserName"}}]}},"_source":["UserName","IpAddress","@timestamp"],"size":20}""")


def _collect_fields(props: dict, prefix: str, out: list):
    for name, data in props.items():
        full = f"{prefix}.{name}" if prefix else name
        out.append(full)
        if "properties" in data:
            _collect_fields(data["properties"], full, out)


async def _get_mapping_fields(es, indices: list[str]) -> str:
    """Return a compact comma-separated list of actual field names from ES mappings."""
    try:
        target = ",".join(indices[:5]) if indices else "_all"
        mapping = await es.indices.get_mapping(index=target)
        fields: list[str] = []
        for idx_data in mapping.values():
            props = idx_data.get("mappings", {}).get("properties", {})
            _collect_fields(props, "", fields)
        # Deduplicate and cap
        seen: set[str] = set()
        unique = []
        for f in fields:
            if f not in seen:
                seen.add(f)
                unique.append(f)
        return ", ".join(unique[:30]) if unique else "(unavailable)"
    except Exception:
        return "(unavailable)"


def _sanitize_query_body(body: dict) -> dict:
    """Fix the common LLM mistake of putting multiple sibling keys inside 'query'."""
    q = body.get("query", {})
    if isinstance(q, dict) and len(q) > 1:
        # Wrap all sibling clauses into bool.must
        body["query"] = {"bool": {"must": [{k: v} for k, v in q.items()]}}
    return body


def _extract_json(text: str) -> dict | None:
    """Pull a JSON object out of freeform LLM output."""
    text = text.strip()
    # Direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Strip markdown code fences
    match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass
    # Find outermost JSON object
    match = re.search(r'\{.*\}', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass
    return None


async def _llm_complete(provider: str, model: str, system: str, user: str) -> str:
    """Single non-streaming LLM call — returns the full text response."""
    messages = [{"role": "user", "content": user}]

    if provider == "claude":
        if not settings.anthropic_api_key:
            return ""
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": settings.anthropic_api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={"model": model, "max_tokens": 2048, "system": system, "messages": messages},
            )
            data = resp.json()
            return data.get("content", [{}])[0].get("text", "")

    elif provider == "openai":
        if not settings.openai_api_key:
            return ""
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {settings.openai_api_key}", "Content-Type": "application/json"},
                json={"model": model, "messages": [{"role": "system", "content": system}] + messages},
            )
            data = resp.json()
            return data.get("choices", [{}])[0].get("message", {}).get("content", "")

    else:  # ollama
        async with httpx.AsyncClient(timeout=300.0) as client:
            resp = await client.post(
                f"{settings.ollama_host}/api/chat",
                json={
                    "model": model,
                    "messages": [{"role": "system", "content": system}] + messages,
                    "stream": False,
                },
            )
            data = resp.json()
            if "error" in data:
                raise ValueError(f"Ollama error: {data['error']}")
            return data.get("message", {}).get("content", "")


async def _smart_search(
    provider: str, model: str, indices: list[str], query: str, max_results: int
) -> tuple[list[dict], dict | None, str | None]:
    """
    Use the LLM to generate an ES query, run it, and return (events, query_body, fallback_reason).
    fallback_reason is set if we fell back to keyword search.
    """
    es = get_es_client()

    index_str = ", ".join(indices) if indices else "all indices"
    fields_str = await _get_mapping_fields(es, indices)
    system = QUERY_GEN_PROMPT.substitute(
        max_results=max_results,
        indices=index_str,
        fields=fields_str,
    )

    raw = await _llm_complete(provider, model, system, query)
    query_body = _extract_json(raw)

    if not query_body or "query" not in query_body:
        # Fall back to keyword search
        events = await _keyword_search(indices, query, max_results)
        detail = raw[:500] if raw.strip() else "(model returned no output — possible OOM or context overflow)"
        return events, None, f"LLM did not return valid query JSON — fell back to keyword search.\n\nLLM output:\n{detail}"

    # Enforce size cap and fix common structural mistakes
    query_body["size"] = min(query_body.get("size", max_results), max_results)
    query_body = _sanitize_query_body(query_body)

    try:
        target = ",".join(indices[:20]) if indices else "_all"
        result = await es.search(index=target, body=query_body)
        events = [hit["_source"] for hit in result["hits"]["hits"]]
        return events, query_body, None
    except Exception as exc:
        events = await _keyword_search(indices, query, max_results)
        return events, query_body, f"Generated query failed ({exc}) — fell back to keyword search."


async def _keyword_search(indices: list[str], query: str, max_results: int) -> list[dict]:
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

                if "error" in chunk:
                    yield ("error", f"Ollama: {chunk['error']}", False, {})
                    return

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
    if not settings.anthropic_api_key:
        yield ("error", "ANTHROPIC_API_KEY is not set in .env", False, {})
        return

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
            json={"model": model, "max_tokens": 8096, "system": system, "messages": non_system, "stream": True},
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
                    input_tokens = event.get("message", {}).get("usage", {}).get("input_tokens", 0)
                elif etype == "message_delta":
                    output_tokens = event.get("usage", {}).get("output_tokens", 0)
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
    if not settings.openai_api_key:
        yield ("error", "OPENAI_API_KEY is not set in .env", False, {})
        return

    async with httpx.AsyncClient(timeout=600.0) as client:
        async with client.stream(
            "POST",
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {settings.openai_api_key}", "Content-Type": "application/json"},
            json={"model": model, "messages": messages, "stream": True, "stream_options": {"include_usage": True}},
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
                    text = choices[0].get("delta", {}).get("content") or ""
                    if text:
                        yield ("content", text, False, {})


@router.post("/chat")
async def chat(req: ChatRequest, user: dict = Depends(require_auth)):
    provider = req.provider or "ollama"
    model    = req.model or settings.ollama_model

    # Restrict requested indices to what this user's JWT allows
    allowed = user.get("indices")
    if allowed is not None:
        allowed_set = set(allowed)
        req = req.model_copy(update={"indices": [i for i in req.indices if i in allowed_set]})

    async def stream_response():
        # ── Phase 1: resolve indices ────────────────────────────────────────────
        indices = req.indices
        if not indices:
            try:
                es = get_es_client()
                resp = await es.cat.indices(format="json", h="index")
                indices = [i["index"] for i in resp if not i["index"].startswith(".")]
            except Exception:
                indices = []

        if req.smart_query:
            # ── Smart query path ────────────────────────────────────────────────
            yield f"data: {json.dumps({'status': 'generating_query'})}\n\n"

            try:
                events, query_body, fallback_reason = await _smart_search(
                    provider, model, indices, req.query, req.max_results
                )
            except httpx.TimeoutException:
                yield f"data: {json.dumps({'error': 'Query generation timed out — try a faster model or disable smart query'})}\n\n"
                return
            except Exception as exc:
                yield f"data: {json.dumps({'error': f'Query generation failed: {exc}'})}\n\n"
                return

            if query_body:
                yield f"data: {json.dumps({'generated_query': query_body})}\n\n"
            if fallback_reason:
                yield f"data: {json.dumps({'query_warning': fallback_reason})}\n\n"

            yield f"data: {json.dumps({'status': 'found', 'count': len(events)})}\n\n"
        else:
            # ── Keyword search path ─────────────────────────────────────────────
            yield f"data: {json.dumps({'status': 'searching', 'indices': len(req.indices)})}\n\n"
            events = await _keyword_search(indices, req.query, req.max_results)
            yield f"data: {json.dumps({'status': 'found', 'count': len(events)})}\n\n"

        yield f"data: {json.dumps({'context': events})}\n\n"

        # ── Phase 2: analyse with LLM ───────────────────────────────────────────
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
