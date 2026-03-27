import asyncio
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
- For "list/show/relationship" queries: use match_all + _source with relevant fields.
- For "count/frequency/top N/how many/how often" queries: use aggregations (aggs) and set size:0.
- Do not invent specific values unless the user names them.

For questions requiring different event types (e.g. lateral movement needs auth events AND process events), return multiple queries:
{"queries":[{"query":{...},"size":N},{"query":{...},"aggs":{...},"size":0}]}
IMPORTANT: every key ("query","aggs","size","_source") must be INSIDE a query object in the array. Never place keys outside the array elements.
Use at most 3 queries. Prefer a single query unless multiple are clearly needed.

Fields ($indices): $fields

Example — "users signing in from 1.2.3.4":
{"query":{"bool":{"must":[{"term":{"IpAddress":"1.2.3.4"}},{"exists":{"field":"UserName"}}]}},"_source":["UserName","IpAddress","@timestamp"],"size":20}

Example — "how often did each user sign in":
{"query":{"match_all":{}},"aggs":{"by_user":{"terms":{"field":"UserName","size":50}}},"size":0}

Example — "username + source IP + count, ordered by count" (nested terms agg):
{"query":{"match_all":{}},"aggs":{"by_user":{"terms":{"field":"UserName","size":50,"order":{"_count":"desc"}},"aggs":{"by_ip":{"terms":{"field":"SourceIP","size":10}}}}},"size":0}

Example — "username + source IP + count" (composite agg, use when order matters across both fields):
{"query":{"match_all":{}},"aggs":{"by_user_ip":{"composite":{"size":100,"sources":[{"user":{"terms":{"field":"UserName"}}},{"ip":{"terms":{"field":"SourceIP"}}}]}}},"size":0}""")


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


_THINKING_MODEL_PATTERNS = ("deepseek", "r1", "qwq", "thinking")


def _supports_thinking(model: str) -> bool:
    name = model.lower()
    return any(p in name for p in _THINKING_MODEL_PATTERNS)


def _friendly_ollama_error(raw: str) -> str:
    """Convert raw Ollama error text to a human-readable message."""
    # Unwrap {"error": "..."} JSON if present
    try:
        msg = json.loads(raw).get("error", raw)
    except (json.JSONDecodeError, AttributeError):
        msg = raw

    m = re.search(r"requires more system memory \((.+?)\) than is available \((.+?)\)", msg)
    if m:
        return (
            f"Not enough RAM: model needs {m.group(1)} but only {m.group(2)} is free. "
            "Switch to a smaller model (e.g. llama3.2:3b) or a cloud provider (Claude / OpenAI)."
        )
    if "no longer running" in msg:
        return (
            "Model process crashed — likely out of memory. "
            "Try a smaller model or reduce the result count."
        )
    if "does not support thinking" in msg:
        return f"Model does not support thinking mode: {msg}"
    return msg


def _sanitize_query_body(body: dict) -> dict:
    """Fix common LLM query mistakes."""
    q = body.get("query", {})
    if isinstance(q, dict):
        if len(q) > 1:
            # Multiple sibling keys — wrap in bool.must
            body["query"] = {"bool": {"must": [{k: v} for k, v in q.items()]}}
        elif "match_all" in q and q["match_all"]:
            # match_all must be empty — LLM sometimes puts fields inside it
            body["query"]["match_all"] = {}

    # Fix composite sources that are strings instead of source-objects
    # e.g. "sources": ["UserName"] → "sources": [{"UserName": {"terms": {"field": "UserName"}}}]
    aggs = body.get("aggs", body.get("aggregations", {}))
    for agg_def in aggs.values():
        composite = agg_def.get("composite", {})
        sources = composite.get("sources")
        if isinstance(sources, list):
            fixed = []
            for src in sources:
                if isinstance(src, str):
                    fixed.append({src: {"terms": {"field": src}}})
                elif isinstance(src, dict):
                    fixed.append(src)
            composite["sources"] = fixed

    return body


def _flatten_agg_buckets(agg_name: str, agg_data: dict, parent: dict) -> list[dict]:
    """Recursively flatten aggregation buckets, carrying parent field values down."""
    rows = []
    for bucket in agg_data.get("buckets", []):
        key = bucket.get("key_as_string") or bucket.get("key")
        row = {**parent, **(dict(key) if isinstance(key, dict) else {agg_name: key})}
        # Recurse into any nested sub-aggregations
        nested = {k: v for k, v in bucket.items() if isinstance(v, dict) and "buckets" in v}
        if nested:
            for sub_name, sub_data in nested.items():
                rows.extend(_flatten_agg_buckets(sub_name, sub_data, row))
        else:
            row["count"] = bucket.get("doc_count", 0)
            rows.append(row)
    return rows


def _extract_hits(result: dict) -> list[dict]:
    """Extract records from an ES response — handles hits, terms/composite/nested aggs."""
    rows = [h["_source"] for h in result.get("hits", {}).get("hits", [])]
    for agg_name, agg_data in result.get("aggregations", {}).items():
        rows.extend(_flatten_agg_buckets(agg_name, agg_data, {}))
    return rows


def _fix_bare_keys(text: str) -> str:
    """Quote bare JS-style object keys: { key: "v" } → { "key": "v" }."""
    return re.sub(r'(?<=[{,])\s*([A-Za-z_]\w*)\s*:', r' "\1":', text)


def _extract_json(text: str) -> dict | None:
    """Pull a JSON object out of freeform LLM output."""
    text = text.strip()

    def _try(s: str) -> dict | list | None:
        for attempt in (s, _fix_bare_keys(s)):
            try:
                return json.loads(attempt)
            except json.JSONDecodeError:
                pass
            repaired = _repair_json(attempt)
            if repaired is not None:
                return repaired
        return None

    # Direct parse
    result = _try(text)
    if result is not None:
        return result if isinstance(result, dict) else {"queries": result}

    # Strip markdown code fences — greedy so nested braces are captured whole
    m = re.search(r'```(?:json)?\s*([\[{].*[\]}])\s*```', text, re.DOTALL)
    candidate = m.group(1) if m else None

    # Fallback: find outermost object or array
    if candidate is None:
        m2 = re.search(r'\{.*\}', text, re.DOTALL)
        candidate = m2.group(0) if m2 else None
    if candidate is None:
        m3 = re.search(r'\[.*\]', text, re.DOTALL)
        candidate = m3.group(0) if m3 else None

    if candidate:
        result = _try(candidate)
        if result is not None:
            return result if isinstance(result, dict) else {"queries": result}
    return None


def _repair_json(text: str) -> dict | list | None:
    """Append missing closing brackets/braces and retry parse."""
    missing_brackets = text.count('[') - text.count(']')
    missing_braces   = text.count('{') - text.count('}')
    if missing_brackets <= 0 and missing_braces <= 0:
        return None
    repaired = text.rstrip()
    trailing = ''
    while repaired.endswith('}') and missing_brackets > 0:
        trailing = '}' + trailing
        repaired  = repaired[:-1]
    repaired += ']' * missing_brackets + trailing
    repaired += '}' * missing_braces
    try:
        return json.loads(repaired)
    except json.JSONDecodeError:
        return None


async def _llm_complete(provider: str, model: str, system: str, user: str) -> str:
    """Single non-streaming LLM call — returns the full text response."""
    messages = [{"role": "user", "content": user}]

    if provider == "claude":
        if not settings.anthropic_api_key:
            raise ValueError("ANTHROPIC_API_KEY is not configured in .env")
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
            raise ValueError("OPENAI_API_KEY is not configured in .env")
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {settings.openai_api_key}", "Content-Type": "application/json"},
                json={"model": model, "messages": [{"role": "system", "content": system}] + messages},
            )
            data = resp.json()
            return data.get("choices", [{}])[0].get("message", {}).get("content", "")

    else:  # ollama
        payload: dict = {
            "model": model,
            "messages": [{"role": "system", "content": system}] + messages,
            "stream": False,
        }
        if _supports_thinking(model):
            payload["think"] = True
        async with httpx.AsyncClient(timeout=300.0) as client:
            resp = await client.post(f"{settings.ollama_host}/api/chat", json=payload)
            data = resp.json()
            if "error" in data:
                raise ValueError(_friendly_ollama_error(data["error"]))
            return data.get("message", {}).get("content", "")


async def _stream_query_gen_ollama(model: str, system: str, user: str):
    """Stream Ollama query generation, yielding ('thinking'|'content'|'error', text) tuples."""
    payload: dict = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "stream": True,
    }
    if _supports_thinking(model):
        payload["think"] = True

    async with httpx.AsyncClient(timeout=300.0) as client:
        async with client.stream(
            "POST",
            f"{settings.ollama_host}/api/chat",
            json=payload,
        ) as response:
            if response.status_code != 200:
                body = await response.aread()
                yield ("error", body.decode())
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
                    yield ("error", chunk["error"])
                    return

                native_think = chunk.get("message", {}).get("thinking", "")
                if native_think:
                    yield ("thinking", native_think)

                content = chunk.get("message", {}).get("content", "")
                if content:
                    buf += content
                    while buf:
                        if not in_think:
                            idx = buf.find("<think>")
                            if idx == -1:
                                hold = _partial_tag_suffix(buf, "<think>")
                                emit, buf = buf[: len(buf) - len(hold)], hold
                                if emit:
                                    yield ("content", emit)
                                break
                            else:
                                if idx > 0:
                                    yield ("content", buf[:idx])
                                buf = buf[idx + len("<think>"):]
                                in_think = True
                        else:
                            idx = buf.find("</think>")
                            if idx == -1:
                                hold = _partial_tag_suffix(buf, "</think>")
                                emit, buf = buf[: len(buf) - len(hold)], hold
                                if emit:
                                    yield ("thinking", emit)
                                break
                            else:
                                if idx > 0:
                                    yield ("thinking", buf[:idx])
                                buf = buf[idx + len("</think>"):]
                                in_think = False

                if chunk.get("done"):
                    if buf:
                        yield ("thinking" if in_think else "content", buf)
                    break


async def _run_query(es, target: str, query_body: dict, size_cap: int) -> list[dict]:
    """Run a single ES query body and return extracted records."""
    query_body["size"] = min(query_body.get("size", size_cap), size_cap)
    query_body = _sanitize_query_body(query_body)
    result = await es.search(index=target, body=query_body)
    return _extract_hits(result)


async def _smart_search(
    provider: str, model: str, indices: list[str], query: str, max_results: int
):
    """
    Async generator: yields ('query_thinking', text) while the LLM reasons about the query,
    then yields ('result', events, query_body_or_list, fallback_reason) once done.
    """
    es = get_es_client()

    index_str = ", ".join(indices) if indices else "all indices"
    fields_str = await _get_mapping_fields(es, indices)
    system = QUERY_GEN_PROMPT.substitute(
        max_results=max_results,
        indices=index_str,
        fields=fields_str,
    )

    # Generate query — stream for Ollama to surface thinking, batch for others
    if provider == "ollama":
        content_parts: list[str] = []
        ollama_error: str | None = None
        async for kind, text in _stream_query_gen_ollama(model, system, query):
            if kind == "thinking":
                yield ("query_thinking", text)
            elif kind == "error":
                ollama_error = text
                break
            else:
                content_parts.append(text)
        if ollama_error:
            events = await _keyword_search(indices, query, max_results)
            yield ("result", events, None, f"Query generation failed: {_friendly_ollama_error(ollama_error)} — fell back to keyword search.")
            return
        raw = "".join(content_parts)
    else:
        raw = await _llm_complete(provider, model, system, query)

    parsed = _extract_json(raw)

    if not parsed or ("query" not in parsed and "queries" not in parsed):
        events = await _keyword_search(indices, query, max_results)
        detail = raw[:500] if raw.strip() else "(model returned no output — possible OOM or context overflow)"
        yield ("result", events, None, f"LLM did not return valid query JSON — fell back to keyword search.\n\nLLM output:\n{detail}")
        return

    target = ",".join(indices[:20]) if indices else "_all"

    if "queries" in parsed:
        # ── Multiple queries — run in parallel ──────────────────────────────────
        raw_queries = parsed["queries"]
        if not isinstance(raw_queries, list) or not raw_queries:
            events = await _keyword_search(indices, query, max_results)
            yield ("result", events, None, "LLM returned empty queries list — fell back to keyword search.")
            return

        valid_raw = [qb for qb in raw_queries[:3] if isinstance(qb, dict) and "query" in qb]
        if not valid_raw:
            events = await _keyword_search(indices, query, max_results)
            yield ("result", events, None, "No valid query objects in LLM response — fell back to keyword search.")
            return

        per_query = max(1, max_results // len(valid_raw))
        total = len(valid_raw)
        all_events: list[dict] = []
        valid_bodies: list[dict] = []
        errors: list[str] = []

        # Launch all ES queries concurrently, yield progress as each completes
        tasks = {asyncio.create_task(_run_query(es, target, qb, per_query)): qb
                 for qb in valid_raw}
        pending = set(tasks)
        completed = 0

        while pending:
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                qb = tasks[task]
                completed += 1
                try:
                    hits = task.result()
                    all_events.extend(hits)
                    valid_bodies.append(qb)
                    yield ("query_progress", completed, total, len(hits))
                except Exception as exc:
                    errors.append(f"{exc} | query: {json.dumps(qb, separators=(',', ':'))[:300]}")
                    yield ("query_progress", completed, total, 0)

        if not valid_bodies:
            events = await _keyword_search(indices, query, max_results)
            yield ("result", events, None, f"All generated queries failed — fell back to keyword search. {'; '.join(errors)}")
            return

        # Deduplicate preserving insertion order
        seen: set[str] = set()
        deduped: list[dict] = []
        for e in all_events:
            k = json.dumps(e, sort_keys=True)
            if k not in seen:
                seen.add(k)
                deduped.append(e)

        fallback = f"Some queries failed: {'; '.join(errors)}" if errors else None
        yield ("result", deduped[:max_results], valid_bodies, fallback)

    else:
        # ── Single query ────────────────────────────────────────────────────────
        try:
            events = await _run_query(es, target, parsed, max_results)
            yield ("result", events, parsed, None)
        except Exception as exc:
            events = await _keyword_search(indices, query, max_results)
            yield ("result", events, parsed, f"Generated query failed ({exc}) — fell back to keyword search.\n\nFailing query: {json.dumps(parsed, separators=(',', ':'))[:400]}")


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
        return _extract_hits(result)
    except Exception:
        return []


_MAX_CONTEXT_CHARS = 24_000  # ~6 000 tokens — leave headroom for system prompt + reply


def _build_context_block(events: list[dict]) -> str:
    if not events:
        return "\n\n[No matching log events found in Elasticsearch for this query.]\n"
    lines = [f"\n\n--- {len(events)} log event(s) retrieved from Elasticsearch ---\n"]
    used = len(lines[0])
    included = 0
    for i, event in enumerate(events, 1):
        # Compact JSON; truncate any single value that is excessively long
        compact = {
            k: (v[:300] + "…" if isinstance(v, str) and len(v) > 300 else v)
            for k, v in event.items()
        }
        entry = f"\n[Event {i}] {json.dumps(compact, separators=(',', ':'))}\n"
        if used + len(entry) > _MAX_CONTEXT_CHARS:
            lines.append(f"\n[…{len(events) - included} more event(s) omitted — reduce result count or narrow your query]\n")
            break
        lines.append(entry)
        used += len(entry)
        included += 1
    return "".join(lines)


def _partial_tag_suffix(buf: str, tag: str) -> str:
    for i in range(min(len(tag) - 1, len(buf)), 0, -1):
        if buf.endswith(tag[:i]):
            return tag[:i]
    return ""


async def _stream_ollama(model: str, messages: list[dict]):
    payload: dict = {"model": model, "messages": messages, "stream": True}
    if _supports_thinking(model):
        payload["think"] = True
    async with httpx.AsyncClient(timeout=600.0) as client:
        async with client.stream(
            "POST",
            f"{settings.ollama_host}/api/chat",
            json=payload,
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
                    yield ("error", _friendly_ollama_error(chunk["error"]), False, {})
                    return

                # Native thinking field — Ollama 0.6+ with think: true
                native_think = chunk.get("message", {}).get("thinking", "")
                if native_think:
                    yield ("thinking", native_think, False, {})

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
                events: list[dict] = []
                query_body = None
                fallback_reason = None
                async for item in _smart_search(provider, model, indices, req.query, req.max_results):
                    if item[0] == "query_thinking":
                        yield f"data: {json.dumps({'query_thinking': item[1]})}\n\n"
                    elif item[0] == "query_progress":
                        _, done, total, count = item
                        yield f"data: {json.dumps({'query_progress': {'done': done, 'total': total, 'count': count}})}\n\n"
                    elif item[0] == "result":
                        events, query_body, fallback_reason = item[1], item[2], item[3]
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
            messages.extend(m.model_dump() for m in req.conversation_history[-20:])
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
