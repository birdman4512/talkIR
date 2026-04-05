import asyncio
import ipaddress
import json
import re
import httpx
from collections import Counter
from datetime import datetime
from string import Template
from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse

from ..auth import require_auth
from ..es_client import get_es_client
from ..models import ChatRequest, EqlRequest
from ..config import settings
from ..request_log import log_request

router = APIRouter()

PERSONAS: dict[str, dict] = {
    "security": {
        "label": "Cybersecurity Analyst",
        "prompt": """You are an expert cybersecurity analyst and threat hunter with deep knowledge of:
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

You will be given raw log events retrieved from Elasticsearch. Analyse them carefully and answer the user's question.""",
    },
    "analyst": {
        "label": "Data Analyst",
        "prompt": """You are an expert data analyst. When analysing data:
1. Lead with key patterns, trends, and anomalies
2. Provide quantitative insights — counts, percentages, averages, rates of change
3. Highlight outliers and unexpected values
4. Flag data quality issues such as missing fields, inconsistencies, or duplicates
5. Use clear structured output — tables and bullet points where they aid clarity
6. Distinguish correlation from causation
7. Suggest follow-up questions that would add value to the analysis

You will be given raw records retrieved from Elasticsearch. Analyse them and answer the user's question accurately.""",
    },
    "devops": {
        "label": "DevOps / SRE",
        "prompt": """You are an expert DevOps engineer and Site Reliability Engineer. When analysing application and infrastructure logs:
1. Lead with service health: errors, latency spikes, resource exhaustion, crash loops
2. Identify error patterns — repeated exceptions, failure cascades, timeouts, OOM kills
3. Map issues to likely root causes: deploys, config changes, traffic spikes, dependency failures
4. Quantify impact — error rate, affected percentage of requests, duration of degradation
5. Recommend immediate mitigations and longer-term fixes
6. Distinguish urgent signals from background noise

You will be given raw log records from Elasticsearch. Analyse them and answer the user's question.""",
    },
    "general": {
        "label": "General Assistant",
        "prompt": """You are a helpful assistant that answers questions about data. Be accurate, concise, and factual. Base your answers only on the data provided. If the data is insufficient to answer a question, say so clearly rather than speculating. Use tables and lists where they aid clarity.

You will be given raw records retrieved from Elasticsearch. Answer the user's question based on those records.""",
    },
}

# Default persona used when none is specified
_DEFAULT_PERSONA = "security"

QUERY_GEN_PROMPT = Template("""Generate an Elasticsearch Query DSL JSON body for this security log query.

Output ONLY a valid JSON object — no markdown, no explanation.

Rules:
- Must have a "query" key. Max size: $max_results.
- Use ONLY the exact field names listed below. No wildcards as field names.
- No join queries (has_child, has_parent, nested) — documents are flat.
- The "query" value must contain EXACTLY ONE top-level key (e.g. "bool", "match", "term", "exists"). NEVER put two query types as sibling keys.
- To combine conditions use bool.must / bool.should / bool.filter arrays.
- For "list/show all X" queries: use exists on the relevant field + _source to return only needed columns.
- For "count/frequency/top N/how many/how often/summary/breakdown/distribution/most common" queries: use aggregations (aggs) and set size:0.
- NEVER use term to match a field name against itself (e.g. term:{IpAddress:"IpAddress"} is wrong). term matches a specific value.
- Do not invent specific values unless the user names them. For "summary of X" never put example values in filter clauses.
- When both a raw field (e.g. DestIP) and an ECS field (e.g. destination.ip) are available, prefer the ECS field — it has the correct type mapping.
- For authentication-style Windows event logs (especially RDPAuth and Security logons), the remote client is usually in source.ip rather than destination.ip.
- bool.should without bool.must means OR — add "minimum_should_match":1 so at least one condition must match. Without it, should clauses are optional.
- NEVER use match on (keyword) fields — use term or terms instead.
- JSON syntax: the colon separating a key from its value is OUTSIDE the quoted string. Write "match_all": {} NOT "match_all:{}". The string "match_all:{}" is a string literal, not a query clause.

Field type guide (use this to choose the right query clause):
- (keyword)   → exact match with term/terms, use directly in aggs
- (text+kw)   → full-text search with match; for exact match or aggs use field.keyword
- (text)       → full-text search with match only; cannot use for term or aggs
- (date)       → range queries with gte/lte; ISO-8601 or epoch_millis
- (ip)         → term or range; use CIDR notation for subnets
- (long/integer/float) → numeric range or term
- (boolean)    → term with true/false

For questions requiring different event types (e.g. lateral movement needs auth events AND process events), return multiple queries:
{"queries":[{"query":{...},"size":N},{"query":{...},"aggs":{...},"size":0}]}
IMPORTANT: every key ("query","aggs","size","_source") must be INSIDE a query object in the array. Never place keys outside the array elements.
Use at most 3 queries. Prefer a single query unless multiple are clearly needed.

Available fields in ($indices):
$fields

Example — "list all IP addresses" (exists — returns records that have the field):
{"query":{"exists":{"field":"IpAddress"}},"_source":["IpAddress","@timestamp"],"size":20}

Example — "users signing in from 1.2.3.4" (term — matches a specific known value):
{"query":{"bool":{"must":[{"term":{"IpAddress":"1.2.3.4"}},{"exists":{"field":"UserName"}}]}},"_source":["UserName","IpAddress","@timestamp"],"size":20}

Example — "how often did each user sign in" (keyword field → terms agg):
{"query":{"match_all":{}},"aggs":{"by_user":{"terms":{"field":"UserName","size":50}}},"size":0}

Example — "username + source IP + count, ordered by count" (nested terms agg):
{"query":{"match_all":{}},"aggs":{"by_user":{"terms":{"field":"UserName","size":50,"order":{"_count":"desc"}},"aggs":{"by_ip":{"terms":{"field":"SourceIP","size":10}}}}},"size":0}

Example — "username + source IP + count" (composite agg):
{"query":{"match_all":{}},"aggs":{"by_user_ip":{"composite":{"size":100,"sources":[{"user":{"terms":{"field":"UserName"}}},{"ip":{"terms":{"field":"SourceIP"}}}]}}},"size":0}

Example — "events in the last 24 hours" (date range):
{"query":{"range":{"@timestamp":{"gte":"now-24h","lte":"now"}}},"size":20}

Example — "summary/breakdown/top destination IPs" (terms agg — NEVER invent values, just aggregate):
{"query":{"match_all":{}},"aggs":{"by_dest_ip":{"terms":{"field":"destination.ip","size":50,"order":{"_count":"desc"}}}},"size":0}

Example — "per user: count successful vs failed logins" (filter sub-aggs — use this pattern for conditional counts within buckets, NOT bucket_count which does not exist):
{"query":{"match_all":{}},"aggs":{"by_user":{"terms":{"field":"UserName","size":50},"aggs":{"successful":{"filter":{"terms":{"EventID":[4624]}}},"failed":{"filter":{"terms":{"EventID":[4625]}}}}}},"size":0}""")


def _collect_fields(props: dict, prefix: str, out: list[tuple[str, str]]):
    """Recursively collect (field_path, type_hint) tuples from an ES mapping properties dict."""
    for name, data in props.items():
        full = f"{prefix}.{name}" if prefix else name
        ftype = data.get("type", "object")
        # For text fields, note if a .keyword sub-field exists for aggregations
        if ftype == "text":
            has_keyword = "keyword" in data.get("fields", {})
            hint = "text+kw" if has_keyword else "text"
        elif ftype == "object" and "properties" in data:
            # Don't emit object nodes — recurse into children instead
            _collect_fields(data["properties"], full, out)
            continue
        else:
            hint = ftype  # keyword, date, ip, long, integer, float, boolean, …
        out.append((full, hint))
        if "properties" in data:
            _collect_fields(data["properties"], full, out)


# Field types where a sample value is worth showing in the prompt
_SAMPLE_TYPES = {"ip", "keyword", "long", "integer", "text+kw"}
# Skip values that are UUIDs, hashes, or SIDs — not helpful for the LLM
import re as _re
_SKIP_SAMPLE_RE = _re.compile(
    r'^[0-9a-f]{32,}$'           # MD5/SHA hashes
    r'|^[0-9a-f-]{36}$'          # UUIDs
    r'|^S-1-\d'                   # Windows SIDs
    r'|^\d{10,}$',                # epoch timestamps, record IDs
    _re.IGNORECASE,
)


def _collect_sample_values(obj, prefix: str, out: dict[str, str], depth: int = 0) -> None:
    """Recursively collect one representative sample value per field path."""
    if depth > 4 or not isinstance(obj, dict):
        return
    for k, v in obj.items():
        key = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            _collect_sample_values(v, key, out, depth + 1)
        elif isinstance(v, list) and v and isinstance(v[0], dict):
            _collect_sample_values(v[0], key, out, depth + 1)
        elif v is not None and key not in out:
            s = str(v).strip()
            if s and s not in ("null", "-", "", "true", "false") and not _SKIP_SAMPLE_RE.match(s):
                out[key] = s[:60]


async def _get_field_samples(es, indices: list[str]) -> dict[str, str]:
    """Return {field_path: example_value} from a small sample of documents."""
    try:
        target = ",".join(indices) if indices else "_all"
        result = await es.search(
            index=target,
            body={"size": 5, "query": {"match_all": {}}, "_source": True},
        )
        samples: dict[str, str] = {}
        for hit in result.get("hits", {}).get("hits", []):
            _collect_sample_values(hit.get("_source", {}), "", samples)
        return samples
    except Exception:
        return {}


async def _get_mapping_fields(
    es, indices: list[str]
) -> tuple[str, dict[str, str], dict[str, str]]:
    """Return (prompt_string, field_type_dict) from ES index mappings.

    prompt_string — "FieldName (type), …" for the query-gen prompt (≤100 fields,
                    security-relevant fields prioritised)
    field_type_dict — {field_name: type_hint} for runtime query sanitisation (all fields)
    """
    # Keywords that signal security-relevant fields — prioritised in the prompt
    _PRIORITY_KEYWORDS = (
        "user", "login", "auth", "event", "ip", "host", "process",
        "account", "domain", "name", "id", "time", "command", "hash",
        "source", "target", "subject", "logon", "privilege", "service",
        "path", "exe", "cmdline", "sid", "computer",
    )
    try:
        target = ",".join(indices) if indices else "_all"
        mapping = await es.indices.get_mapping(index=target)
        fields: list[tuple[str, str]] = []
        for idx_data in mapping.values():
            props = idx_data.get("mappings", {}).get("properties", {})
            _collect_fields(props, "", fields)
        seen: set[str] = set()
        unique: list[tuple[str, str]] = []
        for name, hint in fields:
            if name not in seen:
                seen.add(name)
                unique.append((name, hint))
        if not unique:
            return "(unavailable)", {}
        field_types = dict(unique)
        # Sort: priority fields first (by lowest keyword match position), then alphabetical
        def _priority(item: tuple[str, str]) -> tuple[int, str]:
            name_lower = item[0].lower()
            for i, kw in enumerate(_PRIORITY_KEYWORDS):
                if kw in name_lower:
                    return (i, item[0])
            return (len(_PRIORITY_KEYWORDS), item[0])
        sorted_fields = sorted(unique, key=_priority)
        samples = await _get_field_samples(es, indices)
        parts: list[str] = []
        for n, h in sorted_fields[:100]:
            sample = samples.get(n, "")
            if sample and h in _SAMPLE_TYPES:
                parts.append(f"{n} ({h}, e.g. {sample})")
            else:
                parts.append(f"{n} ({h})")
        prompt_str = ", ".join(parts)
        return prompt_str, field_types, samples
    except Exception:
        return "(unavailable)", {}, {}


def _fix_agg_fields(aggs: dict, field_types: dict[str, str]) -> None:
    """Mutate aggs in-place: rewrite text+kw → field.keyword, remove pure text fields."""
    for agg_name in list(aggs.keys()):
        agg_def = aggs[agg_name]
        if not isinstance(agg_def, dict):
            continue

        # terms aggregation
        if "terms" in agg_def:
            # LLMs sometimes put "size" as a sibling of "terms" inside the agg
            # definition rather than inside "terms" — move it in.
            # e.g. {"terms": {"field": "x"}, "size": 0} → {"terms": {"field": "x", "size": 50}}
            if "size" in agg_def and isinstance(agg_def["size"], int):
                agg_def["terms"].setdefault("size", agg_def.pop("size") or 50)
            field = agg_def["terms"].get("field", "")
            ftype = field_types.get(field, "")
            if ftype == "text+kw":
                agg_def["terms"]["field"] = field + ".keyword"
            elif ftype == "text":
                del aggs[agg_name]
                continue

        # composite aggregation sources
        if "composite" in agg_def:
            sources = agg_def["composite"].get("sources", [])
            fixed = []
            for src in sources:
                if not isinstance(src, dict):
                    continue
                for src_name, src_def in src.items():
                    if "terms" in src_def:
                        field = src_def["terms"].get("field", "")
                        ftype = field_types.get(field, "")
                        if ftype == "text+kw":
                            src_def["terms"]["field"] = field + ".keyword"
                        elif ftype == "text":
                            break  # skip this source entirely
                else:
                    fixed.append(src)
            agg_def["composite"]["sources"] = fixed

        # recurse into sub-aggs
        sub = agg_def.get("aggs") or agg_def.get("aggregations")
        if isinstance(sub, dict):
            _fix_agg_fields(sub, field_types)


def _extract_referenced_fields(obj, out: set[str] | None = None) -> set[str]:
    """Recursively collect every 'field' value referenced in a query/agg body."""
    if out is None:
        out = set()
    if isinstance(obj, dict):
        if "field" in obj and isinstance(obj["field"], str):
            out.add(obj["field"])
        for v in obj.values():
            _extract_referenced_fields(v, out)
    elif isinstance(obj, list):
        for item in obj:
            _extract_referenced_fields(item, out)
    return out


_QUERY_CLAUSE_KEYS = frozenset({
    "term", "terms", "match", "match_phrase", "match_phrase_prefix",
    "range", "prefix", "wildcard", "regexp", "fuzzy",
})


def _extract_clause_key_fields(obj, out: set[str] | None = None) -> set[str]:
    """Collect field names used as query clause keys such as term/range/match."""
    if out is None:
        out = set()
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key in _QUERY_CLAUSE_KEYS and isinstance(value, dict):
                if "field" in value:
                    _extract_clause_key_fields(value, out)
                    continue
                for field_name in value:
                    if isinstance(field_name, str):
                        out.add(field_name)
            elif key == "sort":
                for item in value if isinstance(value, list) else [value]:
                    if isinstance(item, dict):
                        for field_name in item:
                            if isinstance(field_name, str) and not field_name.startswith("_"):
                                out.add(field_name)
            _extract_clause_key_fields(value, out)
    elif isinstance(obj, list):
        for item in obj:
            _extract_clause_key_fields(item, out)
    return out


def _suggest_field(unknown: str, field_types: dict[str, str]) -> str | None:
    """Find the closest known field name via case-insensitive substring matching."""
    lower = unknown.lower().replace(".", "").replace("_", "")
    candidates = []
    for f in field_types:
        f_norm = f.lower().replace(".", "").replace("_", "")
        if lower in f_norm or f_norm in lower:
            candidates.append(f)
    # Prefer shorter names (more specific match)
    candidates.sort(key=lambda x: (len(x), x))
    return candidates[0] if candidates else None


def _check_unknown_fields(body: dict, field_types: dict[str, str]) -> list[str]:
    """Return field names used in body that are not in field_types.
    Returns empty list when field_types is empty (mapping unavailable)."""
    if not field_types:
        return []
    all_known = set(field_types.keys()) | {f + ".keyword" for f in field_types}
    # Also allow meta fields
    all_known |= {"_id", "_index", "_score", "_type", "@timestamp"}
    used = _extract_referenced_fields(body) | _extract_clause_key_fields(body)
    return sorted(f for f in used if f not in all_known)


def _rewrite_unknown_fields(body: dict, field_types: dict[str, str]) -> dict[str, str]:
    """
    Attempt to rewrite unknown field names to their closest known equivalent.
    Returns a dict of {original: replacement} for any rewrites made.
    Operates on body in-place.
    """
    if not field_types:
        return {}
    all_known = set(field_types.keys()) | {f + ".keyword" for f in field_types}
    all_known |= {"_id", "_index", "_score", "_type", "@timestamp"}
    unknown = {
        f for f in (_extract_referenced_fields(body) | _extract_clause_key_fields(body))
        if f not in all_known
    }
    rewrites: dict[str, str] = {}
    for f in unknown:
        suggestion = _suggest_field(f, field_types)
        if suggestion:
            rewrites[f] = suggestion
    if rewrites:
        _apply_field_rewrites(body, rewrites)
    return rewrites


def _apply_field_rewrites(obj, rewrites: dict[str, str]) -> None:
    """Recursively replace field values in a query/agg body."""
    if isinstance(obj, dict):
        if "field" in obj and obj["field"] in rewrites:
            obj["field"] = rewrites[obj["field"]]
        for key, value in list(obj.items()):
            if key in _QUERY_CLAUSE_KEYS and isinstance(value, dict):
                for field_name in list(value.keys()):
                    replacement = rewrites.get(field_name)
                    if replacement and replacement != field_name:
                        value[replacement] = value.pop(field_name)
            elif key == "sort":
                items = value if isinstance(value, list) else [value]
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    for field_name in list(item.keys()):
                        replacement = rewrites.get(field_name)
                        if replacement and replacement != field_name:
                            item[replacement] = item.pop(field_name)
            elif key == "_source" and isinstance(value, list):
                obj[key] = [rewrites.get(v, v) if isinstance(v, str) else v for v in value]
        for v in obj.values():
            _apply_field_rewrites(v, rewrites)
    elif isinstance(obj, list):
        for item in obj:
            _apply_field_rewrites(item, rewrites)


_THINKING_MODEL_PATTERNS = ("deepseek", "r1", "qwq", "thinking")
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
_DOMAIN_RE = re.compile(r"\b(?=.{4,253}\b)(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}\b")


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


def _extract_indicator(query: str) -> tuple[str, str] | None:
    """Extract an obvious hunt indicator from a natural-language query."""
    for token in re.findall(r"[A-Fa-f0-9:.]{2,}", query):
        candidate = token.strip(".,;()[]{}<>\"'")
        if not candidate:
            continue
        try:
            return ("ip", str(ipaddress.ip_address(candidate)))
        except ValueError:
            continue

    hash_match = _HASH_RE.search(query)
    if hash_match:
        return ("hash", hash_match.group(0).lower())

    for match in _DOMAIN_RE.finditer(query):
        domain = match.group(0).lower()
        if not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", domain):
            return ("domain", domain)
    return None


def _indicator_exact_field(field_name: str, field_type: str) -> str | None:
    if field_type in {"keyword", "ip", "long", "integer", "float", "boolean"}:
        return field_name
    if field_type == "text+kw":
        return field_name + ".keyword"
    return None


def _build_indicator_should_clause(field_name: str, field_type: str, indicator_type: str, value: str) -> dict | None:
    exact_field = _indicator_exact_field(field_name, field_type)
    if exact_field:
        if indicator_type == "domain" and field_name == "url.original":
            return {"wildcard": {field_name: {"value": f"*{value}*", "case_insensitive": True}}}
        return {"term": {exact_field: value}}
    if indicator_type == "domain" and field_type in {"text", "wildcard"}:
        return {"wildcard": {field_name: {"value": f"*{value}*", "case_insensitive": True}}}
    return None


def _candidate_indicator_fields(field_types: dict[str, str], indicator_type: str) -> list[tuple[str, str]]:
    candidates: list[tuple[str, str]] = []
    for field_name, field_type in field_types.items():
        name = field_name.lower()
        if indicator_type == "ip":
            if field_type == "ip" or name.endswith(".ip") or "ipaddress" in name or name.endswith("ip"):
                candidates.append((field_name, field_type))
        elif indicator_type == "hash":
            if "hash" in name and field_type in {"keyword", "text+kw", "wildcard"}:
                candidates.append((field_name, field_type))
        elif indicator_type == "domain":
            if (
                "domain" in name
                or field_name in {"url.original", "host.name", "destination.domain", "source.domain"}
            ):
                candidates.append((field_name, field_type))
    return candidates


def _build_indicator_fast_path_query(
    query: str,
    field_types: dict[str, str],
    max_results: int,
) -> dict | None:
    """Build a deterministic indicator-hunt query for obvious IP/hash/domain prompts."""
    indicator = _extract_indicator(query)
    if not indicator or not field_types:
        return None

    indicator_type, indicator_value = indicator
    fields = _candidate_indicator_fields(field_types, indicator_type)
    should = []
    for field_name, field_type in fields:
        clause = _build_indicator_should_clause(field_name, field_type, indicator_type, indicator_value)
        if clause:
            should.append(clause)
    if not should:
        return None

    source_fields = []
    for field_name in (
        "@timestamp", "Timestamp", "TimeCreated",
        "event.action", "event.code", "event.outcome",
        "source.ip", "destination.ip", "SrcIP", "DestIP",
        "process.name", "process.command_line", "Path",
        "user.name", "UserName", "host.name", "Name", "Status", "Type",
    ):
        if field_name in field_types and field_name not in source_fields:
            source_fields.append(field_name)

    sort_fields = []
    for field_name in ("@timestamp", "Timestamp", "TimeCreated", "event.created"):
        if field_name in field_types:
            sort_fields.append({field_name: {"order": "asc"}})
    if not sort_fields:
        sort_fields = [{"_score": "desc"}]

    return {
        "query": {
            "bool": {
                "should": should,
                "minimum_should_match": 1,
            }
        },
        "_source": source_fields or True,
        "sort": sort_fields,
        "size": max_results,
    }


def _build_field_list_fast_path_query(
    query: str,
    schema_profile: dict,
    max_results: int,
) -> dict | None:
    schema_profile = _ensure_schema_profile(schema_profile)
    lower = query.lower()
    if not any(token in lower for token in ("list", "show", "give me", "what are")):
        return None
    if "ip" not in lower:
        return None
    if _looks_like_counts_question(query):
        return None

    field_types = schema_profile.get("field_types", {})
    target_field = None
    if "destination" in lower or "dest " in lower or "destip" in lower:
        target_field = _choose_role_field(schema_profile, "destination_ip")
    elif "source" in lower or "src " in lower or "sourceip" in lower or "srcip" in lower:
        target_field = _choose_role_field(schema_profile, "source_ip")
    elif "host ip" in lower:
        target_field = next((field for field in _choose_role_fields(schema_profile, "ip", 5) if "host" in _normalize_field_name(field)), None)

    if not target_field:
        return None

    source_fields = [target_field]
    if "@timestamp" in field_types:
        source_fields.append("@timestamp")
    elif "Timestamp" in field_types:
        source_fields.append("Timestamp")
    elif "TimeCreated" in field_types:
        source_fields.append("TimeCreated")

    return {
        "query": {"exists": {"field": target_field}},
        "_source": source_fields,
        "size": max_results,
    }


_DATE_RE = re.compile(r"\b(20\d{2}-\d{2}-\d{2})(?:[ T](\d{2}:\d{2}(?::\d{2})?))?\b")


def _extract_date_range(query: str) -> tuple[str, str] | None:
    matches = _DATE_RE.findall(query)
    if len(matches) < 2:
        return None

    values = []
    for date_part, time_part in matches[:2]:
        if time_part:
            values.append(f"{date_part}T{time_part}Z")
        else:
            values.append(f"{date_part}T00:00:00Z")

    start, end = values[0], values[1]
    if start > end:
        start, end = end, start
    if end.endswith("T00:00:00Z"):
        end = end.replace("T00:00:00Z", "T23:59:59Z")
    return start, end


def _pick_first_field(field_types: dict[str, str], candidates: tuple[str, ...]) -> str | None:
    for field in candidates:
        if field in field_types:
            return field
    return None


_ROLE_RULES = {
    "time": {
        "types": {"date", "date_nanos"},
        "keywords": ("time", "timestamp", "created", "modified", "access", "visit", "recordchange", "mtime"),
    },
    "user": {
        "types": {"keyword", "text+kw", "text", "wildcard"},
        "keywords": ("user", "account", "principal", "subject", "targetuser", "username", "logon"),
    },
    "host": {
        "types": {"keyword", "text+kw", "text"},
        "keywords": ("host", "computer", "device", "workstation", "machine"),
    },
    "ip": {
        "types": {"ip"},
        "keywords": ("ip", "address", "addr"),
    },
    "source_ip": {
        "types": {"ip"},
        "keywords": ("source", "src", "client", "remote", "origin", "workstation"),
        "requires": ("ip",),
    },
    "destination_ip": {
        "types": {"ip"},
        "keywords": ("destination", "dest", "target", "server", "peer", "dst"),
        "requires": ("ip",),
    },
    "url": {
        "types": {"keyword", "text+kw", "text", "wildcard"},
        "keywords": ("url", "uri", "visit", "website", "site", "history", "domain", "page", "title"),
    },
    "file_path": {
        "types": {"keyword", "text+kw", "text", "wildcard"},
        "keywords": ("path", "file", "name", "filename", "ospath", "link"),
    },
    "action": {
        "types": {"keyword", "text+kw", "text", "wildcard"},
        "keywords": ("action", "description", "message", "status", "operation", "outcome", "event", "type"),
    },
    "event_code": {
        "types": {"keyword", "long", "integer"},
        "keywords": ("eventid", "event", "code", "id"),
    },
    "outcome": {
        "types": {"keyword", "text+kw", "text"},
        "keywords": ("outcome", "result", "status", "failure", "success"),
    },
}


def _normalize_field_name(field_name: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", field_name.lower()).strip()


def _type_matches_role(field_type: str, allowed: set[str]) -> bool:
    normalized = str(field_type).lower()
    if normalized in allowed:
        return True
    if normalized.startswith("date") and "date" in allowed:
        return True
    return False


def _score_field_for_role(field_name: str, field_type: str, sample: str, role: str) -> int:
    rule = _ROLE_RULES[role]
    normalized_name = _normalize_field_name(field_name)
    condensed_name = normalized_name.replace(" ", "")
    score = 0
    matched_name = False
    matched_type = False

    if _type_matches_role(field_type, rule["types"]):
        score += 4
        matched_type = True

    for kw in rule["keywords"]:
        if kw in normalized_name or kw in condensed_name:
            score += 3
            matched_name = True

    for kw in rule.get("requires", ()):
        if kw in normalized_name or kw in condensed_name:
            score += 2
            matched_name = True
        else:
            return 0

    if sample:
        sample_lower = sample.lower()
        sample_supports = False
        if role in {"source_ip", "destination_ip", "ip"} and re.search(r"(?:\d{1,3}\.){3}\d{1,3}|:", sample_lower):
            score += 2
            sample_supports = True
        if role == "url" and (sample_lower.startswith("http://") or sample_lower.startswith("https://")):
            score += 3
            sample_supports = True
        if role == "time" and "t" in sample_lower and ":" in sample_lower:
            score += 1
            sample_supports = True
        if sample_supports:
            score += 2

    allow_type_only = role in {"ip", "time"}
    allow_sample_only = role in {"url"}
    if not matched_name and not (allow_type_only and matched_type):
        sample_text = sample.lower() if sample else ""
        if not (allow_sample_only and (sample_text.startswith("http://") or sample_text.startswith("https://"))):
            return 0

    if role == "destination_ip" and any(term in normalized_name for term in ("source", "src", "client")):
        score -= 3
    if role == "source_ip" and any(term in normalized_name for term in ("destination", "dest", "target", "server")):
        score -= 3
    if role == "url" and "title" in normalized_name:
        score -= 1

    return score


def _build_schema_profile(field_types: dict[str, str], samples: dict[str, str] | None = None) -> dict:
    sample_values = samples or {}
    roles: dict[str, list[str]] = {}
    role_details: dict[str, list[dict[str, object]]] = {}
    for role in _ROLE_RULES:
        ranked: list[tuple[int, int, str]] = []
        for field_name, field_type in field_types.items():
            score = _score_field_for_role(field_name, field_type, sample_values.get(field_name, ""), role)
            if score > 0:
                ranked.append((score, 1 if sample_values.get(field_name) else 0, field_name))
        ranked.sort(key=lambda item: (-item[0], -item[1], item[2]))
        roles[role] = [field_name for _, _, field_name in ranked]
        role_details[role] = [
            {
                "field": field_name,
                "score": score,
                "sample": sample_values.get(field_name, ""),
                "type": field_types.get(field_name, ""),
            }
            for score, _, field_name in ranked
        ]
    return {
        "field_types": field_types,
        "samples": sample_values,
        "roles": roles,
        "role_details": role_details,
    }


def _ensure_schema_profile(schema_or_field_types) -> dict:
    if isinstance(schema_or_field_types, dict) and "roles" in schema_or_field_types and "field_types" in schema_or_field_types:
        return schema_or_field_types
    if isinstance(schema_or_field_types, dict):
        return _build_schema_profile(schema_or_field_types, {})
    return _build_schema_profile({}, {})


def _choose_role_field(schema_profile: dict, role: str) -> str | None:
    schema_profile = _ensure_schema_profile(schema_profile)
    candidates = schema_profile.get("roles", {}).get(role, [])
    return candidates[0] if candidates else None


def _choose_role_fields(schema_profile: dict, role: str, limit: int = 5) -> list[str]:
    schema_profile = _ensure_schema_profile(schema_profile)
    return list(schema_profile.get("roles", {}).get(role, [])[:limit])


def _get_role_candidates(schema_profile: dict, role: str, limit: int = 5) -> list[dict[str, object]]:
    schema_profile = _ensure_schema_profile(schema_profile)
    details = schema_profile.get("role_details", {}).get(role, [])
    return [dict(item) for item in details[:limit]]


def _role_label(role: str) -> str:
    return role.replace("_", " ")


def _build_clarification_message(
    query: str,
    role: str,
    candidates: list[dict[str, object]],
    reason: str,
) -> dict[str, object]:
    label = _role_label(role)
    options = [str(item.get("field")) for item in candidates if item.get("field")]
    summary = ", ".join(
        f"{item['field']} ({item.get('type') or 'unknown'})"
        for item in candidates[:3]
        if item.get("field")
    )
    if options:
        message = (
            f"I’m not fully sure which {label} field to use for this question. "
            f"I found: {summary}. Which one should I search?"
        )
    else:
        message = (
            f"I couldn’t find a confident {label} field for this question in the selected data. "
            f"Please tell me which field I should use or choose a different data view."
        )
    return {
        "message": message,
        "reason": reason,
        "query": query,
        "role": role,
        "options": options,
    }


def _resolve_role_field_for_planning(schema_profile: dict, role: str) -> tuple[str | None, dict[str, object] | None]:
    candidates = _get_role_candidates(schema_profile, role, 4)
    if not candidates:
        return None, _build_clarification_message("", role, [], "missing_role")

    top = candidates[0]
    top_score = int(top.get("score", 0) or 0)
    second_score = int(candidates[1].get("score", 0) or 0) if len(candidates) > 1 else 0

    if role == "ip" and len(candidates) > 1:
        return None, _build_clarification_message("", role, candidates, "generic_ip_role")
    if top_score < 6:
        return None, _build_clarification_message("", role, candidates, "low_confidence")
    if len(candidates) > 1 and top_score - second_score <= 1 and top_score < 11:
        return None, _build_clarification_message("", role, candidates, "ambiguous_role")
    return str(top.get("field")), None


def _maybe_build_semantic_clarification(
    query: str,
    indices: list[str],
    schema_profile: dict,
) -> dict[str, object] | None:
    schema_profile = _ensure_schema_profile(schema_profile)
    intent = _parse_query_intent(query)
    name = str(intent.get("name"))

    roles_to_check: list[str] = []
    if name in {"frequency_breakdown", "field_inventory"}:
        role = str(intent.get("entity_role") or "")
        if role:
            roles_to_check.append(role)
    elif name == "history_timeline":
        roles_to_check.extend(["time", "url"])
    elif name == "failed_login_accounts":
        roles_to_check.append("user")
    elif name == "file_timeline":
        roles_to_check.append("time")

    for role in roles_to_check:
        field_name, clarification = _resolve_role_field_for_planning(schema_profile, role)
        if clarification:
            clarification["query"] = query
            clarification["indices"] = indices
            return clarification
        if not field_name:
            clarification = _build_clarification_message(query, role, _get_role_candidates(schema_profile, role, 4), "missing_role")
            clarification["indices"] = indices
            return clarification
    return None


def _looks_like_counts_question(query: str) -> bool:
    lower = query.lower()
    return (
        "count" in lower
        or "counts" in lower
        or "top" in lower
        or "most" in lower
        or "how many" in lower
        or "times they appear" in lower
        or "times it appears" in lower
    )


def _parse_query_intent(query: str) -> dict[str, object]:
    lower = query.lower()
    date_range = _extract_date_range(query)

    if _extract_indicator(query):
        return {"name": "indicator_lookup", "date_range": date_range}
    if "ip" in lower and _looks_like_counts_question(query):
        role = "destination_ip" if ("destination" in lower or "dest " in lower or "destip" in lower) else (
            "source_ip" if ("source" in lower or "src " in lower or "sourceip" in lower or "srcip" in lower) else "ip"
        )
        return {"name": "frequency_breakdown", "entity_role": role, "date_range": date_range}
    if "ip" in lower and any(token in lower for token in ("list", "show", "give me", "what are")):
        role = "destination_ip" if ("destination" in lower or "dest " in lower or "destip" in lower) else (
            "source_ip" if ("source" in lower or "src " in lower or "sourceip" in lower or "srcip" in lower) else "ip"
        )
        return {"name": "field_inventory", "entity_role": role, "date_range": date_range}
    if any(term in lower for term in ("failed login", "failed logon", "login failed", "logon failed", "accounts failed", "failed accounts")):
        return {"name": "failed_login_accounts", "date_range": date_range}
    if date_range and any(term in lower for term in ("website", "websites", "site", "sites", "visited", "history", "url", "urls")):
        return {"name": "history_timeline", "date_range": date_range}
    if date_range and any(term in lower for term in ("file", "files")) and any(term in lower for term in ("changed", "modified", "created", "accessed")):
        return {"name": "file_timeline", "date_range": date_range}
    return {"name": "generic_search", "date_range": date_range}


def _build_ip_count_fast_path_query(
    query: str,
    schema_profile: dict,
    max_results: int,
) -> dict | None:
    schema_profile = _ensure_schema_profile(schema_profile)
    lower = query.lower()
    if "ip" not in lower or not _looks_like_counts_question(query):
        return None

    target_field = None
    agg_name = None
    if "destination" in lower or "dest " in lower or "destip" in lower:
        target_field = _choose_role_field(schema_profile, "destination_ip")
        agg_name = "by_destination_ip"
    elif "source" in lower or "src " in lower or "sourceip" in lower or "srcip" in lower:
        target_field = _choose_role_field(schema_profile, "source_ip")
        agg_name = "by_source_ip"
    elif "host ip" in lower:
        target_field = next((field for field in _choose_role_fields(schema_profile, "ip", 5) if "host" in _normalize_field_name(field)), None)
        agg_name = "by_host_ip"

    if not target_field or not agg_name:
        return None

    return {
        "query": {"exists": {"field": target_field}},
        "aggs": {
            agg_name: {
                "terms": {
                    "field": target_field,
                    "size": min(max_results, 100),
                    "order": {"_count": "desc"},
                }
            }
        },
        "size": 0,
    }


def _build_mft_between_dates_query(
    query: str,
    indices: list[str],
    schema_profile: dict,
    max_results: int,
) -> dict | None:
    schema_profile = _ensure_schema_profile(schema_profile)
    lower = query.lower()
    if not any(idx.lower().startswith("windows.ntfs.mft") for idx in indices):
        return None
    if "between" not in lower and "from" not in lower:
        return None
    if not any(token in lower for token in ("file", "files", "changed", "modified", "created", "accessed")):
        return None

    date_range = _extract_date_range(query)
    if not date_range:
        return None
    start, end = date_range
    field_types = schema_profile.get("field_types", {})

    if "created" in lower:
        time_field = next((field for field in _choose_role_fields(schema_profile, "time", 10) if "created" in _normalize_field_name(field)), None)
    elif "access" in lower:
        time_field = next((field for field in _choose_role_fields(schema_profile, "time", 10) if "access" in _normalize_field_name(field)), None)
    else:
        time_field = next(
            (
                field for field in _choose_role_fields(schema_profile, "time", 12)
                if any(term in _normalize_field_name(field) for term in ("modified", "mtime", "recordchange"))
            ),
            None,
        )
    if not time_field:
        time_field = _choose_role_field(schema_profile, "time")
    if not time_field:
        return None

    source_fields = [
        field for field in (
            "file.path", "file.name", "file.mtime", "file.created", "file.accessed",
            "FileName", "OSPath", "host.name", "@timestamp",
            "LastModified0x10", "LastModified0x30", "LastRecordChange0x10", "LastRecordChange0x30",
        )
        if field in field_types
    ]

    return {
        "query": {"range": {time_field: {"gte": start, "lte": end}}},
        "_source": source_fields or True,
        "sort": [{time_field: {"order": "asc"}}],
        "size": max_results,
    }


def _build_failed_login_accounts_query(
    query: str,
    indices: list[str],
    schema_profile: dict,
    max_results: int,
) -> dict | None:
    schema_profile = _ensure_schema_profile(schema_profile)
    lower = query.lower()
    if not any(term in lower for term in ("failed login", "failed logon", "login failed", "logon failed", "accounts failed", "failed accounts")):
        return None
    if not any(term in lower for term in ("account", "accounts", "user", "users")):
        return None
    if not any(idx.lower().startswith("windows.eventlogs.evtx") or idx.lower().startswith("windows.eventlogs.rdpauth") for idx in indices):
        return None

    field_types = schema_profile.get("field_types", {})
    user_field = _choose_role_field(schema_profile, "user")
    if not user_field:
        return None

    should = []
    if "event.code" in field_types:
        should.append({"term": {"event.code": "4625"}})
    if "EventID" in field_types:
        should.append({"term": {"EventID": 4625}})
    if "event.outcome" in field_types:
        should.append({"term": {"event.outcome": "failure"}})
    if "Description.keyword" in field_types:
        should.append({"term": {"Description.keyword": "LOGON_FAILED"}})
    elif "Description" in field_types:
        should.append({"match": {"Description": "LOGON_FAILED"}})
    if not should:
        return None

    body = {
        "query": {"bool": {"should": should, "minimum_should_match": 1}},
        "aggs": {
            "by_account": {
                "terms": {
                    "field": user_field,
                    "size": min(max_results, 100),
                    "order": {"_count": "desc"},
                }
            }
        },
        "size": 0,
    }

    source_ip_field = _choose_role_field(schema_profile, "source_ip")
    if source_ip_field:
        body["aggs"]["by_account"]["aggs"] = {
            "by_source_ip": {
                "terms": {
                    "field": source_ip_field,
                    "size": 5,
                    "order": {"_count": "desc"},
                }
            }
        }
    return body


def _build_history_between_dates_query(
    query: str,
    indices: list[str],
    schema_profile: dict,
    max_results: int,
) -> dict | None:
    schema_profile = _ensure_schema_profile(schema_profile)
    lower = query.lower()
    if not any(".history" in idx.lower() for idx in indices):
        return None
    if not any(term in lower for term in ("website", "websites", "site", "sites", "visited", "history", "url", "urls")):
        return None

    date_range = _extract_date_range(query)
    if not date_range:
        return None
    start, end = date_range

    field_types = schema_profile.get("field_types", {})
    time_field = _choose_role_field(schema_profile, "time")
    url_field = _choose_role_field(schema_profile, "url")
    if not time_field or not url_field:
        return None

    source_fields = [
        field for field in (
            url_field, "title", time_field, "last_visit_time",
            "user.name", "User", "host.name", "visit_count",
        )
        if field in field_types
    ]

    return {
        "query": {"range": {time_field: {"gte": start, "lte": end}}},
        "_source": source_fields or True,
        "sort": [{time_field: {"order": "asc"}}],
        "size": max_results,
    }


def _build_semantic_fast_path_query(
    query: str,
    indices: list[str],
    schema_profile: dict,
    max_results: int,
) -> tuple[dict, str] | None:
    schema_profile = _ensure_schema_profile(schema_profile)
    intent = _parse_query_intent(query)
    planner_map: dict[str, tuple[str, object]] = {
        "frequency_breakdown": (
            "Used built-in IP counting for a direct source/destination IP summary request.",
            _build_ip_count_fast_path_query,
        ),
        "file_timeline": (
            "Used built-in MFT timeline query for a file-change question between two dates.",
            lambda q, f, m: _build_mft_between_dates_query(q, indices, f, m),
        ),
        "failed_login_accounts": (
            "Used built-in failed-login account summary for an authentication question.",
            lambda q, f, m: _build_failed_login_accounts_query(q, indices, f, m),
        ),
        "history_timeline": (
            "Used built-in browser-history timeline query for a website activity question.",
            lambda q, f, m: _build_history_between_dates_query(q, indices, f, m),
        ),
    }
    planner = planner_map.get(str(intent.get("name")))
    if planner:
        reason, builder = planner
        body = builder(query, schema_profile, max_results)
        if body:
            return body, reason
    return None


def _queries_equivalent(left: dict | list | None, right: dict | list | None) -> bool:
    if left is None or right is None:
        return False
    try:
        return json.dumps(left, sort_keys=True, separators=(",", ":")) == json.dumps(
            right, sort_keys=True, separators=(",", ":")
        )
    except TypeError:
        return left == right


def _collect_referenced_fields(node: object, out: set[str]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "field" and isinstance(value, str):
                out.add(value)
            elif key in _QUERY_CLAUSE_KEYS and isinstance(value, dict):
                for field_name in value.keys():
                    if field_name != "value" and isinstance(field_name, str):
                        out.add(field_name)
            elif key == "_source" and isinstance(value, list):
                out.update(field for field in value if isinstance(field, str))
            _collect_referenced_fields(value, out)
    elif isinstance(node, list):
        for item in node:
            _collect_referenced_fields(item, out)


def _build_zero_result_hint(indices: list[str], query_body: dict | list | None) -> str | None:
    if not query_body:
        return None
    bodies = query_body if isinstance(query_body, list) else [query_body]
    fields: set[str] = set()
    for body in bodies:
        _collect_referenced_fields(body, fields)

    lower_indices = [idx.lower() for idx in indices]
    if any(idx.startswith("windows.eventlogs.rdpauth") for idx in lower_indices):
        if {"destination.ip", "DestIP", "destination.port"}.intersection(fields):
            return (
                "RDPAuth events in this dataset do not populate destination.* fields. "
                "The remote client is recorded in source.ip instead."
            )
    return None


def _sanitize_query_body(body: dict) -> dict:
    """Fix common LLM query mistakes."""
    # Missing "query" key — add match_all so the body is valid
    if "query" not in body:
        body["query"] = {"match_all": {}}

    q = body.get("query", {})
    if isinstance(q, dict):
        # Aggregation syntax inside the query key — LLM confused terms agg with
        # terms query.  Detect by presence of aggregation-only keys (field+size,
        # field+order) and convert to a proper agg body.
        # e.g. {"query": {"terms": {"field": "destination.ip", "size": 50, "order": {...}}}}
        if "terms" in q and isinstance(q["terms"], dict):
            td = q["terms"]
            if "field" in td and ("size" in td or "order" in td):
                field = td["field"]
                agg_def = {"terms": td}
                agg_name = "by_" + field.replace(".", "_").replace("-", "_")
                body["query"] = {"match_all": {}}
                body.setdefault("aggs", {})[agg_name] = agg_def
                body["size"] = 0
                q = body["query"]

        # aggs/aggregations inside query — hoist to top level
        for agg_key in ("aggs", "aggregations"):
            if agg_key in q:
                body[agg_key] = q.pop(agg_key)
        # _source / size inside query — hoist to top level
        for hoist in ("size", "_source"):
            if hoist in q:
                body.setdefault(hoist, q.pop(hoist))
        # After hoisting, if query is now empty replace with match_all
        if not q:
            body["query"] = {"match_all": {}}
        elif len(q) > 1:
            # Multiple sibling keys — wrap in bool.must
            body["query"] = {"bool": {"must": [{k: v} for k, v in q.items()]}}
        elif "match_all" in q and q["match_all"]:
            # match_all must be empty — LLM sometimes puts fields inside it
            body["query"]["match_all"] = {}

    aggs = body.get("aggs", body.get("aggregations", {}))

    # LLMs sometimes put "size" or "_source" as sibling keys inside the aggs
    # object rather than at the top level — hoist them out and remove from aggs.
    for agg_key in ("aggs", "aggregations"):
        if agg_key in body and isinstance(body[agg_key], dict):
            for hoist_key in ("size", "_source"):
                if hoist_key in body[agg_key]:
                    body.setdefault(hoist_key, body[agg_key].pop(hoist_key))
    # Re-read aggs after potential mutation above
    aggs = body.get("aggs", body.get("aggregations", {}))

    # size:0 with no aggregations returns nothing — remove the override and
    # let _run_query apply its normal cap instead
    if body.get("size") == 0 and not aggs:
        del body["size"]

    # aggs present but no size set — default to 0 (return buckets only)
    if aggs and "size" not in body:
        body["size"] = 0

    # term/terms with wildcard "*" value is invalid — rewrite as match_all or exists.
    # e.g. {"term": {"destination.ip": "*"}} → {"match_all": {}}
    def _fix_wildcard_term(node: object) -> object:
        if not isinstance(node, dict):
            return node
        for key in ("term", "terms"):
            if key in node and isinstance(node[key], dict):
                vals = list(node[key].values())
                if vals and (vals[0] == "*" or vals == ["*"]):
                    return {"match_all": {}}
        return {k: _fix_wildcard_term(v) if isinstance(v, dict) else
                   [_fix_wildcard_term(i) for i in v] if isinstance(v, list) else v
                for k, v in node.items()}

    body["query"] = _fix_wildcard_term(body.get("query", {"match_all": {}}))

    # Fix composite sources that are strings instead of source-objects
    # e.g. "sources": ["UserName"] → "sources": [{"UserName": {"terms": {"field": "UserName"}}}]
    for agg_def in aggs.values():
        if not isinstance(agg_def, dict):
            continue
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

    # Fix typeless aggs — agg entries with only an "aggs" key and no type.
    # LLMs sometimes emit sibling aggs as containers instead of sub-aggs of the
    # bucket agg they belong to.  e.g.:
    #   "user_stats": {"terms": {...}}          ← bucket agg
    #   "user_success": {"aggs": {"s": {...}}}  ← typeless — LLM forgot the type
    # Fix: find the bucket agg siblings and move the sub-aggs into them.
    _fix_typeless_aggs(aggs)

    # Fix wrong terms/term query syntax emitted by LLMs that confuse the agg
    # syntax with query syntax.  e.g.:
    #   wrong: {"terms": {"field": "EventID", "value": 4624}}
    #   right: {"terms": {"EventID": [4624]}}
    _fix_terms_query_syntax(body.get("query", {}))
    # Also fix inside agg filters
    _fix_terms_in_aggs(aggs)

    return body


def _fix_terms_query_syntax(node: object) -> None:
    """
    Recursively fix LLM-generated terms/term query clauses that use the wrong
    syntax (agg-style field/value keys instead of query-style field name key).

    Wrong: {"terms": {"field": "EventID", "value": 4624}}
           {"term":  {"field": "EventID", "value": "Login"}}
    Right: {"terms": {"EventID": [4624]}}
           {"term":  {"EventID": "Login"}}
    """
    if not isinstance(node, dict):
        return
    for key, val in list(node.items()):
        if key in ("terms", "term") and isinstance(val, dict):
            field_name = val.get("field")
            if field_name and isinstance(field_name, str) and "value" in val:
                raw_val = val["value"]
                if key == "terms":
                    node[key] = {field_name: raw_val if isinstance(raw_val, list) else [raw_val]}
                else:  # "term"
                    node[key] = {field_name: raw_val}
                continue  # already rewritten, no need to recurse into it
        # Recurse into nested dicts and lists
        if isinstance(val, dict):
            _fix_terms_query_syntax(val)
        elif isinstance(val, list):
            for item in val:
                _fix_terms_query_syntax(item)


def _fix_terms_in_aggs(aggs: dict) -> None:
    """Recursively fix terms/term query syntax inside agg filter clauses."""
    if not isinstance(aggs, dict):
        return
    for agg_def in aggs.values():
        if not isinstance(agg_def, dict):
            continue
        # Fix filter queries
        for fk in ("filter", "filters"):
            fval = agg_def.get(fk)
            if isinstance(fval, dict):
                _fix_terms_query_syntax(fval)
        # Recurse into sub-aggs
        sub = agg_def.get("aggs") or agg_def.get("aggregations")
        if isinstance(sub, dict):
            _fix_terms_in_aggs(sub)


_BUCKET_AGG_TYPES = frozenset({
    "terms", "composite", "date_histogram", "histogram", "range", "date_range",
    "filters", "filter", "nested", "reverse_nested", "sampler", "missing", "global",
    "geotile_grid", "geohex_grid",
})


def _fix_typeless_aggs(aggs: dict) -> None:
    """
    Mutate aggs in-place: merge typeless container aggs into the nearest bucket agg.

    A typeless agg has only 'aggs'/'aggregations' keys and no ES agg type.
    When exactly one bucket agg sibling exists, the orphaned sub-aggs are moved
    into it.  When no bucket sibling exists, the sub-aggs are promoted to the
    current level (flattened).  If multiple bucket siblings exist, the sub-aggs
    are merged into the first one found.
    """
    typeless = {
        name: defn for name, defn in aggs.items()
        if isinstance(defn, dict)
        and not any(k in _BUCKET_AGG_TYPES or k in ("min", "max", "avg", "sum",
                    "cardinality", "value_count", "stats", "extended_stats",
                    "percentiles", "top_hits", "bucket_sort", "bucket_selector",
                    "moving_avg", "derivative", "cumulative_sum", "scripted_metric")
                    for k in defn)
        and ("aggs" in defn or "aggregations" in defn)
    }
    if not typeless:
        return

    # Find bucket agg siblings to absorb the orphaned sub-aggs
    bucket_name = next(
        (n for n, d in aggs.items()
         if n not in typeless and isinstance(d, dict)
         and any(k in _BUCKET_AGG_TYPES for k in d)),
        None,
    )

    for name, defn in typeless.items():
        orphaned_sub = defn.get("aggs") or defn.get("aggregations") or {}
        if bucket_name:
            target = aggs[bucket_name].setdefault("aggs", {})
            target.update(orphaned_sub)
        else:
            # No bucket sibling — promote sub-aggs to current level
            aggs.update(orphaned_sub)
        del aggs[name]

    # Recurse into all remaining agg sub-trees
    for defn in list(aggs.values()):
        if isinstance(defn, dict):
            sub = defn.get("aggs") or defn.get("aggregations")
            if isinstance(sub, dict):
                _fix_typeless_aggs(sub)


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


def _fix_merged_key_obj(text: str) -> str:
    """Fix LLM mistake where key and empty-object value are merged into one string.

    "match_all:{}"  →  "match_all": {}
    "match_all: {}" →  "match_all": {}
    """
    return re.sub(r'"([A-Za-z_][\w.]*?):\s*\{\}"', r'"\1": {}', text)


def _extract_json(text: str) -> dict | None:
    """Pull a JSON object out of freeform LLM output."""
    text = text.strip()
    # Strip JS/C-style comments (LLMs often add these inside JSON)
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.DOTALL)  # /* block comments */
    text = re.sub(r'//[^\n"]*', '', text)                   # // line comments

    def _try(s: str) -> dict | list | None:
        for attempt in (s, _fix_bare_keys(s), _fix_merged_key_obj(s), _fix_merged_key_obj(_fix_bare_keys(s))):
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
    if missing_brackets <= 0 and missing_braces <= 0 and missing_brackets >= 0:
        return None
    repaired = text.rstrip()
    # Strip extra closing brackets that have no matching opener
    if missing_brackets < 0:
        for _ in range(-missing_brackets):
            idx = repaired.rfind(']')
            if idx != -1:
                repaired = repaired[:idx] + repaired[idx+1:]
        missing_brackets = 0
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
        url = "https://api.anthropic.com/v1/messages"
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                url,
                headers={
                    "x-api-key": settings.anthropic_api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={"model": model, "max_tokens": 2048, "system": system, "messages": messages},
            )
            log_request(url, method="POST", source="claude", status_code=resp.status_code,
                        response_summary={"model": model, "prompt_chars": len(system) + len(user)})
            data = resp.json()
            return data.get("content", [{}])[0].get("text", "")

    elif provider == "openai":
        if not settings.openai_api_key:
            raise ValueError("OPENAI_API_KEY is not configured in .env")
        url = "https://api.openai.com/v1/chat/completions"
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                url,
                headers={"Authorization": f"Bearer {settings.openai_api_key}", "Content-Type": "application/json"},
                json={"model": model, "messages": [{"role": "system", "content": system}] + messages},
            )
            log_request(url, method="POST", source="openai", status_code=resp.status_code,
                        response_summary={"model": model, "prompt_chars": len(system) + len(user)})
            data = resp.json()
            return data.get("choices", [{}])[0].get("message", {}).get("content", "")

    else:  # ollama
        payload: dict = {
            "model": model,
            "messages": [{"role": "system", "content": system}] + messages,
            "stream": False,
            "options": {"num_ctx": 8192},  # cap KV cache to reduce memory pressure
        }
        if _supports_thinking(model):
            payload["think"] = True
        async with httpx.AsyncClient(timeout=300.0) as client:
            resp = await client.post(f"{settings.ollama_host}/api/chat", json=payload)
            if resp.status_code != 200:
                raise ValueError(_friendly_ollama_error(resp.text[:300]))
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
        "options": {"num_ctx": 8192},  # cap KV cache to reduce memory pressure
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
    mapping_info = await _get_mapping_fields(es, indices)
    if len(mapping_info) == 3:
        fields_str, field_types, samples = mapping_info
    else:
        fields_str, field_types = mapping_info
        samples = await _get_field_samples(es, indices)
    schema_profile = _build_schema_profile(field_types, samples)
    fast_path_query = _build_indicator_fast_path_query(query, field_types, max_results)
    if fast_path_query:
        target = ",".join(indices) if indices else "_all"
        try:
            events = _sort_events(await _run_query(es, target, fast_path_query, max_results))
            yield ("result", events, fast_path_query, "Used built-in indicator hunt for a direct IP/domain/hash lookup.")
            return
        except Exception as exc:
            events = _sort_events(await _keyword_search(indices, query, max_results))
            yield ("result", events, fast_path_query, f"Built-in indicator hunt failed ({exc}) — fell back to keyword search.")
            return

    clarification = _maybe_build_semantic_clarification(query, indices, schema_profile)
    if clarification:
        yield ("clarification", clarification)
        return

    semantic_fast_path = _build_semantic_fast_path_query(query, indices, schema_profile, max_results)
    if semantic_fast_path:
        semantic_query, semantic_reason = semantic_fast_path
        target = ",".join(indices) if indices else "_all"
        try:
            events = _sort_events(await _run_query(es, target, semantic_query, max_results))
            yield ("result", events, semantic_query, semantic_reason)
            return
        except Exception as exc:
            events = _sort_events(await _keyword_search(indices, query, max_results))
            yield ("result", events, semantic_query, f"{semantic_reason} Built-in planner failed ({exc}) — fell back to keyword search.")
            return

    field_list_query = _build_field_list_fast_path_query(query, schema_profile, max_results)
    if field_list_query:
        target = ",".join(indices) if indices else "_all"
        try:
            events = _sort_events(await _run_query(es, target, field_list_query, max_results))
            yield ("result", events, field_list_query, "Used built-in field listing for a direct field inventory request.")
            return
        except Exception as exc:
            events = _sort_events(await _keyword_search(indices, query, max_results))
            yield ("result", events, field_list_query, f"Built-in field listing failed ({exc}) — fell back to keyword search.")
            return

    system = QUERY_GEN_PROMPT.substitute(
        max_results=max_results,
        indices=index_str,
        fields=fields_str,
    )

    # Surface query-gen prompt in debug mode
    yield ("debug_query_prompt", system, query)

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
            events = _sort_events(await _keyword_search(indices, query, max_results))
            yield ("result", events, None, f"Query generation failed: {_friendly_ollama_error(ollama_error)} — fell back to keyword search.")
            return
        raw = "".join(content_parts)
    else:
        raw = await _llm_complete(provider, model, system, query)

    parsed = _extract_json(raw)

    if not parsed or ("query" not in parsed and "queries" not in parsed):
        events = _sort_events(await _keyword_search(indices, query, max_results))
        detail = raw[:500] if raw.strip() else "(model returned no output — possible OOM or context overflow)"
        yield ("result", events, None, f"LLM did not return valid query JSON — fell back to keyword search.\n\nLLM output:\n{detail}")
        return

    target = ",".join(indices) if indices else "_all"

    if "queries" in parsed:
        # ── Multiple queries — run in parallel ──────────────────────────────────
        raw_queries = parsed["queries"]
        if not isinstance(raw_queries, list) or not raw_queries:
            events = _sort_events(await _keyword_search(indices, query, max_results))
            yield ("result", events, None, "LLM returned empty queries list — fell back to keyword search.")
            return

        valid_raw = [qb for qb in raw_queries[:3] if isinstance(qb, dict)]
        if not valid_raw:
            events = _sort_events(await _keyword_search(indices, query, max_results))
            yield ("result", events, None, "No valid query objects in LLM response — fell back to keyword search.")
            return

        # Sanitize structure first (hoist aggs from inside query), then fix field types
        unknown_fields: list[str] = []
        rewrites_all: dict[str, str] = {}
        for qb in valid_raw:
            _sanitize_query_body(qb)
            rewrites_all.update(_rewrite_unknown_fields(qb, field_types))
            _fix_agg_fields(qb.get("aggs", qb.get("aggregations", {})), field_types)
            unknown_fields.extend(_check_unknown_fields(qb, field_types))

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
            events = _sort_events(await _keyword_search(indices, query, max_results))
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

        parts = []
        if errors:
            parts.append(f"Some queries failed: {'; '.join(errors)}")
        if rewrites_all:
            parts.append(f"Note: auto-corrected field(s): {', '.join(f'{k} → {v}' for k, v in rewrites_all.items())}")
        if unknown_fields:
            suggestions = {f: _suggest_field(f, field_types) for f in unknown_fields}
            parts.append("Warning: unresolvable field(s): " + ", ".join(
                f"{f} (try: {suggestions[f]})" if suggestions[f] else f
                for f in sorted(set(unknown_fields))
            ))
        fallback = "\n\n".join(parts) if parts else None
        yield ("result", _sort_events(deduped)[:max_results], valid_bodies, fallback)

    else:
        # ── Single query ────────────────────────────────────────────────────────
        _sanitize_query_body(parsed)  # hoist aggs from inside query before fixing field types
        rewrites = _rewrite_unknown_fields(parsed, field_types)
        _fix_agg_fields(parsed.get("aggs", parsed.get("aggregations", {})), field_types)
        still_unknown = _check_unknown_fields(parsed, field_types)
        warn_parts = []
        if rewrites:
            warn_parts.append(f"Note: auto-corrected field(s): {', '.join(f'{k} → {v}' for k, v in rewrites.items())}")
        if still_unknown:
            suggestions = {f: _suggest_field(f, field_types) for f in still_unknown}
            warn_parts.append("Warning: unresolvable field(s): " + ", ".join(
                f"{f} (try: {suggestions[f]})" if suggestions[f] else f
                for f in sorted(still_unknown)
            ))
        unknown_warn = ("\n\n" + "\n\n".join(warn_parts)) if warn_parts else None
        if fast_path_query and still_unknown and not _queries_equivalent(parsed, fast_path_query):
            try:
                events = _sort_events(await _run_query(es, target, fast_path_query, max_results))
                rescue_note = "Used built-in indicator hunt because the generated query referenced unresolved field names."
                if unknown_warn:
                    rescue_note = f"{rescue_note}{unknown_warn}"
                yield ("result", events, fast_path_query, rescue_note)
                return
            except Exception:
                pass
        try:
            events = _sort_events(await _run_query(es, target, parsed, max_results))
            if fast_path_query and not events and not _queries_equivalent(parsed, fast_path_query):
                try:
                    rescue_events = _sort_events(await _run_query(es, target, fast_path_query, max_results))
                    if rescue_events:
                        rescue_note = "Used built-in indicator hunt because the generated query returned no matching records."
                        if unknown_warn:
                            rescue_note = f"{rescue_note}{unknown_warn}"
                        yield ("result", rescue_events, fast_path_query, rescue_note)
                        return
                except Exception:
                    pass
            yield ("result", events, parsed, unknown_warn)
        except Exception as exc:
            if fast_path_query and not _queries_equivalent(parsed, fast_path_query):
                try:
                    events = _sort_events(await _run_query(es, target, fast_path_query, max_results))
                    rescue_note = f"Generated query failed ({exc}) — used built-in indicator hunt instead."
                    if unknown_warn:
                        rescue_note = f"{rescue_note}{unknown_warn}"
                    yield ("result", events, fast_path_query, rescue_note)
                    return
                except Exception:
                    pass
            events = _sort_events(await _keyword_search(indices, query, max_results))
            yield ("result", events, parsed, f"Generated query failed ({exc}) — fell back to keyword search.\n\nFailing query: {json.dumps(parsed, separators=(',', ':'))[:400]}{unknown_warn or ''}")


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
            index=",".join(indices),
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


_MAX_EVIDENCE_EXAMPLES = 5


def _get_value(obj: dict, field: str):
    """Read a field from a flat event or a nested dotted path."""
    if field in obj:
        return obj[field]
    current = obj
    for part in field.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _pick_value(obj: dict, candidates: tuple[str, ...]):
    for field in candidates:
        value = _get_value(obj, field)
        if value not in (None, "", [], {}):
            return value
    return None


def _infer_field_type_from_value(value) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "long"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return "text"
        if ("-" in text or "T" in text or ":" in text) and re.search(r"\d{4}-\d{2}-\d{2}", text):
            try:
                datetime.fromisoformat(text.replace("Z", "+00:00"))
                return "date"
            except ValueError:
                pass
        if text.startswith("http://") or text.startswith("https://"):
            return "wildcard"
        return "text+kw"
    return "text"


def _collect_event_schema(obj, prefix: str, field_types: dict[str, str], samples: dict[str, str]) -> None:
    if not isinstance(obj, dict):
        return
    for key, value in obj.items():
        field_name = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            _collect_event_schema(value, field_name, field_types, samples)
        elif isinstance(value, list):
            if value and isinstance(value[0], dict):
                _collect_event_schema(value[0], field_name, field_types, samples)
            elif value and field_name not in field_types:
                field_types[field_name] = _infer_field_type_from_value(value[0])
                samples[field_name] = str(value[0])[:120]
        elif value not in (None, "", [], {}):
            if field_name not in field_types:
                field_types[field_name] = _infer_field_type_from_value(value)
                samples[field_name] = str(value)[:120]


def _build_event_schema_profile(events: list[dict]) -> dict:
    field_types: dict[str, str] = {}
    samples: dict[str, str] = {}
    for event in events[:20]:
        _collect_event_schema(event, "", field_types, samples)
    return _build_schema_profile(field_types, samples)


def _is_aggregate_row(event: dict) -> bool:
    if not isinstance(event, dict):
        return False
    keys = set(event.keys())
    if "count" not in keys:
        return False
    non_count = [k for k in keys if k != "count"]
    return bool(non_count) and all(k.startswith("by_") or k in {"count"} for k in keys)


def _build_aggregate_evidence_summary(events: list[dict]) -> str | None:
    if not events or not all(_is_aggregate_row(event) for event in events):
        return None
    first = events[0]
    group_fields = [k for k in first.keys() if k != "count"]
    lines = [f"- Matching groups: {len(events)}"]
    if group_fields:
        lines.append(f"- Grouped by: {', '.join(group_fields)}")
    top = events[: min(len(events), _MAX_EVIDENCE_EXAMPLES)]
    for idx, row in enumerate(top, 1):
        lines.append(f"- Row {idx}: {json.dumps(row, separators=(',', ':'))}")
    return "\n".join(lines) + "\n"


def _coerce_timestamp(value) -> tuple[float | None, str | None]:
    if value in (None, ""):
        return None, None
    if isinstance(value, (int, float)):
        dt = datetime.utcfromtimestamp(value / 1000 if value > 10_000_000_000 else value)
        return dt.timestamp(), dt.isoformat() + "Z"
    if not isinstance(value, str):
        return None, str(value)
    text = value.strip()
    if not text:
        return None, None
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return dt.timestamp(), text
    except ValueError:
        return None, text


def _event_sort_key(event: dict) -> tuple[int, float, str]:
    schema_profile = _build_event_schema_profile([event])
    time_field = _choose_role_field(schema_profile, "time")
    raw_ts = _get_value(event, time_field) if time_field else None
    epoch, text = _coerce_timestamp(raw_ts)
    if epoch is None:
        return (1, 0.0, json.dumps(event, sort_keys=True))
    return (0, epoch, text or "")


def _sort_events(events: list[dict]) -> list[dict]:
    return sorted(events, key=_event_sort_key)


def _event_glimpse(event: dict, schema_profile: dict) -> dict:
    glimpse: dict[str, object] = {}
    for label, role in (
        ("time", "time"),
        ("action", "action"),
        ("user", "user"),
        ("host", "host"),
        ("ip", "ip"),
        ("artifact", "url"),
    ):
        field_name = _choose_role_field(schema_profile, role)
        value = _get_value(event, field_name) if field_name else None
        if value not in (None, "", [], {}):
            glimpse[label] = value
    if not glimpse:
        for key in list(event.keys())[:4]:
            glimpse[key] = event[key]
    return glimpse


def _format_top(counter: Counter, limit: int = 5) -> str:
    if not counter:
        return "none"
    return ", ".join(f"{value} ({count})" for value, count in counter.most_common(limit))


def _build_evidence_summary(events: list[dict], user_query: str = "") -> str:
    if not events:
        return "- No matching records were retrieved.\n"
    aggregate_summary = _build_aggregate_evidence_summary(events)
    if aggregate_summary:
        return aggregate_summary

    ordered = _sort_events(events)
    schema_profile = _build_event_schema_profile(ordered)
    time_field = _choose_role_field(schema_profile, "time")
    action_field = _choose_role_field(schema_profile, "action")
    user_field = _choose_role_field(schema_profile, "user")
    host_field = _choose_role_field(schema_profile, "host")
    ip_field = _choose_role_field(schema_profile, "ip")

    first_time = _get_value(ordered[0], time_field) if time_field else None
    last_time = _get_value(ordered[-1], time_field) if time_field else None

    action_counts = Counter()
    user_counts = Counter()
    host_counts = Counter()
    ip_counts = Counter()
    for event in ordered:
        for counter, field_name in (
            (action_counts, action_field),
            (user_counts, user_field),
            (host_counts, host_field),
            (ip_counts, ip_field),
        ):
            value = _get_value(event, field_name) if field_name else None
            if value not in (None, "", [], {}):
                counter[str(value)] += 1

    lines = [
        f"- Matching records: {len(events)}",
        f"- First seen: {first_time or 'unknown'}",
        f"- Last seen: {last_time or 'unknown'}",
        f"- Top actions: {_format_top(action_counts, 4)}",
        f"- Top users: {_format_top(user_counts, 4)}",
        f"- Top hosts: {_format_top(host_counts, 4)}",
        f"- Top IPs: {_format_top(ip_counts, 4)}",
    ]

    if user_query:
        query_ips = sorted(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", user_query)))
        if query_ips:
            matches = {ip: ip_counts[ip] for ip in query_ips if ip in ip_counts}
            if matches:
                lines.append(
                    "- Queried indicator matches: " +
                    ", ".join(f"{ip} ({count})" for ip, count in sorted(matches.items()))
                )

    for idx, event in enumerate(ordered[:_MAX_EVIDENCE_EXAMPLES], 1):
        lines.append(f"- Example {idx}: {json.dumps(_event_glimpse(event, schema_profile), separators=(',', ':'))}")
    return "\n".join(lines) + "\n"


def _build_context_block(events: list[dict], user_query: str = "") -> str:
    if not events:
        return (
            "\n\n--- Evidence summary ---\n"
            "- No matching log events found in Elasticsearch for this query.\n"
        )

    ordered = _sort_events(events)
    lines = [
        "\n\n--- Evidence summary ---\n",
        _build_evidence_summary(ordered, user_query),
        f"\n--- {len(ordered)} log event(s) retrieved from Elasticsearch ---\n",
    ]
    used = sum(len(part) for part in lines)
    included = 0
    for i, event in enumerate(ordered, 1):
        compact = {
            k: (v[:300] + "â€¦" if isinstance(v, str) and len(v) > 300 else v)
            for k, v in event.items()
        }
        entry = f"\n[Event {i}] {json.dumps(compact, separators=(',', ':'))}\n"
        if used + len(entry) > _MAX_CONTEXT_CHARS:
            lines.append(f"\n[â€¦{len(ordered) - included} more event(s) omitted â€” reduce result count or narrow your query]\n")
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

    log_request("https://api.anthropic.com/v1/messages", method="POST", source="claude",
                response_summary={"model": model, "prompt_chars": len(system)})
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

    log_request("https://api.openai.com/v1/chat/completions", method="POST", source="openai",
                response_summary={"model": model})
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


def _eql_quote(value) -> str:
    return json.dumps(value)


def _translate_eql_value(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if value is None:
        return "null"
    return _eql_quote(str(value))


def _esql_identifier(field: str) -> str:
    return f"`{field}`" if field.startswith("@") else field


def _translate_esql_condition(query: dict) -> str | None:
    if not isinstance(query, dict) or len(query) != 1:
        return None
    key, value = next(iter(query.items()))

    if key == "match_all":
        return None
    if key == "exists" and isinstance(value, dict):
        field = value.get("field")
        return f"{_esql_identifier(field)} IS NOT NULL" if isinstance(field, str) else None
    if key == "term" and isinstance(value, dict) and len(value) == 1:
        field, field_value = next(iter(value.items()))
        return f"{_esql_identifier(field)} == {_translate_eql_value(field_value)}"
    if key == "terms" and isinstance(value, dict) and len(value) == 1:
        field, field_value = next(iter(value.items()))
        if isinstance(field_value, list):
            joined = ", ".join(_translate_eql_value(v) for v in field_value)
            return f"{_esql_identifier(field)} IN ({joined})"
        return f"{_esql_identifier(field)} == {_translate_eql_value(field_value)}"
    if key == "match" and isinstance(value, dict) and len(value) == 1:
        field, field_value = next(iter(value.items()))
        if isinstance(field_value, dict):
            field_value = field_value.get("query")
        return f"{_esql_identifier(field)} LIKE {_translate_eql_value(f'*{field_value}*')}" if field_value is not None else None
    if key in ("wildcard", "prefix") and isinstance(value, dict) and len(value) == 1:
        field, field_value = next(iter(value.items()))
        if isinstance(field_value, dict):
            field_value = field_value.get("value")
        pattern = str(field_value)
        if key == "prefix":
            pattern = pattern + "*"
        return f"{_esql_identifier(field)} LIKE {_translate_eql_value(pattern)}"
    if key == "range" and isinstance(value, dict) and len(value) == 1:
        field, spec = next(iter(value.items()))
        if not isinstance(spec, dict):
            return None
        parts = []
        for op, esql_op in (("gt", ">"), ("gte", ">="), ("lt", "<"), ("lte", "<=")):
            if op in spec:
                parts.append(f"{_esql_identifier(field)} {esql_op} {_translate_eql_value(spec[op])}")
        return " AND ".join(parts) if parts else None
    if key == "bool" and isinstance(value, dict):
        clauses = []
        must = value.get("must", [])
        if isinstance(must, dict):
            must = [must]
        for clause in must:
            translated = _translate_esql_condition(clause)
            if translated:
                clauses.append(translated)
        filters = value.get("filter", [])
        if isinstance(filters, dict):
            filters = [filters]
        for clause in filters:
            translated = _translate_esql_condition(clause)
            if translated:
                clauses.append(translated)
        should = value.get("should", [])
        if isinstance(should, dict):
            should = [should]
        should_parts = [t for t in (_translate_esql_condition(clause) for clause in should) if t]
        if should_parts:
            should_expr = " OR ".join(should_parts)
            clauses.append(f"({should_expr})" if len(should_parts) > 1 else should_expr)
        must_not = value.get("must_not", [])
        if isinstance(must_not, dict):
            must_not = [must_not]
        for clause in must_not:
            translated = _translate_esql_condition(clause)
            if translated:
                clauses.append(f"NOT ({translated})")
        return " AND ".join(clauses) if clauses else None
    return None


def _translate_esql_sort(body: dict) -> str:
    sort_spec = body.get("sort")
    if not isinstance(sort_spec, list) or not sort_spec:
        return ""
    parts = []
    for entry in sort_spec:
        if isinstance(entry, str):
            parts.append(f"{_esql_identifier(entry)} ASC")
        elif isinstance(entry, dict) and len(entry) == 1:
            field, spec = next(iter(entry.items()))
            if field == "_score":
                continue
            if isinstance(spec, dict):
                order = str(spec.get("order", "asc")).upper()
            else:
                order = str(spec).upper()
            parts.append(f"{_esql_identifier(field)} {order}")
    return f" | SORT {', '.join(parts)}" if parts else ""


def _deterministic_query_body_to_esql(query_body: dict, indices: list[str]) -> str | None:
    if not isinstance(query_body, dict) or not indices:
        return None
    body = json.loads(json.dumps(query_body))
    body = _sanitize_query_body(body)
    source = ", ".join(indices)
    segments = [f"FROM {source}"]

    condition = _translate_esql_condition(body.get("query", {"match_all": {}}))
    if condition:
        segments.append(f"| WHERE {condition}")

    aggs = body.get("aggs") or body.get("aggregations")
    if aggs and isinstance(aggs, dict) and len(aggs) == 1:
        _, agg_def = next(iter(aggs.items()))
        if isinstance(agg_def, dict):
            if "terms" in agg_def and isinstance(agg_def["terms"], dict):
                field = agg_def["terms"].get("field")
                size = agg_def["terms"].get("size")
                order = agg_def["terms"].get("order", {})
                if isinstance(field, str):
                    segments.append(f"| STATS count = COUNT(*) BY {_esql_identifier(field)}")
                    if isinstance(order, dict) and str(order.get("_count", "")).lower() == "desc":
                        segments.append("| SORT count DESC")
                    if isinstance(size, int) and size > 0:
                        segments.append(f"| LIMIT {size}")
                    return " ".join(segments)
            if "composite" in agg_def and isinstance(agg_def["composite"], dict):
                sources = agg_def["composite"].get("sources", [])
                fields = []
                for source_def in sources:
                    if not isinstance(source_def, dict):
                        return None
                    for entry in source_def.values():
                        if not isinstance(entry, dict):
                            return None
                        terms = entry.get("terms")
                        field = terms.get("field") if isinstance(terms, dict) else None
                        if not isinstance(field, str):
                            return None
                        fields.append(_esql_identifier(field))
                if fields:
                    segments.append(f"| STATS count = COUNT(*) BY {', '.join(fields)}")
                    size = agg_def["composite"].get("size")
                    if isinstance(size, int) and size > 0:
                        segments.append(f"| LIMIT {size}")
                    return " ".join(segments)

    source_fields = body.get("_source")
    if isinstance(source_fields, list) and source_fields:
        keep_fields = [field for field in source_fields if isinstance(field, str)]
        if keep_fields:
            segments.append(f"| KEEP {', '.join(_esql_identifier(field) for field in keep_fields)}")

    sort_clause = _translate_esql_sort(body)
    if sort_clause:
        segments.append(sort_clause)

    size = body.get("size")
    if isinstance(size, int) and size > 0:
        segments.append(f"| LIMIT {size}")
    return " ".join(segments)


def _translate_eql_condition(query: dict) -> str | None:
    if not isinstance(query, dict) or len(query) != 1:
        return None
    key, value = next(iter(query.items()))

    if key == "match_all":
        return "true"
    if key == "exists" and isinstance(value, dict):
        field = value.get("field")
        return f"{field} != null" if isinstance(field, str) else None
    if key == "term" and isinstance(value, dict) and len(value) == 1:
        field, field_value = next(iter(value.items()))
        return f"{field} == {_translate_eql_value(field_value)}"
    if key == "terms" and isinstance(value, dict) and len(value) == 1:
        field, field_value = next(iter(value.items()))
        if isinstance(field_value, list):
            joined = ", ".join(_translate_eql_value(v) for v in field_value)
            return f"{field} in ({joined})"
        return f"{field} == {_translate_eql_value(field_value)}"
    if key == "match" and isinstance(value, dict) and len(value) == 1:
        field, field_value = next(iter(value.items()))
        if isinstance(field_value, dict):
            field_value = field_value.get("query")
        return f"{field} : {_translate_eql_value(field_value)}" if field_value is not None else None
    if key in ("wildcard", "prefix") and isinstance(value, dict) and len(value) == 1:
        field, field_value = next(iter(value.items()))
        if isinstance(field_value, dict):
            field_value = field_value.get("value")
        pattern = str(field_value)
        if key == "prefix":
            pattern = pattern + "*"
        return f"{field} like~ {_translate_eql_value(pattern)}"
    if key == "range" and isinstance(value, dict) and len(value) == 1:
        field, spec = next(iter(value.items()))
        if not isinstance(spec, dict):
            return None
        parts = []
        for op, eql_op in (("gt", ">"), ("gte", ">="), ("lt", "<"), ("lte", "<=")):
            if op in spec:
                parts.append(f"{field} {eql_op} {_translate_eql_value(spec[op])}")
        return " and ".join(parts) if parts else None
    if key == "bool" and isinstance(value, dict):
        clauses = []
        must = value.get("must", [])
        if isinstance(must, dict):
            must = [must]
        for clause in must:
            translated = _translate_eql_condition(clause)
            if translated:
                clauses.append(translated)
        filters = value.get("filter", [])
        if isinstance(filters, dict):
            filters = [filters]
        for clause in filters:
            translated = _translate_eql_condition(clause)
            if translated:
                clauses.append(translated)
        should = value.get("should", [])
        if isinstance(should, dict):
            should = [should]
        should_parts = [t for t in (_translate_eql_condition(clause) for clause in should) if t]
        if should_parts:
            should_expr = " or ".join(should_parts)
            clauses.append(f"({should_expr})" if len(should_parts) > 1 else should_expr)
        must_not = value.get("must_not", [])
        if isinstance(must_not, dict):
            must_not = [must_not]
        for clause in must_not:
            translated = _translate_eql_condition(clause)
            if translated:
                clauses.append(f"not ({translated})")
        return " and ".join(clauses) if clauses else "true"
    return None


def _translate_eql_pipe(body: dict) -> str:
    aggs = body.get("aggs") or body.get("aggregations")
    if aggs and isinstance(aggs, dict) and len(aggs) == 1:
        _, agg_def = next(iter(aggs.items()))
        if isinstance(agg_def, dict):
            if "terms" in agg_def and isinstance(agg_def["terms"], dict):
                field = agg_def["terms"].get("field")
                if isinstance(field, str):
                    return f" | stats count() by {field}"
            if "composite" in agg_def and isinstance(agg_def["composite"], dict):
                sources = agg_def["composite"].get("sources", [])
                fields = []
                for source in sources:
                    if not isinstance(source, dict):
                        return ""
                    for source_def in source.values():
                        if not isinstance(source_def, dict) or "terms" not in source_def:
                            return ""
                        field = source_def["terms"].get("field")
                        if not isinstance(field, str):
                            return ""
                        fields.append(field)
                if fields:
                    return f" | stats count() by {', '.join(fields)}"

    size = body.get("size")
    if isinstance(size, int) and size > 0:
        return f" | head {size}"
    return ""


def _deterministic_query_body_to_eql(query_body: dict) -> str | None:
    if not isinstance(query_body, dict):
        return None
    body = json.loads(json.dumps(query_body))
    body = _sanitize_query_body(body)
    query = body.get("query", {"match_all": {}})
    condition = _translate_eql_condition(query)
    if not condition:
        return None
    return f"any where {condition}{_translate_eql_pipe(body)}".strip()


async def _convert_query_body_to_eql(provider: str, model: str, query_body: dict) -> str:
    """Convert an ES DSL body to EQL, preferring a deterministic fallback."""
    deterministic = _deterministic_query_body_to_eql(query_body)
    if deterministic:
        return deterministic
    query_json = json.dumps(query_body, indent=2)
    eql = await _llm_complete(
        provider,
        model,
        system=_EQL_SYSTEM,
        user=f"Convert this ES DSL query to EQL:\n{query_json}",
    )
    eql = re.sub(r'^```(?:eql|sql)?\s*', '', eql.strip(), flags=re.IGNORECASE)
    eql = re.sub(r'\s*```$', '', eql.strip())
    return eql.strip()


async def _convert_query_body_to_kibana_query(
    provider: str,
    model: str,
    query_body: dict,
    indices: list[str],
) -> dict:
    esql = _deterministic_query_body_to_esql(query_body, indices)
    if esql:
        return {"language": "esql", "query": esql}

    eql = await _convert_query_body_to_eql(provider, model, query_body)
    return {"language": "eql", "query": eql}


async def _convert_query_artifacts_to_kibana_queries(
    provider: str,
    model: str,
    query_artifact,
    indices: list[str],
):
    """Return [{query_index, language, query}] for the executed query or queries."""
    if not query_artifact:
        return []
    bodies = query_artifact if isinstance(query_artifact, list) else [query_artifact]
    query_results = []
    for idx, body in enumerate(bodies, 1):
        if not isinstance(body, dict):
            continue
        try:
            kibana_query = await _convert_query_body_to_kibana_query(provider, model, body, indices)
            query_results.append({
                "query_index": idx,
                **kibana_query,
            })
        except Exception as exc:
            query_results.append({
                "query_index": idx,
                "error": str(exc),
            })
    return query_results


@router.get("/personas")
async def list_personas(_: dict = Depends(require_auth)):
    return [{"id": k, "label": v["label"]} for k, v in PERSONAS.items()]


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
                clarification = None
                async for item in _smart_search(provider, model, indices, req.query, req.max_results):
                    if item[0] == "debug_query_prompt":
                        yield f"data: {json.dumps({'debug_query_prompt': {'system': item[1], 'user': item[2]}})}\n\n"
                    elif item[0] == "query_thinking":
                        yield f"data: {json.dumps({'query_thinking': item[1]})}\n\n"
                    elif item[0] == "query_progress":
                        _, done, total, count = item
                        yield f"data: {json.dumps({'query_progress': {'done': done, 'total': total, 'count': count}})}\n\n"
                    elif item[0] == "clarification":
                        clarification = item[1]
                    elif item[0] == "result":
                        events, query_body, fallback_reason = item[1], item[2], item[3]
            except httpx.TimeoutException:
                yield f"data: {json.dumps({'error': 'Query generation timed out — try a faster model or disable smart query'})}\n\n"
                return
            except Exception as exc:
                yield f"data: {json.dumps({'error': f'Query generation failed: {exc}'})}\n\n"
                return

            if clarification:
                yield f"data: {json.dumps({'status': 'clarification_needed'})}\n\n"
                yield f"data: {json.dumps({'clarification': clarification})}\n\n"
                return

            if query_body:
                yield f"data: {json.dumps({'generated_query': query_body})}\n\n"
                yield f"data: {json.dumps({'status': 'converting_query'})}\n\n"
                kibana_queries = await _convert_query_artifacts_to_kibana_queries(provider, model, query_body, indices)
                if kibana_queries:
                    yield f"data: {json.dumps({'generated_eql': kibana_queries})}\n\n"
            if fallback_reason:
                yield f"data: {json.dumps({'query_warning': fallback_reason})}\n\n"
            zero_result_hint = _build_zero_result_hint(indices, query_body)
            if zero_result_hint and not events:
                yield f"data: {json.dumps({'query_warning': zero_result_hint})}\n\n"

            yield f"data: {json.dumps({'status': 'found', 'count': len(events)})}\n\n"
        else:
            # ── Keyword search path ─────────────────────────────────────────────
            yield f"data: {json.dumps({'status': 'searching', 'indices': len(req.indices)})}\n\n"
            events = _sort_events(await _keyword_search(indices, req.query, req.max_results))
            yield f"data: {json.dumps({'status': 'found', 'count': len(events)})}\n\n"

        evidence_summary = _build_evidence_summary(events, req.query)
        yield f"data: {json.dumps({'evidence_summary': evidence_summary})}\n\n"
        yield f"data: {json.dumps({'context': events})}\n\n"

        # ── Phase 1b: threat intel enrichment (optional) ────────────────────────
        enrichment_context = ""
        if req.threat_intel:
            from ..enrichment import extract_ips, enrich_ip, build_enrichment_context
            ips = extract_ips(events)
            if not ips:
                yield f"data: {json.dumps({'enrich_status': 'no public IPs found in results'})}\n\n"
            elif not (settings.abuseipdb_api_key or settings.virustotal_api_key):
                yield f"data: {json.dumps({'enrich_status': 'no threat intel API keys configured — add ABUSEIPDB_API_KEY or VIRUSTOTAL_API_KEY to .env'})}\n\n"
            else:
                yield f"data: {json.dumps({'enrich_status': f'looking up {len(ips)} IP(s)…'})}\n\n"
                enrichments: list[dict] = []
                for idx, ip in enumerate(ips):
                    # VirusTotal free tier: 4 req/min — space out calls after the first
                    if idx > 0 and settings.virustotal_api_key:
                        await asyncio.sleep(16)
                    try:
                        result = await enrich_ip(ip)
                        enrichments.append(result)
                        yield f"data: {json.dumps({'enrichment': result})}\n\n"
                    except Exception as exc:
                        yield f"data: {json.dumps({'enrichment': {'ip': ip, 'error': str(exc)}})}\n\n"
                enrichment_context = build_enrichment_context(enrichments)
                yield f"data: {json.dumps({'enrich_status': f'enriched {len(enrichments)} IP(s)'})}\n\n"

        # ── Phase 2: analyse with LLM ───────────────────────────────────────────
        context_block = _build_context_block(events, req.query) + enrichment_context
        persona_prompt = PERSONAS.get(req.persona or _DEFAULT_PERSONA, PERSONAS[_DEFAULT_PERSONA])["prompt"]
        messages: list[dict] = [{"role": "system", "content": persona_prompt}]
        if req.conversation_history:
            messages.extend(m.model_dump() for m in req.conversation_history[-20:])
        user_message = req.query + context_block
        messages.append({"role": "user", "content": user_message})

        # Emit full prompt to frontend so it can be shown in debug panel
        yield f"data: {json.dumps({'debug_prompt': {'system': persona_prompt, 'user': user_message}})}\n\n"

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


_EQL_SYSTEM = """Convert the given Elasticsearch Query DSL JSON into an equivalent Elasticsearch EQL (Event Query Language) query.

Output ONLY the EQL string — no explanation, no markdown, no code fences.

═══ SYNTAX ═══

Every EQL query: <event_type> where <condition>
  - Use "any" when the event type is unknown or irrelevant: any where <condition>
  - Event type is a bare word, not quoted: any where ...  NOT  "any" where ...

Logical operators (lowercase only — AND / OR / NOT are invalid):
  and, or, not

Comparison operators:
  ==  !=  <  >  <=  >=

String matching:
  field == "exact_value"          exact match (case-sensitive)
  field != "value"                not equal
  field like "admin*"             wildcard, case-sensitive
  field like~ "admin*"            wildcard, case-insensitive  ← prefer this
  field : "value"                 match (like == but works across types)
  field in ("a", "b", "c")       multi-value OR (equivalent to terms)
  field not in ("a", "b")        multi-value NOT

Numeric / IP comparisons:
  EventID == 4624
  source.ip == "192.168.1.1"     IP fields are still quoted strings in EQL

Null / existence checks:
  field != null                   field exists and is not null
  field == null                   field is null or missing

Wildcards in field names are NOT allowed — field names must be exact.

═══ AGGREGATIONS / PIPES ═══

Pipes transform results — append after the where clause:
  any where true | stats count() by field_name
  any where <condition> | stats count() by field1, field2
  any where <condition> | tail 10
  any where <condition> | head 20

Pipe keywords: stats, count, tail, head, unique, unique_count
  - stats count() by field       → top N values with counts
  - count is a function, not a standalone keyword

═══ SEQUENCES ═══

sequence by <shared_field>
  [any where condition1]
  [any where condition2]

═══ COMMON MISTAKES TO AVOID ═══

✗ WRONG  any where EventID = 4624          (= is not valid — use ==)
✓ RIGHT  any where EventID == 4624

✗ WRONG  any where UserName == SYSTEM      (bare word — must quote strings)
✓ RIGHT  any where UserName == "SYSTEM"

✗ WRONG  any where EventID == "4624"       (numeric field — do not quote numbers)
✓ RIGHT  any where EventID == 4624

✗ WRONG  any where EventID IN (4624,4625)  (IN must be lowercase: in)
✓ RIGHT  any where EventID in (4624, 4625)

✗ WRONG  any where NOT UserName == "x"    (NOT must be lowercase: not)
✓ RIGHT  any where not UserName == "x"

✗ WRONG  any where source.ip exists       (no "exists" keyword in EQL)
✓ RIGHT  any where source.ip != null

✗ WRONG  count() by field                 (missing "any where true |")
✓ RIGHT  any where true | stats count() by field

✗ WRONG  any where match_all              (no match_all in EQL)
✓ RIGHT  any where true

✗ WRONG  any where field like "*"         (wildcard-only match — use != null)
✓ RIGHT  any where field != null

✗ WRONG  any where @timestamp >= "2024-01-01"   (date range uses between())
✓ RIGHT  any where @timestamp >= "2024-01-01T00:00:00Z"  (ISO-8601 strings work)

═══ TRANSLATION GUIDE ═══

DSL match_all          → any where true
DSL exists             → field != null
DSL term/terms         → == or in ()
DSL range              → >= / <=  with quoted ISO dates for date fields
DSL bool.must          → and
DSL bool.should        → or  (wrap in parentheses if mixed with and)
DSL bool.must_not      → not
DSL wildcard query     → like~
DSL aggs terms         → | stats count() by field
DSL aggs composite     → | stats count() by field1, field2"""


@router.post("/eql")
async def convert_to_eql(req: EqlRequest, _: dict = Depends(require_auth)):
    """Convert an ES DSL query body to a Kibana-ready query."""
    provider = req.provider or "ollama"
    model = req.model or settings.ollama_model
    try:
        kibana_query = await _convert_query_body_to_kibana_query(provider, model, req.query_body, req.indices)
        response = dict(kibana_query)
        if kibana_query.get("language") == "eql":
            response["eql"] = kibana_query.get("query", "")
        return response
    except Exception as exc:
        return {"error": str(exc)}
