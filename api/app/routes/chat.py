import asyncio
import json
import re
import httpx
from string import Template
from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse

from ..auth import require_auth
from ..es_client import get_es_client
from ..models import ChatRequest, EqlRequest
from ..config import settings

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
- bool.should without bool.must means OR — add "minimum_should_match":1 so at least one condition must match. Without it, should clauses are optional.
- NEVER use match on (keyword) fields — use term or terms instead.

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
        target = ",".join(indices[:5]) if indices else "_all"
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
) -> tuple[str, dict[str, str]]:
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
        target = ",".join(indices[:5]) if indices else "_all"
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
        return prompt_str, field_types
    except Exception:
        return "(unavailable)", {}


def _fix_agg_fields(aggs: dict, field_types: dict[str, str]) -> None:
    """Mutate aggs in-place: rewrite text+kw → field.keyword, remove pure text fields."""
    for agg_name in list(aggs.keys()):
        agg_def = aggs[agg_name]
        if not isinstance(agg_def, dict):
            continue

        # terms aggregation
        if "terms" in agg_def:
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
    used = _extract_referenced_fields(body)
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
    unknown = {f for f in _extract_referenced_fields(body) if f not in all_known}
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
        for v in obj.values():
            _apply_field_rewrites(v, rewrites)
    elif isinstance(obj, list):
        for item in obj:
            _apply_field_rewrites(item, rewrites)


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
    # Missing "query" key — add match_all so the body is valid
    if "query" not in body:
        body["query"] = {"match_all": {}}

    q = body.get("query", {})
    if isinstance(q, dict):
        # aggs/aggregations inside query — hoist to top level
        for agg_key in ("aggs", "aggregations"):
            if agg_key in q:
                body[agg_key] = q.pop(agg_key)
        # size inside query — hoist to top level
        if "size" in q:
            body.setdefault("size", q.pop("size"))
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

    # LLMs sometimes put "size" as a sibling key inside the aggs object rather
    # than at the top level — hoist it out and remove from aggs.
    for agg_key in ("aggs", "aggregations"):
        if agg_key in body and isinstance(body[agg_key], dict) and "size" in body[agg_key]:
            body.setdefault("size", body[agg_key].pop("size"))
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


def _extract_json(text: str) -> dict | None:
    """Pull a JSON object out of freeform LLM output."""
    text = text.strip()
    # Strip JS/C-style comments (LLMs often add these inside JSON)
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.DOTALL)  # /* block comments */
    text = re.sub(r'//[^\n"]*', '', text)                   # // line comments

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
    fields_str, field_types = await _get_mapping_fields(es, indices)
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

        valid_raw = [qb for qb in raw_queries[:3] if isinstance(qb, dict)]
        if not valid_raw:
            events = await _keyword_search(indices, query, max_results)
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
        yield ("result", deduped[:max_results], valid_bodies, fallback)

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
        try:
            events = await _run_query(es, target, parsed, max_results)
            yield ("result", events, parsed, unknown_warn)
        except Exception as exc:
            events = await _keyword_search(indices, query, max_results)
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
                async for item in _smart_search(provider, model, indices, req.query, req.max_results):
                    if item[0] == "debug_query_prompt":
                        yield f"data: {json.dumps({'debug_query_prompt': {'system': item[1], 'user': item[2]}})}\n\n"
                    elif item[0] == "query_thinking":
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
                for ip in ips:
                    try:
                        result = await enrich_ip(ip)
                        enrichments.append(result)
                        yield f"data: {json.dumps({'enrichment': result})}\n\n"
                    except Exception as exc:
                        yield f"data: {json.dumps({'enrichment': {'ip': ip, 'error': str(exc)}})}\n\n"
                enrichment_context = build_enrichment_context(enrichments)
                yield f"data: {json.dumps({'enrich_status': f'enriched {len(enrichments)} IP(s)'})}\n\n"

        # ── Phase 2: analyse with LLM ───────────────────────────────────────────
        context_block = _build_context_block(events) + enrichment_context
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

EQL syntax rules:
- Every query starts with an event category or "any": any where <condition>
- Use "and", "or", "not" for logic; "in ()", "like~", ":" for matching
- Numeric comparisons: ==, !=, <, >, <=, >=
- For sequences: sequence [event1] [event2]
- Field names are unquoted: EventID == 4624
- String values are quoted: UserName == "SYSTEM"
- Wildcards: UserName like~ "admin*"
- For aggregation queries (aggs) that count per field, convert to:
  any where <filter_condition> | stats count() by <field>

Output ONLY the EQL string — no explanation, no markdown, no code fences."""


@router.post("/eql")
async def convert_to_eql(req: EqlRequest, _: dict = Depends(require_auth)):
    """Convert an ES DSL query body to EQL via the LLM."""
    provider = req.provider or "ollama"
    model = req.model or settings.ollama_model
    query_json = json.dumps(req.query_body, indent=2)
    try:
        eql = await _llm_complete(
            provider, model,
            system=_EQL_SYSTEM,
            user=f"Convert this ES DSL query to EQL:\n{query_json}",
        )
        # Strip markdown fences if model wrapped it
        eql = re.sub(r'^```(?:eql|sql)?\s*', '', eql.strip(), flags=re.IGNORECASE)
        eql = re.sub(r'\s*```$', '', eql.strip())
        return {"eql": eql.strip()}
    except Exception as exc:
        return {"error": str(exc)}
