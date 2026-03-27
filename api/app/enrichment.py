"""Threat intelligence enrichment for IP addresses found in ES results."""
import asyncio
import re

import httpx

from .config import settings
from .request_log import log_request

_IP_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\b'
)
_PRIVATE = re.compile(
    r'^(10\.|127\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)'
)

MAX_IPS_PER_REQUEST = 15


def extract_ips(events: list[dict]) -> list[str]:
    """Return unique public IPs found in any field of the events (recurses into nested objects)."""
    seen: set[str] = set()
    result: list[str] = []

    def _scan(obj) -> None:
        if len(result) >= MAX_IPS_PER_REQUEST:
            return
        if isinstance(obj, str):
            for m in _IP_RE.finditer(obj):
                ip = m.group(0)
                if ip not in seen and not _PRIVATE.match(ip):
                    seen.add(ip)
                    result.append(ip)
        elif isinstance(obj, dict):
            for val in obj.values():
                _scan(val)
        elif isinstance(obj, list):
            for item in obj:
                _scan(item)

    for event in events:
        _scan(event)
    return result


async def _lookup_abuseipdb(ip: str) -> dict:
    url = "https://api.abuseipdb.com/api/v2/check"
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.get(
                url,
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
            )
        except Exception as exc:
            log_request(url, ip=ip, source="abuseipdb", error=str(exc))
            return {}
        if resp.status_code != 200:
            log_request(url, ip=ip, source="abuseipdb", status_code=resp.status_code, error=resp.text[:200])
            return {}
        d = resp.json().get("data", {})
        result = {
            "score":   d.get("abuseConfidenceScore", 0),
            "reports": d.get("totalReports", 0),
            "country": d.get("countryCode", ""),
            "isp":     d.get("isp", ""),
            "usage":   d.get("usageType", ""),
        }
        log_request(url, ip=ip, source="abuseipdb", status_code=resp.status_code,
                    response_summary={"score": result["score"], "country": result["country"], "isp": result["isp"]})
        return result


async def _lookup_virustotal(ip: str) -> dict:
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    async with httpx.AsyncClient(timeout=10.0) as client:
        for attempt in range(3):
            try:
                resp = await client.get(url, headers={"x-apikey": settings.virustotal_api_key})
            except Exception as exc:
                log_request(url, ip=ip, source="virustotal", error=str(exc))
                return {}
            if resp.status_code == 429:
                wait = 60 * (attempt + 1)
                log_request(url, ip=ip, source="virustotal", status_code=429,
                            error=f"rate limited — waiting {wait}s before retry")
                await asyncio.sleep(wait)
                continue
            if resp.status_code != 200:
                log_request(url, ip=ip, source="virustotal", status_code=resp.status_code, error=resp.text[:200])
                return {}
            break
        else:
            return {}
        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        result = {
            "malicious":  stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "reputation": attrs.get("reputation", 0),
            "country":    attrs.get("country", ""),
            "as_owner":   attrs.get("as_owner", ""),
        }
        log_request(url, ip=ip, source="virustotal", status_code=resp.status_code,
                    response_summary={"malicious": result["malicious"], "country": result["country"], "org": result["as_owner"]})
        return result


async def enrich_ip(ip: str) -> dict:
    """Look up an IP against all configured threat intel sources concurrently."""
    lookups: list[tuple[str, object]] = []
    if settings.abuseipdb_api_key:
        lookups.append(("abuseipdb", _lookup_abuseipdb(ip)))
    if settings.virustotal_api_key:
        lookups.append(("virustotal", _lookup_virustotal(ip)))

    sources: dict = {}
    if lookups:
        results = await asyncio.gather(*[coro for _, coro in lookups], return_exceptions=True)
        for (name, _), result in zip(lookups, results):
            if isinstance(result, dict) and result:
                sources[name] = result

    return {"ip": ip, "sources": sources}


def build_enrichment_context(enrichments: list[dict]) -> str:
    """Format enrichment results as a context block for the LLM."""
    if not enrichments:
        return ""
    lines = ["\n\n--- Threat Intelligence Enrichment ---\n"]
    for e in enrichments:
        ip = e["ip"]
        sources = e.get("sources", {})
        if not sources:
            lines.append(f"\n{ip}: no data returned from configured sources\n")
            continue
        lines.append(f"\n{ip}:\n")
        ab = sources.get("abuseipdb", {})
        if ab:
            score = ab.get("score", 0)
            verdict = "MALICIOUS" if score >= 80 else "SUSPICIOUS" if score >= 25 else "clean"
            lines.append(
                f"  AbuseIPDB: score={score}% [{verdict}], "
                f"reports={ab.get('reports', 0)}, "
                f"country={ab.get('country', '?')}, "
                f"isp={ab.get('isp', '?')}, "
                f"type={ab.get('usage', '?')}\n"
            )
        vt = sources.get("virustotal", {})
        if vt:
            mal = vt.get("malicious", 0)
            sus = vt.get("suspicious", 0)
            verdict = "MALICIOUS" if mal >= 3 else "SUSPICIOUS" if mal >= 1 or sus >= 3 else "clean"
            lines.append(
                f"  VirusTotal: malicious={mal}, suspicious={sus} [{verdict}], "
                f"reputation={vt.get('reputation', 0)}, "
                f"country={vt.get('country', '?')}, "
                f"org={vt.get('as_owner', '?')}\n"
            )
    return "".join(lines)
