"""Threat intelligence enrichment for IP addresses found in ES results."""
import asyncio
import re

import httpx

from .config import settings

_IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_PRIVATE = re.compile(
    r'^(10\.|127\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)'
)

MAX_IPS_PER_REQUEST = 15


def extract_ips(events: list[dict]) -> list[str]:
    """Return unique public IPs found in any string field of the events."""
    seen: set[str] = set()
    result: list[str] = []
    for event in events:
        for val in event.values():
            if not isinstance(val, str):
                continue
            for m in _IP_RE.finditer(val):
                ip = m.group(0)
                if ip not in seen and not _PRIVATE.match(ip):
                    seen.add(ip)
                    result.append(ip)
                    if len(result) >= MAX_IPS_PER_REQUEST:
                        return result
    return result


async def _lookup_abuseipdb(ip: str) -> dict:
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
        )
        if resp.status_code != 200:
            return {}
        d = resp.json().get("data", {})
        return {
            "score":   d.get("abuseConfidenceScore", 0),
            "reports": d.get("totalReports", 0),
            "country": d.get("countryCode", ""),
            "isp":     d.get("isp", ""),
            "usage":   d.get("usageType", ""),
        }


async def _lookup_virustotal(ip: str) -> dict:
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": settings.virustotal_api_key},
        )
        if resp.status_code != 200:
            return {}
        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "malicious":  stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "reputation": attrs.get("reputation", 0),
            "country":    attrs.get("country", ""),
            "as_owner":   attrs.get("as_owner", ""),
        }


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
