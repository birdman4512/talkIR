"""Log all outbound internet requests to a JSONL file in /app/request_logs/."""
import json
import os
from datetime import datetime, timezone
from pathlib import Path

_LOG_DIR = Path(os.environ.get("REQUEST_LOG_DIR", "/app/request_logs"))


def _log(entry: dict) -> None:
    try:
        _LOG_DIR.mkdir(parents=True, exist_ok=True)
        log_file = _LOG_DIR / "requests.jsonl"
        with log_file.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass  # never crash the main flow due to logging failure


def log_request(
    url: str,
    method: str = "GET",
    status_code: int | None = None,
    ip: str | None = None,
    source: str | None = None,
    response_summary: dict | None = None,
    error: str | None = None,
) -> None:
    entry: dict = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "method": method,
        "url": url,
    }
    if ip:
        entry["queried_ip"] = ip
    if source:
        entry["source"] = source
    if status_code is not None:
        entry["status_code"] = status_code
    if response_summary:
        entry["response"] = response_summary
    if error:
        entry["error"] = error
    _log(entry)
