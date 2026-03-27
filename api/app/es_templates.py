"""
Elasticsearch index templates — applied once at API startup.
Ensures ECS fields are typed correctly (ip, keyword, date_nanos) rather than
relying on dynamic mapping which guesses wrong for high-precision timestamps
and IP address fields.
"""
import logging

logger = logging.getLogger(__name__)

_TEMPLATE_NAME = "talkir-ecs"

_TEMPLATE_BODY = {
    "index_patterns": ["windows.*", "linux.*", "sample_*", "macos.*"],
    "priority": 200,
    "template": {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
        },
        "mappings": {
            "dynamic": True,
            "dynamic_date_formats": [
                "strict_date_optional_time_nanos",
                "strict_date_optional_time",
            ],
            "properties": {
                "@timestamp": {"type": "date_nanos"},
                # ── ECS: network ───────────────────────────────────────────
                "source": {
                    "properties": {
                        "ip":     {"type": "ip"},
                        "port":   {"type": "integer"},
                        "domain": {"type": "keyword"},
                    }
                },
                "destination": {
                    "properties": {
                        "ip":   {"type": "ip"},
                        "port": {"type": "integer"},
                    }
                },
                "network": {
                    "properties": {
                        "transport": {"type": "keyword"},
                        "protocol":  {"type": "keyword"},
                        "direction": {"type": "keyword"},
                    }
                },
                # ── ECS: identity ──────────────────────────────────────────
                "user": {
                    "properties": {
                        "name":   {"type": "keyword"},
                        "domain": {"type": "keyword"},
                        "id":     {"type": "keyword"},
                        "full":   {"type": "keyword"},
                        "target": {"properties": {"name": {"type": "keyword"}}},
                    }
                },
                "host": {
                    "properties": {
                        "name": {"type": "keyword"},
                        "ip":   {"type": "ip"},
                    }
                },
                # ── ECS: event ─────────────────────────────────────────────
                "event": {
                    "properties": {
                        "code":     {"type": "keyword"},
                        "category": {"type": "keyword"},
                        "type":     {"type": "keyword"},
                        "outcome":  {"type": "keyword"},
                        "action":   {"type": "keyword"},
                    }
                },
                # ── ECS: process ───────────────────────────────────────────
                "process": {
                    "properties": {
                        "name":         {"type": "keyword"},
                        "pid":          {"type": "long"},
                        "executable":   {"type": "keyword"},
                        "command_line": {"type": "wildcard"},
                        "parent": {
                            "properties": {
                                "name": {"type": "keyword"},
                                "pid":  {"type": "long"},
                            }
                        },
                        "thread": {
                            "properties": {
                                "id": {"type": "long"},
                            }
                        },
                    }
                },
                # ── ECS: file ──────────────────────────────────────────────
                "file": {
                    "properties": {
                        "path":      {"type": "keyword"},
                        "name":      {"type": "keyword"},
                        "extension": {"type": "keyword"},
                        "size":      {"type": "long"},
                        "created":   {"type": "date_nanos"},
                        "mtime":     {"type": "date_nanos"},
                        "accessed":  {"type": "date_nanos"},
                    }
                },
                # ── ECS: url ───────────────────────────────────────────────
                "url": {
                    "properties": {
                        "original": {"type": "wildcard"},
                    }
                },
                # ── ECS: registry ──────────────────────────────────────────
                "registry": {
                    "properties": {
                        "path": {"type": "keyword"},
                    }
                },
                # ── ECS: code signature ────────────────────────────────────
                "code_signature": {
                    "properties": {
                        "trusted":      {"type": "boolean"},
                        "subject_name": {"type": "keyword"},
                    }
                },
                # ── ECS: winlog (Windows-specific) ─────────────────────────
                "winlog": {
                    "properties": {
                        "logon": {
                            "properties": {
                                "type":         {"type": "keyword"},
                                "auth_package": {"type": "keyword"},
                            }
                        },
                        "event_data": {
                            "dynamic": True,
                            "properties": {
                                "task_name": {"type": "keyword"},
                            }
                        },
                    }
                },
                # ── Velociraptor metadata ──────────────────────────────────
                "velociraptor_artifact": {"type": "keyword"},
                "host_name":             {"type": "keyword"},
                "ps_suspicious":         {"type": "boolean"},
                "ps_indicators":         {"type": "keyword"},
                # ── Common flat Velociraptor fields ────────────────────────
                "EventID":           {"type": "long"},
                "EventTime":         {"type": "date_nanos"},
                "Timestamp":         {"type": "date_nanos"},
                "TimeCreated":       {"type": "date_nanos"},
                "Computer":          {"type": "keyword"},
                "UserName":          {"type": "keyword"},
                "DomainName":        {"type": "keyword"},
                "SourceIP":          {"type": "ip"},
                "SrcIP":             {"type": "ip"},
                "DestIP":            {"type": "ip"},
                "Hash_MD5":          {"type": "keyword"},
                "Hash_SHA1":         {"type": "keyword"},
                "Hash_SHA256":       {"type": "keyword"},
                "Authenticode_Trusted": {"type": "keyword"},
                "visit_time":        {"type": "date_nanos"},
            },
        },
    },
}


async def ensure_index_templates(es) -> None:
    """Create or update the ECS index template. Called once at API startup."""
    try:
        await es.indices.put_index_template(name=_TEMPLATE_NAME, body=_TEMPLATE_BODY)
        logger.info("ECS index template '%s' applied", _TEMPLATE_NAME)
    except Exception as exc:
        # Non-fatal — existing indices will keep working; only new ones miss typing
        logger.warning("Could not apply ECS index template: %s", exc)
