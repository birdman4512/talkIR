"""
Tests for query sanitiser functions in app.routes.chat.

These cover the most common LLM-generated query mistakes that caused real
failures in production, plus the helper functions used by the sanitiser.
"""
import pytest

from app.routes.chat import (
    _sanitize_query_body,
    _fix_terms_query_syntax,
    _fix_terms_in_aggs,
    _fix_typeless_aggs,
    _fix_agg_fields,
    _suggest_field,
    _check_unknown_fields,
    _rewrite_unknown_fields,
    _extract_json,
    _build_evidence_summary,
    _deterministic_query_body_to_eql,
    _deterministic_query_body_to_esql,
    _build_indicator_fast_path_query,
    _build_field_list_fast_path_query,
    _build_ip_count_fast_path_query,
    _build_mft_between_dates_query,
    _build_failed_login_accounts_query,
    _build_history_between_dates_query,
    _build_schema_profile,
    _get_role_candidates,
    _maybe_build_semantic_clarification,
    _parse_query_intent,
    _extract_indicator,
)


# ─── _extract_json ────────────────────────────────────────────────────────────

class TestExtractJson:
    def test_bare_json(self):
        assert _extract_json('{"query": {"match_all": {}}}') == {"query": {"match_all": {}}}

    def test_json_in_markdown_block(self):
        raw = '```json\n{"query": {"match_all": {}}}\n```'
        assert _extract_json(raw) == {"query": {"match_all": {}}}

    def test_json_in_unmarked_code_block(self):
        raw = '```\n{"query": {"match_all": {}}}\n```'
        assert _extract_json(raw) == {"query": {"match_all": {}}}

    def test_json_with_surrounding_text(self):
        raw = 'Here is the query:\n{"query": {"match_all": {}}}\nDone.'
        assert _extract_json(raw) == {"query": {"match_all": {}}}

    def test_invalid_json_returns_none(self):
        assert _extract_json("not json at all") is None

    def test_empty_string_returns_none(self):
        assert _extract_json("") is None


# ─── _sanitize_query_body — missing query key ─────────────────────────────────

class TestSanitizeMissingQueryKey:
    def test_adds_match_all_when_no_query_key(self):
        body = {"size": 10}
        _sanitize_query_body(body)
        assert body["query"] == {"match_all": {}}

    def test_leaves_existing_query_intact(self):
        body = {"query": {"term": {"status": "active"}}}
        _sanitize_query_body(body)
        assert body["query"] == {"term": {"status": "active"}}


# ─── _sanitize_query_body — agg hoisting ─────────────────────────────────────

class TestSanitizeAggHoisting:
    def test_hoists_aggs_from_inside_query(self):
        body = {
            "query": {
                "match_all": {},
                "aggs": {"by_user": {"terms": {"field": "user.keyword"}}},
            }
        }
        _sanitize_query_body(body)
        assert "aggs" in body
        assert "by_user" in body["aggs"]
        assert "aggs" not in body["query"]

    def test_hoists_aggregations_key(self):
        body = {
            "query": {
                "match_all": {},
                "aggregations": {"by_host": {"terms": {"field": "host.keyword"}}},
            }
        }
        _sanitize_query_body(body)
        assert "aggregations" in body
        assert "by_host" in body["aggregations"]

    def test_sets_size_zero_when_aggs_present(self):
        body = {
            "query": {"match_all": {}},
            "aggs": {"by_user": {"terms": {"field": "user.keyword"}}},
        }
        _sanitize_query_body(body)
        assert body["size"] == 0

    def test_removes_size_zero_when_no_aggs(self):
        body = {"query": {"match_all": {}}, "size": 0}
        _sanitize_query_body(body)
        assert "size" not in body


# ─── _fix_terms_query_syntax ─────────────────────────────────────────────────

class TestFixTermsQuerySyntax:
    def test_terms_wrong_syntax_rewritten(self):
        """{"terms": {"field": "EventID", "value": 4624}} → {"terms": {"EventID": [4624]}}"""
        node = {"terms": {"field": "EventID", "value": 4624}}
        _fix_terms_query_syntax(node)
        assert node == {"terms": {"EventID": [4624]}}

    def test_term_wrong_syntax_rewritten(self):
        """{"term": {"field": "Status", "value": "success"}} → {"term": {"Status": "success"}}"""
        node = {"term": {"field": "Status", "value": "success"}}
        _fix_terms_query_syntax(node)
        assert node == {"term": {"Status": "success"}}

    def test_terms_list_value_preserved(self):
        """value already a list — should still rewrite field key but keep list."""
        node = {"terms": {"field": "EventID", "value": [4624, 4625]}}
        _fix_terms_query_syntax(node)
        assert node == {"terms": {"EventID": [4624, 4625]}}

    def test_terms_correct_syntax_unchanged(self):
        """Correct syntax must not be touched."""
        node = {"terms": {"EventID": [4624, 4625]}}
        _fix_terms_query_syntax(node)
        assert node == {"terms": {"EventID": [4624, 4625]}}

    def test_nested_bool_rewritten(self):
        node = {
            "bool": {
                "must": [
                    {"terms": {"field": "EventID", "value": 4624}},
                    {"term": {"field": "Outcome", "value": "success"}},
                ]
            }
        }
        _fix_terms_query_syntax(node)
        assert node["bool"]["must"][0] == {"terms": {"EventID": [4624]}}
        assert node["bool"]["must"][1] == {"term": {"Outcome": "success"}}

    def test_non_dict_node_is_noop(self):
        # Should not raise
        _fix_terms_query_syntax("not a dict")
        _fix_terms_query_syntax(None)
        _fix_terms_query_syntax([1, 2, 3])


# ─── _fix_terms_in_aggs ──────────────────────────────────────────────────────

class TestFixTermsInAggs:
    def test_fixes_terms_in_filter_agg(self):
        """
        Regression: deepseek-r1 generated:
          {"successful_logins": {"filter": {"terms": {"field": "EventID", "value": 4624}}}}
        """
        aggs = {
            "user_stats": {
                "terms": {"field": "UserName.keyword", "size": 50},
                "aggregations": {
                    "successful_logins": {
                        "filter": {"terms": {"field": "EventID", "value": 4624}}
                    },
                    "failed_logins": {
                        "filter": {"terms": {"field": "EventID", "value": 4625}}
                    },
                },
            }
        }
        _fix_terms_in_aggs(aggs)
        sub = aggs["user_stats"]["aggregations"]
        assert sub["successful_logins"]["filter"] == {"terms": {"EventID": [4624]}}
        assert sub["failed_logins"]["filter"] == {"terms": {"EventID": [4625]}}

    def test_non_dict_is_noop(self):
        _fix_terms_in_aggs(None)
        _fix_terms_in_aggs("string")


# ─── _sanitize_query_body end-to-end (terms regression) ──────────────────────

class TestSanitizeTermsRegression:
    def test_full_body_with_bad_filter_terms(self):
        """Full regression body that caused the real BadRequestError."""
        body = {
            "query": {"match_all": {}},
            "_source": ["UserName", "Description", "@timestamp"],
            "aggs": {
                "user_stats": {
                    "terms": {"field": "UserName.keyword", "size": 50},
                    "aggregations": {
                        "successful_logins": {
                            "filter": {"terms": {"field": "EventID", "value": 4624}}
                        },
                        "failed_logins": {
                            "filter": {"terms": {"field": "EventID", "value": 4625}}
                        },
                    },
                }
            },
            "size": 0,
        }
        _sanitize_query_body(body)
        sub = body["aggs"]["user_stats"]["aggregations"]
        assert sub["successful_logins"]["filter"] == {"terms": {"EventID": [4624]}}
        assert sub["failed_logins"]["filter"] == {"terms": {"EventID": [4625]}}


# ─── _fix_typeless_aggs ──────────────────────────────────────────────────────

class TestFixTypelessAggs:
    def test_merges_orphaned_subaggs_into_bucket_sibling(self):
        """
        Regression: LLM emits:
          "user_stats": {"terms": {...}}          ← bucket agg
          "user_success": {"aggs": {"s": {...}}}  ← typeless — no ES type
        Fix: sub-aggs of typeless entry should be merged into user_stats.
        """
        aggs = {
            "user_stats": {"terms": {"field": "user.keyword", "size": 10}},
            "user_success": {"aggs": {"success_count": {"value_count": {"field": "_id"}}}},
        }
        _fix_typeless_aggs(aggs)
        # typeless entry should be removed
        assert "user_success" not in aggs
        # its sub-aggs should be inside the bucket agg
        assert "success_count" in aggs["user_stats"].get("aggs", {})

    def test_valid_aggs_unchanged(self):
        aggs = {
            "by_user": {"terms": {"field": "user.keyword"}},
            "total_events": {"value_count": {"field": "_id"}},
        }
        _fix_typeless_aggs(dict(aggs))  # copy — should not mutate originals


# ─── _fix_agg_fields ─────────────────────────────────────────────────────────

class TestFixAggFields:
    def test_rewrites_text_field_to_keyword(self):
        """text+kw fields should use .keyword variant in aggs."""
        aggs = {"by_user": {"terms": {"field": "UserName"}}}
        field_types = {"UserName": "text+kw", "UserName.keyword": "keyword"}
        _fix_agg_fields(aggs, field_types)
        assert aggs["by_user"]["terms"]["field"] == "UserName.keyword"

    def test_leaves_keyword_only_field_intact(self):
        aggs = {"by_status": {"terms": {"field": "status.keyword"}}}
        field_types = {"status.keyword": "keyword"}
        _fix_agg_fields(aggs, field_types)
        assert aggs["by_status"]["terms"]["field"] == "status.keyword"

    def test_removes_pure_text_field(self):
        """text-only fields cannot be aggregated — agg should be dropped."""
        aggs = {"by_msg": {"terms": {"field": "message"}}}
        field_types = {"message": "text"}
        _fix_agg_fields(aggs, field_types)
        assert "by_msg" not in aggs

    def test_recurses_into_sub_aggs(self):
        aggs = {
            "by_host": {
                "terms": {"field": "host"},
                "aggs": {"by_user": {"terms": {"field": "UserName"}}},
            }
        }
        field_types = {
            "host": "text+kw",
            "host.keyword": "keyword",
            "UserName": "text+kw",
            "UserName.keyword": "keyword",
        }
        _fix_agg_fields(aggs, field_types)
        assert aggs["by_host"]["terms"]["field"] == "host.keyword"
        assert aggs["by_host"]["aggs"]["by_user"]["terms"]["field"] == "UserName.keyword"


# ─── _suggest_field / _check_unknown_fields / _rewrite_unknown_fields ─────────

class TestFieldSuggestion:
    FIELD_TYPES = {
        "UserName": "text+kw",
        "UserName.keyword": "keyword",
        "EventID": "long",
        "SourceAddress": "ip",
        "@timestamp": "date",
    }

    def test_suggest_exact_match(self):
        assert _suggest_field("UserName", self.FIELD_TYPES) == "UserName"

    def test_suggest_case_insensitive(self):
        assert _suggest_field("username", self.FIELD_TYPES) == "UserName"

    def test_suggest_substring(self):
        result = _suggest_field("EventId", self.FIELD_TYPES)
        assert result == "EventID"

    def test_suggest_no_match_returns_none(self):
        assert _suggest_field("XYZNoSuchField", self.FIELD_TYPES) is None

    def test_check_no_unknowns(self):
        # _check_unknown_fields inspects "field" key values (agg/script style)
        body = {"aggs": {"by_event": {"terms": {"field": "EventID"}}}}
        assert _check_unknown_fields(body, self.FIELD_TYPES) == []

    def test_check_detects_unknown(self):
        # SecurityID is not in FIELD_TYPES so it should appear in the unknown list
        body = {"aggs": {"by_sid": {"terms": {"field": "SecurityID"}}}}
        unknowns = _check_unknown_fields(body, self.FIELD_TYPES)
        assert "SecurityID" in unknowns

    def test_check_detects_unknown_term_query_key(self):
        body = {"query": {"term": {"SourceAddressRaw": "1.2.3.4"}}}
        unknowns = _check_unknown_fields(body, self.FIELD_TYPES)
        assert "SourceAddressRaw" in unknowns

    def test_check_skipped_when_no_field_types(self):
        body = {"aggs": {"by_x": {"terms": {"field": "AnyField"}}}}
        assert _check_unknown_fields(body, {}) == []

    def test_rewrite_corrects_unknown_field(self):
        # _rewrite_unknown_fields rewrites "field" values (agg-style), not query keys
        body = {"aggs": {"by_user": {"terms": {"field": "username"}}}}
        rewrites = _rewrite_unknown_fields(body, self.FIELD_TYPES)
        assert "username" in rewrites
        assert rewrites["username"] == "UserName"
        assert body["aggs"]["by_user"]["terms"]["field"] == "UserName"

    def test_rewrite_leaves_known_fields_intact(self):
        body = {"aggs": {"by_event": {"terms": {"field": "EventID"}}}}
        rewrites = _rewrite_unknown_fields(body, self.FIELD_TYPES)
        assert rewrites == {}
        assert body["aggs"]["by_event"]["terms"]["field"] == "EventID"

    def test_rewrite_corrects_term_query_key(self):
        body = {"query": {"term": {"sourceaddress": "1.2.3.4"}}}
        rewrites = _rewrite_unknown_fields(body, self.FIELD_TYPES)
        assert rewrites["sourceaddress"] == "SourceAddress"
        assert body["query"]["term"]["SourceAddress"] == "1.2.3.4"
        assert "sourceaddress" not in body["query"]["term"]


class TestEvidenceSummary:
    def test_evidence_summary_reports_first_and_last_seen(self):
        events = [
            {"@timestamp": "2024-01-02T00:00:00Z", "event_type": "dns", "src_ip": "1.2.3.4"},
            {"@timestamp": "2024-01-01T00:00:00Z", "event_type": "login", "src_ip": "1.2.3.4"},
        ]
        summary = _build_evidence_summary(events, "When have I seen 1.2.3.4 before?")
        assert "First seen: 2024-01-01T00:00:00Z" in summary
        assert "Last seen: 2024-01-02T00:00:00Z" in summary
        assert "Queried indicator matches: 1.2.3.4 (2)" in summary

    def test_evidence_summary_uses_file_mtime_when_timestamp_missing(self):
        events = [
            {"file": {"mtime": "2024-07-12T00:12:35Z", "path": "C:/a.txt"}},
            {"file": {"mtime": "2024-07-13T00:12:35Z", "path": "C:/b.txt"}},
        ]
        summary = _build_evidence_summary(events, "What files changed?")
        assert "First seen: 2024-07-12T00:12:35Z" in summary
        assert "Last seen: 2024-07-13T00:12:35Z" in summary

    def test_evidence_summary_formats_aggregate_rows(self):
        events = [
            {"by_source_ip": "1.2.3.4", "count": 10},
            {"by_source_ip": "5.6.7.8", "count": 5},
        ]
        summary = _build_evidence_summary(events, "List source IPs with counts")
        assert "Matching groups: 2" in summary
        assert 'Row 1: {"by_source_ip":"1.2.3.4","count":10}' in summary


class TestDeterministicEql:
    def test_term_query_translates_without_llm(self):
        body = {"query": {"term": {"source.ip": "1.2.3.4"}}, "size": 5}
        assert _deterministic_query_body_to_eql(body) == 'any where source.ip == "1.2.3.4" | head 5'

    def test_bool_query_translates_without_llm(self):
        body = {
            "query": {
                "bool": {
                    "must": [{"term": {"source.ip": "1.2.3.4"}}],
                    "must_not": [{"term": {"event.outcome": "failure"}}],
                }
            }
        }
        assert _deterministic_query_body_to_eql(body) == 'any where source.ip == "1.2.3.4" and not (event.outcome == "failure")'

    def test_terms_agg_translates_to_stats(self):
        body = {"query": {"match_all": {}}, "aggs": {"by_ip": {"terms": {"field": "source.ip"}}}, "size": 0}
        assert _deterministic_query_body_to_eql(body) == "any where true | stats count() by source.ip"


class TestDeterministicEsql:
    def test_term_query_translates_with_indices(self):
        body = {"query": {"term": {"source.ip": "1.2.3.4"}}, "size": 5}
        assert _deterministic_query_body_to_esql(body, ["auth-*"]) == 'FROM auth-* | WHERE source.ip == "1.2.3.4" | LIMIT 5'

    def test_exists_query_keeps_requested_fields(self):
        body = {"query": {"exists": {"field": "destination.ip"}}, "_source": ["destination.ip", "@timestamp"], "size": 20}
        assert _deterministic_query_body_to_esql(body, ["windows.eventlogs.rdpauth-*"]) == (
            "FROM windows.eventlogs.rdpauth-* | WHERE destination.ip IS NOT NULL | KEEP destination.ip, `@timestamp` | LIMIT 20"
        )

    def test_terms_agg_translates_to_esql_stats(self):
        body = {"query": {"match_all": {}}, "aggs": {"by_ip": {"terms": {"field": "source.ip", "size": 10, "order": {"_count": "desc"}}}}, "size": 0}
        assert _deterministic_query_body_to_esql(body, ["auth-*"]) == (
            "FROM auth-* | STATS count = COUNT(*) BY source.ip | SORT count DESC | LIMIT 10"
        )


class TestIndicatorFastPath:
    def test_extracts_ipv4_indicator(self):
        assert _extract_indicator("When have I seen 1.2.3.4 before?") == ("ip", "1.2.3.4")

    def test_extracts_ipv6_indicator(self):
        assert _extract_indicator("What was ::1 doing?") == ("ip", "::1")

    def test_extracts_ipv6_indicator_from_seen_before_question(self):
        assert _extract_indicator("When have I seen ::1 before and what was it doing?") == ("ip", "::1")

    def test_builds_ip_hunt_query(self):
        field_types = {
            "source.ip": "ip",
            "destination.ip": "ip",
            "@timestamp": "date",
            "process.name": "keyword",
        }
        body = _build_indicator_fast_path_query("When have I seen 1.2.3.4 before?", field_types, 10)
        assert body is not None
        should = body["query"]["bool"]["should"]
        assert {"term": {"source.ip": "1.2.3.4"}} in should
        assert {"term": {"destination.ip": "1.2.3.4"}} in should
        assert body["size"] == 10


class TestFieldListFastPath:
    def test_builds_destination_ip_list_query(self):
        field_types = {"destination.ip": "ip", "@timestamp": "date"}
        body = _build_field_list_fast_path_query("Give me a list of destination IP addresses", field_types, 20)
        assert body == {
            "query": {"exists": {"field": "destination.ip"}},
            "_source": ["destination.ip", "@timestamp"],
            "size": 20,
        }


class TestSemanticFastPaths:
    def test_schema_profile_keeps_role_scores(self):
        profile = _build_schema_profile(
            {"SourceIP": "ip", "DestIP": "ip"},
            {"SourceIP": "192.168.1.10", "DestIP": "192.168.1.20"},
        )
        candidates = _get_role_candidates(profile, "source_ip", 2)
        assert candidates[0]["field"] == "SourceIP"
        assert candidates[0]["score"] >= candidates[1]["score"]

    def test_parses_frequency_breakdown_intent(self):
        intent = _parse_query_intent("Give me a list of source IP addresses and how many times they appear")
        assert intent["name"] == "frequency_breakdown"
        assert intent["entity_role"] == "source_ip"

    def test_builds_destination_ip_count_query(self):
        field_types = {"destination.ip": "ip"}
        body = _build_ip_count_fast_path_query("Give me a list of destination IP addresses with counts", field_types, 20)
        assert body == {
            "query": {"exists": {"field": "destination.ip"}},
            "aggs": {
                "by_destination_ip": {
                    "terms": {"field": "destination.ip", "size": 20, "order": {"_count": "desc"}}
                }
            },
            "size": 0,
        }

    def test_builds_mft_between_dates_query(self):
        field_types = {"file.path": "keyword", "file.mtime": "date", "file.name": "keyword", "@timestamp": "date"}
        body = _build_mft_between_dates_query(
            "What files were changed between 2024-07-01 and 2024-07-03",
            ["windows.ntfs.mft-*"],
            field_types,
            25,
        )
        assert body is not None
        assert body["query"]["range"]["file.mtime"]["gte"] == "2024-07-01T00:00:00Z"
        assert body["query"]["range"]["file.mtime"]["lte"] == "2024-07-03T23:59:59Z"
        assert body["sort"] == [{"file.mtime": {"order": "asc"}}]

    def test_builds_failed_login_account_query(self):
        field_types = {"user.name": "keyword", "event.code": "keyword", "source.ip": "ip"}
        body = _build_failed_login_accounts_query(
            "Tell me about what accounts failed logins",
            ["windows.eventlogs.evtx-*"],
            field_types,
            15,
        )
        assert body is not None
        assert {"term": {"event.code": "4625"}} in body["query"]["bool"]["should"]
        assert body["aggs"]["by_account"]["terms"]["field"] == "user.name"

    def test_builds_history_between_dates_query(self):
        field_types = {"visited_url": "keyword", "url.original": "wildcard", "visit_time": "date", "title": "text+kw", "user.name": "keyword"}
        body = _build_history_between_dates_query(
            "What websites were visited between 2024-07-01 and 2024-07-03",
            ["windows.applications.chrome.history-*"],
            field_types,
            30,
        )
        assert body is not None
        assert body["query"]["range"]["visit_time"]["gte"] == "2024-07-01T00:00:00Z"
        assert body["query"]["range"]["visit_time"]["lte"] == "2024-07-03T23:59:59Z"
        assert body["_source"][0] == "visited_url"
        assert body["sort"] == [{"visit_time": {"order": "asc"}}]

    def test_requests_clarification_for_generic_ip_role(self):
        profile = _build_schema_profile(
            {"ClientIP": "ip", "ServerIP": "ip", "@timestamp": "date"},
            {"ClientIP": "192.168.1.10", "ServerIP": "192.168.1.20"},
        )
        clarification = _maybe_build_semantic_clarification(
            "Give me a list of IP addresses and how many times they appear",
            ["custom.logs-*"],
            profile,
        )
        assert clarification is not None
        assert clarification["role"] == "ip"
        assert "ClientIP" in clarification["options"]
        assert "ServerIP" in clarification["options"]
