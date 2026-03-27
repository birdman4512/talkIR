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
