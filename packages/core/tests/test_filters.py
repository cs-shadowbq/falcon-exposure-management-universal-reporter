"""Tests for the first-class host-group / tag scope filters."""

from femur.filters import (
    DATASET_SCOPE_FIELDS,
    augment_filter,
    build_scope_clause,
    normalize_tag,
)


# ---------------------------------------------------------------------------
# normalize_tag
# ---------------------------------------------------------------------------

class TestNormalizeTag:
    def test_bare_value_gets_falcon_prefix(self):
        assert normalize_tag("Monkey") == "FalconGroupingTags/Monkey"

    def test_value_with_slash_is_left_alone(self):
        assert normalize_tag("SensorGroupingTags/web") == "SensorGroupingTags/web"

    def test_unknown_prefix_is_preserved(self):
        assert normalize_tag("SomethingNew/value") == "SomethingNew/value"

    def test_existing_falcon_prefix_not_doubled(self):
        assert normalize_tag("FalconGroupingTags/x") == "FalconGroupingTags/x"

    def test_strips_surrounding_whitespace(self):
        assert normalize_tag("  heartbeat  ") == "FalconGroupingTags/heartbeat"


# ---------------------------------------------------------------------------
# build_scope_clause — per-dataset field mapping
# ---------------------------------------------------------------------------

class TestBuildScopeClause:
    def test_empty_inputs_yield_empty_string(self):
        assert build_scope_clause("applications") == ""
        assert build_scope_clause("vulnerabilities", group_values=[], tags=[]) == ""

    def test_applications_use_host_groups_and_host_tags(self):
        clause = build_scope_clause(
            "applications", group_values=["Cloud Lab"], tags=["Monkey"]
        )
        assert clause == (
            "host.groups:['Cloud Lab']+host.tags:['FalconGroupingTags/Monkey']"
        )

    def test_vulnerabilities_use_host_info_fields(self):
        clause = build_scope_clause(
            "vulnerabilities", group_values=["abc123"], tags=["Monkey"]
        )
        assert clause == (
            "host_info.groups:['abc123']+host_info.tags:['FalconGroupingTags/Monkey']"
        )

    def test_assessments_use_host_groups_with_ids(self):
        clause = build_scope_clause(
            "assessments", group_values=["abc123"], tags=["heartbeat"]
        )
        assert clause == (
            "host.groups:['abc123']+host.tags:['FalconGroupingTags/heartbeat']"
        )

    def test_multiple_groups_join_with_or_array(self):
        clause = build_scope_clause("applications", group_values=["A", "B"])
        assert clause == "host.groups:['A','B']"

    def test_multiple_tags_join_with_or_array(self):
        clause = build_scope_clause("applications", tags=["Monkey", "heartbeat"])
        assert clause == (
            "host.tags:['FalconGroupingTags/Monkey','FalconGroupingTags/heartbeat']"
        )

    def test_groups_only(self):
        clause = build_scope_clause("vulnerabilities", group_values=["abc123"])
        assert clause == "host_info.groups:['abc123']"

    def test_single_quote_in_value_is_escaped(self):
        clause = build_scope_clause("applications", group_values=["O'Brien Lab"])
        assert clause == "host.groups:['O\\'Brien Lab']"

    def test_every_known_dataset_is_mapped(self):
        assert set(DATASET_SCOPE_FIELDS) == {
            "applications",
            "vulnerabilities",
            "assessments",
        }


# ---------------------------------------------------------------------------
# augment_filter — additive combination with existing FQL
# ---------------------------------------------------------------------------

class TestAugmentFilter:
    def test_no_scope_returns_base_unchanged(self):
        assert augment_filter("status:'open'", "vulnerabilities") == "status:'open'"

    def test_no_scope_and_no_base_returns_none(self):
        assert augment_filter(None, "applications") is None

    def test_scope_appended_to_existing_filter_with_and(self):
        result = augment_filter(
            "status:['open','reopen']",
            "vulnerabilities",
            group_values=["abc123"],
            tags=["Monkey"],
        )
        assert result == (
            "status:['open','reopen']"
            "+host_info.groups:['abc123']"
            "+host_info.tags:['FalconGroupingTags/Monkey']"
        )

    def test_scope_becomes_whole_filter_when_base_is_none(self):
        result = augment_filter(None, "applications", tags=["Monkey"])
        assert result == "host.tags:['FalconGroupingTags/Monkey']"

    def test_scope_becomes_whole_filter_when_base_is_empty_string(self):
        result = augment_filter("", "applications", group_values=["Cloud Lab"])
        assert result == "host.groups:['Cloud Lab']"
