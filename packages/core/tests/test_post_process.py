"""Tests for core post-processing helpers."""

from femur._post_process import (
    assemble_inventory_payload,
    collect_fetch_errors,
    strip_compliance_mappings,
)


class TestStripComplianceMappings:
    def test_strips_from_matching_records(self):
        assessments = [
            {"finding": {"rule": {"name": "r1", "compliance_mappings": {"nist": ["AC-1"]}}}},
            {"finding": {"rule": {"name": "r2", "compliance_mappings": {"pci": ["1.1"]}}}},
        ]
        count = strip_compliance_mappings(assessments)
        assert count == 2
        assert "compliance_mappings" not in assessments[0]["finding"]["rule"]
        assert "compliance_mappings" not in assessments[1]["finding"]["rule"]
        # Other fields are preserved.
        assert assessments[0]["finding"]["rule"]["name"] == "r1"

    def test_skips_records_without_rule(self):
        assessments = [
            {"finding": {"status": "fail"}},
            {"id": "bare"},
        ]
        count = strip_compliance_mappings(assessments)
        assert count == 0

    def test_skips_records_without_compliance_mappings(self):
        assessments = [
            {"finding": {"rule": {"name": "r1"}}},
        ]
        count = strip_compliance_mappings(assessments)
        assert count == 0

    def test_empty_list(self):
        assert strip_compliance_mappings([]) == 0


class TestCollectFetchErrors:
    def test_collects_exceptions(self):
        results = {
            "applications": [{"id": "a1"}],
            "vulnerabilities": RuntimeError("timeout"),
            "assessments": [],
        }
        errors = collect_fetch_errors(results)
        assert len(errors) == 1
        assert errors[0]["dataset"] == "vulnerabilities"
        assert "timeout" in errors[0]["error"]

    def test_skips_none_by_default(self):
        results = {
            "applications": [],
            "host_map": None,
        }
        errors = collect_fetch_errors(results)
        assert errors == []

    def test_reports_none_when_skip_none_false(self):
        results = {"host_map": None}
        errors = collect_fetch_errors(results, skip_none=False)
        assert errors == []  # None is not an Exception

    def test_empty_results(self):
        assert collect_fetch_errors({}) == []

    def test_all_successful(self):
        results = {
            "applications": [1, 2],
            "vulnerabilities": [3],
            "assessments": [],
            "host_map": {},
        }
        assert collect_fetch_errors(results) == []

    def test_multiple_failures(self):
        results = {
            "applications": ValueError("bad"),
            "vulnerabilities": RuntimeError("timeout"),
            "assessments": [],
        }
        errors = collect_fetch_errors(results)
        assert len(errors) == 2
        datasets = {e["dataset"] for e in errors}
        assert datasets == {"applications", "vulnerabilities"}


class TestAssembleInventoryPayload:
    def test_basic_structure(self):
        payload = assemble_inventory_payload(
            applications=[{"id": "a1"}],
            vulnerabilities=[{"id": "v1"}, {"id": "v2"}],
            assessments=[],
            host_map={"h1": {"aid": "x"}},
        )
        assert "generated_at" in payload
        assert payload["counts"] == {
            "applications": 1,
            "vulnerabilities": 2,
            "assessments": 0,
            "host_map": 1,
        }
        assert payload["applications"] == [{"id": "a1"}]
        assert len(payload["vulnerabilities"]) == 2

    def test_no_errors_key_when_none(self):
        payload = assemble_inventory_payload([], [], [], {})
        assert "errors" not in payload

    def test_errors_included(self):
        errs = [{"dataset": "applications", "error": "boom"}]
        payload = assemble_inventory_payload([], [], [], {}, errors=errs)
        assert payload["errors"] == errs

    def test_empty_errors_list_not_included(self):
        payload = assemble_inventory_payload([], [], [], {}, errors=[])
        assert "errors" not in payload
