"""Tests for record transforms."""

import pytest

from femur_pipeline.transforms import (
    AidDecoratorTransform,
    ComplianceMappingStripTransform,
    FieldFilterTransform,
)


# ---------------------------------------------------------------------------
# AidDecoratorTransform
# ---------------------------------------------------------------------------


class TestAidDecoratorTransform:
    HOST_MAP = {
        "host-1": {"cid": "cid-1", "aid": "aid-1"},
        "host-2": {"cid": "cid-2", "aid": "aid-2"},
    }

    def test_injects_aid(self):
        t = AidDecoratorTransform(self.HOST_MAP)
        rec = {"host": {"id": "host-1"}}
        result = t(rec, "applications")
        assert result["aid"] == "aid-1"

    def test_missing_host_id_no_crash(self):
        t = AidDecoratorTransform(self.HOST_MAP)
        rec = {"host": {"id": "not-found"}}
        result = t(rec, "applications")
        assert "aid" not in result

    def test_no_host_key(self):
        t = AidDecoratorTransform(self.HOST_MAP)
        rec = {"name": "app1"}
        result = t(rec, "applications")
        assert result == {"name": "app1"}

    def test_passthrough_non_application(self):
        t = AidDecoratorTransform(self.HOST_MAP)
        rec = {"id": "vuln1"}
        result = t(rec, "vulnerabilities")
        assert result == rec
        assert "aid" not in result


# ---------------------------------------------------------------------------
# ComplianceMappingStripTransform
# ---------------------------------------------------------------------------


class TestComplianceMappingStripTransform:
    def test_strips_compliance_mappings(self):
        t = ComplianceMappingStripTransform()
        rec = {
            "finding": {
                "rule": {
                    "name": "R1",
                    "compliance_mappings": [{"standard": "CIS"}],
                },
                "status": "fail",
            }
        }
        result = t(rec, "assessments")
        assert "compliance_mappings" not in result["finding"]["rule"]
        assert result["finding"]["rule"]["name"] == "R1"

    def test_no_rule_key(self):
        t = ComplianceMappingStripTransform()
        rec = {"finding": {"status": "pass"}}
        result = t(rec, "assessments")
        assert result == rec

    def test_passthrough_non_assessment(self):
        t = ComplianceMappingStripTransform()
        rec = {"id": "app1"}
        result = t(rec, "applications")
        assert result == rec


# ---------------------------------------------------------------------------
# FieldFilterTransform
# ---------------------------------------------------------------------------


class TestFieldFilterTransform:
    def test_include_only(self):
        t = FieldFilterTransform(include={"id", "name"})
        rec = {"id": "1", "name": "app", "extra": "x"}
        result = t(rec, "any")
        assert result == {"id": "1", "name": "app"}

    def test_exclude(self):
        t = FieldFilterTransform(exclude={"extra"})
        rec = {"id": "1", "extra": "x", "name": "app"}
        result = t(rec, "any")
        assert result == {"id": "1", "name": "app"}

    def test_include_beats_exclude(self):
        t = FieldFilterTransform(include={"id"}, exclude={"name"})
        rec = {"id": "1", "name": "app"}
        result = t(rec, "any")
        # include takes precedence
        assert result == {"id": "1"}

    def test_dataset_scoped(self):
        t = FieldFilterTransform(exclude={"extra"}, dataset="apps")
        rec_apps = {"id": "1", "extra": "x"}
        rec_vulns = {"id": "2", "extra": "y"}
        assert t(rec_apps, "apps") == {"id": "1"}
        assert t(rec_vulns, "vulns") == {"id": "2", "extra": "y"}

    def test_no_filters_passthrough(self):
        t = FieldFilterTransform()
        rec = {"id": "1", "x": 2}
        assert t(rec, "ds") == rec
