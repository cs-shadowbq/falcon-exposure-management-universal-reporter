"""Tests for IAVM parsing module and IavmDecoratorTransform."""

import io
import pytest

from femur_pipeline.iavm import parse_iavm_xml, lookup_iavm
from femur_pipeline.transforms import IavmDecoratorTransform


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

MINIMAL_IAVM_XML = """\
<?xml version="1.0" encoding="utf-8"?>
<cvexref xmlns="http://iavm.csd.disa.mil/schemas/IavmNoticeCveXref/1.0">
    <metaData>
        <dateGenerated>2026-06-08</dateGenerated>
    </metaData>
    <notice id="1001" number="2024-T-0001" severity="CAT I" title="Test Notice Alpha">
        <cvelist>
            <cve>CVE-2024-0001</cve>
            <cve>CVE-2024-0002</cve>
            <cve>CVE-2024-0003</cve>
        </cvelist>
    </notice>
    <notice id="1002" number="2024-A-0002" severity="CAT III" title="Test Notice Beta">
        <cvelist>
            <cve>CVE-2024-0003</cve>
            <cve>CVE-2024-0004</cve>
        </cvelist>
    </notice>
</cvexref>
"""

EMPTY_IAVM_XML = """\
<?xml version="1.0" encoding="utf-8"?>
<cvexref xmlns="http://iavm.csd.disa.mil/schemas/IavmNoticeCveXref/1.0">
    <metaData>
        <dateGenerated>2026-06-08</dateGenerated>
    </metaData>
</cvexref>
"""


def _parse_fixture(xml_str: str):
    return parse_iavm_xml(io.StringIO(xml_str))


# ---------------------------------------------------------------------------
# parse_iavm_xml
# ---------------------------------------------------------------------------


class TestParseIavmXml:
    def test_builds_index_from_xml(self):
        index = _parse_fixture(MINIMAL_IAVM_XML)
        assert "CVE-2024-0001" in index
        assert "CVE-2024-0002" in index
        assert "CVE-2024-0003" in index
        assert "CVE-2024-0004" in index

    def test_notice_metadata_correct(self):
        index = _parse_fixture(MINIMAL_IAVM_XML)
        notices = index["CVE-2024-0001"]
        assert len(notices) == 1
        assert notices[0]["iavm_number"] == "2024-T-0001"
        assert notices[0]["iavm_severity"] == "CAT I"
        assert notices[0]["iavm_title"] == "Test Notice Alpha"

    def test_cve_in_multiple_notices(self):
        """CVE-2024-0003 appears in both notices."""
        index = _parse_fixture(MINIMAL_IAVM_XML)
        notices = index["CVE-2024-0003"]
        assert len(notices) == 2
        numbers = {n["iavm_number"] for n in notices}
        assert numbers == {"2024-T-0001", "2024-A-0002"}

    def test_empty_xml_returns_empty_index(self):
        index = _parse_fixture(EMPTY_IAVM_XML)
        assert index == {}

    def test_parses_from_file_path(self, tmp_path):
        xml_file = tmp_path / "iavm.xml"
        xml_file.write_text(MINIMAL_IAVM_XML)
        index = parse_iavm_xml(str(xml_file))
        assert "CVE-2024-0001" in index


# ---------------------------------------------------------------------------
# lookup_iavm
# ---------------------------------------------------------------------------


class TestLookupIavm:
    def test_found(self):
        index = _parse_fixture(MINIMAL_IAVM_XML)
        result = lookup_iavm(index, "CVE-2024-0001")
        assert len(result) == 1
        assert result[0]["iavm_number"] == "2024-T-0001"

    def test_not_found(self):
        index = _parse_fixture(MINIMAL_IAVM_XML)
        result = lookup_iavm(index, "CVE-9999-0000")
        assert result == []

    def test_multiple_notices(self):
        index = _parse_fixture(MINIMAL_IAVM_XML)
        result = lookup_iavm(index, "CVE-2024-0003")
        assert len(result) == 2


# ---------------------------------------------------------------------------
# IavmDecoratorTransform — vulnerabilities
# ---------------------------------------------------------------------------


class TestIavmDecoratorTransformVulnerabilities:
    def _make_transform(self):
        return IavmDecoratorTransform(_parse_fixture(MINIMAL_IAVM_XML))

    def test_decorates_matching_vulnerability(self):
        t = self._make_transform()
        rec = {"vulnerability_id": "CVE-2024-0001", "status": "open"}
        result = t(rec, "vulnerabilities")
        assert "iavm_notices" in result
        assert len(result["iavm_notices"]) == 1
        assert result["iavm_notices"][0]["iavm_number"] == "2024-T-0001"

    def test_no_match_no_field_added(self):
        t = self._make_transform()
        rec = {"vulnerability_id": "CVE-9999-0000", "status": "open"}
        result = t(rec, "vulnerabilities")
        assert "iavm_notices" not in result

    def test_falls_back_to_cve_id_field(self):
        """When vulnerability_id is missing, tries cve.id."""
        t = self._make_transform()
        rec = {"cve": {"id": "CVE-2024-0002"}, "status": "open"}
        result = t(rec, "vulnerabilities")
        assert "iavm_notices" in result
        assert result["iavm_notices"][0]["iavm_number"] == "2024-T-0001"

    def test_multiple_notices_attached(self):
        t = self._make_transform()
        rec = {"vulnerability_id": "CVE-2024-0003"}
        result = t(rec, "vulnerabilities")
        assert len(result["iavm_notices"]) == 2

    def test_existing_fields_preserved(self):
        t = self._make_transform()
        rec = {"vulnerability_id": "CVE-2024-0001", "aid": "agent1", "status": "open"}
        result = t(rec, "vulnerabilities")
        assert result["aid"] == "agent1"
        assert result["status"] == "open"


# ---------------------------------------------------------------------------
# IavmDecoratorTransform — assessments
# ---------------------------------------------------------------------------


class TestIavmDecoratorTransformAssessments:
    def _make_transform(self):
        return IavmDecoratorTransform(_parse_fixture(MINIMAL_IAVM_XML))

    def test_decorates_assessment_with_cve_ids(self):
        t = self._make_transform()
        rec = {
            "finding": {
                "status": "fail",
                "rule": {
                    "name": "Test Rule",
                    "cve_ids": ["CVE-2024-0001", "CVE-2024-0004"],
                },
            }
        }
        result = t(rec, "assessments")
        assert "iavm_notices" in result
        # CVE-2024-0001 → notice 1, CVE-2024-0004 → notice 2
        numbers = {n["iavm_number"] for n in result["iavm_notices"]}
        assert "2024-T-0001" in numbers
        assert "2024-A-0002" in numbers

    def test_no_cve_ids_no_decoration(self):
        t = self._make_transform()
        rec = {
            "finding": {
                "status": "pass",
                "rule": {"name": "No CVEs Here"},
            }
        }
        result = t(rec, "assessments")
        assert "iavm_notices" not in result

    def test_cve_ids_no_match(self):
        t = self._make_transform()
        rec = {
            "finding": {
                "status": "fail",
                "rule": {"name": "Rule", "cve_ids": ["CVE-9999-0000"]},
            }
        }
        result = t(rec, "assessments")
        assert "iavm_notices" not in result


# ---------------------------------------------------------------------------
# IavmDecoratorTransform — passthrough
# ---------------------------------------------------------------------------


class TestIavmDecoratorTransformPassthrough:
    def test_passthrough_applications(self):
        t = IavmDecoratorTransform(_parse_fixture(MINIMAL_IAVM_XML))
        rec = {"vendor": "Google", "name": "Chrome", "version": "120.0"}
        result = t(rec, "applications")
        assert result == rec
        assert "iavm_notices" not in result

    def test_passthrough_unknown_dataset(self):
        t = IavmDecoratorTransform(_parse_fixture(MINIMAL_IAVM_XML))
        rec = {"id": "something"}
        result = t(rec, "host_map")
        assert result == rec
