"""Tests for the FastAPI inventory server."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from femur_server.server.app import create_app
from femur_server.server.jobs import FetchJob
from femur_server.server.store import InventoryStore

try:
    from fastapi.testclient import TestClient
except ImportError:
    pytest.skip("fastapi not installed", allow_module_level=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_jsonl(path: Path, records: list[dict]) -> None:
    with open(path, "w") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")


def _write_manifest(dir_path: Path, manifest: dict) -> None:
    with open(dir_path / "manifest.json", "w") as fh:
        json.dump(manifest, fh)


# ---------------------------------------------------------------------------
# InventoryStore
# ---------------------------------------------------------------------------


class TestInventoryStore:
    def test_load(self, tmp_path):
        _write_jsonl(tmp_path / "applications.jsonl", [{"id": "a1"}])
        _write_jsonl(tmp_path / "vulnerabilities.jsonl", [{"id": "v1"}, {"id": "v2"}])
        _write_jsonl(tmp_path / "assessments.jsonl", [])
        _write_manifest(tmp_path, {
            "generated_at": "2024-01-01T00:00:00Z",
            "counts": {"applications": 1, "vulnerabilities": 2, "assessments": 0},
        })

        store = InventoryStore(str(tmp_path))
        store.load()

        assert store.generated_at == "2024-01-01T00:00:00Z"
        assert store.get_dataset("applications") == [{"id": "a1"}]
        assert len(store.get_dataset("vulnerabilities")) == 2
        assert store.get_dataset("assessments") == []
        assert store.age_seconds is not None
        assert store.age_seconds < 5.0

    def test_load_no_manifest(self, tmp_path):
        store = InventoryStore(str(tmp_path))
        store.load()
        assert store.generated_at is None

    def test_host_map_loading(self, tmp_path):
        _write_jsonl(
            tmp_path / "host_map.jsonl",
            [{"_host_map_id": "h1", "aid": "a1"}, {"_host_map_id": "h2", "aid": "a2"}],
        )
        _write_jsonl(tmp_path / "applications.jsonl", [])
        _write_jsonl(tmp_path / "vulnerabilities.jsonl", [])
        _write_jsonl(tmp_path / "assessments.jsonl", [])
        _write_manifest(tmp_path, {"generated_at": "now", "counts": {}})

        store = InventoryStore(str(tmp_path))
        store.load()

        hm = store.get_host_map()
        assert hm["h1"] == {"aid": "a1"}
        assert hm["h2"] == {"aid": "a2"}


# ---------------------------------------------------------------------------
# FetchJob
# ---------------------------------------------------------------------------


class TestFetchJob:
    def test_trigger_returns_true_first_time(self, tmp_path):
        job = FetchJob(str(tmp_path), env_file="test.env")
        store = MagicMock(spec=InventoryStore)
        with patch("femur_server.server.jobs.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            result = job.trigger(store)
        assert result is True

    def test_double_trigger_returns_false(self, tmp_path):
        job = FetchJob(str(tmp_path))
        store = MagicMock(spec=InventoryStore)
        import threading
        barrier = threading.Event()

        def _slow_run(*args, **kwargs):
            barrier.wait(timeout=5)
            return MagicMock(returncode=0, stderr="")

        with patch("femur_server.server.jobs.subprocess.run", side_effect=_slow_run):
            assert job.trigger(store) is True
            assert job.trigger(store) is False
            barrier.set()


# ---------------------------------------------------------------------------
# FastAPI endpoints (using app factory)
# ---------------------------------------------------------------------------


@pytest.fixture()
def client(tmp_path):
    """Provide a test client with a pre-loaded store."""
    _write_jsonl(tmp_path / "applications.jsonl", [
        {"id": "a0", "aid": "agent1", "cid": "tenant1", "name": "Chrome", "vendor": "Google",
         "version": "120.0", "software_type": "application", "is_suspicious": False,
         "name_vendor": "Chrome-Google", "category": "Browser"},
        {"id": "a1", "aid": "agent1", "cid": "tenant1", "name": "Slack", "vendor": "Salesforce",
         "version": "4.38", "software_type": "application", "is_suspicious": False,
         "name_vendor": "Slack-Salesforce", "category": "Communication"},
        {"id": "a2", "aid": "agent2", "cid": "tenant1", "name": "Mimikatz", "vendor": "Unknown",
         "version": "2.2", "software_type": "application", "is_suspicious": True,
         "name_vendor": "Mimikatz-Unknown", "category": "Security"},
        {"id": "a3", "aid": "agent3", "cid": "tenant2", "name": "Firefox", "vendor": "Mozilla",
         "version": "121.0", "software_type": "application", "is_suspicious": False,
         "name_vendor": "Firefox-Mozilla", "category": "Browser"},
        {"id": "a4", "aid": "agent3", "cid": "tenant2", "name": "Notepad++", "vendor": "Don Ho",
         "version": "8.6", "software_type": "application", "is_suspicious": False,
         "name_vendor": "Notepad++-Don Ho", "category": "IT management"},
    ])
    _write_jsonl(tmp_path / "vulnerabilities.jsonl", [
        {"id": "v1", "aid": "agent1", "cid": "tenant1", "vulnerability_id": "CVE-2024-0001",
         "suppression_info": {"is_suppressed": False}},
        {"id": "v2", "aid": "agent2", "cid": "tenant1", "vulnerability_id": "CVE-2024-0002",
         "suppression_info": {"is_suppressed": True}},
        {"id": "v3", "aid": "agent3", "cid": "tenant2", "vulnerability_id": "CVE-2024-0001",
         "suppression_info": {"is_suppressed": False}},
    ])
    _write_jsonl(tmp_path / "assessments.jsonl", [
        {"id": "s1", "aid": "agent1", "cid": "tenant1",
         "finding": {"status": "fail",
                     "rule": {"name": "BitLocker required", "platform_name": "Windows",
                              "severity": "High", "group_name": "DISA STIG Windows"}}},
        {"id": "s2", "aid": "agent2", "cid": "tenant1",
         "finding": {"status": "pass",
                     "rule": {"name": "Firewall enabled", "platform_name": "Linux",
                              "severity": "Medium", "group_name": "CIS Linux"}}},
        {"id": "s3", "aid": "agent3", "cid": "tenant2",
         "finding": {"status": "unsupported",
                     "rule": {"name": "BitLocker required", "platform_name": "Windows",
                              "severity": "High", "group_name": "DISA STIG Windows"}}},
    ])
    _write_jsonl(tmp_path / "host_map.jsonl", [
        {"_host_map_id": "h1", "aid": "agent1", "cid": "tenant1"},
        {"_host_map_id": "h2", "aid": "agent2", "cid": "tenant1"},
        {"_host_map_id": "h3", "aid": "agent3", "cid": "tenant2"},
    ])
    _write_manifest(tmp_path, {
        "generated_at": "2024-06-01T12:00:00Z",
        "counts": {"applications": 5, "vulnerabilities": 3, "assessments": 3},
    })
    app = create_app(data_dir=str(tmp_path), max_age=999999)
    with TestClient(app) as c:
        yield c


class TestEndpoints:
    def test_root_index(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        data = resp.json()
        assert data["service"] == "Falcon Inventory API"
        assert "/docs" in data["docs"]
        assert "applications" in data["endpoints"]

    def test_health(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["generated_at"] == "2024-06-01T12:00:00Z"
        assert data["stale"] is False

    def test_applications_paginated(self, client):
        resp = client.get("/v1/applications?limit=2&offset=0")
        assert resp.status_code == 200
        data = resp.json()
        assert data["meta"]["total"] == 5
        assert data["meta"]["count"] == 2
        assert len(data["records"]) == 2
        assert data["meta"]["offset"] == 0

    def test_applications_offset(self, client):
        resp = client.get("/v1/applications?limit=10&offset=3")
        data = resp.json()
        assert data["meta"]["count"] == 2  # 5 records, skip 3 → 2 left

    def test_vulnerabilities(self, client):
        resp = client.get("/v1/vulnerabilities")
        assert resp.status_code == 200
        data = resp.json()
        assert data["meta"]["total"] == 3

    def test_assessments(self, client):
        resp = client.get("/v1/assessments")
        data = resp.json()
        assert data["meta"]["total"] == 3

    def test_search_q(self, client):
        resp = client.get("/v1/applications?q=Chrome")
        data = resp.json()
        assert data["meta"]["total"] == 1
        assert data["records"][0]["id"] == "a0"

    def test_host_map(self, client):
        resp = client.get("/v1/host_map")
        assert resp.status_code == 200
        hm = resp.json()["host_map"]
        assert len(hm) == 3

    def test_counts(self, client):
        resp = client.get("/v1/counts")
        data = resp.json()
        assert data["counts"]["applications"] == 5

    def test_fetch_trigger(self, client):
        with patch.object(FetchJob, "trigger", return_value=True):
            resp = client.post("/v1/fetch")
        assert resp.status_code == 200
        assert resp.json()["status"] == "started"

    def test_openapi_schema(self, client):
        resp = client.get("/openapi.json")
        assert resp.status_code == 200
        schema = resp.json()
        assert schema["info"]["title"] == "Falcon Inventory API"
        assert "/health" in schema["paths"]
        assert "/v1/applications" in schema["paths"]
        assert "/v1/vulnerabilities" in schema["paths"]
        assert "/v1/assessments" in schema["paths"]

    def test_staleness_metadata(self, client):
        resp = client.get("/v1/applications")
        data = resp.json()
        assert "data_age_seconds" in data["meta"]
        assert data["meta"]["stale"] is False
        assert data["meta"]["generated_at"] == "2024-06-01T12:00:00Z"


# ---------------------------------------------------------------------------
# Filtering and by-aid endpoints
# ---------------------------------------------------------------------------


class TestApplicationFilters:
    def test_filter_by_aid(self, client):
        data = client.get("/v1/applications?aid=agent1").json()
        assert data["meta"]["total"] == 2
        assert all(r["aid"] == "agent1" for r in data["records"])

    def test_filter_by_cid(self, client):
        data = client.get("/v1/applications?cid=tenant2").json()
        assert data["meta"]["total"] == 2
        assert all(r["cid"] == "tenant2" for r in data["records"])

    def test_filter_by_name(self, client):
        data = client.get("/v1/applications?name=chrome").json()
        assert data["meta"]["total"] == 1
        assert data["records"][0]["name"] == "Chrome"

    def test_filter_by_vendor(self, client):
        data = client.get("/v1/applications?vendor=mozilla").json()
        assert data["meta"]["total"] == 1

    def test_filter_by_version(self, client):
        data = client.get("/v1/applications?version=120.0").json()
        assert data["meta"]["total"] == 1

    def test_filter_by_software_type(self, client):
        data = client.get("/v1/applications?software_type=application").json()
        assert data["meta"]["total"] == 5

    def test_filter_by_is_suspicious(self, client):
        data = client.get("/v1/applications?is_suspicious=true").json()
        assert data["meta"]["total"] == 1
        assert data["records"][0]["name"] == "Mimikatz"

    def test_filter_by_name_vendor(self, client):
        data = client.get("/v1/applications?name_vendor=Chrome-Google").json()
        assert data["meta"]["total"] == 1

    def test_filter_by_category(self, client):
        data = client.get("/v1/applications?category=browser").json()
        assert data["meta"]["total"] == 2

    def test_filter_combined(self, client):
        data = client.get("/v1/applications?cid=tenant1&category=browser").json()
        assert data["meta"]["total"] == 1
        assert data["records"][0]["name"] == "Chrome"

    def test_by_aid_endpoint(self, client):
        data = client.get("/v1/applications/by-aid/agent3").json()
        assert data["meta"]["total"] == 2
        assert all(r["aid"] == "agent3" for r in data["records"])

    def test_by_aid_endpoint_no_match(self, client):
        data = client.get("/v1/applications/by-aid/nonexistent").json()
        assert data["meta"]["total"] == 0


class TestVulnerabilityFilters:
    def test_filter_by_aid(self, client):
        data = client.get("/v1/vulnerabilities?aid=agent1").json()
        assert data["meta"]["total"] == 1

    def test_filter_by_cid(self, client):
        data = client.get("/v1/vulnerabilities?cid=tenant1").json()
        assert data["meta"]["total"] == 2

    def test_filter_by_vulnerability_id(self, client):
        data = client.get("/v1/vulnerabilities?vulnerability_id=CVE-2024-0001").json()
        assert data["meta"]["total"] == 2

    def test_filter_by_is_suppressed_true(self, client):
        data = client.get("/v1/vulnerabilities?is_suppressed=true").json()
        assert data["meta"]["total"] == 1
        assert data["records"][0]["id"] == "v2"

    def test_filter_by_is_suppressed_false(self, client):
        data = client.get("/v1/vulnerabilities?is_suppressed=false").json()
        assert data["meta"]["total"] == 2

    def test_filter_combined(self, client):
        data = client.get("/v1/vulnerabilities?cid=tenant1&is_suppressed=false").json()
        assert data["meta"]["total"] == 1
        assert data["records"][0]["id"] == "v1"

    def test_by_aid_endpoint(self, client):
        data = client.get("/v1/vulnerabilities/by-aid/agent1").json()
        assert data["meta"]["total"] == 1


class TestAssessmentFilters:
    def test_filter_by_aid(self, client):
        data = client.get("/v1/assessments?aid=agent1").json()
        assert data["meta"]["total"] == 1

    def test_filter_by_cid(self, client):
        data = client.get("/v1/assessments?cid=tenant2").json()
        assert data["meta"]["total"] == 1

    def test_filter_by_status(self, client):
        data = client.get("/v1/assessments?status=fail").json()
        assert data["meta"]["total"] == 1
        assert data["records"][0]["id"] == "s1"

    def test_filter_by_status_case_insensitive(self, client):
        data = client.get("/v1/assessments?status=PASS").json()
        assert data["meta"]["total"] == 1

    def test_filter_by_rule_name(self, client):
        data = client.get("/v1/assessments?rule_name=BitLocker").json()
        assert data["meta"]["total"] == 2

    def test_filter_by_rule_platform(self, client):
        data = client.get("/v1/assessments?rule_platform=Linux").json()
        assert data["meta"]["total"] == 1

    def test_filter_by_rule_severity(self, client):
        data = client.get("/v1/assessments?rule_severity=High").json()
        assert data["meta"]["total"] == 2

    def test_filter_by_group_name(self, client):
        data = client.get("/v1/assessments?group_name=CIS").json()
        assert data["meta"]["total"] == 1

    def test_filter_combined(self, client):
        data = client.get("/v1/assessments?status=fail&rule_platform=Windows").json()
        assert data["meta"]["total"] == 1
        assert data["records"][0]["id"] == "s1"

    def test_by_aid_endpoint(self, client):
        data = client.get("/v1/assessments/by-aid/agent2").json()
        assert data["meta"]["total"] == 1
        assert data["records"][0]["id"] == "s2"


class TestHostMapFilters:
    def test_filter_by_aid(self, client):
        data = client.get("/v1/host_map?aid=agent1").json()
        assert len(data["host_map"]) == 1

    def test_filter_by_cid(self, client):
        data = client.get("/v1/host_map?cid=tenant1").json()
        assert len(data["host_map"]) == 2

    def test_by_aid_endpoint(self, client):
        data = client.get("/v1/host_map/by-aid/agent2").json()
        hm = data["host_map"]
        assert len(hm) == 1
        assert list(hm.values())[0]["aid"] == "agent2"

    def test_by_aid_no_match(self, client):
        data = client.get("/v1/host_map/by-aid/nonexistent").json()
        assert len(data["host_map"]) == 0
