"""Tests for AID-bucketed output sink."""

import json
import os
import threading
import zipfile
from pathlib import Path

import pytest

from femur_pipeline.sinks.aid_bucketed import (
    DEFAULT_AID_SHARD_DEPTH,
    AidBucketedSink,
)

# Repo-root-relative schema directory (packages/pipeline/tests -> repo root).
_SCHEMA_DIR = Path(__file__).resolve().parents[3] / "docs" / "schemas"


def _aid_path(tmp_path, aid, depth=DEFAULT_AID_SHARD_DEPTH):
    """Directory for one AID under the sharded layout.

    AID directories live at ``by_aid/<aid[:depth]>/<aid>/``; ``_no_aid`` is
    never sharded.
    """
    by_aid = Path(tmp_path) / "by_aid"
    if depth and aid != "_no_aid":
        return by_aid / aid[:depth] / aid
    return by_aid / aid


def _aid_dirs(tmp_path, depth=DEFAULT_AID_SHARD_DEPTH):
    """Every AID directory, whatever the shard depth."""
    by_aid = Path(tmp_path) / "by_aid"
    if not depth:
        return sorted(p for p in by_aid.iterdir() if p.is_dir())
    found = []
    for shard in by_aid.iterdir():
        if not shard.is_dir():
            continue
        if shard.name == "_no_aid":
            found.append(shard)
        else:
            found.extend(p for p in shard.iterdir() if p.is_dir())
    return sorted(found)


def _read_jsonl(path):
    """Read a JSONL file and return list of dicts."""
    records = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def _find_jsonl(directory, prefix):
    """Find a JSONL file in directory starting with the given prefix."""
    for fname in os.listdir(directory):
        if fname.startswith(prefix) and fname.endswith(".jsonl"):
            return os.path.join(directory, fname)
    return None


def _find_json(directory, prefix):
    """Find a JSON file in directory starting with the given prefix."""
    for fname in os.listdir(directory):
        if fname.startswith(prefix) and fname.endswith(".json"):
            return os.path.join(directory, fname)
    return None


# ---------------------------------------------------------------------------
# Basic routing
# ---------------------------------------------------------------------------


class TestAidBucketedSinkRouting:
    def test_routes_by_aid(self, tmp_path):
        sink = AidBucketedSink(str(tmp_path))
        sink.set_metadata("generated_at", "2026-06-09T00:00:00+00:00")
        sink.write_record("vulnerabilities", {"aid": "aaaa1111bbbb2222", "cid": "cid1", "cve": "CVE-1"})
        sink.write_record("vulnerabilities", {"aid": "cccc3333dddd4444", "cid": "cid2", "cve": "CVE-2"})
        sink.close()

        by_aid = tmp_path / "by_aid"
        dir1 = _aid_path(tmp_path, "aaaa1111bbbb2222")
        dir2 = _aid_path(tmp_path, "cccc3333dddd4444")
        assert dir1.is_dir()
        assert dir2.is_dir()

        f1 = _find_jsonl(str(dir1), "vulnerabilities--")
        f2 = _find_jsonl(str(dir2), "vulnerabilities--")
        assert f1 is not None
        assert f2 is not None

        recs1 = _read_jsonl(f1)
        recs2 = _read_jsonl(f2)
        assert len(recs1) == 1
        assert recs1[0]["cve"] == "CVE-1"
        assert len(recs2) == 1
        assert recs2[0]["cve"] == "CVE-2"

    def test_no_aid_goes_to_no_aid_dir(self, tmp_path):
        sink = AidBucketedSink(str(tmp_path))
        sink.set_metadata("generated_at", "2026-06-09T00:00:00+00:00")
        sink.write_record("host_map", {"_host_map_id": "h1", "cid": "c1"})
        sink.close()

        no_aid_dir = _aid_path(tmp_path, "_no_aid")
        assert no_aid_dir.is_dir()
        f = _find_jsonl(str(no_aid_dir), "host_map--")
        assert f is not None
        recs = _read_jsonl(f)
        assert len(recs) == 1
        assert recs[0]["_host_map_id"] == "h1"

    def test_multiple_datasets_same_aid(self, tmp_path):
        sink = AidBucketedSink(str(tmp_path))
        sink.set_metadata("generated_at", "2026-06-09T00:00:00+00:00")
        aid = "aaaa1111bbbb2222cccc3333dddd4444"
        sink.write_record("applications", {"aid": aid, "cid": "cid1", "name": "Chrome"})
        sink.write_record("vulnerabilities", {"aid": aid, "cid": "cid1", "cve": "CVE-1"})
        sink.close()

        aid_dir = _aid_path(tmp_path, aid)
        assert _find_jsonl(str(aid_dir), "applications--") is not None
        assert _find_jsonl(str(aid_dir), "vulnerabilities--") is not None

    def test_same_aid_multiple_records(self, tmp_path):
        sink = AidBucketedSink(str(tmp_path))
        sink.set_metadata("generated_at", "2026-06-09T00:00:00+00:00")
        aid = "aaaa1111bbbb2222"
        sink.write_record("vulnerabilities", {"aid": aid, "cid": "c1", "cve": "CVE-1"})
        sink.write_record("vulnerabilities", {"aid": aid, "cid": "c1", "cve": "CVE-2"})
        sink.write_record("vulnerabilities", {"aid": aid, "cid": "c1", "cve": "CVE-3"})
        sink.close()

        aid_dir = _aid_path(tmp_path, aid)
        f = _find_jsonl(str(aid_dir), "vulnerabilities--")
        recs = _read_jsonl(f)
        assert len(recs) == 3


# ---------------------------------------------------------------------------
# File naming convention
# ---------------------------------------------------------------------------


class TestAidBucketedSinkNaming:
    def test_filename_format(self, tmp_path):
        """Files follow {dataset}--{cid12}--{aid}--{epoch}.jsonl"""
        sink = AidBucketedSink(str(tmp_path))
        sink.set_metadata("generated_at", "2026-06-09T00:00:00+00:00")
        sink.write_record("vulnerabilities", {
            "aid": "aabbccdd11223344",
            "cid": "5ddb0407bef249c19c7a975f17979a1f",
            "cve": "CVE-1",
        })
        sink.close()

        aid_dir = _aid_path(tmp_path, "aabbccdd11223344")
        files = os.listdir(str(aid_dir))
        vuln_files = [f for f in files if f.startswith("vulnerabilities--")]
        assert len(vuln_files) == 1
        # Check format: vulnerabilities--{cid12}--{aid}--{epoch}.jsonl
        parts = vuln_files[0].replace(".jsonl", "").split("--")
        assert parts[0] == "vulnerabilities"
        assert parts[1] == "5ddb0407bef2"  # first 12 chars of CID
        assert parts[2] == "aabbccdd11223344"
        assert parts[3] == "1780963200"  # 2026-06-09T00:00:00+00:00 as epoch

    def test_manifest_filename_format(self, tmp_path):
        """Manifest follows {manifest}--{cid12}--{aid}--{epoch}.json"""
        sink = AidBucketedSink(str(tmp_path))
        sink.set_metadata("generated_at", "2026-06-09T00:00:00+00:00")
        sink.write_record("vulnerabilities", {
            "aid": "aabbccdd11223344",
            "cid": "5ddb0407bef249c19c7a975f17979a1f",
            "cve": "CVE-1",
        })
        sink.close()

        aid_dir = _aid_path(tmp_path, "aabbccdd11223344")
        manifest_file = _find_json(str(aid_dir), "manifest--")
        assert manifest_file is not None
        assert "5ddb0407bef2" in manifest_file
        assert "aabbccdd11223344" in manifest_file


# ---------------------------------------------------------------------------
# write_batch routing
# ---------------------------------------------------------------------------


class TestAidBucketedSinkBatch:
    def test_batch_routes_to_multiple_aids(self, tmp_path):
        sink = AidBucketedSink(str(tmp_path))
        sink.set_metadata("generated_at", "2026-06-09T00:00:00+00:00")
        records = [
            {"aid": "aid_aaa", "cid": "c1", "cve": "CVE-1"},
            {"aid": "aid_bbb", "cid": "c1", "cve": "CVE-2"},
            {"aid": "aid_aaa", "cid": "c1", "cve": "CVE-3"},
            {"aid": "aid_ccc", "cid": "c1", "cve": "CVE-4"},
        ]
        sink.write_batch("vulnerabilities", records)
        sink.close()

        by_aid = tmp_path / "by_aid"
        recs_a = _read_jsonl(_find_jsonl(str(_aid_path(tmp_path, "aid_aaa")), "vulnerabilities--"))
        recs_b = _read_jsonl(_find_jsonl(str(_aid_path(tmp_path, "aid_bbb")), "vulnerabilities--"))
        recs_c = _read_jsonl(_find_jsonl(str(_aid_path(tmp_path, "aid_ccc")), "vulnerabilities--"))
        assert len(recs_a) == 2
        assert len(recs_b) == 1
        assert len(recs_c) == 1

    def test_batch_mixed_with_no_aid(self, tmp_path):
        sink = AidBucketedSink(str(tmp_path))
        sink.set_metadata("generated_at", "2026-06-09T00:00:00+00:00")
        records = [
            {"aid": "aid_aaa", "cid": "c1", "data": 1},
            {"data": 2},  # no aid
            {"aid": "", "data": 3},  # empty aid
        ]
        sink.write_batch("host_map", records)
        sink.close()

        by_aid = tmp_path / "by_aid"
        recs_a = _read_jsonl(_find_jsonl(str(_aid_path(tmp_path, "aid_aaa")), "host_map--"))
        recs_no = _read_jsonl(_find_jsonl(str(_aid_path(tmp_path, "_no_aid")), "host_map--"))
        assert len(recs_a) == 1
        assert len(recs_no) == 2


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------


class TestAidBucketedSinkManifest:
    def test_aggregate_manifest(self, tmp_path):
        sink = AidBucketedSink(str(tmp_path))
        sink.set_metadata("generated_at", "2026-06-09T00:00:00+00:00")
        sink.write_record("vulnerabilities", {"aid": "aaa", "cid": "c1", "cve": "CVE-1"})
        sink.write_record("vulnerabilities", {"aid": "bbb", "cid": "c1", "cve": "CVE-2"})
        sink.write_record("vulnerabilities", {"aid": "ccc", "cid": "c2", "cve": "CVE-3"})
        sink.close()

        manifest_path = tmp_path / "by_aid" / "manifest.json"
        assert manifest_path.exists()
        manifest = json.loads(manifest_path.read_text())
        assert manifest["total_aids"] == 3
        assert manifest["generated_at"] == "2026-06-09T00:00:00+00:00"

    def test_sub_sink_manifests(self, tmp_path):
        sink = AidBucketedSink(str(tmp_path))
        sink.set_metadata("generated_at", "2026-06-09T00:00:00+00:00")
        sink.write_record("applications", {"aid": "aaa", "cid": "c1", "name": "Chrome"})
        sink.write_record("applications", {"aid": "aaa", "cid": "c1", "name": "Firefox"})
        sink.close()

        aid_dir = _aid_path(tmp_path, "aaa")
        manifest_file = _find_json(str(aid_dir), "manifest--")
        assert manifest_file is not None
        data = json.loads(open(manifest_file).read())
        assert data["counts"]["applications"] == 2

    def test_provenance_in_manifest(self, tmp_path):
        sink = AidBucketedSink(str(tmp_path))
        sink.set_metadata("generated_at", "2026-06-09T00:00:00+00:00")
        sink.set_metadata("app_name", "falcon-exposure-management-universal-reporter")
        sink.set_metadata("app_version", "2.0.0")
        sink.set_metadata("command", "femur -e talon.env --bucket-by-aid")
        sink.write_record("vulnerabilities", {"aid": "aaa", "cid": "c1", "cve": "CVE-1"})
        sink.close()

        # Check per-AID manifest
        aid_dir = _aid_path(tmp_path, "aaa")
        manifest_file = _find_json(str(aid_dir), "manifest--")
        data = json.loads(open(manifest_file).read())
        assert data["app_name"] == "falcon-exposure-management-universal-reporter"
        assert data["app_version"] == "2.0.0"
        assert data["command"] == "femur -e talon.env --bucket-by-aid"

        # Check aggregate manifest
        agg = json.loads((tmp_path / "by_aid" / "manifest.json").read_text())
        assert agg["app_name"] == "falcon-exposure-management-universal-reporter"
        assert agg["app_version"] == "2.0.0"

    def test_iavm_stats_in_per_aid_manifest(self, tmp_path):
        """IAVM severity counts appear in each per-AID manifest."""
        sink = AidBucketedSink(str(tmp_path))
        sink.set_metadata("generated_at", "2026-06-09T00:00:00+00:00")
        sink.write_record("vulnerabilities", {
            "aid": "aaa", "cid": "c1", "cve": "CVE-1",
            "iavm_notices": [{"iavm_severity": "CAT I", "iavm_number": "2024-T-0001", "iavm_title": "T1"}],
        })
        sink.write_record("vulnerabilities", {
            "aid": "aaa", "cid": "c1", "cve": "CVE-2",
            "iavm_notices": [{"iavm_severity": "CAT I", "iavm_number": "2024-T-0002", "iavm_title": "T2"}],
        })
        sink.write_record("vulnerabilities", {
            "aid": "aaa", "cid": "c1", "cve": "CVE-3",
            "iavm_notices": [{"iavm_severity": "CAT III", "iavm_number": "2024-A-0003", "iavm_title": "T3"}],
        })
        sink.write_record("vulnerabilities", {
            "aid": "bbb", "cid": "c1", "cve": "CVE-4",
            "iavm_notices": [{"iavm_severity": "CAT II", "iavm_number": "2024-B-0004", "iavm_title": "T4"}],
        })
        sink.write_record("vulnerabilities", {"aid": "aaa", "cid": "c1", "cve": "CVE-5"})  # no IAVM
        sink.close()

        manifest_aaa = json.loads(open(_find_json(str(_aid_path(tmp_path, "aaa")), "manifest--")).read())
        assert "iavm_summary" in manifest_aaa
        assert manifest_aaa["iavm_summary"]["CAT I"] == 2
        assert manifest_aaa["iavm_summary"]["CAT III"] == 1

        manifest_bbb = json.loads(open(_find_json(str(_aid_path(tmp_path, "bbb")), "manifest--")).read())
        assert manifest_bbb["iavm_summary"]["CAT II"] == 1

    def test_iavm_stats_in_aggregate_manifest(self, tmp_path):
        """Aggregate manifest has combined IAVM totals."""
        sink = AidBucketedSink(str(tmp_path))
        sink.set_metadata("generated_at", "2026-06-09T00:00:00+00:00")
        sink.write_record("vulnerabilities", {
            "aid": "aaa", "cid": "c1", "cve": "CVE-1",
            "iavm_notices": [{"iavm_severity": "CAT I", "iavm_number": "N1", "iavm_title": "T"}],
        })
        sink.write_record("vulnerabilities", {
            "aid": "bbb", "cid": "c1", "cve": "CVE-2",
            "iavm_notices": [{"iavm_severity": "CAT I", "iavm_number": "N2", "iavm_title": "T"}],
        })
        sink.write_record("vulnerabilities", {
            "aid": "bbb", "cid": "c1", "cve": "CVE-3",
            "iavm_notices": [{"iavm_severity": "CAT II", "iavm_number": "N3", "iavm_title": "T"}],
        })
        sink.close()

        agg = json.loads((tmp_path / "by_aid" / "manifest.json").read_text())
        assert agg["iavm_summary"]["CAT I"] == 2
        assert agg["iavm_summary"]["CAT II"] == 1
        assert agg["iavm_aids_affected"] == 2

    def test_no_iavm_no_stats_in_manifest(self, tmp_path):
        """When no records have IAVM notices, no iavm_summary key appears."""
        sink = AidBucketedSink(str(tmp_path))
        sink.set_metadata("generated_at", "2026-06-09T00:00:00+00:00")
        sink.write_record("vulnerabilities", {"aid": "aaa", "cid": "c1", "cve": "CVE-1"})
        sink.close()

        agg = json.loads((tmp_path / "by_aid" / "manifest.json").read_text())
        assert "iavm_summary" not in agg


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


class TestAidBucketedSinkThreadSafety:
    def test_concurrent_writes(self, tmp_path):
        """Multiple threads writing different datasets concurrently."""
        sink = AidBucketedSink(str(tmp_path))
        sink.set_metadata("generated_at", "2026-06-09T00:00:00+00:00")
        aids = [f"agent{i:04d}" for i in range(10)]

        def _write_dataset(dataset_name, n_records):
            for i in range(n_records):
                aid = aids[i % len(aids)]
                sink.write_record(dataset_name, {"aid": aid, "cid": "c1", "idx": i, "ds": dataset_name})

        threads = [
            threading.Thread(target=_write_dataset, args=("applications", 50)),
            threading.Thread(target=_write_dataset, args=("vulnerabilities", 50)),
            threading.Thread(target=_write_dataset, args=("assessments", 50)),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        sink.close()

        # Verify total records across all AID dirs
        total = 0
        for aid_dir in _aid_dirs(tmp_path):
            for jsonl_file in aid_dir.glob("*.jsonl"):
                total += len(_read_jsonl(str(jsonl_file)))
        assert total == 150  # 50 * 3 datasets


# ---------------------------------------------------------------------------
# Compression: --compressed (per-file zip)
# ---------------------------------------------------------------------------


class TestAidBucketedSinkCompressed:
    def test_individual_files_zipped(self, tmp_path):
        sink = AidBucketedSink(str(tmp_path), compressed=True)
        sink.set_metadata("generated_at", "2026-06-09T00:00:00+00:00")
        sink.write_record("vulnerabilities", {"aid": "aaa", "cid": "c1", "cve": "CVE-1"})
        sink.write_record("vulnerabilities", {"aid": "aaa", "cid": "c1", "cve": "CVE-2"})
        sink.close()

        aid_dir = _aid_path(tmp_path, "aaa")
        # No raw jsonl files remain
        assert list(aid_dir.glob("*.jsonl")) == []
        # Zip files exist
        zip_files = list(aid_dir.glob("*.jsonl.zip"))
        assert len(zip_files) == 1
        # Manifest also zipped
        manifest_zips = list(aid_dir.glob("*.json.zip"))
        assert len(manifest_zips) == 1

    def test_zip_contains_correct_data(self, tmp_path):
        sink = AidBucketedSink(str(tmp_path), compressed=True)
        sink.set_metadata("generated_at", "2026-06-09T00:00:00+00:00")
        sink.write_record("vulnerabilities", {"aid": "aaa", "cid": "c1", "cve": "CVE-1"})
        sink.close()

        aid_dir = _aid_path(tmp_path, "aaa")
        zip_files = list(aid_dir.glob("vulnerabilities*.zip"))
        assert len(zip_files) == 1
        with zipfile.ZipFile(str(zip_files[0])) as zf:
            names = zf.namelist()
            assert len(names) == 1
            content = zf.read(names[0]).decode("utf-8").strip()
            rec = json.loads(content)
            assert rec["cve"] == "CVE-1"

    def test_multiple_aids_compressed(self, tmp_path):
        sink = AidBucketedSink(str(tmp_path), compressed=True)
        sink.set_metadata("generated_at", "2026-06-09T00:00:00+00:00")
        sink.write_record("vulnerabilities", {"aid": "aaa", "cid": "c1", "cve": "CVE-1"})
        sink.write_record("vulnerabilities", {"aid": "bbb", "cid": "c1", "cve": "CVE-2"})
        sink.close()

        for aid in ("aaa", "bbb"):
            aid_dir = _aid_path(tmp_path, aid)
            assert list(aid_dir.glob("*.jsonl")) == []
            assert len(list(aid_dir.glob("*.zip"))) >= 1

    def test_aggregate_manifest_not_zipped(self, tmp_path):
        """The top-level aggregate manifest stays uncompressed for discoverability."""
        sink = AidBucketedSink(str(tmp_path), compressed=True)
        sink.set_metadata("generated_at", "2026-06-09T00:00:00+00:00")
        sink.write_record("vulnerabilities", {"aid": "aaa", "cid": "c1", "cve": "CVE-1"})
        sink.close()

        agg_manifest = tmp_path / "by_aid" / "manifest.json"
        assert agg_manifest.exists()


# ---------------------------------------------------------------------------
# Compression: --compressed-by-aid (per-folder zip)
# ---------------------------------------------------------------------------


class TestAidBucketedSinkCompressedByAid:
    def test_aid_directory_becomes_zip(self, tmp_path):
        sink = AidBucketedSink(str(tmp_path), compressed_by_aid=True)
        sink.set_metadata("generated_at", "2026-06-09T00:00:00+00:00")
        sink.write_record("vulnerabilities", {"aid": "aaa", "cid": "c1", "cve": "CVE-1"})
        sink.write_record("applications", {"aid": "aaa", "cid": "c1", "name": "Chrome"})
        sink.close()

        by_aid = tmp_path / "by_aid"
        # Directory removed
        assert not (_aid_path(tmp_path, "aaa")).is_dir()
        # Zip archive created
        assert (_aid_path(tmp_path, "aaa").with_suffix(".zip")).exists()

    def test_zip_contains_all_files(self, tmp_path):
        sink = AidBucketedSink(str(tmp_path), compressed_by_aid=True)
        sink.set_metadata("generated_at", "2026-06-09T00:00:00+00:00")
        sink.write_record("vulnerabilities", {"aid": "aaa", "cid": "c1", "cve": "CVE-1"})
        sink.write_record("applications", {"aid": "aaa", "cid": "c1", "name": "Chrome"})
        sink.close()

        with zipfile.ZipFile(str(_aid_path(tmp_path, "aaa.zip"))) as zf:
            names = zf.namelist()
            # Should contain vulnerabilities, applications, and manifest
            assert any("vulnerabilities" in n for n in names)
            assert any("applications" in n for n in names)
            assert any("manifest" in n for n in names)

    def test_multiple_aids_each_zipped(self, tmp_path):
        sink = AidBucketedSink(str(tmp_path), compressed_by_aid=True)
        sink.set_metadata("generated_at", "2026-06-09T00:00:00+00:00")
        sink.write_record("vulnerabilities", {"aid": "aaa", "cid": "c1", "cve": "CVE-1"})
        sink.write_record("vulnerabilities", {"aid": "bbb", "cid": "c2", "cve": "CVE-2"})
        sink.close()

        by_aid = tmp_path / "by_aid"
        assert (_aid_path(tmp_path, "aaa").with_suffix(".zip")).exists()
        assert (_aid_path(tmp_path, "bbb").with_suffix(".zip")).exists()
        assert not (_aid_path(tmp_path, "aaa")).is_dir()
        assert not (_aid_path(tmp_path, "bbb")).is_dir()

    def test_aggregate_manifest_not_zipped(self, tmp_path):
        sink = AidBucketedSink(str(tmp_path), compressed_by_aid=True)
        sink.set_metadata("generated_at", "2026-06-09T00:00:00+00:00")
        sink.write_record("vulnerabilities", {"aid": "aaa", "cid": "c1", "cve": "CVE-1"})
        sink.close()

        assert (tmp_path / "by_aid" / "manifest.json").exists()


# ---------------------------------------------------------------------------
# File descriptor budget
#
# A production run with --bucket-by-aid over 625,389 unique AIDs exhausted the
# 65,536 fd soft limit at bucket 65,531, because every (AID, dataset) pair held
# an open handle until close().  These tests pin the bounded-handle contract.
# ---------------------------------------------------------------------------


resource = pytest.importorskip("resource")


class TestAidBucketedSinkFileDescriptors:
    def test_survives_low_fd_limit(self, tmp_path):
        """Writing many AIDs must not scale open descriptors with AID count."""
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if hard != resource.RLIM_INFINITY and hard < 128:
            pytest.skip("hard fd limit too low to exercise this path")

        resource.setrlimit(resource.RLIMIT_NOFILE, (128, hard))
        try:
            sink = AidBucketedSink(str(tmp_path))
            sink.set_metadata("generated_at", "2026-06-09T00:00:00+00:00")
            sink.write_batch(
                "host_map",
                [
                    {"_host_map_id": f"h{i}", "aid": f"aid{i:06d}", "cid": "c1"}
                    for i in range(2000)
                ],
            )
            sink.close()
        finally:
            resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))

        by_aid = tmp_path / "by_aid"
        assert len(_aid_dirs(tmp_path)) == 2000
        manifest = json.loads((by_aid / "manifest.json").read_text())
        assert manifest["total_aids"] == 2000

    def test_one_append_per_file_for_single_batch(self, tmp_path, monkeypatch):
        """A single batch must cost exactly one write per (AID, dataset) file."""
        from femur_pipeline.sinks import aid_bucketed

        calls = []
        real = aid_bucketed._append_bytes

        def _spy(path, payload, truncate=False):
            calls.append(path)
            return real(path, payload, truncate=truncate)

        monkeypatch.setattr(aid_bucketed, "_append_bytes", _spy)

        sink = AidBucketedSink(str(tmp_path))
        sink.set_metadata("generated_at", "2026-06-09T00:00:00+00:00")
        sink.write_batch(
            "host_map",
            [
                {"_host_map_id": f"h{i}", "aid": f"aid{i:04d}", "cid": "c1"}
                for i in range(500)
            ],
        )

        assert len(calls) == 500
        assert len(set(calls)) == 500
        sink.close()


# ---------------------------------------------------------------------------
# Append semantics
#
# Switching from a held-open "wb" handle to per-write O_APPEND must not
# truncate.  These are the primary regression risk of that change.
# ---------------------------------------------------------------------------


class TestAidBucketedSinkAppendSemantics:
    def test_repeated_batches_append_not_truncate(self, tmp_path):
        sink = AidBucketedSink(str(tmp_path))
        sink.set_metadata("generated_at", "2026-06-09T00:00:00+00:00")
        for b in range(10):
            sink.write_batch(
                "vulnerabilities",
                [{"aid": "aaa", "cid": "c1", "cve": f"CVE-{b}-{i}"} for i in range(5)],
            )
        sink.close()

        d = str(_aid_path(tmp_path, "aaa"))
        assert len(_read_jsonl(_find_jsonl(d, "vulnerabilities--"))) == 50
        with open(_find_json(d, "manifest--")) as fh:
            assert json.load(fh)["counts"]["vulnerabilities"] == 50

    def test_interleaved_datasets_same_aid_do_not_clobber(self, tmp_path):
        """Creating dataset B's file must not truncate dataset A's."""
        sink = AidBucketedSink(str(tmp_path))
        sink.set_metadata("generated_at", "2026-06-09T00:00:00+00:00")
        for i in range(5):
            sink.write_record("applications", {"aid": "aaa", "cid": "c1", "n": i})
            sink.write_record("vulnerabilities", {"aid": "aaa", "cid": "c1", "n": i})
            sink.write_record("assessments", {"aid": "aaa", "cid": "c1", "n": i})
        sink.close()

        d = str(_aid_path(tmp_path, "aaa"))
        for ds in ("applications", "vulnerabilities", "assessments"):
            assert len(_read_jsonl(_find_jsonl(d, ds + "--"))) == 5

    def test_concurrent_writes_same_aid(self, tmp_path):
        """Four datasets hammering one AID: one dir, no lost records."""
        sink = AidBucketedSink(str(tmp_path))
        sink.set_metadata("generated_at", "2026-06-09T00:00:00+00:00")

        def _write(dataset_name):
            for i in range(200):
                sink.write_batch(dataset_name, [{"aid": "aaa", "cid": "c1", "i": i}])

        datasets = ("applications", "vulnerabilities", "assessments", "host_map")
        threads = [threading.Thread(target=_write, args=(d,)) for d in datasets]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        sink.close()

        d = str(_aid_path(tmp_path, "aaa"))
        with open(_find_json(d, "manifest--")) as fh:
            counts = json.load(fh)["counts"]
        for ds in datasets:
            assert counts[ds] == 200
            assert len(_read_jsonl(_find_jsonl(d, ds + "--"))) == 200


# ---------------------------------------------------------------------------
# Finalization robustness
# ---------------------------------------------------------------------------


class TestAidBucketedSinkFinalization:
    def test_one_bad_fileset_does_not_lose_aggregate(self, tmp_path, monkeypatch):
        """A single per-AID failure must not abort the whole close()."""
        sink = AidBucketedSink(str(tmp_path))
        sink.set_metadata("generated_at", "2026-06-09T00:00:00+00:00")
        for aid in ("aaa", "bbb", "ccc"):
            sink.write_record("vulnerabilities", {"aid": aid, "cid": "c1", "cve": "CVE-1"})

        fileset_cls = type(sink._filesets["bbb"])
        real_close = fileset_cls.close

        def _boom(self, metadata):
            if self._aid == "bbb":
                raise OSError("disk full")
            return real_close(self, metadata)

        monkeypatch.setattr(fileset_cls, "close", _boom)
        sink.close()

        by_aid = tmp_path / "by_aid"
        assert (by_aid / "manifest.json").exists()
        assert _find_json(str(_aid_path(tmp_path, "ccc")), "manifest--") is not None


# ---------------------------------------------------------------------------
# XML output
#
# Characterization tests: this sink's XML path had no coverage at all, and the
# bounded-handle change replaces lxml's xmlfile streaming with manual framing.
# Output must stay byte-for-byte identical and schema-valid.
# ---------------------------------------------------------------------------


lxml_etree = pytest.importorskip("lxml.etree")


class TestAidBucketedSinkXml:
    _NS = "urn:femur:schema:host_map:1.0.0"

    def _write(self, tmp_path, n_batches=3):
        sink = AidBucketedSink(str(tmp_path), output_format="xml")
        sink.set_metadata("generated_at", "2026-06-09T00:00:00+00:00")
        for b in range(n_batches):
            sink.write_batch(
                "host_map",
                [
                    {"_host_map_id": f"h{b}{i}", "cid": "c1", "aid": "aaa"}
                    for i in range(2)
                ],
            )
        sink.close()
        d = _aid_path(tmp_path, "aaa")
        return next(p for p in d.iterdir() if p.name.startswith("host_map--"))

    def test_single_prologue_and_root_across_batches(self, tmp_path):
        data = self._write(tmp_path).read_bytes()
        assert data.count(b"<?xml") == 1
        assert data.count(b"<host_map") == 1
        assert data.endswith(b"</host_map>")

    def test_no_redundant_xmlns_on_records(self, tmp_path):
        """lxml stamps xmlns on every child if a record is appended to a ns'd root."""
        assert self._write(tmp_path).read_bytes().count(b"xmlns=") == 1

    def test_record_count_and_wellformed(self, tmp_path):
        root = lxml_etree.parse(str(self._write(tmp_path))).getroot()
        assert root.tag == f"{{{self._NS}}}host_map"
        assert len(root.findall(f"{{{self._NS}}}record")) == 6

    @pytest.mark.skipif(not _SCHEMA_DIR.is_dir(), reason="schemas not in this install")
    def test_validates_against_xsd(self, tmp_path):
        xsd = lxml_etree.XMLSchema(
            lxml_etree.parse(str(_SCHEMA_DIR / "host_map.xsd"))
        )
        doc = lxml_etree.parse(str(self._write(tmp_path)))
        assert xsd.validate(doc), xsd.error_log

    @pytest.mark.skipif(not _SCHEMA_DIR.is_dir(), reason="schemas not in this install")
    def test_manifests_validate_against_xsd(self, tmp_path):
        self._write(tmp_path)
        by_aid = tmp_path / "by_aid"
        per_aid = next(
            p for p in (_aid_path(tmp_path, "aaa")).iterdir() if p.name.startswith("manifest--")
        )
        for xsd_name, doc_path in (
            ("manifest-by-aid.xsd", per_aid),
            ("manifest-aggregate.xsd", by_aid / "manifest.xml"),
        ):
            xsd = lxml_etree.XMLSchema(lxml_etree.parse(str(_SCHEMA_DIR / xsd_name)))
            doc = lxml_etree.parse(str(doc_path))
            assert xsd.validate(doc), f"{xsd_name}: {xsd.error_log}"


# ---------------------------------------------------------------------------
# AID directory sharding
#
# A flat by_aid/ puts one directory per host in a single directory. At 625K
# hosts that is unusable with ordinary tooling and would hit the ~64,999
# subdirectory cap on ext3 / ext4 without dir_nlink. AIDs are lowercase hex,
# so each shard character yields 16 buckets.
# ---------------------------------------------------------------------------


class TestAidBucketedSinkSharding:
    _AID = "f813cb0b9eaa4b6b884ce5782cc7b6e4"

    def _write_one(self, tmp_path, **kwargs):
        sink = AidBucketedSink(str(tmp_path), **kwargs)
        sink.set_metadata("generated_at", "2026-06-09T00:00:00+00:00")
        sink.write_record("vulnerabilities", {"aid": self._AID, "cid": "c1", "cve": "CVE-1"})
        sink.close()
        return tmp_path / "by_aid"

    def test_default_depth_is_two(self):
        assert DEFAULT_AID_SHARD_DEPTH == 2

    def test_default_shards_on_first_two_chars(self, tmp_path):
        by_aid = self._write_one(tmp_path)
        assert (by_aid / "f8" / self._AID).is_dir()
        assert not (by_aid / self._AID).exists()

    def test_depth_one_shards_on_first_char(self, tmp_path):
        by_aid = self._write_one(tmp_path, aid_shard_depth=1)
        assert (by_aid / "f" / self._AID).is_dir()

    def test_depth_zero_is_flat(self, tmp_path):
        by_aid = self._write_one(tmp_path, aid_shard_depth=0)
        assert (by_aid / self._AID).is_dir()
        assert not (by_aid / "f8").exists()

    def test_records_are_readable_through_the_shard(self, tmp_path):
        by_aid = self._write_one(tmp_path)
        d = str(by_aid / "f8" / self._AID)
        assert len(_read_jsonl(_find_jsonl(d, "vulnerabilities--"))) == 1

    def test_filenames_are_unaffected_by_sharding(self, tmp_path):
        """The shard is a directory level only; file naming must not change."""
        flat = tmp_path / "flat"
        sharded = tmp_path / "sharded"
        for root, depth in ((flat, 0), (sharded, 2)):
            sink = AidBucketedSink(str(root), aid_shard_depth=depth)
            sink.set_metadata("generated_at", "2026-06-09T00:00:00+00:00")
            sink.write_record("vulnerabilities", {"aid": self._AID, "cid": "c1", "cve": "CVE-1"})
            sink.close()
        flat_names = sorted(os.listdir(flat / "by_aid" / self._AID))
        shard_names = sorted(os.listdir(sharded / "by_aid" / "f8" / self._AID))
        assert flat_names == shard_names

    def test_no_aid_bucket_is_never_sharded(self, tmp_path):
        """_no_aid is a single directory, so keep it findable at the top."""
        sink = AidBucketedSink(str(tmp_path))
        sink.set_metadata("generated_at", "2026-06-09T00:00:00+00:00")
        sink.write_record("host_map", {"_host_map_id": "h1", "cid": "c1"})
        sink.close()
        assert (tmp_path / "by_aid" / "_no_aid").is_dir()
        assert not (tmp_path / "by_aid" / "_n").exists()

    def test_shard_depth_is_clamped_to_prefix_len(self, tmp_path):
        """A shard cannot be longer than the directory name it comes from."""
        sink = AidBucketedSink(str(tmp_path), aid_prefix_len=2, aid_shard_depth=4)
        sink.set_metadata("generated_at", "2026-06-09T00:00:00+00:00")
        sink.write_record("vulnerabilities", {"aid": self._AID, "cid": "c1", "cve": "CVE-1"})
        sink.close()
        # key is "f8" (prefix_len=2), so the shard can be at most "f8".
        assert (tmp_path / "by_aid" / "f8" / "f8").is_dir()

    def test_negative_depth_is_treated_as_flat(self, tmp_path):
        by_aid = self._write_one(tmp_path, aid_shard_depth=-1)
        assert (by_aid / self._AID).is_dir()

    def test_bounds_subdirs_per_directory(self, tmp_path):
        """The whole point: no single directory holds every host."""
        import random

        random.seed(7)
        n = 3000
        aids = [f"{random.getrandbits(128):032x}" for _ in range(n)]
        sink = AidBucketedSink(str(tmp_path))
        sink.set_metadata("generated_at", "2026-06-09T00:00:00+00:00")
        sink.write_batch(
            "host_map",
            [{"_host_map_id": f"h{i}", "aid": a, "cid": "c1"} for i, a in enumerate(aids)],
        )
        sink.close()

        by_aid = tmp_path / "by_aid"
        shards = [p for p in by_aid.iterdir() if p.is_dir()]
        assert len(shards) <= 256
        worst = max(len(os.listdir(s)) for s in shards)
        assert worst < n, f"one directory holds {worst} of {n} AIDs"
        assert len(_aid_dirs(tmp_path)) == n

    def test_aggregate_manifest_lists_bare_aids(self, tmp_path):
        """Consumers derive the shard as aid[:depth]; the manifest stays flat."""
        by_aid = self._write_one(tmp_path)
        manifest = json.loads((by_aid / "manifest.json").read_text())
        assert manifest["aid_directories"] == [self._AID]
        assert manifest["total_aids"] == 1

    def test_compressed_by_aid_archives_inside_the_shard(self, tmp_path):
        by_aid = self._write_one(tmp_path, compressed_by_aid=True)
        archive = by_aid / "f8" / f"{self._AID}.zip"
        assert archive.exists()
        assert not (by_aid / "f8" / self._AID).is_dir()
        with zipfile.ZipFile(str(archive)) as zf:
            assert any("vulnerabilities--" in n for n in zf.namelist())

    def test_compressed_individual_files_inside_the_shard(self, tmp_path):
        by_aid = self._write_one(tmp_path, compressed=True)
        d = by_aid / "f8" / self._AID
        names = os.listdir(d)
        assert any(n.endswith(".jsonl.zip") for n in names)
        assert not any(n.endswith(".jsonl") for n in names)

    def test_xml_output_is_sharded_and_valid(self, tmp_path):
        sink = AidBucketedSink(str(tmp_path), output_format="xml")
        sink.set_metadata("generated_at", "2026-06-09T00:00:00+00:00")
        sink.write_record("host_map", {"_host_map_id": "h1", "aid": self._AID, "cid": "c1"})
        sink.close()
        d = tmp_path / "by_aid" / "f8" / self._AID
        assert d.is_dir()
        doc = next(p for p in d.iterdir() if p.name.startswith("host_map--"))
        root = lxml_etree.parse(str(doc)).getroot()
        assert root.tag == "{urn:femur:schema:host_map:1.0.0}host_map"
