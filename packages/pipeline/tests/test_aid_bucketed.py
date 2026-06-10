"""Tests for AID-bucketed output sink."""

import json
import os
import threading
import zipfile

from femur_pipeline.sinks.aid_bucketed import AidBucketedSink


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
        dir1 = by_aid / "aaaa1111bbbb2222"
        dir2 = by_aid / "cccc3333dddd4444"
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

        no_aid_dir = tmp_path / "by_aid" / "_no_aid"
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

        aid_dir = tmp_path / "by_aid" / aid
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

        aid_dir = tmp_path / "by_aid" / aid
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

        aid_dir = tmp_path / "by_aid" / "aabbccdd11223344"
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

        aid_dir = tmp_path / "by_aid" / "aabbccdd11223344"
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
        recs_a = _read_jsonl(_find_jsonl(str(by_aid / "aid_aaa"), "vulnerabilities--"))
        recs_b = _read_jsonl(_find_jsonl(str(by_aid / "aid_bbb"), "vulnerabilities--"))
        recs_c = _read_jsonl(_find_jsonl(str(by_aid / "aid_ccc"), "vulnerabilities--"))
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
        recs_a = _read_jsonl(_find_jsonl(str(by_aid / "aid_aaa"), "host_map--"))
        recs_no = _read_jsonl(_find_jsonl(str(by_aid / "_no_aid"), "host_map--"))
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

        aid_dir = tmp_path / "by_aid" / "aaa"
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
        aid_dir = tmp_path / "by_aid" / "aaa"
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

        manifest_aaa = json.loads(open(_find_json(str(tmp_path / "by_aid" / "aaa"), "manifest--")).read())
        assert "iavm_summary" in manifest_aaa
        assert manifest_aaa["iavm_summary"]["CAT I"] == 2
        assert manifest_aaa["iavm_summary"]["CAT III"] == 1

        manifest_bbb = json.loads(open(_find_json(str(tmp_path / "by_aid" / "bbb"), "manifest--")).read())
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
        by_aid = tmp_path / "by_aid"
        total = 0
        for aid_dir in by_aid.iterdir():
            if not aid_dir.is_dir():
                continue
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

        aid_dir = tmp_path / "by_aid" / "aaa"
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

        aid_dir = tmp_path / "by_aid" / "aaa"
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
            aid_dir = tmp_path / "by_aid" / aid
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
        assert not (by_aid / "aaa").is_dir()
        # Zip archive created
        assert (by_aid / "aaa.zip").exists()

    def test_zip_contains_all_files(self, tmp_path):
        sink = AidBucketedSink(str(tmp_path), compressed_by_aid=True)
        sink.set_metadata("generated_at", "2026-06-09T00:00:00+00:00")
        sink.write_record("vulnerabilities", {"aid": "aaa", "cid": "c1", "cve": "CVE-1"})
        sink.write_record("applications", {"aid": "aaa", "cid": "c1", "name": "Chrome"})
        sink.close()

        with zipfile.ZipFile(str(tmp_path / "by_aid" / "aaa.zip")) as zf:
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
        assert (by_aid / "aaa.zip").exists()
        assert (by_aid / "bbb.zip").exists()
        assert not (by_aid / "aaa").is_dir()
        assert not (by_aid / "bbb").is_dir()

    def test_aggregate_manifest_not_zipped(self, tmp_path):
        sink = AidBucketedSink(str(tmp_path), compressed_by_aid=True)
        sink.set_metadata("generated_at", "2026-06-09T00:00:00+00:00")
        sink.write_record("vulnerabilities", {"aid": "aaa", "cid": "c1", "cve": "CVE-1"})
        sink.close()

        assert (tmp_path / "by_aid" / "manifest.json").exists()
