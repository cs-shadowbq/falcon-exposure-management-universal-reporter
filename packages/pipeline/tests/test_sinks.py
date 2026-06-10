"""Tests for output sinks — JSONL, legacy JSON, composite, and factory."""

import json
import os
import zipfile

import pytest

from femur_pipeline.pipeline import DataSink, stream_dataset
from femur_pipeline.sinks import create_sink
from femur_pipeline.sinks.composite import CompositeSink
from femur_pipeline.sinks.compression import compress_output_files
from femur_pipeline.sinks.jsonlines import JsonLinesSink
from femur_pipeline.sinks.legacy_json import LegacyJsonSink


# ---------------------------------------------------------------------------
# JsonLinesSink
# ---------------------------------------------------------------------------


class TestJsonLinesSink:
    def test_produces_jsonl_files(self, tmp_path):
        out = str(tmp_path / "out")
        with JsonLinesSink(out) as sink:
            sink.open_dataset("apps")
            sink.write_record("apps", {"id": "a1"})
            sink.write_record("apps", {"id": "a2"})

        lines = (tmp_path / "out" / "apps.jsonl").read_text().strip().split("\n")
        assert len(lines) == 2
        assert json.loads(lines[0]) == {"id": "a1"}

    def test_write_batch(self, tmp_path):
        out = str(tmp_path / "out")
        with JsonLinesSink(out) as sink:
            sink.open_dataset("ds")
            sink.write_batch("ds", [{"n": i} for i in range(5)])

        lines = (tmp_path / "out" / "ds.jsonl").read_text().strip().split("\n")
        assert len(lines) == 5

    def test_manifest(self, tmp_path):
        out = str(tmp_path / "out")
        with JsonLinesSink(out) as sink:
            sink.open_dataset("apps")
            sink.write_batch("apps", [{"id": i} for i in range(3)])
            sink.set_metadata("generated_at", "2024-01-01T00:00:00Z")

        manifest = json.loads((tmp_path / "out" / "manifest.json").read_text())
        assert manifest["counts"]["apps"] == 3
        assert manifest["generated_at"] == "2024-01-01T00:00:00Z"

    def test_zip_compression(self, tmp_path):
        out = str(tmp_path / "out")
        with JsonLinesSink(out) as sink:
            sink.open_dataset("ds")
            sink.write_record("ds", {"compressed": True})

        compress_output_files(str(tmp_path / "out"))
        zip_path = tmp_path / "out" / "ds.jsonl.zip"
        assert zip_path.exists()
        assert not (tmp_path / "out" / "ds.jsonl").exists()
        with zipfile.ZipFile(zip_path, "r") as zf:
            rec = json.loads(zf.read("ds.jsonl"))
        assert rec == {"compressed": True}

    def test_multiple_datasets(self, tmp_path):
        out = str(tmp_path / "out")
        with JsonLinesSink(out) as sink:
            sink.open_dataset("a")
            sink.open_dataset("b")
            sink.write_record("a", {"ds": "a"})
            sink.write_record("b", {"ds": "b"})

        assert (tmp_path / "out" / "a.jsonl").exists()
        assert (tmp_path / "out" / "b.jsonl").exists()


# ---------------------------------------------------------------------------
# LegacyJsonSink
# ---------------------------------------------------------------------------


class TestLegacyJsonSink:
    def test_monolithic_output(self, tmp_path):
        out = str(tmp_path / "output.json")
        with LegacyJsonSink(out) as sink:
            sink.open_dataset("applications")
            sink.write_record("applications", {"id": "a1"})
            sink.open_dataset("vulnerabilities")
            sink.write_record("vulnerabilities", {"id": "v1"})
            sink.open_dataset("assessments")
            sink.set_metadata("generated_at", "2024-06-01T12:00:00Z")

        data = json.loads((tmp_path / "output.json").read_text())
        assert data["applications"] == [{"id": "a1"}]
        assert data["vulnerabilities"] == [{"id": "v1"}]
        assert data["assessments"] == []
        assert data["generated_at"] == "2024-06-01T12:00:00Z"

    def test_host_map_reconstruction(self, tmp_path):
        out = str(tmp_path / "output.json")
        with LegacyJsonSink(out) as sink:
            sink.open_dataset("host_map")
            sink.write_record("host_map", {"_host_map_id": "h1", "aid": "a1"})
            sink.write_record("host_map", {"_host_map_id": "h2", "aid": "a2"})
            sink.open_dataset("applications")
            sink.open_dataset("vulnerabilities")
            sink.open_dataset("assessments")

        data = json.loads((tmp_path / "output.json").read_text())
        assert data["host_map"] == {
            "h1": {"aid": "a1"},
            "h2": {"aid": "a2"},
        }


# ---------------------------------------------------------------------------
# CompositeSink
# ---------------------------------------------------------------------------


class TestCompositeSink:
    def test_fanout(self, tmp_path):
        out1 = str(tmp_path / "s1")
        out2 = str(tmp_path / "s2")
        s1 = JsonLinesSink(out1)
        s2 = JsonLinesSink(out2)
        with CompositeSink([s1, s2]) as cs:
            cs.open_dataset("ds")
            cs.write_record("ds", {"id": "1"})
            cs.write_batch("ds", [{"id": "2"}, {"id": "3"}])
            cs.set_metadata("key", "value")

        for d in [tmp_path / "s1", tmp_path / "s2"]:
            lines = (d / "ds.jsonl").read_text().strip().split("\n")
            assert len(lines) == 3
            manifest = json.loads((d / "manifest.json").read_text())
            assert manifest["counts"]["ds"] == 3


# ---------------------------------------------------------------------------
# create_sink factory
# ---------------------------------------------------------------------------


class TestCreateSink:
    def test_creates_jsonl(self, tmp_path):
        sink = create_sink("jsonl", str(tmp_path / "out"))
        assert isinstance(sink, JsonLinesSink)
        sink.close()

    def test_creates_json(self, tmp_path):
        sink = create_sink("json", str(tmp_path / "out.json"))
        assert isinstance(sink, LegacyJsonSink)
        sink.close()

    def test_unknown_format_raises(self):
        with pytest.raises(ValueError, match="Unknown output format"):
            create_sink("csv", "/tmp/dummy")


# ---------------------------------------------------------------------------
# Integration: stream_dataset → JSONL sink
# ---------------------------------------------------------------------------


class TestStreamToJsonl:
    def test_end_to_end(self, tmp_path):
        out = str(tmp_path / "out")
        records = [{"id": i, "name": f"app{i}"} for i in range(12)]

        with JsonLinesSink(out) as sink:
            count = stream_dataset(iter(records), sink, "applications", batch_size=5)

        assert count == 12
        lines = (tmp_path / "out" / "applications.jsonl").read_text().strip().split("\n")
        assert len(lines) == 12
        assert json.loads(lines[0])["id"] == 0
        assert json.loads(lines[-1])["id"] == 11
