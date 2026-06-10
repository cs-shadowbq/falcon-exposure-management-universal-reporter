"""Tests for the streaming pipeline core."""

from unittest.mock import MagicMock, call

import pytest

from femur_pipeline.pipeline import (
    ChainedTransform,
    DataSink,
    RecordTransform,
    stream_dataset,
)


# ---------------------------------------------------------------------------
# RecordTransform / ChainedTransform
# ---------------------------------------------------------------------------


class TestRecordTransform:
    def test_passthrough(self):
        t = RecordTransform()
        rec = {"id": "1"}
        assert t(rec, "apps") == rec


class _UpperNameTransform(RecordTransform):
    def __call__(self, record, dataset_name):
        record = dict(record)
        name = record.get("name")
        if name:
            record["name"] = name.upper()
        return record


class _DropOdd(RecordTransform):
    """Drop records whose ``n`` value is odd."""

    def __call__(self, record, dataset_name):
        if record.get("n", 0) % 2 == 1:
            return None
        return record


class TestChainedTransform:
    def test_chains_in_order(self):
        chain = ChainedTransform([_UpperNameTransform()])
        out = chain({"name": "hello"}, "ds")
        assert out == {"name": "HELLO"}

    def test_short_circuits_on_none(self):
        chain = ChainedTransform([_DropOdd(), _UpperNameTransform()])
        assert chain({"n": 1, "name": "hi"}, "ds") is None
        assert chain({"n": 2, "name": "hi"}, "ds") == {"n": 2, "name": "HI"}

    def test_empty_chain(self):
        chain = ChainedTransform([])
        rec = {"a": 1}
        assert chain(rec, "ds") is rec


# ---------------------------------------------------------------------------
# Spy sink for testing stream_dataset
# ---------------------------------------------------------------------------


class _SpySink(DataSink):
    """Records all calls for assertions."""

    def __init__(self):
        self.opened = []
        self.records = []
        self.batches = []
        self.metadata = {}
        self.closed = False

    def open_dataset(self, dataset_name):
        self.opened.append(dataset_name)

    def write_record(self, dataset_name, record):
        self.records.append((dataset_name, record))

    def write_batch(self, dataset_name, records):
        self.batches.append((dataset_name, list(records)))
        for r in records:
            self.records.append((dataset_name, r))

    def set_metadata(self, key, value):
        self.metadata[key] = value

    def close(self):
        self.closed = True


# ---------------------------------------------------------------------------
# stream_dataset
# ---------------------------------------------------------------------------


class TestStreamDataset:
    def test_basic_flow(self):
        sink = _SpySink()
        data = [{"id": i} for i in range(5)]
        count = stream_dataset(iter(data), sink, "test_ds", batch_size=3)
        assert count == 5
        assert sink.opened == ["test_ds"]
        assert [r for _, r in sink.records] == data

    def test_batch_boundaries(self):
        sink = _SpySink()
        data = [{"id": i} for i in range(7)]
        stream_dataset(iter(data), sink, "ds", batch_size=3)
        # 7 records / batch 3 → batches of [3, 3, 1]
        batch_sizes = [len(recs) for _, recs in sink.batches]
        assert batch_sizes == [3, 3, 1]

    def test_empty_iterator(self):
        sink = _SpySink()
        count = stream_dataset(iter([]), sink, "empty")
        assert count == 0
        assert sink.opened == ["empty"]
        assert sink.records == []

    def test_with_transform(self):
        sink = _SpySink()
        data = [{"name": "a"}, {"name": "b"}]
        count = stream_dataset(
            iter(data), sink, "ds", transform=_UpperNameTransform(), batch_size=10,
        )
        assert count == 2
        names = [r["name"] for _, r in sink.records]
        assert names == ["A", "B"]

    def test_transform_drops_records(self):
        sink = _SpySink()
        data = [{"n": i} for i in range(6)]  # 0..5
        count = stream_dataset(
            iter(data), sink, "ds", transform=_DropOdd(), batch_size=10,
        )
        # Only even n: 0, 2, 4
        assert count == 3
        ns = [r["n"] for _, r in sink.records]
        assert ns == [0, 2, 4]


# ---------------------------------------------------------------------------
# DataSink context manager protocol
# ---------------------------------------------------------------------------

class TestDataSinkContextManager:
    def test_close_called_on_exit(self):
        sink = _SpySink()
        with sink:
            sink.open_dataset("x")
        assert sink.closed

    def test_close_called_on_exception(self):
        sink = _SpySink()
        with pytest.raises(RuntimeError):
            with sink:
                raise RuntimeError("boom")
        assert sink.closed

    def test_default_write_batch_delegates(self):
        """DataSink.write_batch default loops write_record."""
        sink = MagicMock(spec=DataSink)
        # Call the real default implementation
        DataSink.write_batch(sink, "ds", [{"a": 1}, {"b": 2}])
        assert sink.write_record.call_count == 2
        sink.write_record.assert_any_call("ds", {"a": 1})
        sink.write_record.assert_any_call("ds", {"b": 2})
