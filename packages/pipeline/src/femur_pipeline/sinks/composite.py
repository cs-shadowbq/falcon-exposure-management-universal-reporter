"""Fan-out sink — write to multiple sinks simultaneously."""

import threading
from typing import Any, List, Sequence

from ..pipeline import DataSink


class CompositeSink(DataSink):
    """Dispatch every write to all wrapped sinks.

    Example::

        with CompositeSink([JsonLinesSink("/tmp/jsonl"), XmlSink("/tmp/xml")]) as sink:
            stream_dataset(iterator, sink, "applications")
    """

    def __init__(self, sinks: Sequence[DataSink]) -> None:
        self._sinks: List[DataSink] = list(sinks)

    def open_dataset(self, dataset_name: str) -> None:
        for s in self._sinks:
            s.open_dataset(dataset_name)

    def write_record(self, dataset_name: str, record: dict) -> None:
        for s in self._sinks:
            s.write_record(dataset_name, record)

    def write_batch(self, dataset_name: str, records: List[dict]) -> None:
        for s in self._sinks:
            s.write_batch(dataset_name, records)

    def set_metadata(self, key: str, value: Any) -> None:
        for s in self._sinks:
            s.set_metadata(key, value)

    def close(self) -> None:
        for s in self._sinks:
            s.close()
