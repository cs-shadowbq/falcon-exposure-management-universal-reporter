"""Core streaming pipeline abstractions for bounded-memory output.

The :class:`DataSink` interface decouples the fetch layer (which already
uses generators) from output serialization.  Concrete sinks live in the
:mod:`~femur.sinks` sub-package.

Typical usage inside the CLI streaming path::

    with create_sink("jsonl", "/tmp/inventory_jsonl") as sink:
        count = stream_dataset(
            iter_applications(creds, on_page=cb),
            sink,
            "applications",
            transform=AidDecoratorTransform(host_map),
        )
"""

from abc import ABC, abstractmethod
from typing import Any, Callable, Iterator, List, Optional, Sequence


# ---------------------------------------------------------------------------
# DataSink ABC
# ---------------------------------------------------------------------------

class DataSink(ABC):
    """Abstract base for record output backends.

    Implementations **must** be thread-safe: the CLI runs up to four
    dataset fetches concurrently, each calling :meth:`write_batch`
    from its own thread.
    """

    @abstractmethod
    def open_dataset(self, dataset_name: str) -> None:
        """Signal that records for *dataset_name* are about to arrive."""

    @abstractmethod
    def write_record(self, dataset_name: str, record: dict) -> None:
        """Write a single record to the named dataset."""

    def write_batch(self, dataset_name: str, records: List[dict]) -> None:
        """Write a batch of records.  Default loops :meth:`write_record`."""
        for rec in records:
            self.write_record(dataset_name, rec)

    @abstractmethod
    def set_metadata(self, key: str, value: Any) -> None:
        """Store a metadata key/value (counts, generated_at, errors)."""

    @abstractmethod
    def close(self) -> None:
        """Flush buffers and release all resources."""

    def __enter__(self) -> "DataSink":
        return self

    def __exit__(self, *exc_info: Any) -> bool:
        self.close()
        return False


# ---------------------------------------------------------------------------
# RecordTransform protocol
# ---------------------------------------------------------------------------

class RecordTransform:
    """Base class for per-record transformations.

    Subclass and override :meth:`__call__`.  Return the (possibly mutated)
    record, or ``None`` to drop it from the output.
    """

    def __call__(self, record: dict, dataset_name: str) -> Optional[dict]:
        return record  # pragma: no cover – subclasses override


class ChainedTransform:
    """Apply a sequence of transforms in order.  Short-circuits on ``None``."""

    def __init__(self, transforms: Sequence[RecordTransform]) -> None:
        self._transforms = list(transforms)

    def __call__(self, record: dict, dataset_name: str) -> Optional[dict]:
        for t in self._transforms:
            result = t(record, dataset_name)
            if result is None:
                return None
            record = result
        return record


# ---------------------------------------------------------------------------
# stream_dataset — the core streaming loop
# ---------------------------------------------------------------------------

def stream_dataset(
    iterator: Iterator[dict],
    sink: DataSink,
    dataset_name: str,
    transform: Optional[RecordTransform] = None,
    batch_size: int = 500,
) -> int:
    """Consume *iterator*, apply *transform*, write to *sink*.

    Memory usage is bounded by *batch_size* records at a time.
    Returns the total number of records written.
    """
    sink.open_dataset(dataset_name)
    written = 0
    batch: List[dict] = []

    for record in iterator:
        if transform is not None:
            result = transform(record, dataset_name)
            if result is None:
                continue
            record = result
        batch.append(record)
        if len(batch) >= batch_size:
            sink.write_batch(dataset_name, batch)
            written += len(batch)
            batch = []

    if batch:
        sink.write_batch(dataset_name, batch)
        written += len(batch)

    return written
