"""JSON Lines output sink with optional ``orjson`` acceleration.

Produces one ``.jsonl`` file per dataset plus a ``manifest.json``
with metadata and record counts.  Thread-safe via per-dataset locks.

Install ``orjson`` for 10–50× faster serialisation::

    pip install orjson
"""

import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List

from ..pipeline import DataSink

try:
    import orjson

    def _dumps(obj: Any) -> bytes:
        return orjson.dumps(obj, default=str)
except ImportError:
    import json

    def _dumps(obj: Any) -> bytes:
        return json.dumps(obj, default=str, ensure_ascii=False).encode("utf-8")


class JsonLinesSink(DataSink):
    """Write one JSON object per line, one file per dataset.

    Directory layout::

        output_dir/
            applications.jsonl
            vulnerabilities.jsonl
            assessments.jsonl
            host_map.jsonl
            manifest.json

    Parameters
    ----------
    output_dir : str
        Directory to write files into (created if absent).
    """

    def __init__(self, output_dir: str, **kwargs: Any) -> None:
        self._output_dir = output_dir
        self._files: Dict[str, Any] = {}
        self._locks: Dict[str, threading.Lock] = {}
        self._counts: Dict[str, int] = {}
        self._metadata: Dict[str, Any] = {}
        self._global_lock = threading.Lock()
        os.makedirs(output_dir, exist_ok=True)

    # -- DataSink interface --------------------------------------------------

    def open_dataset(self, dataset_name: str) -> None:
        with self._global_lock:
            if dataset_name in self._files:
                return
            path = os.path.join(self._output_dir, f"{dataset_name}.jsonl")
            fh = open(path, "wb")
            self._files[dataset_name] = fh
            self._locks[dataset_name] = threading.Lock()
            self._counts[dataset_name] = 0

    def write_record(self, dataset_name: str, record: dict) -> None:
        lock = self._locks[dataset_name]
        with lock:
            self._files[dataset_name].write(_dumps(record))
            self._files[dataset_name].write(b"\n")
            self._counts[dataset_name] += 1

    def write_batch(self, dataset_name: str, records: List[dict]) -> None:
        lines = b"".join(_dumps(r) + b"\n" for r in records)
        lock = self._locks[dataset_name]
        with lock:
            self._files[dataset_name].write(lines)
            self._counts[dataset_name] += len(records)

    def set_metadata(self, key: str, value: Any) -> None:
        with self._global_lock:
            self._metadata[key] = value

    def close(self) -> None:
        for fh in self._files.values():
            fh.close()
        self._files.clear()
        manifest = {
            "generated_at": self._metadata.get(
                "generated_at",
                datetime.now(timezone.utc).isoformat(),
            ),
            "counts": dict(self._counts),
        }
        for k, v in self._metadata.items():
            if k not in manifest:
                manifest[k] = v
        manifest_path = os.path.join(self._output_dir, "manifest.json")
        with open(manifest_path, "wb") as fh:
            fh.write(_dumps(manifest))
            fh.write(b"\n")
