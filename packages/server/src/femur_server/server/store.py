"""Thread-safe in-memory inventory store backed by JSONL files on disk.

The :class:`InventoryStore` reads JSONL files produced by the CLI pipeline
(``femur --output-format jsonl``) and serves records to the
FastAPI controllers.
"""

import gzip
import json
import logging
import threading
import time
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger("femur.server")

_DATASETS = ("applications", "vulnerabilities", "assessments")


class InventoryStore:
    """Cache for inventory data loaded from JSONL files.

    Thread-safe: controllers may read concurrently with a background
    reload triggered by :class:`~.jobs.FetchJob`.
    """

    def __init__(self, data_dir: str) -> None:
        self.data_dir = Path(data_dir)
        self._data: dict[str, list[dict]] = {ds: [] for ds in _DATASETS}
        self._host_map: dict[str, dict] = {}
        self._manifest: dict[str, Any] = {}
        self._lock = threading.Lock()
        self._loaded_at: Optional[float] = None

    # -- Properties ----------------------------------------------------------

    @property
    def generated_at(self) -> Optional[str]:
        return self._manifest.get("generated_at")

    @property
    def age_seconds(self) -> Optional[float]:
        if self._loaded_at is None:
            return None
        return time.time() - self._loaded_at

    @property
    def counts(self) -> dict[str, int]:
        return self._manifest.get("counts", {})

    # -- Load ----------------------------------------------------------------

    def load(self) -> None:
        """(Re)load data from JSONL files in *data_dir*."""
        manifest_path = self.data_dir / "manifest.json"
        if not manifest_path.exists():
            log.warning("No manifest.json in %s — store is empty", self.data_dir)
            return

        with open(manifest_path) as fh:
            manifest = json.load(fh)

        new_data: dict[str, list[dict]] = {}
        for ds in _DATASETS:
            records: list[dict] = []
            for ext in (".jsonl", ".jsonl.gz"):
                path = self.data_dir / f"{ds}{ext}"
                if path.exists():
                    opener = gzip.open if ext.endswith(".gz") else open
                    with opener(path, "rt", encoding="utf-8") as fh:
                        for line in fh:
                            line = line.strip()
                            if line:
                                records.append(json.loads(line))
                    break
            new_data[ds] = records

        # host_map
        host_map: dict[str, dict] = {}
        for ext in (".jsonl", ".jsonl.gz"):
            hm_path = self.data_dir / f"host_map{ext}"
            if hm_path.exists():
                opener = gzip.open if ext.endswith(".gz") else open
                with opener(hm_path, "rt", encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if line:
                            rec = json.loads(line)
                            hid = rec.pop("_host_map_id", None)
                            if hid:
                                host_map[hid] = rec
                break

        with self._lock:
            self._data = new_data
            self._host_map = host_map
            self._manifest = manifest
            self._loaded_at = time.time()

        total = sum(len(v) for v in new_data.values())
        log.info(
            "Loaded %d records from %s (generated %s)",
            total,
            self.data_dir,
            manifest.get("generated_at", "?"),
        )

    # -- Read ----------------------------------------------------------------

    def get_dataset(self, name: str) -> list[dict]:
        with self._lock:
            return self._data.get(name, [])

    def get_host_map(self) -> dict[str, dict]:
        with self._lock:
            return dict(self._host_map)
