"""Legacy single-file JSON sink — backward compatible with original output.

Accumulates all records in memory and writes the traditional monolithic
JSON file on :meth:`close`.  This is fine for environments up to ~3K
endpoints (~2–3 GB output).  For larger environments use
:class:`~femur.sinks.jsonlines.JsonLinesSink`.
"""

import json
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..pipeline import DataSink


class LegacyJsonSink(DataSink):
    """Write the traditional single ``femur_inventory.json`` file.

    .. warning::

       This sink accumulates **all records in memory** before writing.
       At 250K endpoints the process will need 200+ GB of RAM.
       Use ``--output-format jsonl`` for large environments.
    """

    def __init__(
        self,
        output_path: str,
        indent: Optional[int] = 2,
        **kwargs: Any,
    ) -> None:
        self._output_path = output_path
        self._indent = indent if indent and indent > 0 else None
        self._datasets: Dict[str, List[dict]] = {}
        self._metadata: Dict[str, Any] = {}
        self._lock = threading.Lock()

    def open_dataset(self, dataset_name: str) -> None:
        with self._lock:
            self._datasets.setdefault(dataset_name, [])

    def write_record(self, dataset_name: str, record: dict) -> None:
        with self._lock:
            self._datasets[dataset_name].append(record)

    def write_batch(self, dataset_name: str, records: List[dict]) -> None:
        with self._lock:
            self._datasets[dataset_name].extend(records)

    def set_metadata(self, key: str, value: Any) -> None:
        with self._lock:
            self._metadata[key] = value

    def close(self) -> None:
        apps = self._datasets.get("applications", [])
        vulns = self._datasets.get("vulnerabilities", [])
        asmts = self._datasets.get("assessments", [])
        host_map = self._datasets.get("host_map", [])
        # host_map was stored as list-of-dicts; rebuild as dict keyed on id.
        host_map_dict: Dict[str, Any] = {}
        for entry in host_map:
            hid = entry.get("_host_map_id")
            if hid:
                val = {k: v for k, v in entry.items() if k != "_host_map_id"}
                host_map_dict[hid] = val
            else:
                # Fallback: if records were written as-is from build_host_map
                host_map_dict.update(entry)

        payload: dict = {
            "generated_at": self._metadata.get(
                "generated_at",
                datetime.now(timezone.utc).isoformat(),
            ),
            "counts": {
                "applications": len(apps),
                "vulnerabilities": len(vulns),
                "assessments": len(asmts),
                "host_map": len(host_map_dict),
            },
            "applications": apps,
            "vulnerabilities": vulns,
            "assessments": asmts,
            "host_map": host_map_dict,
        }
        errors = self._metadata.get("errors")
        if errors:
            payload["errors"] = errors

        with open(self._output_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=self._indent, default=str)
            fh.write("\n")
