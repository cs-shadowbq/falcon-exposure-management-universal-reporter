"""AID-bucketed output sink — route records to per-AID subdirectories.

Wraps the streaming pipeline and routes each record to a per-AID directory
with files named using the convention::

    {dataset}--{cid}--{aid}--{epoch}.{ext}

Output structure::

    output_dir/
        by_aid/
            190a664e08e2488ca2fc49b19a3a29ae/
                vulnerabilities--5ddb0407bef2--190a664e08e2488ca2fc49b19a3a29ae--1749465600.jsonl
                applications--5ddb0407bef2--190a664e08e2488ca2fc49b19a3a29ae--1749465600.jsonl
                manifest--5ddb0407bef2--190a664e08e2488ca2fc49b19a3a29ae--1749465600.json
            eb083e8db5834b1aa60818dd91c606dd/
                vulnerabilities--7277b699df52--eb083e8db5834b1aa60818dd91c606dd--1749465600.jsonl
                manifest--7277b699df52--eb083e8db5834b1aa60818dd91c606dd--1749465600.json
            _no_aid/
                host_map--unknown--_no_aid--1749465600.jsonl
                manifest--unknown--_no_aid--1749465600.json
            manifest.json
"""

import os
import re
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from ..pipeline import DataSink
from .compression import compress_directories_parallel

try:
    import orjson

    def _dumps(obj: Any) -> bytes:
        return orjson.dumps(obj, default=str)
except ImportError:
    import json

    def _dumps(obj: Any) -> bytes:
        return json.dumps(obj, default=str, ensure_ascii=False).encode("utf-8")


# Extension map for output formats.
_FORMAT_EXT = {
    "jsonl": ".jsonl",
    "xml": ".xml",
    "json": ".jsonl",  # bucketed JSON uses JSONL (one record per line)
}


class _AidFileSet:
    """Manages file handles for a single AID's output directory."""

    def __init__(
        self, output_dir: str, aid: str, cid: str, epoch: str, fmt: str = "jsonl"
    ) -> None:
        self._output_dir = output_dir
        self._aid = aid
        self._cid = cid
        self._epoch = epoch
        self._fmt = fmt
        self._ext = _FORMAT_EXT.get(fmt, ".jsonl")
        self._files: Dict[str, Any] = {}
        self._xml_state: Dict[str, dict] = {}
        self._locks: Dict[str, threading.Lock] = {}
        self._counts: Dict[str, int] = {}
        self._global_lock = threading.Lock()
        os.makedirs(output_dir, exist_ok=True)

    def _filename(self, dataset_name: str, ext: Optional[str] = None) -> str:
        return f"{dataset_name}--{self._cid}--{self._aid}--{self._epoch}{ext or self._ext}"

    def open_dataset(self, dataset_name: str) -> None:
        with self._global_lock:
            if dataset_name in self._files:
                return
            fname = self._filename(dataset_name)
            path = os.path.join(self._output_dir, fname)
            fh = open(path, "wb")
            self._files[dataset_name] = fh
            self._locks[dataset_name] = threading.Lock()
            self._counts[dataset_name] = 0

            if self._fmt == "xml":
                from lxml.etree import QName, xmlfile
                fh.write(b'<?xml version="1.0" encoding="UTF-8"?>\n')
                xf_cm = xmlfile(fh, encoding="utf-8")
                xf = xf_cm.__enter__()
                ns = _DATASET_NAMESPACES.get(dataset_name)
                root_tag = QName(ns, dataset_name) if ns else dataset_name
                root_cm = xf.element(root_tag, nsmap={None: ns} if ns else None)
                root_cm.__enter__()
                self._xml_state[dataset_name] = {
                    "xf_cm": xf_cm,
                    "xf": xf,
                    "root_cm": root_cm,
                }

    def write_record(self, dataset_name: str, record: dict) -> None:
        lock = self._locks[dataset_name]
        with lock:
            if self._fmt == "xml":
                self._write_xml_record(dataset_name, record)
            else:
                self._files[dataset_name].write(_dumps(record))
                self._files[dataset_name].write(b"\n")
            self._counts[dataset_name] += 1

    def write_batch(self, dataset_name: str, records: List[dict]) -> None:
        lock = self._locks[dataset_name]
        with lock:
            if self._fmt == "xml":
                for rec in records:
                    self._write_xml_record(dataset_name, rec)
            else:
                lines = b"".join(_dumps(r) + b"\n" for r in records)
                self._files[dataset_name].write(lines)
            self._counts[dataset_name] += len(records)

    def _write_xml_record(self, dataset_name: str, record: dict) -> None:
        """Write a single record as XML (must be called under lock)."""
        from lxml.etree import Element
        xf = self._xml_state[dataset_name]["xf"]
        el = _dict_to_element("record", record)
        xf.write(el)

    def close(self, metadata: Dict[str, Any]) -> None:
        # Close XML context managers first.
        for dataset_name, state in self._xml_state.items():
            state["root_cm"].__exit__(None, None, None)
            state["xf_cm"].__exit__(None, None, None)
        self._xml_state.clear()

        for fh in self._files.values():
            fh.close()
        self._files.clear()

        # Write manifest with custom filename.
        manifest_data = {
            "generated_at": metadata.get(
                "generated_at",
                datetime.now(timezone.utc).isoformat(),
            ),
            "counts": dict(self._counts),
        }
        for k, v in metadata.items():
            if k not in manifest_data:
                manifest_data[k] = v

        if self._fmt == "xml":
            from lxml.etree import Element as El, QName, tostring

            ns = _DATASET_NAMESPACES.get("manifest-by-aid")
            root = El(
                QName(ns, "manifest") if ns else "manifest",
                nsmap={None: ns} if ns else None,
            )
            gen_el = El("generated_at")
            gen_el.text = str(manifest_data["generated_at"])
            root.append(gen_el)

            counts_el = El("counts")
            for name, count in self._counts.items():
                cel = El(name)
                cel.text = str(count)
                counts_el.append(cel)
            root.append(counts_el)

            for k, v in metadata.items():
                if k in ("generated_at",):
                    continue
                root.append(_dict_to_element(k, v))

            manifest_fname = self._filename("manifest", ext=".xml")
            manifest_path = os.path.join(self._output_dir, manifest_fname)
            with open(manifest_path, "wb") as fh:
                fh.write(b'<?xml version="1.0" encoding="UTF-8"?>\n')
                fh.write(tostring(root, pretty_print=True))
        else:
            manifest_fname = self._filename("manifest", ext=".json")
            manifest_path = os.path.join(self._output_dir, manifest_fname)
            with open(manifest_path, "wb") as fh:
                fh.write(_dumps(manifest_data))
                fh.write(b"\n")

    @property
    def counts(self) -> Dict[str, int]:
        return dict(self._counts)


_ILLEGAL_XML_CHARS = re.compile(
    "[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x84\x86-\x9f]"
)

# URN namespace mapping for FEMUR XML schema identity.
_SCHEMA_VERSION = "1.0.0"
_NAMESPACE_BASE = "urn:femur:schema"
_DATASET_NAMESPACES: Dict[str, str] = {
    "host_map": f"{_NAMESPACE_BASE}:host_map:{_SCHEMA_VERSION}",
    "applications": f"{_NAMESPACE_BASE}:applications:{_SCHEMA_VERSION}",
    "vulnerabilities": f"{_NAMESPACE_BASE}:vulnerabilities:{_SCHEMA_VERSION}",
    "assessments": f"{_NAMESPACE_BASE}:assessments:{_SCHEMA_VERSION}",
    "manifest": f"{_NAMESPACE_BASE}:manifest:{_SCHEMA_VERSION}",
    "manifest-by-aid": f"{_NAMESPACE_BASE}:manifest-by-aid:{_SCHEMA_VERSION}",
    "manifest-aggregate": f"{_NAMESPACE_BASE}:manifest-aggregate:{_SCHEMA_VERSION}",
}


def _dict_to_element(tag: str, data: Any) -> "Any":
    """Recursively convert a Python value to an XML Element tree."""
    from lxml.etree import Element

    safe_tag = tag.replace(" ", "_")
    if safe_tag and safe_tag[0].isdigit():
        safe_tag = "_" + safe_tag

    el = Element(safe_tag)
    if isinstance(data, dict):
        for key, val in data.items():
            el.append(_dict_to_element(str(key), val))
    elif isinstance(data, (list, tuple)):
        for item in data:
            el.append(_dict_to_element("item", item))
    elif isinstance(data, bool):
        el.text = "true" if data else "false"
    elif data is not None:
        el.text = _ILLEGAL_XML_CHARS.sub("", str(data))
    return el


class AidBucketedSink(DataSink):
    """Route records to per-AID subdirectory sinks.

    Each unique AID gets its own output directory with files named::

        {dataset}--{cid}--{aid}--{epoch}.{ext}

    Records without an ``aid`` field are routed to a ``_no_aid/``
    subdirectory.

    Parameters
    ----------
    output_dir : str
        Root output directory.  A ``by_aid/`` subdirectory is created
        within it.
    output_format : str
        Output format: ``"jsonl"`` (default), ``"xml"``, or ``"json"``.
    aid_prefix_len : int
        Number of characters from the AID to use in directory names.
        Default 32 (full AID).
    compressed : bool
        When ``True``, each individual output file is zipped after writing
        (e.g. ``vulnerabilities--...--1780963200.jsonl.zip``). Originals
        are removed. Default ``False``.
    compressed_by_aid : bool
        When ``True``, each AID directory is zipped into a single archive
        (e.g. ``190a664e08e2488ca2fc49b19a3a29ae.zip``). The directory is
        removed after archiving. Default ``False``.
    """

    def __init__(
        self,
        output_dir: str,
        output_format: str = "jsonl",
        aid_prefix_len: int = 32,
        compressed: bool = False,
        compressed_by_aid: bool = False,
        **kwargs: Any,
    ) -> None:
        self._output_dir = os.path.join(output_dir, "by_aid")
        self._fmt = output_format
        self._prefix_len = aid_prefix_len
        self._compressed = compressed
        self._compressed_by_aid = compressed_by_aid
        self._filesets: Dict[str, _AidFileSet] = {}
        self._aid_cids: Dict[str, str] = {}
        self._lock = threading.Lock()
        self._metadata: Dict[str, Any] = {}
        # Per-AID IAVM severity counters: {aid_key: {"CAT I": N, ...}}
        self._iavm_stats: Dict[str, Dict[str, int]] = {}
        self._iavm_stats_lock = threading.Lock()
        os.makedirs(self._output_dir, exist_ok=True)

    def _get_epoch(self) -> str:
        """Get the epoch seconds from generated_at metadata."""
        generated_at = self._metadata.get("generated_at", "")
        if generated_at:
            try:
                dt = datetime.fromisoformat(generated_at)
                return str(int(dt.timestamp()))
            except (ValueError, TypeError):
                pass
        return str(int(datetime.now(timezone.utc).timestamp()))

    def _get_fileset(self, aid: str, cid: str) -> _AidFileSet:
        """Get or create the file set for the given AID."""
        key = aid[:self._prefix_len] if aid else "_no_aid"
        if key in self._filesets:
            return self._filesets[key]
        with self._lock:
            if key not in self._filesets:
                sub_dir = os.path.join(self._output_dir, key)
                epoch = self._get_epoch()
                cid_short = cid[:12] if cid else "unknown"
                self._filesets[key] = _AidFileSet(
                    sub_dir, key, cid_short, epoch, fmt=self._fmt
                )
                self._aid_cids[key] = cid_short
            return self._filesets[key]

    # -- DataSink interface --------------------------------------------------

    def open_dataset(self, dataset_name: str) -> None:
        # File sets open datasets lazily on first write.
        pass

    def _track_iavm(self, key: str, record: dict) -> None:
        """Accumulate IAVM severity counts for a record (O(1) per record)."""
        notices = record.get("iavm_notices")
        if not notices:
            return
        with self._iavm_stats_lock:
            counters = self._iavm_stats.setdefault(key, {})
            for notice in notices:
                sev = notice.get("iavm_severity", "UNKNOWN")
                counters[sev] = counters.get(sev, 0) + 1

    def write_record(self, dataset_name: str, record: dict) -> None:
        aid = record.get("aid", "")
        cid = record.get("cid", "")
        key = aid[:self._prefix_len] if aid else "_no_aid"
        fileset = self._get_fileset(aid, cid)
        fileset.open_dataset(dataset_name)
        fileset.write_record(dataset_name, record)
        self._track_iavm(key, record)

    def write_batch(self, dataset_name: str, records: List[dict]) -> None:
        # Group records by AID, then route each group to its file set.
        buckets: Dict[str, Tuple[str, List[dict]]] = {}
        for rec in records:
            aid = rec.get("aid", "")
            cid = rec.get("cid", "")
            key = aid[:self._prefix_len] if aid else "_no_aid"
            if key not in buckets:
                buckets[key] = (cid, [])
            buckets[key][1].append(rec)
        for key, (cid, group) in buckets.items():
            aid = group[0].get("aid", "")
            fileset = self._get_fileset(aid, cid)
            fileset.open_dataset(dataset_name)
            fileset.write_batch(dataset_name, group)
            for rec in group:
                self._track_iavm(key, rec)

    def set_metadata(self, key: str, value: Any) -> None:
        self._metadata[key] = value

    def close(self) -> None:
        # Build per-AID metadata including IAVM stats, then close.
        for key, fileset in self._filesets.items():
            per_aid_meta = dict(self._metadata)
            iavm_counts = self._iavm_stats.get(key)
            if iavm_counts:
                per_aid_meta["iavm_summary"] = iavm_counts
            fileset.close(per_aid_meta)

        # Compress files if requested (parallelized across AIDs).
        if self._compressed or self._compressed_by_aid:
            self._compress_outputs()

        # Write aggregate manifest.
        aggregate_iavm: Dict[str, int] = {}
        for counters in self._iavm_stats.values():
            for sev, count in counters.items():
                aggregate_iavm[sev] = aggregate_iavm.get(sev, 0) + count

        manifest: Dict[str, Any] = {
            "generated_at": self._metadata.get(
                "generated_at",
                datetime.now(timezone.utc).isoformat(),
            ),
            "app_name": self._metadata.get("app_name", ""),
            "app_version": self._metadata.get("app_version", ""),
            "command": self._metadata.get("command", ""),
            "total_aids": len(self._filesets),
            "aid_directories": sorted(self._filesets.keys()),
        }
        if self._metadata.get("iavm_date_generated"):
            manifest["iavm_date_generated"] = self._metadata["iavm_date_generated"]
        if aggregate_iavm:
            manifest["iavm_summary"] = aggregate_iavm
            manifest["iavm_aids_affected"] = sum(
                1 for k in self._iavm_stats if self._iavm_stats[k]
            )

        if self._fmt == "xml":
            from lxml.etree import Element as El, QName, tostring

            ns = _DATASET_NAMESPACES.get("manifest-aggregate")
            root = El(
                QName(ns, "manifest") if ns else "manifest",
                nsmap={None: ns} if ns else None,
            )
            for k, v in manifest.items():
                root.append(_dict_to_element(k, v))
            manifest_path = os.path.join(self._output_dir, "manifest.xml")
            with open(manifest_path, "wb") as fh:
                fh.write(b'<?xml version="1.0" encoding="UTF-8"?>\n')
                fh.write(tostring(root, pretty_print=True))
        else:
            manifest_path = os.path.join(self._output_dir, "manifest.json")
            with open(manifest_path, "wb") as fh:
                fh.write(_dumps(manifest))
                fh.write(b"\n")

    def _compress_outputs(self) -> None:
        """Compress output files or directories in parallel."""
        aid_dirs = [
            os.path.join(self._output_dir, key)
            for key in self._filesets
        ]
        if self._compressed_by_aid:
            compress_directories_parallel(aid_dirs, mode="directory")
        elif self._compressed:
            compress_directories_parallel(aid_dirs, mode="individual")
