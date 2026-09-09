"""AID-bucketed output sink — route records to per-AID subdirectories.

Wraps the streaming pipeline and routes each record to a per-AID directory
with files named using the convention::

    {dataset}--{cid}--{aid}--{epoch}.{ext}

Output structure — AIDs are grouped under a short shard directory taken from
their leading characters, so no single directory holds every host::

    output_dir/
        by_aid/
            19/
                190a664e08e2488ca2fc49b19a3a29ae/
                    vulnerabilities--5ddb0407bef2--190a664e08e2488ca2fc49b19a3a29ae--1749465600.jsonl
                    applications--5ddb0407bef2--190a664e08e2488ca2fc49b19a3a29ae--1749465600.jsonl
                    manifest--5ddb0407bef2--190a664e08e2488ca2fc49b19a3a29ae--1749465600.json
            eb/
                eb083e8db5834b1aa60818dd91c606dd/
                    vulnerabilities--7277b699df52--eb083e8db5834b1aa60818dd91c606dd--1749465600.jsonl
                    manifest--7277b699df52--eb083e8db5834b1aa60818dd91c606dd--1749465600.json
            _no_aid/
                host_map--unknown--_no_aid--1749465600.jsonl
                manifest--unknown--_no_aid--1749465600.json
            manifest.json

Scale note — directory fan-out
------------------------------
AIDs are lowercase hex, so each shard character yields 16 buckets; the default
depth of 2 gives 256, holding any one directory to a few thousand entries even
in a tenant with hundreds of thousands of hosts.  ``aid_shard_depth=0``
restores the flat ``by_aid/<aid>/`` layout.  The shard for any AID is simply
``aid[:depth]``, so the aggregate manifest keeps listing bare AIDs.

Scale note — file descriptors
-----------------------------
This sink is used with environments containing hundreds of thousands of AIDs,
so it never holds an output file open between writes.  Each write is a
short-lived ``open``/``write``/``close`` in append mode, which keeps the
descriptor count proportional to the number of *writer threads* rather than
the number of AIDs.  Holding one handle per (AID, dataset) previously exhausted
the process descriptor limit at ~65K AIDs, which in turn starved the HTTPS
connection pools and surfaced as spurious API errors.
"""

import concurrent.futures
import logging
import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from ..fdbudget import (
    FD_EXHAUSTED_ERRNOS,
    FdExhaustionError,
    format_fd_state,
)
from ..pipeline import DataSink
from ._xml_common import (
    _DATASET_NAMESPACES,
    dict_to_element as _dict_to_element,
    xml_frame as _xml_frame,
)
from .compression import compress_directories_parallel, zip_directory, zip_individual_files

log = logging.getLogger("femur")

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

# Number of lock stripes shared across all (AID, dataset) pairs.  A per-pair
# lock would mean millions of Lock objects at scale; a fixed set of stripes
# protects a superset of the state, which is still correct.  Contention is
# negligible because only a handful of threads write concurrently.
_LOCK_STRIPES = 64

# Threads used to finalize (close tags, manifest, optional zip) per-AID dirs.
_FINALIZE_WORKERS = 8

# AIDs per finalize task.  Chunking keeps the number of in-flight Future
# objects bounded — one per AID would be hundreds of MB at scale.
_FINALIZE_CHUNK = 512

# Above this many AIDs the aggregate XML manifest is streamed rather than
# built as an in-memory tree (which costs ~300 B per AID plus a full
# serialized copy).  Below it, the pretty-printed tree output is preserved.
_XML_STREAM_THRESHOLD = 10_000

# Warn once per this many AID buckets, to make the on-disk fan-out visible
# while a large run is still in progress.
_FANOUT_WARN_AT = 50_000

# Datasets plus manifest, i.e. the upper bound on files per AID directory.
_FILES_PER_AID = 5

# Bucket name for records that carry no aid.
_NO_AID_KEY = "_no_aid"

# Leading AID characters used as an intermediate shard directory.  AIDs are
# lowercase hex, so each character yields 16 shards: depth 2 gives 256, keeping
# any single directory to a few thousand entries even in the largest tenants.
# A flat layout puts every AID in one directory, which stays correct but makes
# ordinary tooling (ls, tab-completion, tar, backup agents) painful, and would
# hit the ~64,999 subdirectory cap on ext3 or ext4 without dir_nlink.
DEFAULT_AID_SHARD_DEPTH = 2


def _write_all(fd: int, buf: bytes) -> None:
    """Write *buf* to *fd* in full, tolerating short writes."""
    view = memoryview(buf)
    while view:
        view = view[os.write(fd, view) :]


def _append_bytes(path: str, payload: bytes, truncate: bool = False) -> None:
    """Append *payload* to *path*, creating it when *truncate* is set.

    Uses raw descriptors rather than a buffered file object: this runs once
    per (AID, dataset, batch) and is called millions of times in large
    environments, so the buffered wrapper's extra ``fstat`` and Python object
    churn is worth avoiding.  Mode ``0o666`` matches what the builtin ``open``
    would request, leaving the final permissions to the process umask.
    """
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if truncate else os.O_APPEND)
    try:
        fd = os.open(path, flags, 0o666)
    except OSError as exc:
        # Descriptor exhaustion here would otherwise surface as a bare
        # [Errno 24] with no indication of the limit in force.
        if exc.errno in FD_EXHAUSTED_ERRNOS:
            raise FdExhaustionError(
                context="writing per-AID output", path=path
            ) from exc
        raise
    try:
        _write_all(fd, payload)
    finally:
        os.close(fd)


class _StripedLocks:
    """A fixed pool of locks addressed by hashable key."""

    __slots__ = ("_locks", "_n")

    def __init__(self, n: int = _LOCK_STRIPES) -> None:
        self._locks = tuple(threading.Lock() for _ in range(n))
        self._n = n

    def get(self, key: Any) -> threading.Lock:
        return self._locks[hash(key) % self._n]


class _DatasetState:
    """Per-(AID, dataset) bookkeeping: no file handle, just where and how much."""

    __slots__ = ("path", "count", "created")

    def __init__(self, path: str) -> None:
        self.path = path
        self.count = 0
        self.created = False


class _AidFileSet:
    """Routes one AID's records to its output directory.

    Holds no open file handles.  Files are created on first write (so an AID
    that receives no records leaves no directory behind) and appended to
    thereafter.
    """

    __slots__ = (
        "_output_dir",
        "_aid",
        "_cid",
        "_epoch",
        "_fmt",
        "_ext",
        "_states",
        "_locks",
        "_dir_created",
    )

    def __init__(
        self,
        output_dir: str,
        aid: str,
        cid: str,
        epoch: str,
        fmt: str = "jsonl",
        locks: Optional[_StripedLocks] = None,
    ) -> None:
        self._output_dir = output_dir
        self._aid = aid
        self._cid = cid
        self._epoch = epoch
        self._fmt = fmt
        self._ext = _FORMAT_EXT.get(fmt, ".jsonl")
        self._states: Dict[str, _DatasetState] = {}
        self._locks = locks if locks is not None else _StripedLocks()
        self._dir_created = False

    def _filename(self, dataset_name: str, ext: Optional[str] = None) -> str:
        return f"{dataset_name}--{self._cid}--{self._aid}--{self._epoch}{ext or self._ext}"

    def _ensure_dir(self) -> None:
        """Create this AID's directory.  Idempotent and race-tolerant."""
        if self._dir_created:
            return
        try:
            os.mkdir(self._output_dir)
        except FileExistsError:
            pass
        except FileNotFoundError:
            # First AID to land in this shard, so the shard directory does not
            # exist yet.  Only taken once per shard, not once per AID.
            os.makedirs(self._output_dir, exist_ok=True)
        self._dir_created = True

    def open_dataset(self, dataset_name: str) -> None:
        """Register *dataset_name*.  Pure bookkeeping — performs no I/O.

        Creating the file here would put the truncating open under a
        different lock than the appends, which is how a re-entrant call could
        silently discard another thread's records.  Creation is instead fused
        into the first write, where it is covered by the write lock.
        """
        if dataset_name in self._states:
            return
        with self._locks.get((self._aid, "\x00datasets")):
            if dataset_name not in self._states:
                path = os.path.join(self._output_dir, self._filename(dataset_name))
                self._states[dataset_name] = _DatasetState(path)

    def _encode(self, dataset_name: str, records: List[dict]) -> bytes:
        if self._fmt == "xml":
            from lxml.etree import tostring

            return b"".join(
                tostring(_dict_to_element("record", rec)) for rec in records
            )
        return b"".join(_dumps(rec) + b"\n" for rec in records)

    def _emit(self, dataset_name: str, state: _DatasetState, payload: bytes) -> None:
        """Write *payload*.  Must be called under the dataset's lock."""
        if state.created:
            _append_bytes(state.path, payload)
            return
        self._ensure_dir()
        prologue = _xml_frame(dataset_name)[0] if self._fmt == "xml" else b""
        _append_bytes(state.path, prologue + payload, truncate=True)
        state.created = True

    def write_record(self, dataset_name: str, record: dict) -> None:
        self.write_batch(dataset_name, [record])

    def write_batch(self, dataset_name: str, records: List[dict]) -> None:
        state = self._states[dataset_name]
        # Serialize outside the lock: it is pure CPU, and building the payload
        # before opening the descriptor means a serialization failure cannot
        # leave a half-written record on disk.
        payload = self._encode(dataset_name, records)
        with self._locks.get((self._aid, dataset_name)):
            self._emit(dataset_name, state, payload)
            state.count += len(records)

    def close(self, metadata: Dict[str, Any]) -> None:
        counts = {name: st.count for name, st in self._states.items()}

        # Seal XML documents that were actually created.
        if self._fmt == "xml":
            for dataset_name, state in self._states.items():
                if state.created:
                    _append_bytes(state.path, _xml_frame(dataset_name)[1])

        self._ensure_dir()

        # Write manifest with custom filename.
        manifest_data = {
            "generated_at": metadata.get(
                "generated_at",
                datetime.now(timezone.utc).isoformat(),
            ),
            "counts": counts,
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
            for name, count in counts.items():
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
            _append_bytes(manifest_path, _dumps(manifest_data) + b"\n", truncate=True)


class AidBucketedSink(DataSink):
    """Route records to per-AID subdirectory sinks.

    Each unique AID gets its own output directory with files named::

        {dataset}--{cid}--{aid}--{epoch}.{ext}

    Records without an ``aid`` field are routed to a ``_no_aid/``
    subdirectory.

    Output files are opened in append mode for each write rather than held
    open, so the descriptor count does not grow with the number of AIDs.

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
    aid_shard_depth : int
        Number of leading AID characters used as an intermediate shard
        directory, so no single directory holds every host. Default 2 (256
        shards, since AIDs are hex). ``0`` writes the flat
        ``by_aid/<aid>/`` layout. Clamped to *aid_prefix_len*. The
        ``_no_aid`` bucket is never sharded.
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
        aid_shard_depth: int = DEFAULT_AID_SHARD_DEPTH,
        compressed: bool = False,
        compressed_by_aid: bool = False,
        **kwargs: Any,
    ) -> None:
        self._output_dir = os.path.join(output_dir, "by_aid")
        self._fmt = output_format
        self._prefix_len = aid_prefix_len
        self._shard_depth = max(0, min(int(aid_shard_depth), aid_prefix_len))
        self._compressed = compressed
        self._compressed_by_aid = compressed_by_aid
        self._filesets: Dict[str, _AidFileSet] = {}
        self._aid_cids: Dict[str, str] = {}
        self._lock = threading.Lock()
        self._write_locks = _StripedLocks()
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

    def _shard(self, key: str) -> str:
        """Return the shard directory component for an AID key, or ``""``.

        The ``_no_aid`` bucket is never sharded: it is a single directory, so
        it carries no fan-out risk and is easier to find at the top level.
        """
        if not self._shard_depth or key == _NO_AID_KEY:
            return ""
        return key[:self._shard_depth]

    def _aid_dir(self, key: str) -> str:
        """Absolute path to an AID's output directory, including its shard."""
        shard = self._shard(key)
        if shard:
            return os.path.join(self._output_dir, shard, key)
        return os.path.join(self._output_dir, key)

    def _get_fileset(self, aid: str, cid: str) -> _AidFileSet:
        """Get or create the file set for the given AID."""
        key = aid[:self._prefix_len] if aid else _NO_AID_KEY
        if key in self._filesets:
            return self._filesets[key]
        with self._lock:
            if key not in self._filesets:
                sub_dir = self._aid_dir(key)
                epoch = self._get_epoch()
                cid_short = cid[:12] if cid else "unknown"
                # No I/O here: the directory is created on first write, so
                # this critical section stays free of blocking syscalls.
                self._filesets[key] = _AidFileSet(
                    sub_dir, key, cid_short, epoch, fmt=self._fmt,
                    locks=self._write_locks,
                )
                self._aid_cids[key] = cid_short
                self._warn_on_fanout(len(self._filesets))
            return self._filesets[key]

    def _warn_on_fanout(self, n_aids: int) -> None:
        """Warn as the AID count crosses each power-of-ten scale marker.

        Every AID becomes a directory holding several small files, so the tree
        grows much faster than the data in it.  The run is allowed to proceed —
        this only makes the cost visible while there is still time to react.
        """
        if n_aids < _FANOUT_WARN_AT or n_aids % _FANOUT_WARN_AT != 0:
            return
        log.warning(
            "--bucket-by-aid has reached %s AID buckets: ~%s directories and "
            "~%s files projected so far (%s per AID). File descriptors: %s",
            f"{n_aids:,}",
            f"{n_aids:,}",
            f"{n_aids * _FILES_PER_AID:,}",
            _FILES_PER_AID,
            format_fd_state(),
        )

    # -- DataSink interface --------------------------------------------------

    def open_dataset(self, dataset_name: str) -> None:
        # File sets open datasets lazily on first write.
        pass

    @staticmethod
    def _iavm_counts(records: List[dict]) -> Dict[str, int]:
        """Tally IAVM severities for *records* without taking any lock."""
        counters: Dict[str, int] = {}
        for record in records:
            notices = record.get("iavm_notices")
            if not notices:
                continue
            for notice in notices:
                sev = notice.get("iavm_severity", "UNKNOWN")
                counters[sev] = counters.get(sev, 0) + 1
        return counters

    def _merge_iavm(self, key: str, counters: Dict[str, int]) -> None:
        """Fold a locally-tallied count into the shared stats under one lock."""
        if not counters:
            return
        with self._iavm_stats_lock:
            target = self._iavm_stats.setdefault(key, {})
            for sev, count in counters.items():
                target[sev] = target.get(sev, 0) + count

    def write_record(self, dataset_name: str, record: dict) -> None:
        self.write_batch(dataset_name, [record])

    def write_batch(self, dataset_name: str, records: List[dict]) -> None:
        # Group records by AID, then route each group to its file set.
        buckets: Dict[str, Tuple[str, List[dict]]] = {}
        for rec in records:
            aid = rec.get("aid", "")
            cid = rec.get("cid", "")
            key = aid[:self._prefix_len] if aid else _NO_AID_KEY
            if key not in buckets:
                buckets[key] = (cid, [])
            buckets[key][1].append(rec)
        for key, (cid, group) in buckets.items():
            aid = group[0].get("aid", "")
            fileset = self._get_fileset(aid, cid)
            fileset.open_dataset(dataset_name)
            fileset.write_batch(dataset_name, group)
            # Tally locally, then merge once — the shared lock is process-wide
            # and would otherwise be acquired once per record.
            self._merge_iavm(key, self._iavm_counts(group))

    def set_metadata(self, key: str, value: Any) -> None:
        self._metadata[key] = value

    def _finalize_one(self, key: str, compress_mode: Optional[str]) -> None:
        """Seal, manifest and optionally zip a single AID directory."""
        fileset = self._filesets[key]
        per_aid_meta = dict(self._metadata)
        iavm_counts = self._iavm_stats.get(key)
        if iavm_counts:
            per_aid_meta["iavm_summary"] = iavm_counts
        fileset.close(per_aid_meta)
        if compress_mode == "directory":
            zip_directory(self._aid_dir(key))
        elif compress_mode == "individual":
            zip_individual_files(self._aid_dir(key))

    def _finalize_all(self) -> int:
        """Finalize every AID directory in parallel.  Returns failure count.

        A failure on one AID must not cost the remaining AIDs their manifests
        (or, in XML mode, their closing tags) nor lose the aggregate manifest,
        so each is isolated and logged.
        """
        compress_mode = None
        if self._compressed_by_aid:
            compress_mode = "directory"
        elif self._compressed:
            compress_mode = "individual"

        keys = list(self._filesets)
        failures = 0

        def _run_chunk(chunk: List[str]) -> int:
            failed = 0
            for key in chunk:
                try:
                    self._finalize_one(key, compress_mode)
                except Exception:
                    failed += 1
                    log.exception("Failed to finalize AID directory %s", key)
            return failed

        if len(keys) <= _FINALIZE_CHUNK:
            return _run_chunk(keys)

        # Chunk the work so the number of live Future objects stays bounded.
        chunks = [
            keys[i : i + _FINALIZE_CHUNK]
            for i in range(0, len(keys), _FINALIZE_CHUNK)
        ]
        workers = min(_FINALIZE_WORKERS, len(chunks))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            for failed in pool.map(_run_chunk, chunks):
                failures += failed
        return failures

    def close(self) -> None:
        # Seal each AID's files, write its manifest, and compress if asked —
        # one pass over the tree rather than two.
        failures = self._finalize_all()

        # Write aggregate manifest.
        aggregate_iavm: Dict[str, int] = {}
        for counters in self._iavm_stats.values():
            for sev, count in counters.items():
                aggregate_iavm[sev] = aggregate_iavm.get(sev, 0) + count

        aid_directories = sorted(self._filesets)
        manifest: Dict[str, Any] = {
            "generated_at": self._metadata.get(
                "generated_at",
                datetime.now(timezone.utc).isoformat(),
            ),
            "app_name": self._metadata.get("app_name", ""),
            "app_version": self._metadata.get("app_version", ""),
            "command": self._metadata.get("command", ""),
            "total_aids": len(self._filesets),
            "aid_directories": aid_directories,
        }
        if self._metadata.get("iavm_date_generated"):
            manifest["iavm_date_generated"] = self._metadata["iavm_date_generated"]
        if aggregate_iavm:
            manifest["iavm_summary"] = aggregate_iavm
            manifest["iavm_aids_affected"] = sum(
                1 for k in self._iavm_stats if self._iavm_stats[k]
            )

        # Diagnostics go to the log, not the manifest: the published
        # manifest-aggregate XSD uses a closed xs:all, so adding fields here
        # would make the XML output schema-invalid.
        log.info(
            "Bucketed output finalized: %s AID directories, %s finalize "
            "failures. File descriptors: %s",
            f"{len(aid_directories):,}",
            failures,
            format_fd_state(),
        )
        if failures:
            log.error(
                "%s of %s AID directories failed to finalize; see earlier "
                "errors for details",
                failures,
                f"{len(aid_directories):,}",
            )

        if self._fmt == "xml":
            self._write_aggregate_xml(manifest, aid_directories)
        else:
            manifest_path = os.path.join(self._output_dir, "manifest.json")
            _append_bytes(manifest_path, _dumps(manifest) + b"\n", truncate=True)

    def _write_aggregate_xml(
        self, manifest: Dict[str, Any], aid_directories: List[str]
    ) -> None:
        """Write ``by_aid/manifest.xml``.

        Above :data:`_XML_STREAM_THRESHOLD` AIDs the document is streamed:
        building the tree costs roughly 300 bytes per AID plus a full
        serialized copy, which at 625K AIDs is a few hundred MB spent inside
        the call that is supposed to be finishing the run.
        """
        from lxml.etree import Element as El, QName, tostring, xmlfile

        ns = _DATASET_NAMESPACES.get("manifest-aggregate")
        root_tag = QName(ns, "manifest") if ns else "manifest"
        nsmap = {None: ns} if ns else None
        manifest_path = os.path.join(self._output_dir, "manifest.xml")

        if len(aid_directories) <= _XML_STREAM_THRESHOLD:
            root = El(root_tag, nsmap=nsmap)
            for k, v in manifest.items():
                root.append(_dict_to_element(k, v))
            with open(manifest_path, "wb") as fh:
                fh.write(b'<?xml version="1.0" encoding="UTF-8"?>\n')
                fh.write(tostring(root, pretty_print=True))
            return

        with open(manifest_path, "wb") as fh:
            fh.write(b'<?xml version="1.0" encoding="UTF-8"?>\n')
            with xmlfile(fh, encoding="utf-8") as xf:
                with xf.element(root_tag, nsmap=nsmap):
                    for k, v in manifest.items():
                        if k == "aid_directories":
                            with xf.element("aid_directories"):
                                for aid in v:
                                    item = El("item")
                                    item.text = aid
                                    xf.write(item)
                        else:
                            xf.write(_dict_to_element(k, v))

    def _compress_outputs(self) -> None:
        """Compress output files or directories in parallel.

        Retained for callers that compress independently of ``close()``;
        ``close()`` itself folds compression into its single finalize pass.
        """
        aid_dirs = [self._aid_dir(key) for key in self._filesets]
        if self._compressed_by_aid:
            compress_directories_parallel(aid_dirs, mode="directory")
        elif self._compressed:
            compress_directories_parallel(aid_dirs, mode="individual")
