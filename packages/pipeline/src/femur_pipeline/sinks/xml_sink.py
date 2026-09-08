"""Streaming XML output sink using ``lxml``.

Produces one XML file per dataset plus a ``manifest.xml``.
Each file is written incrementally via ``lxml.etree.xmlfile`` so
memory usage stays bounded regardless of record count.

Install ``lxml``::

    pip install lxml
"""

import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List

from lxml.etree import Element, QName, xmlfile

from ..pipeline import DataSink
from ._xml_common import _DATASET_NAMESPACES, dict_to_element as _dict_to_element

class XmlSink(DataSink):
    """Write each dataset to a streaming XML file.

    Directory layout::

        output_dir/
            applications.xml
            vulnerabilities.xml
            assessments.xml
            host_map.xml
            manifest.json

    Parameters
    ----------
    output_dir : str
        Directory to write files into (created if absent).
    record_tag : str
        Element name used for each record (default ``"record"``).
    """

    def __init__(
        self,
        output_dir: str,
        record_tag: str = "record",
        **kwargs: Any,
    ) -> None:
        self._output_dir = output_dir
        self._record_tag = record_tag
        self._state: Dict[str, dict] = {}
        self._locks: Dict[str, threading.Lock] = {}
        self._counts: Dict[str, int] = {}
        self._metadata: Dict[str, Any] = {}
        self._global_lock = threading.Lock()
        os.makedirs(output_dir, exist_ok=True)

    # -- DataSink interface --------------------------------------------------

    def open_dataset(self, dataset_name: str) -> None:
        with self._global_lock:
            if dataset_name in self._state:
                return
            path = os.path.join(self._output_dir, f"{dataset_name}.xml")
            fh = open(path, "wb")
            fh.write(b'<?xml version="1.0" encoding="UTF-8"?>\n')
            xf_cm = xmlfile(fh, encoding="utf-8")
            xf = xf_cm.__enter__()
            ns = _DATASET_NAMESPACES.get(dataset_name)
            root_tag = QName(ns, dataset_name) if ns else dataset_name
            root_cm = xf.element(root_tag, nsmap={None: ns} if ns else None)
            root_cm.__enter__()
            self._state[dataset_name] = {
                "fh": fh,
                "xf_cm": xf_cm,
                "xf": xf,
                "root_cm": root_cm,
                "ns": ns,
            }
            self._locks[dataset_name] = threading.Lock()
            self._counts[dataset_name] = 0

    def write_record(self, dataset_name: str, record: dict) -> None:
        xf = self._state[dataset_name]["xf"]
        el = _dict_to_element(self._record_tag, record)
        with self._locks[dataset_name]:
            xf.write(el)
            self._counts[dataset_name] += 1

    def write_batch(self, dataset_name: str, records: List[dict]) -> None:
        xf = self._state[dataset_name]["xf"]
        with self._locks[dataset_name]:
            for rec in records:
                xf.write(_dict_to_element(self._record_tag, rec))
            self._counts[dataset_name] += len(records)

    def set_metadata(self, key: str, value: Any) -> None:
        with self._global_lock:
            self._metadata[key] = value

    def close(self) -> None:
        for state in self._state.values():
            state["root_cm"].__exit__(None, None, None)
            state["xf_cm"].__exit__(None, None, None)
            state["fh"].close()
        self._state.clear()

        # Write manifest as XML.
        manifest_path = os.path.join(self._output_dir, "manifest.xml")
        ns = _DATASET_NAMESPACES.get("manifest")
        root = Element(
            QName(ns, "manifest") if ns else "manifest",
            nsmap={None: ns} if ns else None,
        )

        gen_at = self._metadata.get(
            "generated_at",
            datetime.now(timezone.utc).isoformat(),
        )
        el_gen = Element("generated_at")
        el_gen.text = str(gen_at)
        root.append(el_gen)

        counts_el = Element("counts")
        for name, count in self._counts.items():
            cel = Element(name)
            cel.text = str(count)
            counts_el.append(cel)
        root.append(counts_el)

        for k, v in self._metadata.items():
            if k in ("generated_at",):
                continue
            root.append(_dict_to_element(k, v))

        from lxml.etree import tostring

        with open(manifest_path, "wb") as fh:
            fh.write(b'<?xml version="1.0" encoding="UTF-8"?>\n')
            fh.write(tostring(root, pretty_print=True))
