"""Streaming XML output sink using ``lxml``.

Produces one XML file per dataset plus a ``manifest.xml``.
Each file is written incrementally via ``lxml.etree.xmlfile`` so
memory usage stays bounded regardless of record count.

Install ``lxml``::

    pip install lxml
"""

import os
import re
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List

from lxml.etree import Element, QName, xmlfile

from ..pipeline import DataSink

# URN namespace mapping for FEMUR XML schema identity.
# Each dataset root element declares its namespace via xmlns.
_SCHEMA_VERSION = "1.0.0"
_NAMESPACE_BASE = "urn:femur:schema"
_DATASET_NAMESPACES: Dict[str, str] = {
    "host_map": f"{_NAMESPACE_BASE}:host_map:{_SCHEMA_VERSION}",
    "applications": f"{_NAMESPACE_BASE}:applications:{_SCHEMA_VERSION}",
    "vulnerabilities": f"{_NAMESPACE_BASE}:vulnerabilities:{_SCHEMA_VERSION}",
    "assessments": f"{_NAMESPACE_BASE}:assessments:{_SCHEMA_VERSION}",
    "manifest": f"{_NAMESPACE_BASE}:manifest:{_SCHEMA_VERSION}",
}

_ILLEGAL_XML_CHARS = re.compile(
    "[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x84\x86-\x9f]"
)


def _dict_to_element(tag: str, data: Any) -> Element:
    """Recursively convert a Python value to an XML :class:`Element` tree."""
    # Sanitise tag: XML names cannot start with a digit or contain spaces.
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
