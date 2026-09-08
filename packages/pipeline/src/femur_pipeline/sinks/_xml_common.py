"""Shared XML serialization helpers for output sinks.

Both :mod:`~femur_pipeline.sinks.xml_sink` and
:mod:`~femur_pipeline.sinks.aid_bucketed` emit the same XML dialect, and each
previously carried its own copy of these helpers.  The copies had already
drifted — only one of them knew about the per-AID and aggregate manifest
namespaces — so they live here instead.
"""

import re
from functools import lru_cache
from typing import Any, Dict, Tuple

# Control characters that are not legal in XML 1.0 character data.
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

_XML_PROLOGUE = b'<?xml version="1.0" encoding="UTF-8"?>\n'


def dict_to_element(tag: str, data: Any) -> "Any":
    """Recursively convert a Python value to an XML Element tree.

    The returned element is *detached* and carries no namespace.  Appending it
    to a namespaced root makes lxml stamp an ``xmlns`` attribute on it, so
    callers that frame documents themselves must serialize it as-is.
    """
    from lxml.etree import Element

    safe_tag = tag.replace(" ", "_")
    if safe_tag and safe_tag[0].isdigit():
        safe_tag = "_" + safe_tag

    el = Element(safe_tag)
    if isinstance(data, dict):
        for key, val in data.items():
            el.append(dict_to_element(str(key), val))
    elif isinstance(data, (list, tuple)):
        for item in data:
            el.append(dict_to_element("item", item))
    elif isinstance(data, bool):
        el.text = "true" if data else "false"
    elif data is not None:
        el.text = _ILLEGAL_XML_CHARS.sub("", str(data))
    return el


@lru_cache(maxsize=None)
def xml_frame(dataset_name: str) -> Tuple[bytes, bytes]:
    """Return ``(prologue + open_root, close_root)`` byte fragments.

    Used by sinks that cannot hold a file handle open for the life of a
    document and so must append to it in separate writes.  The fragments are
    derived from lxml itself — a root element containing a sentinel child is
    serialized and split on the sentinel — so namespace serialization stays
    lxml's responsibility and the result is byte-identical to what lxml's
    incremental ``xmlfile`` writer produces.
    """
    from lxml.etree import Element, QName, tostring

    ns = _DATASET_NAMESPACES.get(dataset_name)
    root = Element(
        QName(ns, dataset_name) if ns else dataset_name,
        nsmap={None: ns} if ns else None,
    )
    root.append(Element("SPLIT"))
    open_tag, close_tag = tostring(root).split(b"<SPLIT/>")
    return _XML_PROLOGUE + open_tag, close_tag
