"""Output sink implementations for the data pipeline.

Available sinks
---------------
- :class:`~.jsonlines.JsonLinesSink` — JSON Lines (``.jsonl``) with optional
  ``orjson`` acceleration.
- :class:`~.xml_sink.XmlSink` — Streaming XML via ``lxml.etree.xmlfile``.
- :class:`~.legacy_json.LegacyJsonSink` — Single-file monolithic JSON
  (backward-compatible with the original ``femur`` output).
- :class:`~.composite.CompositeSink` — Fan-out to multiple sinks at once.
- :class:`~.aid_bucketed.AidBucketedSink` — Route records to per-AID
  subdirectory sinks for per-host file discovery.

Post-write zip compression is provided by :mod:`~.compression`.

The :func:`create_sink` factory resolves a format name to the right class.
"""

from typing import Any

from ..pipeline import DataSink


_SINK_REGISTRY = {
    "jsonl": "femur_pipeline.sinks.jsonlines:JsonLinesSink",
    "xml": "femur_pipeline.sinks.xml_sink:XmlSink",
    "json": "femur_pipeline.sinks.legacy_json:LegacyJsonSink",
}


def create_sink(format: str, output_path: str, **kwargs: Any) -> DataSink:
    """Instantiate a :class:`DataSink` by *format* name.

    Parameters
    ----------
    format : str
        One of ``"jsonl"``, ``"xml"``, ``"json"``.
    output_path : str
        File or directory path passed to the sink constructor.
    **kwargs :
        Extra arguments forwarded to the sink (``record_tag``,
        ``indent``, etc.).
    """
    entry = _SINK_REGISTRY.get(format)
    if entry is None:
        available = ", ".join(sorted(_SINK_REGISTRY))
        raise ValueError(
            f"Unknown output format {format!r}. Available: {available}"
        )
    module_path, cls_name = entry.rsplit(":", 1)
    import importlib
    mod = importlib.import_module(module_path)
    cls = getattr(mod, cls_name)
    return cls(output_path, **kwargs)
