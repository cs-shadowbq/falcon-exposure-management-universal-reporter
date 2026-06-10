"""falcon-application-inventory-pipeline — streaming data pipeline and output sinks.

This package provides the :class:`DataSink` abstraction, record transforms,
and concrete sink implementations (JSONL, XML, legacy JSON) for bounded-memory
output of CrowdStrike Falcon Exposure Management Universal Reporter data.

Typical usage::

    from femur_pipeline import (
        DataSink,
        RecordTransform,
        ChainedTransform,
        stream_dataset,
        create_sink,
    )

    with create_sink("jsonl", "/tmp/output") as sink:
        count = stream_dataset(data_iter, sink, "applications")
"""

from .pipeline import ChainedTransform, DataSink, RecordTransform, stream_dataset
from .sinks import create_sink
from .transforms import (
    AidDecoratorTransform,
    ComplianceMappingStripTransform,
    CpeDecoratorTransform,
    IavmDecoratorTransform,
    FieldFilterTransform,
)

__all__ = [
    # Pipeline core
    "DataSink",
    "RecordTransform",
    "ChainedTransform",
    "stream_dataset",
    # Sink factory
    "create_sink",
    # Transforms
    "AidDecoratorTransform",
    "ComplianceMappingStripTransform",
    "CpeDecoratorTransform",
    "IavmDecoratorTransform",
    "FieldFilterTransform",
]
