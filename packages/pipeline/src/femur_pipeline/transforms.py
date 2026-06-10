"""Streaming record transforms for the data pipeline.

Each transform is a callable with signature::

    (record: dict, dataset_name: str) -> Optional[dict]

Returning ``None`` drops the record from the output.
Transforms are dataset-aware: they check *dataset_name* and pass through
records from datasets they don't apply to.
"""

from typing import Dict, List, Optional, Set

from .cpe import generate_cpe_for_record


class AidDecoratorTransform:
    """Inject ``aid`` into application records using a pre-built host map.

    The host map is ``{discover_host_id: {"cid": ..., "aid": ...}}``,
    exactly as returned by :func:`~femur.build_host_map`.
    """

    def __init__(self, host_map: Dict[str, Dict[str, str]]) -> None:
        self._host_map = host_map

    def __call__(self, record: dict, dataset_name: str) -> Optional[dict]:
        if dataset_name != "applications":
            return record
        host = record.get("host")
        if isinstance(host, dict):
            host_id = host.get("id")
            if host_id:
                entry = self._host_map.get(host_id)
                if entry:
                    record["aid"] = entry.get("aid")
        return record


class ComplianceMappingStripTransform:
    """Remove ``compliance_mappings`` from assessment finding rules."""

    def __call__(self, record: dict, dataset_name: str) -> Optional[dict]:
        if dataset_name != "assessments":
            return record
        rule = record.get("finding", {}).get("rule")
        if isinstance(rule, dict):
            rule.pop("compliance_mappings", None)
        return record


class CpeDecoratorTransform:
    """Generate and attach CPE 2.3 URIs to application records.

    Decorates each application record with ``cpe`` and ``cpe_match_type``
    fields derived from the record's ``vendor``, ``name``, and ``version``.

    Parameters
    ----------
    normalize : bool
        When ``True`` , applies vendor/product alias resolution,
        suffix stripping, and vendor override corrections for higher-quality
        CPE strings.  When ``False``(default), uses raw values lowercased.
    """

    def __init__(self, normalize: bool = False) -> None:
        self._normalize = normalize

    def __call__(self, record: dict, dataset_name: str) -> Optional[dict]:
        if dataset_name != "applications":
            return record
        result = generate_cpe_for_record(record, normalize=self._normalize)
        if result is not None:
            record["cpe"] = result["cpe"]
            record["cpe_match_type"] = result["cpe_match_type"]
        return record


class IavmDecoratorTransform:
    """Decorate vulnerability and assessment records with IAVM notice metadata.

    Looks up the CVE ID from each record against a pre-parsed IAVM index
    and attaches matching notice metadata as ``iavm_notices``.

    Parameters
    ----------
    iavm_index : dict
        CVE -> notices lookup as returned by
        :func:`~femur_pipeline.iavm.parse_iavm_xml`.
    """

    def __init__(self, iavm_index: Dict[str, List[Dict[str, str]]]) -> None:
        self._index = iavm_index

    def __call__(self, record: dict, dataset_name: str) -> Optional[dict]:
        if dataset_name == "vulnerabilities":
            cve_id = record.get("vulnerability_id") or ""
            if not cve_id:
                cve = record.get("cve")
                if isinstance(cve, dict):
                    cve_id = cve.get("id", "")
            notices = self._index.get(cve_id)
            if notices:
                record["iavm_notices"] = notices
        elif dataset_name == "assessments":
            rule = record.get("finding", {}).get("rule", {})
            cve_ids = rule.get("cve_ids", [])
            if isinstance(cve_ids, list):
                all_notices: List[Dict[str, str]] = []
                for cve_id in cve_ids:
                    notices = self._index.get(cve_id)
                    if notices:
                        all_notices.extend(notices)
                if all_notices:
                    record["iavm_notices"] = all_notices
        return record


class FieldFilterTransform:
    """Keep or discard specific top-level fields.

    Parameters
    ----------
    include : set of str, optional
        If given, only these fields are kept.
    exclude : set of str, optional
        If given, these fields are removed.  Ignored when *include* is set.
    dataset : str, optional
        Apply only to this dataset; pass through others unchanged.
    """

    def __init__(
        self,
        include: Optional[Set[str]] = None,
        exclude: Optional[Set[str]] = None,
        dataset: Optional[str] = None,
    ) -> None:
        self._include = include
        self._exclude = exclude or set()
        self._dataset = dataset

    def __call__(self, record: dict, dataset_name: str) -> Optional[dict]:
        if self._dataset and dataset_name != self._dataset:
            return record
        if self._include is not None:
            return {k: v for k, v in record.items() if k in self._include}
        if self._exclude:
            return {k: v for k, v in record.items() if k not in self._exclude}
        return record
