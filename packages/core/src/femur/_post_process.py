"""Post-processing helpers for inventory data.

These functions operate on collections of records returned by the
fetch layer and prepare them for output (JSON, JSONL, etc.).
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

log = logging.getLogger("femur")


def strip_compliance_mappings(assessments: List[dict]) -> int:
    """Remove ``compliance_mappings`` from assessment finding rules in-place.

    Returns the number of records that were modified.
    """
    stripped = 0
    for rec in assessments:
        rule = rec.get("finding", {}).get("rule")
        if isinstance(rule, dict) and "compliance_mappings" in rule:
            del rule["compliance_mappings"]
            stripped += 1
    return stripped


def collect_fetch_errors(
    results: Dict[str, Any],
    skip_none: bool = True,
) -> List[dict]:
    """Extract error information from a dict of fetch results.

    Parameters
    ----------
    results :
        Mapping of dataset name to result (list/dict on success,
        Exception on failure, None if skipped).
    skip_none :
        If True, treat ``None`` values as "skipped" rather than errors.

    Returns a list of ``{"dataset": ..., "error": ...}`` dicts for results
    that are Exception instances.
    """
    errors: List[dict] = []
    for dataset_name, result in results.items():
        if result is None and skip_none:
            continue
        if isinstance(result, Exception):
            errors.append({"dataset": dataset_name, "error": str(result)})
    return errors


def assemble_inventory_payload(
    applications: List[dict],
    vulnerabilities: List[dict],
    assessments: List[dict],
    host_map: dict,
    errors: Optional[List[dict]] = None,
) -> dict:
    """Build the standard inventory output payload.

    Returns a dict suitable for JSON serialisation with ``generated_at``,
    ``counts``, and the four dataset collections.
    """
    payload: dict = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": {
            "applications": len(applications),
            "vulnerabilities": len(vulnerabilities),
            "assessments": len(assessments),
            "host_map": len(host_map),
        },
        "applications": applications,
        "vulnerabilities": vulnerabilities,
        "assessments": assessments,
        "host_map": host_map,
    }
    if errors:
        payload["errors"] = errors
    return payload
