"""femur — CrowdStrike Falcon higher-level API library.

This is the **core** package providing API wrappers for CrowdStrike Falcon
Discover, Spotlight, Configuration Assessment, and Host Group services.

For the streaming data pipeline and output sinks, install
``femur-pipeline``.

For the CLI tool, install ``femur-cli``.

For the REST API server, install ``femur-server``.
"""

from ._auth import load_credentials
from ._exceptions import FalconAPIError
from ._pagination import build_fql
from .configuration import (
    get_all_assessments,
    get_evaluation_logic,
    get_rule_details,
    iter_assessments,
    iter_assessments_by_severity,
    iter_assessments_cross_flat,
)
from .discover import (
    build_host_map,
    decorate_applications_with_aid,
    get_all_applications,
    get_all_hosts,
    iter_applications,
    iter_applications_mac_buckets,
    iter_applications_parallel_offset,
    iter_hosts,
)
from .host_groups import (
    get_all_group_members,
    get_all_host_groups,
    get_host_group_ids,
    iter_group_members,
    iter_host_groups,
)
from ._post_process import (
    assemble_inventory_payload,
    collect_fetch_errors,
    strip_compliance_mappings,
)
from .spotlight import (
    get_all_vulnerabilities,
    get_remediations,
    get_vulnerability_details,
    iter_vulnerabilities,
    iter_vulnerabilities_by_severity,
    iter_vulnerabilities_parallel,
)

__all__ = [
    # Auth
    "load_credentials",
    # Exceptions
    "FalconAPIError",
    # Utilities
    "build_fql",
    # Discover
    "iter_hosts",
    "get_all_hosts",
    "build_host_map",
    "decorate_applications_with_aid",
    "iter_applications",
    "iter_applications_parallel_offset",
    "iter_applications_mac_buckets",
    "get_all_applications",
    # Spotlight
    "iter_vulnerabilities",
    "iter_vulnerabilities_by_severity",
    "iter_vulnerabilities_parallel",
    "get_all_vulnerabilities",
    "get_vulnerability_details",
    "get_remediations",
    # Configuration Assessment
    "iter_assessments",
    "iter_assessments_by_severity",
    "iter_assessments_cross_flat",
    "get_all_assessments",
    "get_rule_details",
    "get_evaluation_logic",
    # Host Groups
    "iter_host_groups",
    "get_all_host_groups",
    "iter_group_members",
    "get_all_group_members",
    "get_host_group_ids",
    # Post-processing
    "strip_compliance_mappings",
    "collect_fetch_errors",
    "assemble_inventory_payload",
]
