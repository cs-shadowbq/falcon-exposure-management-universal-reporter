"""CrowdStrike Falcon Configuration Assessment (Secure Configuration Assessment) APIs.

Requires API scope: ``configuration-assessment:read``

The combined assessments endpoint returns ``HostFinding`` entities — one record
per host per rule finding.  Use the ``facet`` parameter to enrich results with
host details, rule metadata, and evaluation logic.

Fetch strategies
----------------
Three iterators are available with different concurrency trade-offs:

:func:`iter_assessments`
    **Serial** — a single ``query_combined_assessments`` cursor chain.
    Use for small datasets or when you need deterministic ordering.

:func:`iter_assessments_by_severity`
    **Default parallel** — six concurrent cursor chains, one per
    ``finding.rule.severity`` level (CRITICAL / HIGH / MEDIUM / LOW /
    INFORMATIONAL + catch-all).  Provides good load balance because
    CIS/STIG benchmarks distribute findings across all levels.  This is
    the strategy used by the CLI unless ``--assessment-large-env`` is set.

:func:`iter_assessments_cross_flat`
    **Large-environment parallel** — up to 30 concurrent cursor chains
    formed by crossing every ``finding.status`` value with every
    ``finding.rule.severity`` level.  Use when a single severity bucket
    still contains millions of records.  Enabled by ``--assessment-large-env``.

.. note::
    Unlike the Spotlight API, ``ConfigurationAssessment`` exposes only a
    combined endpoint — there is no separate IDs-only query.  A two-phase
    strategy (collect IDs then batch-fetch details in parallel) is therefore
    not possible.  Bucket parallelism is the only available mechanism.

Supported facet values
----------------------
- ``host`` — hostname, platform, IP, groups, tags
- ``finding.rule`` — rule ID, name, benchmark, severity
- ``finding.evaluation_logic`` — the logic used to evaluate the rule

FQL filter examples
-------------------
Filter by agent ID::

    aid:'8e7656b27d8c49a34a1af416424d6231'

Filter by host group ID::

    host.groups:['03f0b54af2692e99c4cec945818fbef7']

Filter by host tag::

    host.tags:['FalconTag/Production']

Filter by platform::

    host.platform_name:'Windows'

Filter by finding status::

    finding.status:'fail'

Filter by benchmark::

    finding.rule.benchmark_name:'CIS'

Combine with :func:`~femur.build_fql`::

    from femur import build_fql
    fql = build_fql(
        "host.platform_name:'Windows'",
        "finding.status:'fail'",
    )
"""

import concurrent.futures
import threading
from itertools import product
from typing import Callable, Iterator, List, Optional

from falconpy import ConfigurationAssessment, ConfigurationAssessmentEvaluationLogic

from ._pagination import _batch_ids, _check_response, _paginate_after

SUPPORTED_FACETS: List[str] = ["host", "finding.rule", "finding.evaluation_logic"]
"""Valid values for the ``facet`` parameter of :func:`iter_assessments`."""

# NOTE: ``finding.rule`` MUST always be included.  Without it the API
# returns only the bare rule ID — no name, severity, benchmark, authority
# or compliance mappings — making assessment records uninterpretable for
# end users.  The CLI always appends this facet automatically.
ASSESSMENT_BASE_FACETS: List[str] = ["finding.rule"]
"""Facets that are always requested for every assessment fetch.

``finding.rule`` cannot be omitted: without it each finding carries only
a raw rule ID and the data has no human-readable context (no name,
severity, benchmark, or compliance mappings).
"""

DEFAULT_ASSESSMENT_FILTER = "created_timestamp:>='2000-01-01T00:00:00Z'"
"""Default FQL filter applied when no ``fql_filter`` is provided.

The Configuration Assessment API requires a filter on every call; this
default returns all findings regardless of status or platform.
"""

# Severity levels used to build per-bucket FQL filters for
# iter_assessments_by_severity.
_RULE_SEVERITY_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]

# Catch-all bucket: any record whose finding.rule.severity is not one of the
# named levels.
_RULE_SEVERITY_CATCHALL_FILTER = (
    "finding.rule.severity:!['CRITICAL','HIGH','MEDIUM','LOW','INFORMATIONAL']"
)

# Status levels used by iter_assessments_cross_flat.
_STATUS_LEVELS = ["fail", "pass", "manual", "unsupported"]
_STATUS_CATCHALL_FILTER = "finding.status:!['fail','pass','manual','unsupported']"


def iter_assessments(
    credentials: dict,
    fql_filter: Optional[str] = None,
    sort: Optional[str] = None,
    facet: Optional[List[str]] = None,
    page_size: int = 5000,
    on_page: Optional[Callable[[int, Optional[int]], None]] = None,
) -> Iterator[dict]:
    """Iterate over all secure configuration assessment findings.

    **Serial strategy** — a single ``query_combined_assessments`` cursor chain
    that pages sequentially through all results.  Records are yielded in
    API-returned order and pagination is fully controllable (early exit is
    safe).

    Use this when you need deterministic ordering or are working with a small,
    filtered dataset.  For large environments, prefer the parallel alternatives:
    :func:`iter_assessments_by_severity` (6 threads, default) or
    :func:`iter_assessments_cross_flat` (up to 30 threads, large-env).

    Args:
        credentials: Dict with ``client_id``, ``client_secret``, ``base_url``.
        fql_filter: FQL expression. See module docstring for examples. When
            omitted all findings are returned.
        sort: Sort expression, e.g. ``"created_timestamp|desc"``.
        facet: List of detail blocks to include. See :data:`SUPPORTED_FACETS`.
            Example: ``["host", "finding.rule"]``.
        page_size: Records per API page (max 5000).
        on_page: Optional callback invoked after each page with
            ``(records_on_page, api_total_or_None)``.

    Yields:
        HostFinding resource dicts.

    Raises:
        :class:`~femur.FalconAPIError`: On API errors.
    """
    falcon = ConfigurationAssessment(**credentials)
    effective_filter = fql_filter if fql_filter is not None else DEFAULT_ASSESSMENT_FILTER
    kwargs: dict = {"filter": effective_filter}
    if sort:
        kwargs["sort"] = sort
    if facet:
        kwargs["facet"] = facet
    yield from _paginate_after(
        falcon.query_combined_assessments,
        min(page_size, 5000),
        "query_combined_assessments",
        on_page=on_page,
        **kwargs,
    )


def get_all_assessments(
    credentials: dict,
    fql_filter: Optional[str] = None,
    sort: Optional[str] = None,
    facet: Optional[List[str]] = None,
    page_size: int = 5000,
) -> List[dict]:
    """Return all configuration assessment findings as a list.

    Args:
        credentials: Dict with ``client_id``, ``client_secret``, ``base_url``.
        fql_filter: FQL expression.
        sort: Sort expression.
        facet: Detail blocks to include. See :data:`SUPPORTED_FACETS`.
        page_size: Records per API page (max 5000).

    Returns:
        List of HostFinding resource dicts.

    Raises:
        :class:`~femur.FalconAPIError`: On API errors.
    """
    return list(
        iter_assessments(
            credentials,
            fql_filter=fql_filter,
            sort=sort,
            facet=facet,
            page_size=page_size,
        )
    )


def iter_assessments_by_severity(
    credentials: dict,
    fql_filter: Optional[str] = None,
    facet: Optional[List[str]] = None,
    page_size: int = 5000,
    on_page: Optional[Callable[[int, Optional[int]], None]] = None,
) -> Iterator[dict]:
    """Fetch all assessments in parallel using finding.rule.severity bucketing.

    **Default parallel strategy** — runs six independent
    ``query_combined_assessments`` cursor chains concurrently, one per
    ``finding.rule.severity`` level:

    +--------------+------------------------------------------------------+
    | Bucket       | FQL clause appended                                  |
    +==============+======================================================+
    | CRITICAL     | ``finding.rule.severity:'CRITICAL'``                 |
    | HIGH         | ``finding.rule.severity:'HIGH'``                     |
    | MEDIUM       | ``finding.rule.severity:'MEDIUM'``                   |
    | LOW          | ``finding.rule.severity:'LOW'``                      |
    | INFORMATIONAL| ``finding.rule.severity:'INFORMATIONAL'``             |
    | OTHER        | negated catch-all for any remaining values            |
    +--------------+------------------------------------------------------+

    Each chain advances its own independent cursor, so all buckets page
    simultaneously.  The severity axis was chosen because CIS and STIG
    benchmarks distribute findings reasonably evenly across levels, avoiding
    heavy skew in any single thread.

    .. note::
        ``ConfigurationAssessment`` exposes only a combined endpoint — there
        is no separate IDs-only query, so a two-phase parallel approach
        (as used for Spotlight vulnerabilities) is not possible.  Bucket
        parallelism is the mechanism available.

    .. note::
        Include ``"finding.rule"`` in *facet* (or use :data:`ASSESSMENT_BASE_FACETS`)
        so that rule metadata — name, severity, benchmark — is populated in
        the response.  Without it the API returns only a bare rule ID.

    When one severity level dominates (e.g. millions of MEDIUM findings in a
    large CIS environment), consider :func:`iter_assessments_cross_flat` which
    further splits by ``finding.status``, capping the largest chain at
    ``max_status_fraction × max_severity_fraction`` of the total.

    Args:
        credentials: Dict with ``client_id``, ``client_secret``, ``base_url``.
        fql_filter: Base FQL expression.  Each bucket appends its severity
            clause with ``+``, e.g.
            ``"finding.status:'fail'+finding.rule.severity:'HIGH'``".
            When omitted the severity clause alone forms the complete filter.
        facet: Detail blocks to include.  See :data:`SUPPORTED_FACETS`.
        page_size: Records per API page per bucket (max 5 000).
        on_page: Optional progress callback invoked from worker threads with
            ``(records_on_page, grand_total_or_None)``.
            *grand_total* is the sum of each bucket's API-reported total;
            it stabilises once all six first pages have been received.

    Yields:
        HostFinding resource dicts.  Ordering reflects bucket completion,
        not the original API sort order.

    Raises:
        :class:`~femur.FalconAPIError`: On API errors.
    """
    capped_page = min(page_size, 5000)
    lock = threading.Lock()
    bucket_totals: dict = {}
    num_buckets = len(_RULE_SEVERITY_LEVELS) + 1  # 5 named + 1 catch-all

    if fql_filter:
        bucket_filters: List = [
            (sev, f"{fql_filter}+finding.rule.severity:'{sev}'")
            for sev in _RULE_SEVERITY_LEVELS
        ]
        bucket_filters.append(("OTHER", f"{fql_filter}+{_RULE_SEVERITY_CATCHALL_FILTER}"))
    else:
        bucket_filters = [
            (sev, f"finding.rule.severity:'{sev}'")
            for sev in _RULE_SEVERITY_LEVELS
        ]
        bucket_filters.append(("OTHER", _RULE_SEVERITY_CATCHALL_FILTER))

    def _fetch_bucket(bucket_name: str, bucket_fql: str) -> List[dict]:
        falcon = ConfigurationAssessment(**credentials)
        kwargs: dict = {"filter": bucket_fql}
        if facet:
            kwargs["facet"] = facet
        records: List[dict] = []

        def _on_bucket_page(n: int, api_total: Optional[int]) -> None:
            if on_page is None:
                return
            with lock:
                if api_total is not None:
                    bucket_totals.setdefault(bucket_name, api_total)
                known = sum(bucket_totals.values())
                grand = known if len(bucket_totals) == num_buckets else None
            on_page(n, grand)

        for record in _paginate_after(
            falcon.query_combined_assessments,
            capped_page,
            "query_combined_assessments",
            on_page=_on_bucket_page,
            **kwargs,
        ):
            records.append(record)
        return records

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_buckets) as pool:
        futs = [
            pool.submit(_fetch_bucket, name, fql)
            for name, fql in bucket_filters
        ]
        for fut in concurrent.futures.as_completed(futs):
            yield from fut.result()


def iter_assessments_cross_flat(
    credentials: dict,
    fql_filter: Optional[str] = None,
    facet: Optional[List[str]] = None,
    page_size: int = 5000,
    on_page: Optional[Callable[[int, Optional[int]], None]] = None,
    max_workers: int = 30,
) -> Iterator[dict]:
    """Fetch assessments using status × severity cross-product bucketing.

    **Large-environment parallel strategy** — creates up to 30 independent
    ``query_combined_assessments`` cursor chains by crossing every known
    ``finding.status`` value with every ``finding.rule.severity`` level:

    - Status buckets (5): ``fail``, ``pass``, ``manual``, ``unsupported``,
      plus a catch-all for any other values.
    - Severity buckets (6): ``CRITICAL``, ``HIGH``, ``MEDIUM``, ``LOW``,
      ``INFORMATIONAL``, plus a catch-all.
    - Total chains: 5 × 6 = **30**.

    All chains are submitted simultaneously to a flat ``ThreadPoolExecutor``.
    Empty buckets cost only one API call each (immediate empty response).

    **When to use this instead of** :func:`iter_assessments_by_severity`:
    In large environments the dominant severity level (typically MEDIUM in
    CIS deployments) can still hold millions of records.  Crossing with status
    caps the largest single chain at approximately
    ``max_status_fraction × max_severity_fraction`` of the total — roughly
    2–3× smaller than the equivalent single-dimension severity bucket.

    **Concurrency warning**: 30 simultaneous HTTP connections may approach
    API rate limits in environments with strict quotas.  Use *max_workers* to
    throttle if needed; the built-in retry backoff handles transient 429s.

    Args:
        credentials: Dict with ``client_id``, ``client_secret``, ``base_url``.
        fql_filter: Base FQL expression.  Each bucket appends both a status
            clause and a severity clause with ``+``.
        facet: Detail blocks to include.  See :data:`SUPPORTED_FACETS`.
        page_size: Records per API page per bucket (max 5 000).
        on_page: Optional progress callback invoked from worker threads with
            ``(records_on_page, grand_total_or_None)``.
            *grand_total* stabilises once all 30 buckets have completed their
            first page — later than for :func:`iter_assessments_by_severity`.
        max_workers: Thread pool size (default: 30, one per bucket).
            Reduce to limit concurrent API connections.

    Yields:
        HostFinding resource dicts.  Ordering reflects bucket completion,
        not the original API sort order.

    Raises:
        :class:`~femur.FalconAPIError`: On API errors.
    """
    capped_page = min(page_size, 5000)
    lock = threading.Lock()
    bucket_totals: dict = {}

    status_filters: List = [
        (s, f"finding.status:'{s}'") for s in _STATUS_LEVELS
    ] + [("OTHER_STATUS", _STATUS_CATCHALL_FILTER)]

    severity_filters: List = [
        (v, f"finding.rule.severity:'{v}'") for v in _RULE_SEVERITY_LEVELS
    ] + [("OTHER_SEV", _RULE_SEVERITY_CATCHALL_FILTER)]

    buckets: List = []
    for (sname, sfql), (vname, vfql) in product(status_filters, severity_filters):
        name = f"{sname}+{vname}"
        fql = f"{fql_filter}+{sfql}+{vfql}" if fql_filter else f"{sfql}+{vfql}"
        buckets.append((name, fql))

    num_buckets = len(buckets)

    def _fetch_bucket(bucket_name: str, bucket_fql: str) -> List[dict]:
        falcon = ConfigurationAssessment(**credentials)
        kwargs: dict = {"filter": bucket_fql}
        if facet:
            kwargs["facet"] = facet
        records: List[dict] = []

        def _on_bucket_page(n: int, api_total: Optional[int]) -> None:
            if on_page is None:
                return
            with lock:
                if api_total is not None:
                    bucket_totals.setdefault(bucket_name, api_total)
                known = sum(bucket_totals.values())
                grand = known if len(bucket_totals) == num_buckets else None
            on_page(n, grand)

        for record in _paginate_after(
            falcon.query_combined_assessments,
            capped_page,
            "query_combined_assessments",
            on_page=_on_bucket_page,
            **kwargs,
        ):
            records.append(record)
        return records

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futs = [
            pool.submit(_fetch_bucket, name, fql)
            for name, fql in buckets
        ]
        for fut in concurrent.futures.as_completed(futs):
            yield from fut.result()


def get_rule_details(
    credentials: dict,
    ids: List[str],
) -> List[dict]:
    """Fetch rule detail records for a list of rule IDs.

    Automatically batches ``ids`` into groups of 400 (API maximum).

    Args:
        credentials: Dict with ``client_id``, ``client_secret``, ``base_url``.
        ids: Rule IDs to look up.  Found in assessment records under
            ``finding.rule.id`` when the ``finding.rule`` facet is requested.

    Returns:
        List of rule detail dicts.

    Raises:
        :class:`~femur.FalconAPIError`: On API errors.
    """
    falcon = ConfigurationAssessment(**credentials)
    results: List[dict] = []
    for batch in _batch_ids(ids, 400):
        response = falcon.get_rule_details(ids=batch)
        results.extend(_check_response(response, "get_rule_details"))
    return results


def get_evaluation_logic(
    credentials: dict,
    ids: List[str],
) -> List[dict]:
    """Fetch evaluation logic records for a list of finding IDs.

    Automatically batches ``ids`` into groups of 400 (API maximum).

    Args:
        credentials: Dict with ``client_id``, ``client_secret``, ``base_url``.
        ids: Evaluation logic finding IDs.  Found in assessment records under
            ``finding.evaluation_logic.id`` when that facet is requested.

    Returns:
        List of evaluation logic dicts.

    Raises:
        :class:`~femur.FalconAPIError`: On API errors.
    """
    falcon = ConfigurationAssessmentEvaluationLogic(**credentials)
    results: List[dict] = []
    for batch in _batch_ids(ids, 400):
        response = falcon.get_evaluation_logic(ids=batch)
        results.extend(_check_response(response, "get_evaluation_logic"))
    return results
