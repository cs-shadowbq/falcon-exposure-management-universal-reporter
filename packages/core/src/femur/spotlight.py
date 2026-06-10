"""CrowdStrike Falcon Spotlight Vulnerabilities API.

Requires API scope: ``spotlight-vulnerabilities:read``

A filter is **required** by the Spotlight API. When no ``fql_filter`` is
supplied, the library defaults to ``status:['open','reopen']``.

FQL filter examples
-------------------
Filter by status::

    status:['open','reopen']
    status:!'closed'

Filter by CVE severity (values must be ALL CAPS)::

    cve.severity:'CRITICAL'
    cve.severity:['HIGH','CRITICAL']

Filter by host group ID (obtain IDs via :func:`~femur.get_host_group_ids`)::

    host_info.groups:['03f0b54af2692e99c4cec945818fbef7']

Filter by host tag::

    host_info.tags:['ephemeral']
    host_info.tags:!['search','ephemeral']

Filter for actively exploited CVEs (CISA KEV)::

    cve.is_cisa_kev:true+status:['open','reopen']

Filter by ExPRT rating::

    cve.exprt_rating:['HIGH','CRITICAL']+status:['open','reopen']

Filter by exploit status (0=unproven, 30=available, 60=easy, 90=active)::

    cve.exploit_status:!'0'+status:['open','reopen']

Filter by platform::

    host_info.platform_name:'Windows'+status:['open','reopen']

Filter by product type::

    host_info.product_type_desc:'Server'+status:['open','reopen']

Combine with :func:`~femur.build_fql`::

    from femur import build_fql
    fql = build_fql(
        "status:['open','reopen']",
        "cve.severity:'CRITICAL'",
        "host_info.platform_name:'Linux'",
    )
"""

import concurrent.futures
import threading
from typing import Callable, Iterator, List, Optional

from falconpy import SpotlightVulnerabilities

from ._pagination import _batch_ids, _check_response, _paginate_after, _retrying_call

DEFAULT_VULN_FILTER = "status:['open','reopen']"
"""Default FQL filter applied when no ``fql_filter`` is provided.

The Spotlight API requires a filter on every call; this default returns all
open and reopened vulnerabilities.
"""

# Severity levels used to build per-bucket FQL filters for
# iter_vulnerabilities_by_severity.
_SEVERITY_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

# Catch-all bucket: any record whose cve.severity is not one of the four
# named levels (e.g. NONE, UNKNOWN, or absent).
_SEVERITY_CATCHALL_FILTER = "cve.severity:!['CRITICAL','HIGH','MEDIUM','LOW']"


def iter_vulnerabilities(
    credentials: dict,
    fql_filter: Optional[str] = None,
    sort: Optional[str] = None,
    facet: Optional[str] = None,
    page_size: int = 400,
    on_page: Optional[Callable[[int, Optional[int]], None]] = None,
) -> Iterator[dict]:
    """Iterate over all vulnerabilities matching an FQL filter.

    Uses scrollable ``after``-token pagination. The Spotlight API requires a
    filter string; when ``fql_filter`` is omitted :data:`DEFAULT_VULN_FILTER`
    (``status:['open','reopen']``) is used automatically.

    Args:
        credentials: Dict with ``client_id``, ``client_secret``, ``base_url``.
        fql_filter: FQL expression. See module docstring for examples. Defaults
            to :data:`DEFAULT_VULN_FILTER` when ``None``.
        sort: Sort expression, e.g. ``"created_timestamp|desc"``.
        facet: Extra detail blocks. Supported values: ``host_info``,
            ``remediation``, ``cve``, ``evaluation_logic``.
        page_size: Records per API page (max 5000).

    Yields:
        Vulnerability resource dicts.

    Raises:
        :class:`~femur.FalconAPIError`: On API errors.
    """
    falcon = SpotlightVulnerabilities(**credentials)
    effective_filter = fql_filter if fql_filter is not None else DEFAULT_VULN_FILTER
    kwargs: dict = {"filter": effective_filter}
    if sort:
        kwargs["sort"] = sort
    if facet:
        kwargs["facet"] = facet
    yield from _paginate_after(
        falcon.query_vulnerabilities_combined,
        min(page_size, 5000),
        "query_vulnerabilities_combined",
        on_page=on_page,
        **kwargs,
    )


def get_all_vulnerabilities(
    credentials: dict,
    fql_filter: Optional[str] = None,
    sort: Optional[str] = None,
    facet: Optional[str] = None,
    page_size: int = 400,
) -> List[dict]:
    """Return all vulnerabilities matching an FQL filter as a list.

    Args:
        credentials: Dict with ``client_id``, ``client_secret``, ``base_url``.
        fql_filter: FQL expression. Defaults to :data:`DEFAULT_VULN_FILTER`.
        sort: Sort expression.
        facet: Extra detail blocks.
        page_size: Records per API page (max 5000).

    Returns:
        List of vulnerability resource dicts.

    Raises:
        :class:`~femur.FalconAPIError`: On API errors.
    """
    return list(
        iter_vulnerabilities(
            credentials,
            fql_filter=fql_filter,
            sort=sort,
            facet=facet,
            page_size=page_size,
        )
    )


def iter_vulnerabilities_parallel(
    credentials: dict,
    fql_filter: Optional[str] = None,
    facet: Optional[str] = None,
    workers: int = 8,
    id_page_size: int = 400,
    detail_batch_size: int = 400,
    on_page: Optional[Callable[[int, Optional[int]], None]] = None,
    on_ids_page: Optional[Callable[[int, Optional[int]], None]] = None,
) -> Iterator[dict]:
    """Fetch vulnerabilities using a fast two-phase parallel strategy.

    **Phase 1 — ID collection (sequential, fast):** Pages through the
    ``query_vulnerabilities`` endpoint which returns only vulnerability IDs
    (no body data). Pages are small so this phase completes much faster than
    fetching full records.

    **Phase 2 — Detail fetch (parallel):** Splits the collected IDs into
    batches of *detail_batch_size* and fetches full records concurrently using
    *workers* threads calling ``get_vulnerabilities``.  Results are yielded as
    batches complete (completion order, not submission order).

    For a typical environment with ~1 M vulnerabilities, ``workers=8`` reduces
    wall-clock time from ~60 minutes (single stream) to ~10–15 minutes.

    Args:
        credentials: Dict with ``client_id``, ``client_secret``, ``base_url``.
        fql_filter: FQL expression.  Defaults to :data:`DEFAULT_VULN_FILTER`.
        facet: Extra detail blocks for the entity fetch.  Supported values:
            ``host_info``, ``remediation``, ``cve``, ``evaluation_logic``.
        workers: Number of concurrent ``get_vulnerabilities`` threads in
            phase 2 (default 8).  Increase cautiously to avoid 429s —
            the built-in retry backoff handles transient rate limits.
        id_page_size: IDs per page in phase 1 (max 400).
        detail_batch_size: IDs per ``get_vulnerabilities`` call in phase 2
            (max 400).
        on_page: Optional callback for phase 2 (record detail fetches). Invoked
            with ``(0, total_ids)`` once phase 1 completes to signal the
            denominator, then with ``(batch_count, total_ids)`` for each
            phase 2 batch. Used for single-row progress.
        on_ids_page: Optional callback invoked after each phase 1 page with
            ``(ids_on_page, api_total)``. Enables a separate progress row for
            the ID-scan phase. When provided, the early phase 1 signal is
            suppressed from *on_page* (which then only fires for phase 2).

    Yields:
        Vulnerability resource dicts.

    Raises:
        :class:`~femur.FalconAPIError`: On API errors.
    """
    falcon = SpotlightVulnerabilities(**credentials)
    effective_filter = fql_filter if fql_filter is not None else DEFAULT_VULN_FILTER
    capped_batch = min(detail_batch_size, 400)
    lock = threading.Lock()
    # Captured from phase 1 so worker threads can pass the denominator to on_page
    # without waiting for the post-loop signal.
    api_total_ref: List[Optional[int]] = [None]

    def _fetch_batch(batch: List[str]) -> List[dict]:
        call_kwargs: dict = {"ids": batch}
        if facet:
            call_kwargs["facet"] = facet
        response = _retrying_call(
            falcon.get_vulnerabilities, call_kwargs, "get_vulnerabilities"
        )
        records = _check_response(response, "get_vulnerabilities")
        # Fire on_page from the worker thread as soon as the batch lands so
        # phase-2 progress is visible during phase 1, not only after it ends.
        if on_page is not None:
            with lock:
                on_page(len(records), api_total_ref[0])
        return records

    # ------------------------------------------------------------------
    # Pipelined two-phase fetch:
    #   Phase 1 (main thread, sequential): pages query_vulnerabilities for
    #     IDs only — fast/lightweight, 400 IDs per page.
    #   Phase 2 (thread pool, parallel): each batch of IDs is submitted to
    #     the pool *as it fills*, so workers run concurrently with phase 1.
    # Total wall time ≈ max(phase1, phase2) instead of phase1 + phase2.
    # ------------------------------------------------------------------
    pending: List[str] = []
    futs: List[concurrent.futures.Future] = []
    total_ids = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        # Phase 1 page callback:
        #   Two-row mode (on_ids_page set): fire per-page ID count for scan row.
        #   One-row mode (on_ids_page None): fire on_page(0, total) once on the
        #     first page that returns an api_total, to show denominator early.
        phase1_total_reported = False

        def _on_phase1_page(n: int, api_total: Optional[int]) -> None:
            nonlocal phase1_total_reported
            # Capture api_total so _fetch_batch worker threads can use it as the
            # denominator in their on_page calls.
            if api_total is not None and api_total_ref[0] is None:
                api_total_ref[0] = api_total
            if on_ids_page is not None:
                # Two-row mode: report per-page ID count to the scan row.
                on_ids_page(n, api_total)
            elif not phase1_total_reported and api_total is not None and on_page is not None:
                # One-row mode: signal total known as early as possible.
                with lock:
                    on_page(0, api_total)
                phase1_total_reported = True

        for id_ in _paginate_after(
            falcon.query_vulnerabilities,
            min(id_page_size, 400),
            "query_vulnerabilities",
            on_page=_on_phase1_page,
            filter=effective_filter,
        ):
            pending.append(id_)
            total_ids += 1
            if len(pending) >= capped_batch:
                futs.append(pool.submit(_fetch_batch, pending))
                pending = []

        if pending:
            futs.append(pool.submit(_fetch_batch, pending))

        total = total_ids

        # Signal caller that phase 1 is done and we know the total
        if on_page is not None:
            on_page(0, total)

        if not total:
            return

        for fut in concurrent.futures.as_completed(futs):
            yield from fut.result()  # on_page already fired in _fetch_batch


def iter_vulnerabilities_by_severity(
    credentials: dict,
    fql_filter: Optional[str] = None,
    facet: Optional[str] = None,
    page_size: int = 5000,
    on_page: Optional[Callable[[int, Optional[int]], None]] = None,
) -> Iterator[dict]:
    """Fetch vulnerabilities in parallel using severity-level bucketing.

    Runs five independent ``query_vulnerabilities_combined`` cursor chains
    concurrently — one each for CRITICAL, HIGH, MEDIUM, LOW and a catch-all
    for anything else (e.g. NONE, UNKNOWN).  All chains fetch full entity
    records directly with no two-phase ID scan, using the combined endpoint
    at up to 5 000 records per page.

    The per-bucket severity clause is appended to *fql_filter* with ``+``.
    If the base filter already constrains severity, irrelevant bucket chains
    simply return zero records without error.

    Args:
        credentials: Dict with ``client_id``, ``client_secret``, ``base_url``.
        fql_filter: Base FQL expression.  Defaults to :data:`DEFAULT_VULN_FILTER`.
        facet: Extra detail blocks.  Supported values: ``host_info``,
            ``remediation``, ``cve``, ``evaluation_logic``.
        page_size: Records per API page per bucket (max 5 000).
        on_page: Optional callback invoked after each page across all buckets
            with ``(records_on_page, grand_total_or_None)``.  The grand total
            is the sum of each bucket's API-reported total; it stabilises once
            every bucket has returned its first page.

    Yields:
        Vulnerability resource dicts.  Order is not guaranteed — results
        arrive as bucket chains complete their pages.

    Raises:
        :class:`~femur.FalconAPIError`: On API errors.
    """
    effective_filter = fql_filter if fql_filter is not None else DEFAULT_VULN_FILTER
    capped_page = min(page_size, 5000)
    lock = threading.Lock()

    # Per-bucket totals reported by the API on each chain's first page.
    bucket_totals: dict = {}
    num_buckets = len(_SEVERITY_LEVELS) + 1  # 4 named + 1 catch-all

    # Build (name, FQL) pairs for each bucket.
    bucket_filters: List[Tuple[str, str]] = [
        (level, f"{effective_filter}+cve.severity:'{level}'")
        for level in _SEVERITY_LEVELS
    ]
    bucket_filters.append(
        ("OTHER", f"{effective_filter}+{_SEVERITY_CATCHALL_FILTER}")
    )

    def _fetch_bucket(bucket_name: str, bucket_fql: str) -> List[dict]:
        # Each bucket needs its own SDK client so threads don't share state.
        falcon = SpotlightVulnerabilities(**credentials)
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
            falcon.query_vulnerabilities_combined,
            capped_page,
            "query_vulnerabilities_combined",
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


def get_vulnerability_details(
    credentials: dict,
    ids: List[str],
) -> List[dict]:
    """Fetch full vulnerability detail records for a list of vulnerability IDs.

    Automatically batches ``ids`` into groups of 400 (API maximum).

    Args:
        credentials: Dict with ``client_id``, ``client_secret``, ``base_url``.
        ids: Vulnerability IDs to look up.  Obtain these from
            :func:`iter_vulnerabilities` or the ``id`` field of a combined
            query result.

    Returns:
        List of full vulnerability resource dicts.

    Raises:
        :class:`~femur.FalconAPIError`: On API errors.
    """
    falcon = SpotlightVulnerabilities(**credentials)
    results: List[dict] = []
    for batch in _batch_ids(ids, 400):
        response = falcon.get_vulnerabilities(ids=batch)
        results.extend(_check_response(response, "get_vulnerabilities"))
    return results


def get_remediations(
    credentials: dict,
    ids: List[str],
) -> List[dict]:
    """Fetch remediation records for a list of remediation IDs.

    Automatically batches ``ids`` into groups of 400.

    Args:
        credentials: Dict with ``client_id``, ``client_secret``, ``base_url``.
        ids: Remediation IDs to look up.  Found in vulnerability records under
            ``apps.remediation.ids``.

    Returns:
        List of remediation resource dicts.

    Raises:
        :class:`~femur.FalconAPIError`: On API errors.
    """
    falcon = SpotlightVulnerabilities(**credentials)
    results: List[dict] = []
    for batch in _batch_ids(ids, 400):
        response = falcon.get_remediations_v2(ids=batch)
        results.extend(_check_response(response, "get_remediations_v2"))
    return results
