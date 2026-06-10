"""CrowdStrike Falcon Discover API — hosts and applications.

Requires API scope: ``discover:read``

FQL filter examples
-------------------
Filter by host group (use group *name* in Discover, group *ID* in Spotlight)::

    host.groups:['Workstations']
    host.groups:!['QA Computers']

Filter by sensor / cloud tag::

    host.tags:['FalconTag/Production']
    host.tags:*'Falcon*'

Filter by platform or product type::

    host.platform_name:'Windows'
    host.product_type_desc:'Server'
    host.product_type_desc:['Server','Domain Controller']

Filter by hostname or IP::

    hostname:'web-prod-01'
    host.external_ip:'10.0.0.0/8'

Combine with :func:`~femur.build_fql`::

    from femur import build_fql
    fql = build_fql("host.platform_name:'Windows'", "host.tags:['FalconTag/Prod']")

Application filter fields
-------------------------
Filter by software name, vendor, or version::

    name:'Chrome'
    vendor:'Microsoft'
    version:'10.0.17763.1697'

Filter by category (requires **FalconPy ≥ 1.6.1**)::

    category:'Web Browsers'
    category:'Office productivity'

Filter by normalisation state or suspicion flag::

    is_normalized:true
    is_suspicious:true

Filter by host group or tag (same syntax as host filters)::

    host.groups:['Workstations']
    host.tags:['FalconTag/Production']
"""

import concurrent.futures
import logging
import threading
from typing import Callable, Dict, Iterator, List, Optional, Tuple

from falconpy import Discover

from ._pagination import _check_response, _paginate_after, _retrying_call


def iter_hosts(
    credentials: dict,
    fql_filter: Optional[str] = None,
    sort: Optional[str] = None,
    facet: Optional[str] = None,
    page_size: int = 1000,
) -> Iterator[dict]:
    """Iterate over all discovered hosts matching an optional FQL filter.

    Uses scrollable ``after``-token pagination so callers can stop early
    without fetching all pages.

    Args:
        credentials: Dict with ``client_id``, ``client_secret``, ``base_url``.
            Obtain via :func:`~femur.load_credentials`.
        fql_filter: FQL expression to filter hosts. See module docstring for
            examples. When omitted, all hosts are returned.
        sort: Sort expression, e.g. ``"hostname|asc"`` or
            ``"last_seen_timestamp|desc"``.
        facet: Extra detail block to include. Supported values:
            ``system_insights``, ``third_party``, ``risk_factors``.
        page_size: Records per API page (max 1000).

    Yields:
        Host resource dicts as returned by the Discover API.

    Raises:
        :class:`~femur.FalconAPIError`: On API errors.
    """
    falcon = Discover(**credentials)
    kwargs: dict = {}
    if fql_filter:
        kwargs["filter"] = fql_filter
    if sort:
        kwargs["sort"] = sort
    if facet:
        kwargs["facet"] = facet
    yield from _paginate_after(
        falcon.query_combined_hosts,
        min(page_size, 1000),
        "query_combined_hosts",
        **kwargs,
    )


def get_all_hosts(
    credentials: dict,
    fql_filter: Optional[str] = None,
    sort: Optional[str] = None,
    facet: Optional[str] = None,
    page_size: int = 1000,
) -> List[dict]:
    """Return all discovered hosts matching an optional FQL filter as a list.

    Collects every page from :func:`iter_hosts`.  For environments with 200k+
    hosts this will hold the full dataset in memory; prefer :func:`iter_hosts`
    when streaming into a background job or database.

    Args:
        credentials: Dict with ``client_id``, ``client_secret``, ``base_url``.
        fql_filter: FQL expression to filter hosts.
        sort: Sort expression.
        facet: Extra detail block to include.
        page_size: Records per API page (max 1000).

    Returns:
        List of host resource dicts.

    Raises:
        :class:`~femur.FalconAPIError`: On API errors.
    """
    return list(
        iter_hosts(
            credentials,
            fql_filter=fql_filter,
            sort=sort,
            facet=facet,
            page_size=page_size,
        )
    )


def iter_applications(
    credentials: dict,
    fql_filter: Optional[str] = None,
    sort: Optional[str] = None,
    facet: Optional[str] = None,
    page_size: int = 1000,
    on_page: Optional[Callable[[int, Optional[int]], None]] = None,
) -> Iterator[dict]:
    """Iterate over all discovered applications matching an optional FQL filter.

    Serial baseline using ``query_combined_applications`` with cursor-based
    pagination.  Records are streamed one page at a time in API-returned order.

    For large environments (> 100k applications) consider the parallel strategy
    :func:`iter_applications_parallel_offset` which uses numeric offset
    pagination to scan ID pages concurrently before fetching full records.

    Application FQL filter examples::

        name:'Chrome'
        vendor:'Microsoft Corporation'
        category:'Web Browsers'
        host.tags:['FalconTag/Prod']
        host.groups:['Workstations']
        is_suspicious:true

    Args:
        credentials: Dict with ``client_id``, ``client_secret``, ``base_url``.
        fql_filter: FQL expression. See module docstring and above for examples.
        sort: Sort expression, e.g. ``"name|asc"``.
        facet: Extra detail blocks. Supported values: ``browser_extension``,
            ``host_info``, ``install_usage``, ``package``, ``ide_extension``.
        page_size: Records per API page (max 1000).

    Yields:
        Application resource dicts.

    Raises:
        :class:`~femur.FalconAPIError`: On API errors.
    """
    falcon = Discover(**credentials)
    kwargs: dict = {}
    if fql_filter:
        kwargs["filter"] = fql_filter
    if sort:
        kwargs["sort"] = sort
    if facet:
        kwargs["facet"] = facet
    yield from _paginate_after(
        falcon.query_combined_applications,
        min(page_size, 1000),
        "query_combined_applications",
        on_page=on_page,
        **kwargs,
    )


def get_all_applications(
    credentials: dict,
    fql_filter: Optional[str] = None,
    sort: Optional[str] = None,
    facet: Optional[str] = None,
    page_size: int = 1000,
) -> List[dict]:
    """Return all discovered applications matching an optional FQL filter as a list.

    Args:
        credentials: Dict with ``client_id``, ``client_secret``, ``base_url``.
        fql_filter: FQL expression.
        sort: Sort expression.
        facet: Extra detail blocks to include.
        page_size: Records per API page (max 1000).

    Returns:
        List of application resource dicts.

    Raises:
        :class:`~femur.FalconAPIError`: On API errors.
    """
    return list(
        iter_applications(
            credentials,
            fql_filter=fql_filter,
            sort=sort,
            facet=facet,
            page_size=page_size,
        )
    )


def iter_applications_parallel_offset(
    credentials: dict,
    fql_filter: Optional[str] = None,
    facet: Optional[str] = None,
    id_page_workers: int = 32,
    detail_workers: int = 8,
    page_size: int = 100,
    on_page: Optional[Callable[[int, Optional[int]], None]] = None,
) -> Iterator[dict]:
    """Fetch applications using a fully-parallel two-phase offset strategy.

    Unlike cursor-based pagination (where each page must wait for the previous
    page's token), offset-based pagination allows any page to be fetched
    independently once the total record count is known.  This enables both
    phases of the fetch to run in parallel:

    **Phase 0 — Probe (1 call, main thread):**
        Fetches page 0 of ``query_applications`` to obtain the total count from
        the pagination envelope.  Computes all subsequent page offsets upfront.

    **Phase 1 — Parallel ID scan (``id_page_workers`` threads):**
        All remaining ID pages are submitted to a thread pool simultaneously.
        Because no page depends on any other page's token, workers fetch any
        page independently.  Up to ``id_page_workers`` pages are in-flight
        at once; the rest queue internally in the executor.

    **Phase 2 — Parallel detail fetch (``detail_workers`` threads, pipelined):**
        As ID batches arrive from Phase 1 they are immediately submitted to
        ``get_applications`` workers.  Phase 2 runs concurrently with Phase 1 —
        detail fetches start before the ID scan finishes.

    Both pools share a single ``ThreadPoolExecutor`` sized
    ``id_page_workers + detail_workers``.

    .. note::
        Offset-based pagination is not cursor-stable.  If records are inserted
        or deleted during the scan, a small number of records may appear in
        two pages or be absent.  For a point-in-time snapshot inventory this
        trade-off is acceptable.

    .. note::
        The ``query_applications`` endpoint enforces ``offset + limit ≤ 10 000``.
        When the environment contains more than 10 000 application records the
        parallel offset strategy cannot reach all pages.  In that case this
        function automatically falls back to a sequential
        ``query_combined_applications`` cursor chain (identical to
        :func:`iter_applications`) and logs a ``WARNING``.  The caller receives
        all records with no data loss; only the parallelism benefit is reduced.

    Args:
        credentials: Dict with ``client_id``, ``client_secret``, ``base_url``.
            Obtain via :func:`~femur.load_credentials`.
        fql_filter: FQL expression for application filtering.  See module
            docstring for supported fields.
        facet: Extra detail blocks to include.  Supported values:
            ``browser_extension``, ``host_info``, ``install_usage``,
            ``package``, ``ide_extension``.
        id_page_workers: Maximum concurrent ``query_applications`` threads in
            Phase 1 (default 32).  The API returns only IDs so pages are small
            and fast; higher concurrency is safe up to rate-limit ceiling.
            Ignored when the environment total exceeds the 10 000 offset cap
            and the sequential fallback is used.
        detail_workers: Maximum concurrent ``get_applications`` threads in
            Phase 2 (default 8).  Each call fetches up to 100 full records.
            Ignored when the sequential fallback is active.
        page_size: IDs per ``query_applications`` page (max 100).
        on_page: Optional callback invoked after each ``get_applications`` batch
            with ``(records_in_batch, grand_total_or_None)``.  The grand total
            is derived from the Phase 0 probe and is available after the first
            ``on_page`` call with ``n=0`` (fired once Phase 0 completes).

    Yields:
        Application resource dicts in batch-completion order (not sorted by
        any field — order depends on which detail batches complete first).
        When the sequential fallback is active records are yielded in
        API-returned cursor order.

    Raises:
        :class:`~femur.FalconAPIError`: On API errors.
    """
    _log = logging.getLogger("femur.discover")
    capped = min(page_size, 100)
    # The query_applications endpoint enforces: offset + limit <= 10 000.
    # With limit=capped the maximum valid offset is (10000 - capped).
    _OFFSET_CAP = 10000 - capped  # e.g.: 9900 when capped=100
    lock = threading.Lock()
    pending_ids: List[str] = []
    detail_futs: List[concurrent.futures.Future] = []
    api_total_ref: List[Optional[int]] = [None]

    id_falcon = Discover(**credentials)
    detail_falcon = Discover(**credentials)

    def _fetch_id_page(offset: int) -> Tuple[int, List[str]]:
        call_kwargs: dict = {"limit": capped, "offset": offset}
        if fql_filter:
            call_kwargs["filter"] = fql_filter
        response = _retrying_call(
            id_falcon.query_applications, call_kwargs, "query_applications"
        )
        ids = _check_response(response, "query_applications")
        return offset, ids

    def _fetch_detail_batch(batch: List[str]) -> List[dict]:
        call_kwargs: dict = {"ids": batch}
        if facet:
            call_kwargs["facet"] = facet
        response = _retrying_call(
            detail_falcon.get_applications, call_kwargs, "get_applications"
        )
        records = _check_response(response, "get_applications")
        if on_page is not None:
            with lock:
                on_page(len(records), api_total_ref[0])
        return records

    # Phase 0: probe for total count.
    phase0_kwargs: dict = {"limit": capped}
    if fql_filter:
        phase0_kwargs["filter"] = fql_filter
    phase0_resp = _retrying_call(
        id_falcon.query_applications, phase0_kwargs, "query_applications"
    )
    page0_ids = _check_response(phase0_resp, "query_applications")
    pagination = (
        (phase0_resp.get("body") or {}).get("meta", {}).get("pagination", {})
    )
    total = pagination.get("total")
    api_total_ref[0] = total

    if on_page is not None:
        on_page(0, total)

    if not page0_ids:
        return

    # ------------------------------------------------------------------
    # API offset cap check.
    # query_applications enforces offset + limit <= 10 000.  When the
    # environment has more than 10 000 records the remaining offsets would
    # exceed the cap and produce 400 errors.  Fall back to a sequential
    # cursor chain via query_combined_applications (no offset limit) so
    # all records are returned without data loss.
    #
    # The page-0 IDs already fetched by the probe are discarded (one
    # wasted API call); query_combined_applications restarts from the
    # beginning and returns complete records directly.
    # ------------------------------------------------------------------
    if total is not None and total > _OFFSET_CAP + capped:
        _log.warning(
            "iter_applications_parallel_offset: total %d exceeds the "
            "query_applications offset cap (%d records max). "
            "Falling back to sequential query_combined_applications cursor. "
            "Use a tighter fql_filter to stay within the offset limit for "
            "full parallel benefit.",
            total,
            _OFFSET_CAP + capped,
        )
        cursor_kwargs: dict = {}
        if fql_filter:
            cursor_kwargs["filter"] = fql_filter
        if facet:
            cursor_kwargs["facet"] = facet
        yield from _paginate_after(
            Discover(**credentials).query_combined_applications,
            1000,  # query_combined_applications supports up to 1000 per page
            "query_combined_applications",
            on_page=on_page,
            **cursor_kwargs,
        )
        return

    remaining_offsets = list(range(capped, total, capped)) if total else []

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=id_page_workers + detail_workers
    ) as pool:

        def _submit_details_if_full(ids_to_add: List[str]) -> None:
            nonlocal pending_ids
            pending_ids.extend(ids_to_add)
            while len(pending_ids) >= capped:
                batch = pending_ids[:capped]
                pending_ids = pending_ids[capped:]
                detail_futs.append(pool.submit(_fetch_detail_batch, batch))

        _submit_details_if_full(page0_ids)

        id_page_futs: List[concurrent.futures.Future] = [
            pool.submit(_fetch_id_page, off) for off in remaining_offsets
        ]

        for id_fut in concurrent.futures.as_completed(id_page_futs):
            _, page_ids = id_fut.result()
            _submit_details_if_full(page_ids)

        if pending_ids:
            detail_futs.append(pool.submit(_fetch_detail_batch, pending_ids[:]))
            pending_ids = []

        for detail_fut in concurrent.futures.as_completed(detail_futs):
            yield from detail_fut.result()


_HEX_CHARS = "0123456789ABCDEF"
# All 256 two-char hex first-octet prefixes (uppercase — matching the API format).
_MAC_PREFIXES: List[str] = [a + b for a in _HEX_CHARS for b in _HEX_CHARS]


def iter_applications_mac_buckets(
    credentials: dict,
    fql_filter: Optional[str] = None,
    facet: Optional[str] = None,
    probe_workers: int = 4,
    bucket_workers: int = 16,
    page_size: int = 1000,
    on_page: Optional[Callable[[int, Optional[int]], None]] = None,
    on_probe: Optional[Callable[[int, int], None]] = None,
) -> Iterator[dict]:
    """Fetch applications using MAC-address first-octet bucket parallelism.

    Splits the full application set into independent
    ``query_combined_applications`` cursor chains by filtering on the first
    two hex characters of ``host.current_mac_address`` (e.g. ``00-*``,
    ``7C-*``).  Each chain is cursor-stable and independent, so all chains run
    simultaneously in a thread pool.

    **Strategy overview**

    *Phase 0 — Bucket probe (≈ 15–40 s):*
    All 256 possible two-char hex prefixes (``00``–``FF``) are probed with
    ``limit=1`` queries using ``probe_workers`` threads (default 4) to discover
    non-empty buckets.  A null bucket catches the few records that have no MAC
    address.  Typically only 20–50 prefixes are non-empty in a given
    environment (vendor OUIs are concentrated).

    The low default for ``probe_workers`` deliberately limits the concurrent
    ``query_applications`` burst.  When run alongside ``--assessment-large-env``
    and ``--worker-by-severity`` the API is already handling 30+ concurrent
    assessment and vulnerability chains; firing 64 probe calls simultaneously
    saturates the rate-limit budget and triggers cascading exponential back-off.

    *Phase 1 — Parallel bucket chains:*
    One ``query_combined_applications`` cursor chain per non-empty bucket (plus
    the null bucket) is submitted to a flat ``ThreadPoolExecutor``.  All chains
    stream concurrently; wall-clock time is bounded by the **largest single
    bucket**, not the sum.

    **Performance** (measured against talon1, 333k applications):

    - Serial baseline: ~7:54
    - MAC-bucket parallel (32 buckets, largest = ``00-*`` at ~99k records): ~2:21
    - **Speedup: ~3.4×**

    Bucket distribution is data-dependent.  Virtual environments dominated by
    a single hypervisor vendor (e.g. VMware ``00:0C:29``) will have a larger
    bottleneck bucket and lower effective speedup.

    **Null / no-MAC records** are collected in a separate chain using
    ``host.current_mac_address:!*'*'`` and are always included.

    .. note::
        Cursor-based pagination is used within each bucket so records are
        stable during the scan.  The same record cannot appear in two buckets
        (bucket key is deterministic per host).

    Args:
        credentials: Dict with ``client_id``, ``client_secret``, ``base_url``.
            Obtain via :func:`~femur.load_credentials`.
        fql_filter: Base FQL expression.  Each bucket appends its MAC clause
            with ``+``.
        facet: Extra detail blocks.  Supported values: ``browser_extension``,
            ``host_info``, ``install_usage``, ``package``, ``ide_extension``.
        probe_workers: Thread count for Phase 0 bucket discovery (default 4).
            Each probe is a ``limit=1`` ``query_applications`` request.  Keep
            this low (2–8) when running alongside other parallel operations
            (assessments, vulnerabilities) to avoid saturating the API
            rate-limit budget shared across all concurrent requests.
        bucket_workers: Thread count for Phase 1 bucket chains (default 16).
            The actual number of threads used equals
            ``min(bucket_workers, non_empty_bucket_count)``.
        page_size: Records per ``query_combined_applications`` page (max 1000).
        on_page: Optional callback invoked from worker threads with
            ``(records_on_page, grand_total_or_None)``.  *grand_total*
            stabilises once all bucket totals are known.
        on_probe: Optional callback invoked from the main generator thread
            once per completed probe with ``(probes_done, probes_total)``.
            Useful for reporting Phase 0 progress to a UI.

    Yields:
        Application resource dicts in bucket-completion order.

    Raises:
        :class:`~femur.FalconAPIError`: On API errors.
    """
    _log = logging.getLogger("femur.discover")
    capped = min(page_size, 1000)
    lock = threading.Lock()
    bucket_totals: dict = {}

    # Build base kwargs shared by all chains.
    def _chain_kwargs(mac_fql: str) -> dict:
        combined = f"{fql_filter}+{mac_fql}" if fql_filter else mac_fql
        kw: dict = {"filter": combined}
        if facet:
            kw["facet"] = facet
        return kw

    # -----------------------------------------------------------------------
    # Phase 0: probe all 256 prefixes + null bucket in parallel.
    # One Discover instance is shared across all probe worker threads to avoid
    # 257 independent auth calls (which can trigger token-rotation 401s under
    # concurrent load).
    # -----------------------------------------------------------------------
    probe_falcon = Discover(**credentials)

    def _probe(prefix: str) -> tuple:
        mac_fql = f"host.current_mac_address:*'{prefix}-*'"
        combined = f"{fql_filter}+{mac_fql}" if fql_filter else mac_fql
        resp = _retrying_call(
            probe_falcon.query_applications,
            {"limit": 1, "filter": combined},
            "query_applications",
        )
        _check_response(resp, "query_applications")
        total = (resp.get("body") or {}).get("meta", {}).get("pagination", {}).get("total", 0)
        return prefix, total

    def _probe_null() -> tuple:
        null_fql = "host.current_mac_address:!*'*'"
        combined = f"{fql_filter}+{null_fql}" if fql_filter else null_fql
        try:
            resp = _retrying_call(
                probe_falcon.query_applications,
                {"limit": 1, "filter": combined},
                "query_applications",
            )
            _check_response(resp, "query_applications")
            total = (resp.get("body") or {}).get("meta", {}).get("pagination", {}).get("total", 0)
        except Exception:
            total = 0
        return "__NULL__", total

    _total_probes = len(_MAC_PREFIXES) + 1  # 256 prefixes + null bucket
    _log.debug("iter_applications_mac_buckets: probing %d MAC prefixes", len(_MAC_PREFIXES))
    probe_t0 = __import__("time").perf_counter()
    active_buckets: List[tuple] = []  # list of (label, chain_kwargs)
    with concurrent.futures.ThreadPoolExecutor(max_workers=probe_workers) as probe_pool:
        probe_futs = {probe_pool.submit(_probe, p): p for p in _MAC_PREFIXES}
        probe_futs[probe_pool.submit(_probe_null)] = "__NULL__"
        probes_done = 0
        for fut in concurrent.futures.as_completed(probe_futs):
            label, total = fut.result()
            probes_done += 1
            if on_probe is not None:
                on_probe(probes_done, _total_probes)
            if total > 0:
                if label == "__NULL__":
                    mac_fql = "host.current_mac_address:!*'*'"
                else:
                    mac_fql = f"host.current_mac_address:*'{label}-*'"
                active_buckets.append((label, _chain_kwargs(mac_fql), total))

    probe_elapsed = __import__("time").perf_counter() - probe_t0
    _log.debug(
        "iter_applications_mac_buckets: probe done in %.1fs, %d non-empty buckets",
        probe_elapsed, len(active_buckets),
    )

    if not active_buckets:
        return

    num_buckets = len(active_buckets)
    grand_total = sum(t for _, _, t in active_buckets)
    if on_page is not None:
        on_page(0, grand_total)

    # -----------------------------------------------------------------------
    # Phase 1: run one cursor chain per bucket.
    # -----------------------------------------------------------------------
    def _fetch_bucket(label: str, chain_kw: dict, bucket_total: int) -> List[dict]:
        falcon = Discover(**credentials)
        records: List[dict] = []

        def _on_bucket_page(n: int, _api_total: Optional[int]) -> None:
            if on_page is None:
                return
            with lock:
                bucket_totals.setdefault(label, bucket_total)
                known = sum(bucket_totals.values())
                grand = known if len(bucket_totals) == num_buckets else None
            on_page(n, grand)

        for record in _paginate_after(
            falcon.query_combined_applications,
            capped,
            "query_combined_applications",
            on_page=_on_bucket_page,
            **chain_kw,
        ):
            records.append(record)
        return records

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(bucket_workers, num_buckets)
    ) as pool:
        futs = [
            pool.submit(_fetch_bucket, label, chain_kw, bucket_total)
            for label, chain_kw, bucket_total in active_buckets
        ]
        for fut in concurrent.futures.as_completed(futs):
            yield from fut.result()


def build_host_map(
    credentials: dict,
    page_size: int = 1000,
    on_page: Optional[Callable[[int, Optional[int]], None]] = None,
) -> Dict[str, Dict[str, str]]:
    """Build a lookup from Discover host ID to CID and agent ID (aid / device_id).

    The Discover applications API returns a ``host.id`` (a Discover-internal
    composite key) but does **not** include the CrowdStrike Sensor agent ID
    (``aid`` / ``device_id``).  This function fetches all discovered hosts and
    returns a dict that resolves any ``host.id`` back to its ``cid`` and ``aid``.

    Typical usage — join applications to their sensor::

        host_map = build_host_map(credentials)
        for app in applications:
            disc_id = (app.get("host") or {}).get("id")
            entry = host_map.get(disc_id)   # None for unmanaged hosts
            if entry:
                cid, aid = entry["cid"], entry["aid"]

    Cardinality note: each Discover host ID maps to exactly one ``aid``.
    Unmanaged / agentless assets (no Falcon sensor) have no ``aid`` and are
    excluded from the returned dict.

    Args:
        credentials: Dict with ``client_id``, ``client_secret``, ``base_url``.
            Obtain via :func:`~femur.load_credentials`.
        page_size: Records per API page.  Capped at 1000 (the endpoint maximum).
        on_page: Optional callback invoked after each page with
            ``(n_records, total)``.  Used by the CLI for progress display.

    Returns:
        ``{discover_host_id: {"cid": cid, "aid": aid}}`` dict.

    Raises:
        :class:`~femur.FalconAPIError`: On API errors.
    """
    falcon = Discover(**credentials)
    result: Dict[str, Dict[str, str]] = {}
    for host in _paginate_after(
        falcon.query_combined_hosts,
        min(page_size, 1000),
        "query_combined_hosts",
        on_page=on_page,
        filter="aid:!''",
    ):
        disc_id = host.get("id")
        aid = host.get("aid")
        cid = host.get("cid")
        if disc_id and aid:
            result[disc_id] = {"cid": cid, "aid": aid}
    return result


def decorate_applications_with_aid(
    applications: List[dict],
    host_map: Dict[str, Dict[str, str]],
) -> int:
    """Annotate application records in-place with the sensor ``aid``.

    For each application whose ``host.id`` resolves in *host_map*, a top-level
    ``"aid"`` key is added to the application dict.  Applications whose
    ``host.id`` is absent from the map (e.g. agentless assets) are left
    unchanged.

    The ``cid`` field is already present on every application record returned
    by the Discover API, so it is not duplicated here.

    Example output record after decoration::

        {
          "id": "...",
          "cid": "f6a47fa...",
          "aid": "5f92125f...",   # ← injected
          "name": "nginx",
          ...
          "host": {"id": "f6a47fa..._ATDu0h9..."}
        }

    Args:
        applications: List of application dicts as returned by
            :func:`iter_applications` /  :func:`get_all_applications`.
            Modified **in-place**.
        host_map: Mapping of ``{discover_host_id: {"cid": ..., "aid": ...}}``
            as returned by :func:`build_host_map`.

    Returns:
        Number of applications successfully decorated (i.e. aid resolved).
    """
    decorated = 0
    for app in applications:
        disc_id = (app.get("host") or {}).get("id")
        if disc_id:
            entry = host_map.get(disc_id)
            if entry:
                app["aid"] = entry["aid"]
                decorated += 1
    return decorated
