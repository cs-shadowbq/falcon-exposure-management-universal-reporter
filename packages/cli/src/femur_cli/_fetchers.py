"""Concurrent fetch strategies for the ``femur`` CLI.

This module contains the strategy selection helpers and the two async
fetch orchestrators (legacy accumulate-in-memory and streaming-to-sink).
"""

import asyncio
import concurrent.futures
import logging
from functools import partial
from typing import Any, Dict, List, Optional, Tuple

from femur import (
    build_host_map,
    iter_applications,
    iter_applications_mac_buckets,
    iter_applications_parallel_offset,
    iter_assessments,
    iter_assessments_by_severity,
    iter_assessments_cross_flat,
    iter_vulnerabilities,
    iter_vulnerabilities_by_severity,
    iter_vulnerabilities_parallel,
)
from femur_pipeline.pipeline import ChainedTransform, stream_dataset
from femur_pipeline.transforms import AidDecoratorTransform

from .constants import MAX_CONCURRENT_FETCHES
from ._progress import ProgressReporter

log = logging.getLogger("femur")


# ---------------------------------------------------------------------------
# Strategy selection helpers
# ---------------------------------------------------------------------------

def _select_app_iter(creds: dict, app_filter: Optional[str], app_large_env: bool):
    """Return ``(iter_fn, needs_probe)`` for the application fetch strategy."""
    if app_large_env:
        return partial(iter_applications_mac_buckets, creds, fql_filter=app_filter), True
    return partial(iter_applications, creds, fql_filter=app_filter), False


def _select_vuln_iter(
    creds: dict,
    vuln_filter: Optional[str],
    vuln_facet: Optional[str],
    vuln_workers: int,
    by_severity: bool,
):
    """Return ``(iter_fn, is_two_phase)`` for the vulnerability fetch strategy."""
    if by_severity:
        return partial(
            iter_vulnerabilities_by_severity, creds,
            fql_filter=vuln_filter, facet=vuln_facet,
        ), False
    if vuln_workers > 1:
        return partial(
            iter_vulnerabilities_parallel, creds,
            fql_filter=vuln_filter, facet=vuln_facet, workers=vuln_workers,
        ), True
    return partial(
        iter_vulnerabilities, creds,
        fql_filter=vuln_filter, facet=vuln_facet,
    ), False


def _select_asmt_iter(
    creds: dict,
    assessment_filter: Optional[str],
    assessment_facet: Optional[List[str]],
    assessment_large_env: bool,
):
    """Return ``iter_fn`` for the assessment fetch strategy."""
    if assessment_large_env:
        return partial(
            iter_assessments_cross_flat, creds,
            fql_filter=assessment_filter, facet=assessment_facet,
        )
    return partial(
        iter_assessments_by_severity, creds,
        fql_filter=assessment_filter, facet=assessment_facet,
    )


# ---------------------------------------------------------------------------
# Concurrent fetch (legacy: accumulate in memory)
# ---------------------------------------------------------------------------

async def run_concurrent(
    creds: dict,
    app_filter: Optional[str],
    vuln_filter: Optional[str],
    assessment_filter: Optional[str],
    reporter: ProgressReporter,
    task_ids: Dict[str, Any],
    vuln_workers: int = 1,
    vuln_facet: Optional[str] = None,
    by_severity: bool = False,
    skip_host_map: bool = False,
    assessment_facet: Optional[List[str]] = None,
    assessment_large_env: bool = False,
    app_large_env: bool = False,
) -> Tuple[Any, Any, Any, Any]:
    """Run the four blocking SDK fetches concurrently via a thread pool.

    Each task updates the shared ``reporter`` display when it completes.
    Returns a tuple of ``(applications, vulnerabilities, assessments, host_map)``
    where each element is a list/dict on success or an :class:`Exception` on
    failure.  ``host_map`` is ``None`` when ``skip_host_map=True``.
    """
    loop = asyncio.get_running_loop()

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_CONCURRENT_FETCHES) as pool:
        async def _fetch(iter_fn: Any, task_key: str, label: str, make_extra_fn_kwargs=None) -> Any:
            task_id = task_ids[task_key]
            log.info("Starting fetch: %s", label)

            def _run() -> list:
                on_page = reporter.make_on_page(task_id, label)
                extra_kw = make_extra_fn_kwargs(task_id, label) if make_extra_fn_kwargs else {}
                return list(iter_fn(on_page=on_page, **extra_kw))

            try:
                result = await loop.run_in_executor(pool, _run)
                log.info("Completed %s: %d records", label, len(result))
                reporter.mark_success(task_id, label, len(result))
                return result
            except Exception as exc:
                log.error("Failed to fetch %s: %s", label, exc, exc_info=True)
                reporter.mark_failed(task_id, label, exc)
                return exc

        async def _fetch_vulns_parallel() -> Any:
            scan_id = task_ids["vulns_scan"]
            detail_id = task_ids["vulns_detail"]
            log.info("Starting fetch: Vulnerabilities (parallel, %d workers)", vuln_workers)

            def _run() -> list:
                on_ids_page, on_page = reporter.make_two_phase_callbacks(
                    scan_id, detail_id, "Vulnerabilities",
                )
                return list(iter_vulnerabilities_parallel(
                    creds,
                    fql_filter=vuln_filter,
                    facet=vuln_facet,
                    workers=vuln_workers,
                    on_page=on_page,
                    on_ids_page=on_ids_page,
                ))

            try:
                result = await loop.run_in_executor(pool, _run)
                log.info("Completed Vulnerabilities: %d records", len(result))
                reporter.mark_success(scan_id, "Vuln IDs scanned")
                reporter.mark_success(detail_id, "Vulnerabilities", len(result))
                return result
            except Exception as exc:
                log.error("Failed to fetch Vulnerabilities: %s", exc, exc_info=True)
                reporter.mark_failed(scan_id, "Vuln IDs")
                reporter.mark_failed(detail_id, "Vulnerabilities", exc)
                return exc

        # -- Strategy selection -----------------------------------------------
        app_iter, app_needs_probe = _select_app_iter(creds, app_filter, app_large_env)
        if app_needs_probe:
            def _mac_extra(tid, lbl):
                return {"on_probe": reporter.make_on_probe(tid, lbl)}
            apps_coro = _fetch(app_iter, "apps", "Applications", make_extra_fn_kwargs=_mac_extra)
        else:
            apps_coro = _fetch(app_iter, "apps", "Applications")

        asmt_iter = _select_asmt_iter(creds, assessment_filter, assessment_facet, assessment_large_env)
        asmt_coro = _fetch(asmt_iter, "asmt", "Assessments")

        vuln_iter, vuln_is_two_phase = _select_vuln_iter(
            creds, vuln_filter, vuln_facet, vuln_workers, by_severity,
        )
        vuln_coro = _fetch_vulns_parallel() if vuln_is_two_phase else _fetch(vuln_iter, "vulns", "Vulnerabilities")

        # -- Host map ---------------------------------------------------------
        async def _fetch_host_map() -> Any:
            if skip_host_map:
                reporter.mark_skipped(task_ids["hosts"], "Host Map")
                return None
            task_id = task_ids["hosts"]
            log.info("Starting fetch: Host map (discover host ID → aid)")

            def _run() -> dict:
                on_page = reporter.make_on_page(task_id, "Host Map", unit="hosts")
                return build_host_map(creds, on_page=on_page)

            try:
                result = await loop.run_in_executor(pool, _run)
                log.info("Completed Host map: %d entries", len(result))
                reporter.mark_success(task_id, "Host Map", len(result), unit="entries")
                return result
            except Exception as exc:
                log.error("Failed to fetch Host map: %s", exc, exc_info=True)
                reporter.mark_failed(task_id, "Host Map", exc)
                return exc

        results = await asyncio.gather(apps_coro, vuln_coro, asmt_coro, _fetch_host_map())

    return results[0], results[1], results[2], results[3]


# ---------------------------------------------------------------------------
# Streaming concurrent fetch — bounded memory via DataSink
# ---------------------------------------------------------------------------

async def run_concurrent_streaming(
    creds: dict,
    sink: Any,  # DataSink
    app_filter: Optional[str],
    vuln_filter: Optional[str],
    assessment_filter: Optional[str],
    reporter: ProgressReporter,
    task_ids: Dict[str, Any],
    transform: Optional[Any] = None,
    vuln_workers: int = 1,
    vuln_facet: Optional[str] = None,
    by_severity: bool = False,
    skip_host_map: bool = False,
    assessment_facet: Optional[List[str]] = None,
    assessment_large_env: bool = False,
    app_large_env: bool = False,
    decorate_aids: bool = False,
) -> Tuple[Any, Any, Any, Any]:
    """Like :func:`run_concurrent` but writes to *sink* instead of accumulating.

    When *decorate_aids* is ``True`` **and** *skip_host_map* is ``False``, the
    host map is fetched **first** so that an :class:`AidDecoratorTransform` can
    be injected into the transform chain before any application records are
    streamed.  This guarantees every app record is decorated with its ``aid``.

    Returns ``(app_count_or_exc, vuln_count_or_exc, asmt_count_or_exc, hm_count_or_exc)``.
    """
    loop = asyncio.get_running_loop()

    # -- Host-map-first pre-step (when aid decoration is requested) ----------
    hm_result: Any = 0  # default when skipped or not decorated
    if decorate_aids and not skip_host_map:
        host_map_dict, hm_result = await _prefetch_host_map(
            creds, sink, reporter, task_ids, loop,
        )
        # If the host map succeeded, inject AidDecoratorTransform.
        if host_map_dict:
            aid_transform = AidDecoratorTransform(host_map_dict)
            if transform is not None:
                transform = ChainedTransform([aid_transform, transform])
            else:
                transform = aid_transform

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_CONCURRENT_FETCHES) as pool:
        async def _stream(iter_fn: Any, dataset_name: str, task_key: str,
                          label: str, make_extra_fn_kwargs=None) -> Any:
            task_id = task_ids[task_key]
            log.info("Starting fetch+stream: %s", label)

            def _run() -> int:
                on_page = reporter.make_on_page(task_id, label)
                extra_kw = make_extra_fn_kwargs(task_id, label) if make_extra_fn_kwargs else {}
                return stream_dataset(
                    iter_fn(on_page=on_page, **extra_kw),
                    sink, dataset_name, transform=transform,
                )

            try:
                count = await loop.run_in_executor(pool, _run)
                log.info("Completed %s: %d records streamed", label, count)
                reporter.mark_success(task_id, label, count)
                return count
            except Exception as exc:
                log.error("Failed to fetch %s: %s", label, exc, exc_info=True)
                reporter.mark_failed(task_id, label, exc)
                return exc

        # -- Strategy selection -----------------------------------------------
        app_iter, app_needs_probe = _select_app_iter(creds, app_filter, app_large_env)
        if app_needs_probe:
            def _mac_extra(tid, lbl):
                return {"on_probe": reporter.make_on_probe(tid, lbl)}
            apps_coro = _stream(app_iter, "applications", "apps", "Applications", make_extra_fn_kwargs=_mac_extra)
        else:
            apps_coro = _stream(app_iter, "applications", "apps", "Applications")

        asmt_iter = _select_asmt_iter(creds, assessment_filter, assessment_facet, assessment_large_env)
        asmt_coro = _stream(asmt_iter, "assessments", "asmt", "Assessments")

        vuln_iter, _ = _select_vuln_iter(
            creds, vuln_filter, vuln_facet, vuln_workers, by_severity,
        )
        vuln_coro = _stream(vuln_iter, "vulnerabilities", "vulns", "Vulnerabilities")

        # -- Host map (parallel path: when not already fetched above) ---------
        async def _stream_host_map() -> Any:
            if skip_host_map:
                reporter.mark_skipped(task_ids["hosts"], "Host Map")
                return 0
            task_id = task_ids["hosts"]
            log.info("Starting fetch: Host map (discover host ID → aid)")

            def _run() -> int:
                on_page = reporter.make_on_page(task_id, "Host Map", unit="hosts")
                hm = build_host_map(creds, on_page=on_page)
                sink.open_dataset("host_map")
                batch = [{"_host_map_id": k, **v} for k, v in hm.items()]
                if batch:
                    sink.write_batch("host_map", batch)
                return len(hm)

            try:
                count = await loop.run_in_executor(pool, _run)
                log.info("Completed Host map: %d entries streamed", count)
                reporter.mark_success(task_id, "Host Map", count, unit="entries")
                return count
            except Exception as exc:
                log.error("Failed to fetch Host map: %s", exc, exc_info=True)
                reporter.mark_failed(task_id, "Host Map", exc)
                return exc

        # If host_map was already fetched in the pre-step, use a no-op future.
        if decorate_aids and not skip_host_map:
            hm_fut: asyncio.Future[Any] = loop.create_future()
            hm_fut.set_result(hm_result)
            hm_coro = hm_fut
        else:
            hm_coro = _stream_host_map()

        results = await asyncio.gather(
            apps_coro, vuln_coro, asmt_coro, hm_coro,
        )

    return results[0], results[1], results[2], results[3]


async def _prefetch_host_map(
    creds: dict,
    sink: Any,
    reporter: ProgressReporter,
    task_ids: Dict[str, Any],
    loop: asyncio.AbstractEventLoop,
) -> Tuple[Dict[str, Any], Any]:
    """Fetch the host map and write it to the sink before dataset streaming.

    Returns ``(host_map_dict, count_or_exception)``.  On success the first
    element is the raw host map dict (for building an
    :class:`AidDecoratorTransform`), and the second is the entry count.
    On failure the first element is an empty dict and the second is the
    :class:`Exception`.
    """
    task_id = task_ids["hosts"]
    log.info("Pre-fetching host map for aid decoration")
    result_map: Dict[str, Any] = {}

    def _run() -> Tuple[Dict[str, Any], int]:
        on_page = reporter.make_on_page(task_id, "Host Map", unit="hosts")
        hm = build_host_map(creds, on_page=on_page)
        sink.open_dataset("host_map")
        batch = [{"_host_map_id": k, **v} for k, v in hm.items()]
        if batch:
            sink.write_batch("host_map", batch)
        return hm, len(hm)

    try:
        hm, count = await loop.run_in_executor(None, _run)
        log.info("Pre-fetched host map: %d entries", count)
        reporter.mark_success(task_id, "Host Map", count, unit="entries")
        return hm, count
    except Exception as exc:
        log.error("Failed to pre-fetch host map: %s", exc, exc_info=True)
        reporter.mark_failed(task_id, "Host Map", exc)
        return {}, exc
