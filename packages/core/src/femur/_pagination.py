import logging
import random
import time
from typing import Any, Callable, Iterator, List, Optional

from ._exceptions import FalconAPIError

_log = logging.getLogger("femur.retry")

# 204 (No Content) is falconpy's transient "empty/undecodable body" path: under
# heavy concurrency (e.g. --large-env's 30 assessment buckets) the API
# occasionally returns an empty body which falconpy surfaces as a
# NoContentWarning with status_code=204 and an error message. A genuinely
# empty result set comes back as 200 with resources=[], so a 204 is treated as
# transient and retried rather than aborting the whole dataset.
_RETRY_STATUS_CODES = frozenset({204, 401, 429, 500, 502, 503, 504})
_RATE_LIMIT_CODE = 429
_AUTH_CODE = 401
_NO_CONTENT_CODE = 204
_MAX_RETRIES = 6
_MAX_AUTH_RETRIES = 3   # 401s: limited retries for token refresh
_BASE_DELAY = 1.0   # seconds
_MAX_DELAY = 64.0   # seconds cap


def _retrying_call(
    sdk_fn: Callable,
    call_kwargs: dict,
    operation: str,
    max_retries: int = _MAX_RETRIES,
) -> dict:
    """Call ``sdk_fn(**call_kwargs)`` with exponential back-off on retryable errors.

    Retries on HTTP 429 (rate limit) and transient server errors (500, 502, 503,
    504) up to *max_retries* times.  The wait is taken from the ``Retry-After``
    response header when present, otherwise from an exponential back-off formula
    with full jitter: ``min(base * 2^attempt, max_delay) + uniform(0, 1)``.

    Args:
        sdk_fn: Bound falconpy service-class method to call.
        call_kwargs: Keyword arguments to forward to *sdk_fn*.
        operation: Human-readable name for error / log messages.
        max_retries: Maximum number of retry attempts after the first failure.

    Returns:
        The last response dict returned by *sdk_fn*, regardless of status.
        The caller is responsible for validating the response via
        :func:`_check_response`.
    """
    auth_attempts = 0
    for attempt in range(max_retries + 1):
        response = sdk_fn(**call_kwargs)
        status_code = response.get("status_code", 0)
        if status_code not in _RETRY_STATUS_CODES or attempt == max_retries:
            return response
        if status_code == _AUTH_CODE:
            auth_attempts += 1
            if auth_attempts > _MAX_AUTH_RETRIES:
                return response
        # Determine wait time.
        headers = response.get("headers") or {}
        raw_retry_after = headers.get("Retry-After") or headers.get("retry-after")
        try:
            wait = float(raw_retry_after) if raw_retry_after is not None else None
        except (TypeError, ValueError):
            wait = None
        if wait is None:
            wait = min(_BASE_DELAY * (2 ** attempt), _MAX_DELAY) + random.uniform(0, 1)
        if status_code == _RATE_LIMIT_CODE:
            _log.warning(
                "Rate limited on %s (attempt %d/%d) — retrying in %.1fs",
                operation,
                attempt + 1,
                max_retries,
                wait,
            )
        elif status_code == 401:
            _log.warning(
                "Auth 401 on %s (attempt %d/%d) — token may have expired, retrying in %.1fs",
                operation,
                attempt + 1,
                max_retries,
                wait,
            )
        elif status_code == _NO_CONTENT_CODE:
            _log.warning(
                "Empty body (204 No Content) on %s (attempt %d/%d) — "
                "transient, retrying in %.1fs",
                operation,
                attempt + 1,
                max_retries,
                wait,
            )
        else:
            _log.warning(
                "Transient %d on %s (attempt %d/%d) — retrying in %.1fs",
                status_code,
                operation,
                attempt + 1,
                max_retries,
                wait,
            )
        time.sleep(wait)
    return response  # unreachable but keeps type-checker happy


def _check_response(response: dict, operation: str) -> List[Any]:
    """Validate a falconpy response and return the resources list.

    Raises:
        FalconAPIError: If ``status_code >= 400`` or the body contains errors,
            except for the transient 204 "No Content" case (see below).

    Returns:
        The ``body.resources`` list, or an empty list when absent.

    A ``204`` response is falconpy's "empty/undecodable body" signal. It is
    retried upstream by :func:`_retrying_call`; if it still arrives here (the
    blip persisted through every retry), it is treated as an **empty page**
    rather than a fatal error so a single transient hiccup in one pagination
    chain does not discard the entire dataset. Genuine errors always carry a
    ``status_code >= 400`` or an error entry with a non-empty ``code``.
    """
    status_code = response.get("status_code", 0)
    body = response.get("body") or {}
    errors = body.get("errors") or []

    # Transient empty-body 204: not a real error — treat as an empty page.
    if status_code == _NO_CONTENT_CODE:
        _log.warning(
            "Persistent 204 No Content on %s after retries — "
            "treating as empty page (no records for this request)",
            operation,
        )
        return body.get("resources") or []

    if status_code >= 400 or errors:
        raise FalconAPIError(
            operation=operation,
            status_code=status_code,
            errors=errors,
        )
    return body.get("resources") or []


def _paginate_after(
    sdk_fn: Callable,
    page_size: int,
    operation: str,
    on_page: Optional[Callable[[int, Optional[int]], None]] = None,
    **kwargs: Any,
) -> Iterator[Any]:
    """Paginate a falconpy endpoint that uses an ``after`` cursor token.

    Yields individual resources from every page until the API returns no
    further ``after`` token or an empty page.

    Args:
        sdk_fn: Bound falconpy service-class method to call.
        page_size: Number of records to request per page.
        operation: Human-readable name used in :class:`FalconAPIError` messages.
        on_page: Optional callback invoked after each page with
            ``(n_records, total)`` where ``total`` is the API-reported total
            count (may be ``None`` if the endpoint does not expose it).
        **kwargs: Additional query parameters forwarded verbatim to ``sdk_fn``.
    """
    after = None
    while True:
        call_kwargs = dict(kwargs)
        call_kwargs["limit"] = page_size
        if after is not None:
            call_kwargs["after"] = after
        response = _retrying_call(sdk_fn, call_kwargs, operation)
        resources = _check_response(response, operation)
        yield from resources
        pagination = (
            (response.get("body") or {})
            .get("meta", {})
            .get("pagination", {})
        )
        after = pagination.get("after")
        if on_page is not None:
            on_page(len(resources), pagination.get("total"))
        if not after or not resources:
            break


def _paginate_offset(
    sdk_fn: Callable,
    page_size: int,
    operation: str,
    **kwargs: Any,
) -> Iterator[Any]:
    """Paginate a falconpy endpoint that uses an integer ``offset``.

    Yields individual resources from every page. Stops when a page returns
    fewer records than ``page_size``, indicating the last page.

    Args:
        sdk_fn: Bound falconpy service-class method to call.
        page_size: Number of records to request per page.
        operation: Human-readable name used in :class:`FalconAPIError` messages.
        **kwargs: Additional query parameters forwarded verbatim to ``sdk_fn``.
    """
    offset = 0
    while True:
        call_kwargs = dict(kwargs)
        call_kwargs["limit"] = page_size
        call_kwargs["offset"] = offset
        response = _retrying_call(sdk_fn, call_kwargs, operation)
        resources = _check_response(response, operation)
        yield from resources
        if len(resources) < page_size:
            break
        offset += len(resources)


def _batch_ids(ids: list, size: int) -> Iterator[list]:
    """Yield successive fixed-size chunks from ``ids``.

    Args:
        ids: Full list of IDs to split.
        size: Maximum number of IDs per batch.
    """
    for i in range(0, len(ids), size):
        yield ids[i: i + size]


def build_fql(*clauses: str) -> str:
    """Join one or more FQL clauses with ``+`` (logical AND).

    Empty strings are ignored, so callers can conditionally include clauses
    without extra branching::

        fql = build_fql(
            "status:['open','reopen']",
            "host_info.platform_name:'Windows'" if windows_only else "",
        )

    Args:
        *clauses: Individual FQL filter expressions.

    Returns:
        A single FQL expression string, e.g. ``"status:'open'+platform:'Windows'"``.
    """
    return "+".join(c for c in clauses if c)
