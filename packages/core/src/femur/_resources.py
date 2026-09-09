"""Detection of local resource exhaustion masquerading as API failures.

When a process runs out of file descriptors, ``socket()`` starts failing with
``EMFILE``.  The HTTP client reports that as a connection error, and falconpy
surfaces it as a response dict with ``status_code`` 500 and the exception text
in the error body — indistinguishable, by status code alone, from a genuine
server-side 500.

The distinction matters for two reasons:

* A remote 500 is worth retrying; local descriptor exhaustion is not.  It
  cannot self-heal, so retrying only burns the back-off budget (six attempts
  with exponential sleep, per call, per thread) before failing anyway.
* Reporting it as an API error sends the operator looking at the wrong system.

This module is deliberately dependency-free so it can be used from the lowest
layer of the package.
"""

import errno
from typing import Any, Optional

#: ``errno`` values meaning "no file descriptor was available".
FD_EXHAUSTED_ERRNOS = frozenset({errno.EMFILE, errno.ENFILE})

# Substrings that identify local descriptor/socket exhaustion once the original
# OSError has been stringified by the HTTP client stack.
_LOCAL_EXHAUSTION_MARKERS = (
    "too many open files",
    "errno 24",
    "errno 23",
    "emfile",
    "enfile",
)


def is_local_exhaustion_text(text: str) -> bool:
    """True when *text* carries the signature of local descriptor exhaustion."""
    if not text:
        return False
    lowered = text.lower()
    return any(marker in lowered for marker in _LOCAL_EXHAUSTION_MARKERS)


def is_local_exhaustion(exc: BaseException) -> bool:
    """True when *exc* is, or wraps, a local descriptor-exhaustion error."""
    if isinstance(exc, OSError) and exc.errno in FD_EXHAUSTED_ERRNOS:
        return True
    return is_local_exhaustion_text(str(exc))


def response_local_exhaustion(response: Any) -> Optional[str]:
    """Inspect a falconpy response dict for evidence of local exhaustion.

    Returns the offending message when found, otherwise ``None``.  Only the
    error body is examined: a real server error will not mention the local
    process's descriptor limits.
    """
    if not isinstance(response, dict):
        return None
    body = response.get("body") or {}
    if not isinstance(body, dict):
        return None
    for entry in body.get("errors") or []:
        message = entry.get("message", "") if isinstance(entry, dict) else str(entry)
        if is_local_exhaustion_text(message):
            return message
    return None


LOCAL_EXHAUSTION_ADVICE = (
    "This is local file-descriptor exhaustion in this process, not a "
    "server-side failure. No further sockets can be opened, so other "
    "concurrent fetches will fail the same way. Reduce the output fan-out "
    "(narrow --host-groups) or raise the process open-file limit."
)
