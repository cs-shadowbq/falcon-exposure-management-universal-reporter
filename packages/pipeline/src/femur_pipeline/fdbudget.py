"""File-descriptor budget introspection and diagnostics.

Large ``--bucket-by-aid`` runs create a very large number of output files and
run dozens of HTTPS connections concurrently, so descriptor exhaustion is a
real failure mode.  When it happens the symptom is misleading: ``socket()``
starts returning ``EMFILE``, the Falcon SDK reports what looks like an API
error, and the true cause is invisible.  This module exists so the numbers
that matter — the limit actually in force and how many descriptors are open —
can be reported instead of guessed.

The limit that matters is the one in force *inside this process*, which is not
necessarily what ``ulimit -n`` shows in the operator's shell (a container may
impose its own).  Always read it from :func:`fd_limits`.
"""

import errno
import os
from typing import Optional, Tuple

try:
    import resource
except ImportError:  # pragma: no cover - Windows
    resource = None  # type: ignore[assignment]

# Descriptor tables exposed by the OS, in preference order.
_FD_DIRS = ("/proc/self/fd", "/dev/fd")

#: ``errno`` values that mean "no descriptor was available".
FD_EXHAUSTED_ERRNOS = frozenset({errno.EMFILE, errno.ENFILE})

#: Soft limit :func:`raise_soft_limit` aims for.  Ample for any run given the
#: sinks bound their own descriptor use, without asking for "unlimited".
SOFT_LIMIT_TARGET = 1_048_576


def fd_limits() -> Tuple[Optional[int], Optional[int]]:
    """Return the ``(soft, hard)`` open-file limits for this process.

    Returns ``(None, None)`` where the platform does not expose them.
    """
    if resource is None:
        return None, None
    try:
        return resource.getrlimit(resource.RLIMIT_NOFILE)
    except (OSError, ValueError):  # pragma: no cover - defensive
        return None, None


def open_fd_count() -> Optional[int]:
    """Return the number of descriptors currently open, or ``None`` if unknown.

    Reads the kernel's descriptor directory (``/proc/self/fd`` on Linux,
    ``/dev/fd`` on macOS/BSD).  The listing itself consumes a descriptor, which
    is subtracted.
    """
    for path in _FD_DIRS:
        try:
            return max(0, len(os.listdir(path)) - 1)
        except OSError:
            continue
    return None


def raise_soft_limit() -> Optional[int]:
    """Raise the soft open-file limit toward the hard limit.

    Cheap headroom, and explicitly *not* a substitute for bounding descriptor
    use.  The target is capped at :data:`SOFT_LIMIT_TARGET` rather than set to
    the hard limit outright: an "unlimited" hard limit does not mean the kernel
    will honour it (macOS enforces ``kern.maxfilesperproc``, Linux
    ``fs.nr_open``), and a soft limit of ``RLIM_INFINITY`` is both unhelpful to
    report and rejected on some platforms.

    Returns the soft limit now in force, or ``None`` if it could not be read.
    """
    if resource is None:
        return None
    soft, hard = fd_limits()
    if soft is None or hard is None:
        return None

    if hard == resource.RLIM_INFINITY:
        target = max(soft, SOFT_LIMIT_TARGET)
    else:
        target = min(hard, max(soft, SOFT_LIMIT_TARGET))
    if target <= soft:
        return soft

    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
    except (OSError, ValueError):
        return soft
    return fd_limits()[0]


def is_fd_exhaustion(exc: BaseException) -> bool:
    """True when *exc* is — or wraps — a descriptor-exhaustion error.

    Recognises both a raw :class:`OSError` and the string form that appears
    once the error has been through an HTTP client and been re-raised as a
    connection failure.
    """
    if isinstance(exc, OSError) and exc.errno in FD_EXHAUSTED_ERRNOS:
        return True
    return "too many open files" in str(exc).lower()


def _describe_limit(value: Optional[int]) -> str:
    """Render a limit, collapsing RLIM_INFINITY to a readable word."""
    if value is None:
        return "unknown"
    if resource is not None and value == resource.RLIM_INFINITY:
        return "unlimited"
    return f"{value:,}"


def format_fd_state() -> str:
    """Render the current descriptor state as a single human-readable line."""
    soft, hard = fd_limits()
    count = open_fd_count()
    parts = ["open" if count is None else f"open {count:,}"]
    if soft is None and hard is None:
        parts.append("limits unavailable")
    else:
        parts.append(
            f"soft limit {_describe_limit(soft)}, "
            f"hard limit {_describe_limit(hard)}"
        )
    return "; ".join(parts)


def fd_report() -> dict:
    """Return the descriptor state as a dict, for logs and manifests."""
    soft, hard = fd_limits()
    infinite = resource is not None and resource.RLIM_INFINITY
    return {
        "open_fds": open_fd_count(),
        "soft_limit": None if soft == infinite else soft,
        "hard_limit": None if hard == infinite else hard,
    }


def describe_fd_exhaustion(context: str = "") -> str:
    """Build the diagnostic message for a descriptor-exhaustion failure.

    The point is to state the numbers outright, so the failure is not
    mistaken for a server-side error.
    """
    lines = [
        "Ran out of file descriptors"
        + (f" while {context}" if context else "")
        + f" ({format_fd_state()}).",
        "This is a local resource limit, not an API failure: once descriptors "
        "are exhausted no new sockets can be opened either, so concurrent "
        "dataset fetches may also report connection or HTTP 500 errors.",
    ]
    return " ".join(lines)


class FdExhaustionError(OSError):
    """Raised when a sink cannot open a file because no descriptors remain.

    Carries the descriptor accounting so the operator sees the actual numbers
    rather than a bare ``[Errno 24]``.
    """

    def __init__(self, context: str = "", path: str = "") -> None:
        self.fd_state = fd_report()
        self.path = path
        message = describe_fd_exhaustion(context)
        if path:
            message += f" Failed on: {path}"
        super().__init__(errno.EMFILE, message)

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.strerror or super().__str__()
