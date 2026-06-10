"""Rich progress helpers for the CLI fetch pipeline.

The :class:`ProgressReporter` wraps a :class:`rich.progress.Progress`
instance and provides callback factories that standardise the progress
description formatting used across all fetch strategies.
"""

from typing import Any, Callable, Dict, Optional, Tuple

from rich.markup import escape
from rich.progress import Progress


class ProgressReporter:
    """Stateful progress tracker for concurrent fetch tasks."""

    def __init__(self, progress: Progress) -> None:
        self._progress = progress
        self._states: Dict[Any, Dict[str, Any]] = {}

    def _get_state(self, task_id: Any) -> Dict[str, Any]:
        if task_id not in self._states:
            self._states[task_id] = {"count": 0, "total": None}
        return self._states[task_id]

    # -- Callback factories --------------------------------------------------

    def make_on_page(
        self,
        task_id: Any,
        label: str,
        unit: str = "records",
    ) -> Callable[[int, Optional[int]], None]:
        """Return an ``on_page(n, total)`` callback for *task_id*."""
        state = self._get_state(task_id)

        def on_page(n: int, total: Optional[int]) -> None:
            state["count"] += n
            if total is not None and state["total"] is None:
                state["total"] = total
            count = state["count"]
            t = state["total"]
            if t:
                if count == 0:
                    desc = (
                        f"  [dim]Scanning[/dim] [bold]{label}[/bold]...  "
                        f"[dim]0 / {t:,}[/dim]"
                    )
                else:
                    pct = min(100, int(100 * count / t))
                    desc = (
                        f"  Fetching [bold]{label}[/bold]...  "
                        f"[dim]{count:,} / {t:,} ({pct}%)[/dim]"
                    )
            else:
                desc = (
                    f"  Fetching [bold]{label}[/bold]...  "
                    f"[dim]{count:,} {unit}[/dim]"
                )
            self._progress.update(task_id, description=desc)

        return on_page

    def make_two_phase_callbacks(
        self,
        scan_task_id: Any,
        detail_task_id: Any,
        label: str,
    ) -> Tuple[Callable, Callable]:
        """Return ``(on_ids_page, on_page)`` for the two-phase parallel vuln fetch.

        Phase 1 (ID scan) updates *scan_task_id*.
        Phase 2 (record fetch) updates *detail_task_id*.
        When phase 1 discovers the total, it pre-seeds phase 2's denominator.
        """
        ids_state = self._get_state(scan_task_id)
        rec_state = self._get_state(detail_task_id)

        def on_ids_page(n: int, total: Optional[int]) -> None:
            ids_state["count"] += n
            if total is not None:
                ids_state["total"] = total
            count = ids_state["count"]
            t = ids_state["total"]
            # Seed the detail row total so it shows "0 / N" while phase 2 warms up.
            if total is not None and rec_state["total"] is None:
                rec_state["total"] = total
                self._progress.update(
                    detail_task_id,
                    description=(
                        f"  Fetching [bold]{label}[/bold]...  "
                        f"[dim]0 / {total:,}[/dim]"
                    ),
                )
            if t:
                pct = min(100, int(100 * count / t))
                self._progress.update(
                    scan_task_id,
                    description=(
                        f"  [dim]Scanning[/dim] [bold]Vuln IDs[/bold]...  "
                        f"[dim]{count:,} / {t:,} ({pct}%)[/dim]"
                    ),
                )
            else:
                self._progress.update(
                    scan_task_id,
                    description=(
                        f"  [dim]Scanning[/dim] [bold]Vuln IDs[/bold]...  "
                        f"[dim]{count:,} IDs[/dim]"
                    ),
                )

        def on_page(n: int, total: Optional[int]) -> None:
            rec_state["count"] += n
            if total is not None and rec_state["total"] is None:
                rec_state["total"] = total
            count = rec_state["count"]
            t = rec_state["total"]
            if t:
                if count > 0:
                    pct = min(100, int(100 * count / t))
                    self._progress.update(
                        detail_task_id,
                        description=(
                            f"  Fetching [bold]{label}[/bold]...  "
                            f"[dim]{count:,} / {t:,} ({pct}%)[/dim]"
                        ),
                    )
                else:
                    self._progress.update(
                        detail_task_id,
                        description=(
                            f"  Fetching [bold]{label}[/bold]...  "
                            f"[dim]0 / {t:,}[/dim]"
                        ),
                    )
            elif count > 0:
                self._progress.update(
                    detail_task_id,
                    description=(
                        f"  Fetching [bold]{label}[/bold]...  "
                        f"[dim]{count:,} records[/dim]"
                    ),
                )

        return on_ids_page, on_page

    def make_on_probe(
        self,
        task_id: Any,
        label: str,
    ) -> Callable[[int, int], None]:
        """Return an ``on_probe(done, total)`` callback for MAC-bucket probing."""

        def on_probe(done: int, total: int) -> None:
            self._progress.update(
                task_id,
                description=(
                    f"  [dim]Probing[/dim] [bold]{label}[/bold]...  "
                    f"[dim]{done} / {total} buckets[/dim]"
                ),
            )

        return on_probe

    # -- Status markers ------------------------------------------------------

    def mark_success(
        self,
        task_id: Any,
        label: str,
        count: Optional[int] = None,
        unit: str = "records",
    ) -> None:
        """Mark a task as successfully completed."""
        if count is not None:
            desc = f"[green]✓[/green]  {label} [dim]({count:,} {unit})[/dim]"
        else:
            desc = f"[green]✓[/green]  {label}"
        self._progress.update(task_id, description=desc, completed=1, total=1)

    def mark_failed(
        self,
        task_id: Any,
        label: str,
        exc: Optional[Exception] = None,
    ) -> None:
        """Mark a task as failed."""
        if exc is not None:
            short = escape(str(exc)[:120])
            desc = (
                f"[red]✗[/red]  {label}  [red]FAILED[/red]"
                f" [dim]— {short}[/dim]"
            )
        else:
            desc = f"[red]✗[/red]  {label}  [red]FAILED[/red]"
        self._progress.update(task_id, description=desc, completed=1, total=1)

    def mark_skipped(self, task_id: Any, label: str) -> None:
        """Mark a task as skipped."""
        self._progress.update(
            task_id,
            description=f"  {label}  [dim]skipped[/dim]",
            completed=1,
            total=1,
        )
