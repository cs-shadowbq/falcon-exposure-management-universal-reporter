"""femur CLI

Concurrently downloads CrowdStrike Falcon application inventory,
vulnerabilities, and configuration assessment results, then writes
the combined dataset to one or more output files.

Usage::

    femur --env-file talon1.env --output inventory.json

    femur -e talon1.env -o results.json \\
        --vuln-filter "cve.severity:'CRITICAL'+status:['open','reopen']" \\
        --assessment-filter "finding.status:'fail'"

    # Streaming JSONL for large environments (bounded memory)
    femur -e talon1.env --output-format jsonl --output-dir ./inventory

    # XML for downstream SOAP/enterprise ingestors
    femur -e talon1.env --output-format xml --output-dir ./inventory_xml
"""

import argparse
import asyncio
import json
import logging
import os
import sys
from typing import Any, Dict, List, Optional

from rich import box
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.traceback import Traceback

from femur import (
    assemble_inventory_payload,
    collect_fetch_errors,
    decorate_applications_with_aid,
    load_credentials,
    strip_compliance_mappings,
)
from femur_pipeline.pipeline import ChainedTransform
from femur_pipeline.sinks import create_sink
from femur.configuration import ASSESSMENT_BASE_FACETS, DEFAULT_ASSESSMENT_FILTER
from femur_pipeline.transforms import (
    ComplianceMappingStripTransform,
    CpeDecoratorTransform,
    IavmDecoratorTransform,
)

from .constants import (
    DEFAULT_OUTPUT_FORMAT,
    CORE_DATASETS,
)
from ._progress import ProgressReporter
from .parser import build_parser
from ._fetchers import run_concurrent, run_concurrent_streaming

# All interactive output goes to stderr so stdout stays clean for piping.
console = Console(stderr=True, highlight=False)

log = logging.getLogger("femur")


def _setup_logging(verbose: bool, log_file: Optional[str]) -> None:
    """Configure Python logging for the CLI session.

    Always installs a :class:`~rich.logging.RichHandler` so any warnings
    emitted by falconpy or urllib3 are rendered through Rich.  ``--verbose``
    lowers the level to DEBUG.  ``--log-file`` additionally writes a plain-text
    log with timestamps.
    """
    level = logging.DEBUG if verbose else logging.WARNING
    rich_handler = RichHandler(
        console=console,
        rich_tracebacks=True,
        tracebacks_show_locals=verbose,
        show_path=verbose,
        markup=True,
    )
    rich_handler.setLevel(level)
    handlers: List[logging.Handler] = [rich_handler]

    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s  %(levelname)-8s  %(name)s: %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S",
            )
        )
        handlers.append(file_handler)

    # Configure root logger explicitly. basicConfig(force=True) can sometimes
    # fail to attach the file handler when Rich's Live display is active.
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    for h in root.handlers[:]:
        root.removeHandler(h)
        h.close()
    for h in handlers:
        root.addHandler(h)
    # Explicitly set our own logger family to DEBUG so the file handler always
    # captures INFO/DEBUG messages regardless of the console WARNING threshold.
    logging.getLogger("femur").setLevel(logging.DEBUG)
    # Inherit our level for falconpy and urllib3 so --verbose exposes HTTP traffic.
    for lib in ("falconpy", "urllib3", "urllib3.connectionpool"):
        logging.getLogger(lib).setLevel(level)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> None:  # noqa: C901
    parser = build_parser()
    args = parser.parse_args(argv)

    _setup_logging(verbose=args.verbose, log_file=args.log_file)
    log.info("Inventory run started")

    # ------------------------------------------------------------------
    # Header
    # ------------------------------------------------------------------
    console.print()
    console.rule("[bold red]CrowdStrike Falcon Exposure Management Universal Reporter[/bold red]")
    console.print()

    # ------------------------------------------------------------------
    # Credentials
    # ------------------------------------------------------------------
    try:
        creds = load_credentials(env_file=args.env_file)
    except Exception as exc:  # pragma: no cover
        console.print(f"[bold red]ERROR:[/bold red] Failed to load credentials: {exc}")
        sys.exit(1)

    if not creds.get("client_id") or not creds.get("client_secret"):
        console.print(
            "[bold red]ERROR:[/bold red] CLIENT_ID and CLIENT_SECRET must be set "
            "via environment variables or in the --env-file."
        )
        sys.exit(1)

    # Normalise empty string → None so the library applies its own defaults.
    app_filter: Optional[str] = args.app_filter or None
    vuln_filter: Optional[str] = args.vuln_filter or None
    assessment_filter: Optional[str] = args.assessment_filter or None
    # Parse comma-separated facet string into a list, or None if not provided.
    vuln_facet: Optional[List[str]] = (
        [f.strip() for f in args.vuln_facet.split(",") if f.strip()]
        if args.vuln_facet
        else None
    )
    # Always include finding.rule — without it findings carry only a bare ID
    # with no human-readable name, severity, or benchmark information.
    # Optionally extend with finding.evaluation_logic via --assessment-evidence.
    assessment_facet: List[str] = list(ASSESSMENT_BASE_FACETS)
    if args.assessment_evidence:
        assessment_facet.append("finding.evaluation_logic")

    # Config summary table
    _print_config_summary(args, creds, app_filter, vuln_filter, assessment_filter,
                          vuln_facet, assessment_facet)

    # ------------------------------------------------------------------
    # Concurrent fetch with live progress
    # ------------------------------------------------------------------
    indent: Optional[int] = args.indent if args.indent > 0 else None
    output_format = getattr(args, "output_format", DEFAULT_OUTPUT_FORMAT)
    use_streaming = output_format != "json"

    if use_streaming:
        _main_streaming(
            args, creds, app_filter, vuln_filter, assessment_filter,
            vuln_facet, assessment_facet, output_format,
        )
    else:
        _main_legacy(
            args, creds, app_filter, vuln_filter, assessment_filter,
            vuln_facet, assessment_facet, indent,
        )


def _print_config_summary(
    args: argparse.Namespace,
    creds: dict,
    app_filter: Optional[str],
    vuln_filter: Optional[str],
    assessment_filter: Optional[str],
    vuln_facet: Optional[List[str]],
    assessment_facet: List[str],
) -> None:
    """Print a Rich table summarising the current run configuration."""
    cfg = Table(box=None, show_header=False, padding=(0, 2))
    cfg.add_column(style="dim", no_wrap=True)
    cfg.add_column()
    cfg.add_row("Base URL", f"[bold]{creds['base_url']}[/bold]")
    cfg.add_row("Output", f"[bold]{args.output}[/bold]")
    output_format = getattr(args, "output_format", DEFAULT_OUTPUT_FORMAT)
    if output_format != "json":
        output_dir = args.output_dir or os.path.splitext(args.output)[0]
        cfg.add_row("Output format", f"[cyan]{output_format}[/cyan]")
        cfg.add_row("Output dir", f"[bold]{output_dir}[/bold]")
        if args.compressed:
            cfg.add_row("Compression", "[cyan]zip[/cyan]")
    cfg.add_row("Applications filter", app_filter or "[dim](all)[/dim]")
    if args.app_large_env:
        cfg.add_row("Applications mode", "[cyan]MAC-bucket parallel (16 threads)[/cyan]")
    if args.decorate_aids:
        decorate_label = "[cyan]on[/cyan]"
        if not args.skip_host_map:
            decorate_label += " [dim](blocking pre-fetch)[/dim]"
        cfg.add_row("Application AID Enrichment", decorate_label)
    cfg.add_row("Assessments filter", assessment_filter or "[dim](all)[/dim]")
    cfg.add_row(
        "Assessments facets",
        (f"[dim]{', '.join(assessment_facet)}[/dim] + [cyan]evaluation_logic[/cyan]"
         if args.assessment_evidence
         else f"[dim]{', '.join(assessment_facet)}[/dim]"),
    )
    if not args.assessment_compliance_mapping:
        cfg.add_row("Compliance mappings", "[yellow]stripped[/yellow]")
    if args.assessment_large_env:
        cfg.add_row("Assessments mode", "[cyan]cross-bucket (30 threads)[/cyan]")
    else:
        cfg.add_row("Assessments mode", "[dim]severity buckets (6 threads)[/dim]")
    if args.vuln_workers > 1:
        cfg.add_row("Vulnerabilities workers", f"[cyan]{args.vuln_workers}[/cyan] (parallel mode)")
    if args.worker_by_severity:
        cfg.add_row("Vulnerabilities mode", "[cyan]severity buckets[/cyan] (5 parallel threads)")
    if vuln_facet:
        cfg.add_row("Vulnerabilities facets", f"[dim]{', '.join(vuln_facet)}[/dim]")
    if args.skip_host_map:
        cfg.add_row("Host map", "[yellow]skipped[/yellow]")
    if args.verbose:
        cfg.add_row("Verbose", "[yellow]on[/yellow]")
    if args.log_file:
        cfg.add_row("Log file", f"[bold]{args.log_file}[/bold]")
    console.print(cfg)
    console.print()


# ---------------------------------------------------------------------------
# Streaming path
# ---------------------------------------------------------------------------

def _main_streaming(
    args: argparse.Namespace,
    creds: dict,
    app_filter: Optional[str],
    vuln_filter: Optional[str],
    assessment_filter: Optional[str],
    vuln_facet: Optional[List[str]],
    assessment_facet: List[str],
    output_format: str,
) -> None:
    """Streaming path: bounded-memory fetch → sink → disk."""
    output_dir = args.output_dir or os.path.splitext(args.output)[0]

    # Build transforms
    transforms = []
    if not args.assessment_compliance_mapping:
        transforms.append(ComplianceMappingStripTransform())
    transforms.append(CpeDecoratorTransform())
    if args.iavm_file:
        import os
        if not os.path.isfile(args.iavm_file):
            console.print(
                f"[bold red]Error:[/] IAVM file not found: {args.iavm_file}",
            )
            raise SystemExit(1)
        from femur_pipeline.iavm import parse_iavm_xml
        iavm_index = parse_iavm_xml(args.iavm_file)
        transforms.append(IavmDecoratorTransform(iavm_index))
    transform = ChainedTransform(transforms) if transforms else None
    decorate_aids = args.decorate_aids and not args.skip_host_map

    # --bucket-by-aid implies --decorate-aids (applications need aid field)
    if args.bucket_by_aid and not args.skip_host_map:
        decorate_aids = True

    if args.bucket_by_aid:
        from femur_pipeline.sinks.aid_bucketed import AidBucketedSink
        sink = AidBucketedSink(
            output_dir,
            output_format=output_format,
            compressed=args.compressed,
            compressed_by_aid=args.compressed_by_aid,
        )
    else:
        sink = create_sink(output_format, output_dir)

    with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        reporter = ProgressReporter(progress)
        task_ids: Dict[str, Any] = {
            "apps": progress.add_task(
                "  Fetching [bold]Applications[/bold]...", total=None
            ),
            "vulns": progress.add_task(
                "  Fetching [bold]Vulnerabilities[/bold]...", total=None
            ),
            "asmt": progress.add_task(
                "  Fetching [bold]Assessments[/bold]...", total=None
            ),
            "hosts": progress.add_task(
                "  Fetching [bold]Host Map[/bold]...", total=None
            ),
        }
        try:
            from datetime import datetime, timezone
            import sys
            with sink:
                sink.set_metadata(
                    "generated_at",
                    datetime.now(timezone.utc).isoformat(),
                )
                sink.set_metadata("app_name", "falcon-exposure-management-universal-reporter")
                sink.set_metadata("app_version", "2.0.0")
                sink.set_metadata("command", " ".join(sys.argv))
                if args.iavm_file:
                    from femur_pipeline.iavm import parse_iavm_metadata
                    iavm_meta = parse_iavm_metadata(args.iavm_file)
                    if iavm_meta.get("date_generated"):
                        sink.set_metadata("iavm_date_generated", iavm_meta["date_generated"])
                apps_r, vulns_r, asmts_r, hm_r = asyncio.run(
                    run_concurrent_streaming(
                        creds, sink, app_filter, vuln_filter,
                        assessment_filter, reporter, task_ids,
                        transform=transform,
                        vuln_workers=args.vuln_workers,
                        vuln_facet=args.vuln_facet,
                        by_severity=args.worker_by_severity,
                        skip_host_map=args.skip_host_map,
                        assessment_facet=assessment_facet,
                        assessment_large_env=args.assessment_large_env,
                        app_large_env=args.app_large_env,
                        decorate_aids=decorate_aids,
                    )
                )
                fetch_errors = collect_fetch_errors({
                    "applications": apps_r,
                    "vulnerabilities": vulns_r,
                    "assessments": asmts_r,
                    "host_map": hm_r,
                })
                if fetch_errors:
                    sink.set_metadata("errors", fetch_errors)
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted.[/yellow]")
            sys.exit(130)

    # Post-write compression for non-bucketed output.
    if args.compressed and not args.bucket_by_aid:
        from femur_pipeline.sinks.compression import compress_output_files
        console.print("  Compressing output files...")
        compress_output_files(output_dir)

    console.print()

    # Summary
    summary = Table(title="Results", box=box.ROUNDED, show_lines=False)
    summary.add_column("Dataset", style="bold")
    summary.add_column("Records", justify="right", style="cyan")
    summary.add_column("Status", justify="center")
    for label, result in [
        ("Applications", apps_r),
        ("Vulnerabilities", vulns_r),
        ("Assessments", asmts_r),
        ("Host Map", hm_r),
    ]:
        if isinstance(result, Exception):
            summary.add_row(label, "[dim]—[/dim]", "[red]✗ failed[/red]")
        else:
            summary.add_row(label, f"{result:,}", "[green]✓[/green]")
    console.print(summary)
    console.print()
    console.print(f"[green]✓[/green] Written to [bold]{output_dir!r}[/bold] ({output_format})")
    console.print()


# ---------------------------------------------------------------------------
# Legacy (monolithic JSON) path
# ---------------------------------------------------------------------------

def _main_legacy(
    args: argparse.Namespace,
    creds: dict,
    app_filter: Optional[str],
    vuln_filter: Optional[str],
    assessment_filter: Optional[str],
    vuln_facet: Optional[List[str]],
    assessment_facet: List[str],
    indent: Optional[int],
) -> None:
    """Legacy path: accumulate all data in memory → single JSON file."""
    with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        reporter = ProgressReporter(progress)
        if args.vuln_workers > 1 and not args.worker_by_severity:
            task_ids: Dict[str, Any] = {
                "apps": progress.add_task(
                    "  Fetching [bold]Applications[/bold]...", total=None
                ),
                "vulns_scan": progress.add_task(
                    "  [dim]Scanning[/dim] [bold]Vuln IDs[/bold]...", total=None
                ),
                "vulns_detail": progress.add_task(
                    "  Fetching [bold]Vulnerabilities[/bold]...", total=None
                ),
                "asmt": progress.add_task(
                    "  Fetching [bold]Assessments[/bold]...", total=None
                ),
                "hosts": progress.add_task(
                    "  Fetching [bold]Host Map[/bold]...", total=None
                ),
            }
        else:
            task_ids = {
                "apps": progress.add_task(
                    "  Fetching [bold]Applications[/bold]...", total=None
                ),
                "vulns": progress.add_task(
                    "  Fetching [bold]Vulnerabilities[/bold]...", total=None
                ),
                "asmt": progress.add_task(
                    "  Fetching [bold]Assessments[/bold]...", total=None
                ),
                "hosts": progress.add_task(
                    "  Fetching [bold]Host Map[/bold]...", total=None
                ),
            }
        try:
            applications, vulnerabilities, assessments, host_map = asyncio.run(
                run_concurrent(
                    creds, app_filter, vuln_filter, assessment_filter,
                    reporter, task_ids,
                    vuln_workers=args.vuln_workers,
                    vuln_facet=args.vuln_facet,
                    by_severity=args.worker_by_severity,
                    skip_host_map=args.skip_host_map,
                    assessment_facet=assessment_facet,
                    assessment_large_env=args.assessment_large_env,
                    app_large_env=args.app_large_env,
                )
            )
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted.[/yellow]")
            sys.exit(130)

    console.print()

    # ------------------------------------------------------------------
    # Error handling — partial failures are reported but don't abort
    # ------------------------------------------------------------------
    results_map = {
        "applications": applications,
        "vulnerabilities": vulnerabilities,
        "assessments": assessments,
        "host_map": host_map,
    }
    fetch_errors = collect_fetch_errors(results_map)

    for err in fetch_errors:
        exc = results_map[err["dataset"]]
        console.print(
            Panel(
                str(exc),
                title=f"[red]Error — {err['dataset']}[/red]",
                border_style="red",
            )
        )
        if args.verbose and exc.__traceback__ is not None:
            console.print(
                Traceback.from_exception(
                    type(exc), exc, exc.__traceback__,
                    show_locals=False,
                )
            )

    core_failures = {e["dataset"] for e in fetch_errors} & set(CORE_DATASETS)
    if len(core_failures) == 3:
        console.print(
            "[bold red]All three fetches failed — nothing to write. Aborting.[/bold red]"
        )
        sys.exit(1)

    # ------------------------------------------------------------------
    # Coerce results to safe types
    # ------------------------------------------------------------------
    apps_list: List[dict] = applications if isinstance(applications, list) else []
    vulns_list: List[dict] = vulnerabilities if isinstance(vulnerabilities, list) else []
    assessments_list: List[dict] = (
        assessments if isinstance(assessments, list) else []
    )
    host_map_dict: dict = (
        host_map if isinstance(host_map, dict) else {}
    )

    # ------------------------------------------------------------------
    # Post-processing
    # ------------------------------------------------------------------
    decorated_count: Optional[int] = None
    _pp_steps = []
    if not args.assessment_compliance_mapping:
        _pp_steps.append(f"strip compliance_mappings ({len(assessments_list):,} assessments)")
    if args.decorate_aids and not args.skip_host_map and host_map_dict:
        _pp_steps.append(f"decorate aids ({len(apps_list):,} applications)")

    if _pp_steps:
        with console.status(
            "  [bold]Post-processing[/bold]  "
            f"[dim]{' · '.join(_pp_steps)}[/dim]"
        ):
            if not args.assessment_compliance_mapping:
                stripped = strip_compliance_mappings(assessments_list)
                log.info(
                    "Stripped compliance_mappings from %d assessment finding rules",
                    stripped,
                )

            if args.decorate_aids:
                if args.skip_host_map:
                    console.print(
                        "[yellow]Warning:[/yellow] --decorate-aids has no effect when "
                        "--skip-host-map is set (no host map available)."
                    )
                elif host_map_dict:
                    decorated_count = decorate_applications_with_aid(apps_list, host_map_dict)
                    log.info(
                        "Decorated %d/%d applications with aid",
                        decorated_count, len(apps_list),
                    )
                else:
                    log.warning("decorate-aids: host_map is empty, no applications decorated")
    else:
        if args.decorate_aids and args.skip_host_map:
            console.print(
                "[yellow]Warning:[/yellow] --decorate-aids has no effect when "
                "--skip-host-map is set (no host map available)."
            )

    # ------------------------------------------------------------------
    # Summary table
    # ------------------------------------------------------------------
    failed_datasets = {e["dataset"] for e in fetch_errors}

    summary = Table(title="Results", box=box.ROUNDED, show_lines=False)
    summary.add_column("Dataset", style="bold")
    summary.add_column("Records", justify="right", style="cyan")
    summary.add_column("Status", justify="center")

    for label, data, key in [
        ("Applications", apps_list, "applications"),
        ("Vulnerabilities", vulns_list, "vulnerabilities"),
        ("Assessments", assessments_list, "assessments"),
        ("Host Map", host_map_dict, "host_map"),
    ]:
        if key in failed_datasets:
            summary.add_row(label, "[dim]—[/dim]", "[red]✗ failed[/red]")
        elif key == "host_map" and args.skip_host_map:
            summary.add_row(label, "[dim]—[/dim]", "[dim]skipped[/dim]")
        elif key == "applications" and decorated_count is not None:
            summary.add_row(
                label,
                f"{len(data):,}",
                f"[green]\u2713[/green] [dim]({decorated_count:,} aids decorated)[/dim]",
            )
        else:
            count = len(data)
            summary.add_row(label, f"{count:,}", "[green]✓[/green]")

    console.print(summary)
    console.print()

    # ------------------------------------------------------------------
    # Assemble + write JSON
    # ------------------------------------------------------------------
    payload = assemble_inventory_payload(
        apps_list, vulns_list, assessments_list, host_map_dict,
        errors=fetch_errors or None,
    )

    log.info(
        "Inventory complete: apps=%d, vulns=%d, assessments=%d",
        len(apps_list), len(vulns_list), len(assessments_list),
    )
    total_records = len(apps_list) + len(vulns_list) + len(assessments_list)
    try:
        with console.status(
            f"  [bold]Writing[/bold] [dim]{args.output!r}[/dim]  "
            f"[dim]({total_records:,} records → JSON)[/dim]"
        ):
            with open(args.output, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=indent, default=str)
                fh.write("\n")
    except OSError as exc:
        console.print(
            f"[bold red]ERROR:[/bold red] Could not write to {args.output!r}: {exc}"
        )
        sys.exit(1)

    console.print(f"[green]✓[/green] Written to [bold]{args.output!r}[/bold]")
    console.print()


if __name__ == "__main__":
    main()
