"""Argument parser for the ``femur`` CLI."""

import argparse

from femur.spotlight import DEFAULT_VULN_FILTER
from femur.configuration import DEFAULT_ASSESSMENT_FILTER

from .constants import (
    DEFAULT_INDENT,
    DEFAULT_OUTPUT_FILE,
    DEFAULT_OUTPUT_FORMAT,
    DEFAULT_VULN_WORKERS,
)


def build_parser() -> argparse.ArgumentParser:
    """Build and return the :mod:`argparse` parser for ``femur``.

    Arguments are organised into titled groups so ``--help`` renders in
    scannable sections (Credentials & Output, Filtering & Scoping,
    Performance, Data Enrichment, Host Map, Output Layout & Compression,
    Logging).  Grouping is cosmetic — it does not change any flag name,
    default, or behaviour.
    """
    parser = argparse.ArgumentParser(
        prog="femur",
        description=(
            "Download CrowdStrike Falcon application inventory, "
            "vulnerabilities, and configuration assessment results to a "
            "single JSON file. All three datasets are fetched concurrently."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  femur --env-file talon1.env
  femur -e talon1.env -o results.json --indent 0
  femur -e talon1.env \\
      --vuln-filter "cve.severity:'CRITICAL'+status:['open','reopen']" \\
      --assessment-filter "finding.status:'fail'"

  # Large environment: one flag enables the full best-practice recipe
  femur -e talon1.env --large-env --output-dir ./inventory
        """,
    )

    # ------------------------------------------------------------------
    # Credentials & Output
    # ------------------------------------------------------------------
    g_io = parser.add_argument_group(
        "Credentials & Output",
        "Where credentials come from and how/where results are written.",
    )
    g_io.add_argument(
        "--env-file", "-e",
        metavar="FILE",
        help=(
            "Path to a .env file containing CLIENT_ID, CLIENT_SECRET, "
            "and optionally BASE_URL. Environment variables take priority "
            "over file values."
        ),
    )
    g_io.add_argument(
        "--output", "-o",
        default=DEFAULT_OUTPUT_FILE,
        metavar="FILE",
        help="Output JSON file path (default: %(default)s).",
    )
    g_io.add_argument(
        "--output-format",
        choices=["json", "jsonl", "xml"],
        default=None,
        help=(
            "Output format. 'json' writes a single monolithic JSON file "
            "(the original behaviour, requires all data in memory). "
            "'jsonl' writes one JSON-Lines file per dataset with bounded "
            "memory (ideal for large environments + jq exploration). "
            "'xml' writes one XML file per dataset for downstream SOAP / "
            "enterprise ingestors. Note: --large-env selects 'jsonl' unless "
            f"you set this explicitly. (default: {DEFAULT_OUTPUT_FORMAT})"
        ),
    )
    g_io.add_argument(
        "--output-dir",
        metavar="DIR",
        default=None,
        help=(
            "Directory for multi-file output formats (jsonl, xml). "
            "Created automatically if it does not exist. "
            "Ignored when --output-format=json. "
            "(default: derived from --output filename)"
        ),
    )

    # ------------------------------------------------------------------
    # Filtering & Scoping
    # ------------------------------------------------------------------
    g_filter = parser.add_argument_group(
        "Filtering & Scoping",
        "Narrow each dataset with FQL, or scope every dataset by host group / tag.",
    )
    g_filter.add_argument(
        "--app-filter",
        metavar="FQL",
        help=(
            "FQL filter for the Discover applications query, e.g. "
            "\"host.platform_name:'Windows'\"."
        ),
    )
    g_filter.add_argument(
        "--vuln-filter",
        metavar="FQL",
        default=DEFAULT_VULN_FILTER,
        help=(
            "FQL filter for the Spotlight vulnerabilities query. "
            "Pass an empty string to use the library default. "
            f"(default: {DEFAULT_VULN_FILTER!r})"
        ),
    )
    g_filter.add_argument(
        "--assessment-filter",
        metavar="FQL",
        default=DEFAULT_ASSESSMENT_FILTER,
        help=(
            "FQL filter for the Configuration Assessment query, e.g. "
            "\"finding.status:'fail'\". "
            f"(default: {DEFAULT_ASSESSMENT_FILTER!r})"
        ),
    )
    g_filter.add_argument(
        "--host-groups",
        metavar="NAMES",
        default=None,
        help=(
            "Comma-separated host group NAMES to scope every dataset to, e.g. "
            "\"Production Servers,Development\". Applied additively (AND) on top "
            "of any --app/--vuln/--assessment-filter. Multiple groups match with "
            "OR (a host in any listed group). Group names are resolved to IDs "
            "automatically for the Spotlight and Configuration Assessment queries "
            "(requires the host-groups:read scope); Discover uses the names "
            "directly. (default: none)"
        ),
    )
    g_filter.add_argument(
        "--tags",
        metavar="TAGS",
        default=None,
        help=(
            "Comma-separated host grouping TAGS to scope every dataset to, e.g. "
            "\"Monkey,heartbeat\". Applied additively (AND) on top of any filter; "
            "multiple tags match with OR. A bare value is prefixed with "
            "\"FalconGroupingTags/\"; a value already containing a \"prefix/\" "
            "segment (e.g. \"SensorGroupingTags/web\") is used as-is. "
            "(default: none)"
        ),
    )

    # ------------------------------------------------------------------
    # Performance / Large Environments
    # ------------------------------------------------------------------
    g_perf = parser.add_argument_group(
        "Performance / Large Environments",
        "Parallelism strategies for environments with hundreds of thousands "
        "of hosts. Start with --large-env.",
    )
    g_perf.add_argument(
        "--large-env",
        action="store_true",
        default=False,
        help=(
            "Promoted convenience flag bundling the best-practice recipe for "
            "very large environments. Enables --app-large-env, "
            "--worker-by-severity and --assessment-large-env; switches "
            "--output-format to 'jsonl' for bounded memory (unless you set "
            "--output-format explicitly); and enables --decorate-aids (unless "
            "--skip-host-map is set). The recommended starting point for "
            "environments with hundreds of thousands of hosts. (default: off)"
        ),
    )
    g_perf.add_argument(
        "--app-large-env",
        action="store_true",
        default=False,
        help=(
            "Fetch applications using MAC-address first-octet bucket parallelism. "
            "Phase 0 probes all 256 two-char hex prefixes in parallel (~1-3s) to "
            "discover non-empty OUI buckets (~20-50 in typical environments). "
            "Phase 1 runs one query_combined_applications cursor chain per bucket "
            "concurrently (up to 16 threads). Wall-clock time is bounded by the "
            "largest single bucket rather than the sum. "
            "Measured speedup on a 333k-record environment: ~3.4x (7:54 -> ~2:21). "
            "Cursor-based pagination within each bucket ensures no record duplication "
            "or omission. (default: off)"
        ),
    )
    g_perf.add_argument(
        "--worker-by-severity",
        action="store_true",
        default=False,
        help=(
            "Fetch vulnerabilities using severity-level bucketing. "
            "Runs five parallel query_vulnerabilities_combined streams "
            "(CRITICAL, HIGH, MEDIUM, LOW, and a catch-all), each with its "
            "own cursor chain. No two-phase ID scan — full records returned "
            "directly at up to 5,000 per page. "
            "Cannot be combined with --vuln-workers > 1 "
            "(severity mode takes precedence). (default: off)"
        ),
    )
    g_perf.add_argument(
        "--vuln-workers",
        type=int,
        default=DEFAULT_VULN_WORKERS,
        metavar="N",
        help=(
            "Number of parallel workers for the vulnerability fetch. "
            "When N > 1 a two-phase strategy is used: first collects all "
            "vulnerability IDs (fast), then fetches full records in N "
            "concurrent threads. Recommended: 8. Raise cautiously — the API "
            "rate-limits at high concurrency. (default: %(default)s)"
        ),
    )
    g_perf.add_argument(
        "--assessment-large-env",
        action="store_true",
        default=False,
        help=(
            "Use a 30-thread status × severity cross-product strategy for "
            "assessments (finding.status × finding.rule.severity). "
            "Recommended for very large environments where a single severity "
            "bucket in the default strategy would still be slow, e.g. millions "
            "of findings. Spawns up to 30 concurrent cursor chains instead of "
            "the default 6. (default: off)"
        ),
    )

    # ------------------------------------------------------------------
    # Data Enrichment
    # ------------------------------------------------------------------
    g_enrich = parser.add_argument_group(
        "Data Enrichment",
        "Decorate records with additional context as they are fetched.",
    )
    g_enrich.add_argument(
        "--decorate-aids",
        action="store_true",
        default=False,
        help=(
            "Annotate each application record with an \"aid\" field resolved "
            "from the host map (discover host ID → aid). "
            "Requires the host map to be present (incompatible with "
            "--skip-host-map). Applications whose host ID cannot be resolved "
            "(e.g. agentless assets) are left unmodified. (default: off)"
        ),
    )
    g_enrich.add_argument(
        "--iavm-file",
        metavar="FILE",
        default=None,
        help=(
            "Path to a DISA IAVM CVE cross-reference XML file. When provided, "
            "vulnerability and assessment records are decorated with matching "
            "IAVM notice metadata (number, severity, title). (default: off)"
        ),
    )
    g_enrich.add_argument(
        "--assessment-evidence",
        action="store_true",
        default=False,
        help=(
            "Include evaluation logic (evidence) in each assessment finding. "
            "Adds the finding.evaluation_logic facet which returns the actual "
            "checks performed on the host — registry keys, values observed, "
            "and pass/fail result per condition. Increases response payload "
            "size. (default: off)"
        ),
    )
    g_enrich.add_argument(
        "--vuln-facet",
        metavar="FACET",
        default=None,
        help=(
            "Extra detail block(s) to request for vulnerabilities. "
            "Supported values: host_info, remediation, cve, evaluation_logic. "
            "Comma-separate multiple values, e.g. \"host_info,remediation,cve\". "
            "Note: --vuln-workers > 1 always returns host_info, app and "
            "remediation.entities from the API regardless of this setting. "
            "(default: none)"
        ),
    )
    g_enrich.add_argument(
        "--assessment-compliance-mapping",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "Include compliance framework mappings (NIST, PCI DSS, SOC2, ISO, "
            "etc.) in each assessment finding rule. When disabled, the "
            "compliance_mappings field is stripped from every finding.rule "
            "object, reducing output size. (default: on)"
        ),
    )

    # ------------------------------------------------------------------
    # Host Map
    # ------------------------------------------------------------------
    g_hostmap = parser.add_argument_group(
        "Host Map",
        "Control the discover host ID → agent ID (aid) mapping fetch.",
    )
    g_hostmap.add_argument(
        "--skip-host-map",
        action="store_true",
        default=False,
        help=(
            "Skip the discover host ID → aid mapping fetch. "
            "The output JSON will contain an empty \"host_map\" object. "
            "Use when you do not need to resolve discover host IDs to agent IDs "
            "and want to reduce the number of API calls. (default: off)"
        ),
    )

    # ------------------------------------------------------------------
    # Output Layout & Compression
    # ------------------------------------------------------------------
    g_layout = parser.add_argument_group(
        "Output Layout & Compression",
        "How records are laid out on disk and whether output is compressed.",
    )
    g_layout.add_argument(
        "--bucket-by-aid",
        action="store_true",
        default=False,
        help=(
            "Route output records to per-AID subdirectories. Each unique agent "
            "ID gets its own directory under <output-dir>/by_aid/ containing "
            "one file per dataset. Enables per-host file discovery without "
            "post-processing. Implies --decorate-aids for applications. "
            "(default: off)"
        ),
    )
    g_layout.add_argument(
        "--compress", "--compressed",
        dest="compressed",
        action="store_true",
        default=False,
        help=(
            "Zip each individual output file after writing. With "
            "--bucket-by-aid, zips per-AID files in parallel. Without "
            "--bucket-by-aid, zips the flat output files (jsonl/xml). "
            "Originals are removed; manifest stays uncompressed "
            "for discoverability. (default: off)"
        ),
    )
    g_layout.add_argument(
        "--compressed-by-aid",
        action="store_true",
        default=False,
        help=(
            "When used with --bucket-by-aid, zip each AID directory into a "
            "single archive (e.g. 190a664e08e2488ca2fc49b19a3a29ae.zip). "
            "The directory is removed after archiving. Slower than "
            "--compressed for selective access but produces fewer files. "
            "(default: off)"
        ),
    )
    g_layout.add_argument(
        "--indent",
        type=int,
        default=DEFAULT_INDENT,
        metavar="N",
        help=(
            "JSON indentation spaces. Use 0 for compact output "
            "(default: %(default)s)."
        ),
    )

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------
    g_log = parser.add_argument_group("Logging")
    g_log.add_argument(
        "--verbose", "-v",
        action="store_true",
        default=False,
        help=(
            "Enable verbose logging (DEBUG level). Shows full tracebacks "
            "on failures and HTTP traffic from the SDK."
        ),
    )
    g_log.add_argument(
        "--log-file",
        metavar="FILE",
        help=(
            "Write a timestamped plain-text log to FILE at DEBUG level "
            "in addition to the terminal output."
        ),
    )

    return parser
