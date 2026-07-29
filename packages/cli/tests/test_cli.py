import json
import os
import sys
from unittest.mock import AsyncMock, patch

import pytest

from femur_cli.cli import main
from femur_cli.cli import _setup_logging as _real_setup_logging


CREDS = {"client_id": "test_id", "client_secret": "test_secret", "base_url": "US1"}

APPS = [{"id": "app1", "name": "nginx"}]
VULNS = [{"id": "vuln1", "cve": {"id": "CVE-2024-1234"}}]
ASSESSMENTS = [{"id": "asmt1", "finding": {"status": "fail"}}]


@pytest.fixture(autouse=True)
def _suppress_logging_setup():
    """Prevent _setup_logging from reconfiguring the root logger during tests."""
    with patch("femur_cli.cli._setup_logging"):
        yield


@pytest.fixture(autouse=True)
def _mock_build_host_map():
    """Return an empty host map for all tests unless overridden."""
    with patch("femur_cli._fetchers.build_host_map", return_value={}):
        yield


def _patch_all(apps=APPS, vulns=VULNS, assessments=ASSESSMENTS):
    """Context manager that patches credentials + all three fetch functions."""
    return (
        patch("femur_cli.cli.load_credentials", return_value=CREDS),
        patch("femur_cli._fetchers.iter_applications", return_value=apps),
        patch("femur_cli._fetchers.iter_vulnerabilities", return_value=vulns),
        patch("femur_cli._fetchers.iter_assessments_by_severity", return_value=assessments),
    )


class TestMainSuccess:
    def test_writes_json_file(self, tmp_path):
        out = str(tmp_path / "out.json")
        with (
            patch("femur_cli.cli.load_credentials", return_value=CREDS),
            patch("femur_cli._fetchers.iter_applications", return_value=APPS),
            patch("femur_cli._fetchers.iter_vulnerabilities", return_value=VULNS),
            patch("femur_cli._fetchers.iter_assessments_by_severity", return_value=ASSESSMENTS),
        ):
            main(["--env-file", "fake.env", "--output", out])

        with open(out) as fh:
            payload = json.load(fh)

        assert payload["applications"] == APPS
        assert payload["vulnerabilities"] == VULNS
        assert payload["assessments"] == ASSESSMENTS

    def test_payload_has_generated_at(self, tmp_path):
        out = str(tmp_path / "out.json")
        with (
            patch("femur_cli.cli.load_credentials", return_value=CREDS),
            patch("femur_cli._fetchers.iter_applications", return_value=[]),
            patch("femur_cli._fetchers.iter_vulnerabilities", return_value=[]),
            patch("femur_cli._fetchers.iter_assessments_by_severity", return_value=[]),
        ):
            main(["--output", out])

        with open(out) as fh:
            payload = json.load(fh)

        assert "generated_at" in payload

    def test_payload_counts_are_correct(self, tmp_path):
        out = str(tmp_path / "out.json")
        with (
            patch("femur_cli.cli.load_credentials", return_value=CREDS),
            patch("femur_cli._fetchers.iter_applications", return_value=APPS),
            patch("femur_cli._fetchers.iter_vulnerabilities", return_value=VULNS),
            patch("femur_cli._fetchers.iter_assessments_by_severity", return_value=ASSESSMENTS),
        ):
            main(["--output", out])

        with open(out) as fh:
            payload = json.load(fh)

        assert payload["counts"] == {
            "applications": 1,
            "vulnerabilities": 1,
            "assessments": 1,
            "host_map": 0,
        }

    def test_default_output_filename(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        with (
            patch("femur_cli.cli.load_credentials", return_value=CREDS),
            patch("femur_cli._fetchers.iter_applications", return_value=[]),
            patch("femur_cli._fetchers.iter_vulnerabilities", return_value=[]),
            patch("femur_cli._fetchers.iter_assessments_by_severity", return_value=[]),
        ):
            main([])

        assert (tmp_path / "femur_inventory.json").exists()

    def test_compact_output_with_indent_zero(self, tmp_path):
        out = str(tmp_path / "out.json")
        with (
            patch("femur_cli.cli.load_credentials", return_value=CREDS),
            patch("femur_cli._fetchers.iter_applications", return_value=APPS),
            patch("femur_cli._fetchers.iter_vulnerabilities", return_value=[]),
            patch("femur_cli._fetchers.iter_assessments_by_severity", return_value=[]),
        ):
            main(["--output", out, "--indent", "0"])

        with open(out) as fh:
            content = fh.read()

        # Compact JSON has no newlines inside the object (just the trailing \n)
        assert "\n  " not in content

    def test_passes_app_filter_to_library(self, tmp_path):
        out = str(tmp_path / "out.json")
        with (
            patch("femur_cli.cli.load_credentials", return_value=CREDS),
            patch(
                "femur_cli._fetchers.iter_applications", return_value=[]
            ) as mock_apps,
            patch("femur_cli._fetchers.iter_vulnerabilities", return_value=[]),
            patch("femur_cli._fetchers.iter_assessments_by_severity", return_value=[]),
        ):
            main(["--output", out, "--app-filter", "host.platform_name:'Linux'"])

        mock_apps.assert_called_once()
        assert mock_apps.call_args[1]["fql_filter"] == "host.platform_name:'Linux'"

    def test_passes_vuln_filter_to_library(self, tmp_path):
        out = str(tmp_path / "out.json")
        custom_filter = "cve.severity:'CRITICAL'+status:['open','reopen']"
        with (
            patch("femur_cli.cli.load_credentials", return_value=CREDS),
            patch("femur_cli._fetchers.iter_applications", return_value=[]),
            patch(
                "femur_cli._fetchers.iter_vulnerabilities", return_value=[]
            ) as mock_vulns,
            patch("femur_cli._fetchers.iter_assessments_by_severity", return_value=[]),
        ):
            main(["--output", out, "--vuln-filter", custom_filter])

        assert mock_vulns.call_args[1]["fql_filter"] == custom_filter

    def test_passes_assessment_filter_to_library(self, tmp_path):
        out = str(tmp_path / "out.json")
        with (
            patch("femur_cli.cli.load_credentials", return_value=CREDS),
            patch("femur_cli._fetchers.iter_applications", return_value=[]),
            patch("femur_cli._fetchers.iter_vulnerabilities", return_value=[]),
            patch(
                "femur_cli._fetchers.iter_assessments_by_severity", return_value=[]
            ) as mock_asmt,
        ):
            main(["--output", out, "--assessment-filter", "finding.status:'fail'"])

        assert mock_asmt.call_args[1]["fql_filter"] == "finding.status:'fail'"

    def test_no_errors_key_when_all_succeed(self, tmp_path):
        out = str(tmp_path / "out.json")
        with (
            patch("femur_cli.cli.load_credentials", return_value=CREDS),
            patch("femur_cli._fetchers.iter_applications", return_value=[]),
            patch("femur_cli._fetchers.iter_vulnerabilities", return_value=[]),
            patch("femur_cli._fetchers.iter_assessments_by_severity", return_value=[]),
        ):
            main(["--output", out])

        with open(out) as fh:
            payload = json.load(fh)

        assert "errors" not in payload


class TestMainPartialFailure:
    def test_partial_failure_still_writes_output(self, tmp_path):
        out = str(tmp_path / "out.json")
        from femur._exceptions import FalconAPIError

        with (
            patch("femur_cli.cli.load_credentials", return_value=CREDS),
            patch(
                "femur_cli._fetchers.iter_applications",
                side_effect=FalconAPIError("op", 403, [{"code": 403, "message": "Forbidden"}]),
            ),
            patch("femur_cli._fetchers.iter_vulnerabilities", return_value=VULNS),
            patch("femur_cli._fetchers.iter_assessments_by_severity", return_value=ASSESSMENTS),
        ):
            main(["--output", out])

        with open(out) as fh:
            payload = json.load(fh)

        assert payload["applications"] == []
        assert payload["vulnerabilities"] == VULNS
        assert len(payload["errors"]) == 1
        assert payload["errors"][0]["dataset"] == "applications"

    def test_partial_failure_count_is_zero_for_failed_dataset(self, tmp_path):
        out = str(tmp_path / "out.json")
        from femur._exceptions import FalconAPIError

        with (
            patch("femur_cli.cli.load_credentials", return_value=CREDS),
            patch("femur_cli._fetchers.iter_applications", return_value=APPS),
            patch(
                "femur_cli._fetchers.iter_vulnerabilities",
                side_effect=FalconAPIError("op", 401, []),
            ),
            patch("femur_cli._fetchers.iter_assessments_by_severity", return_value=[]),
        ):
            main(["--output", out])

        with open(out) as fh:
            payload = json.load(fh)

        assert payload["counts"]["vulnerabilities"] == 0


class TestMainErrors:
    def test_exits_1_when_missing_client_id(self, tmp_path):
        out = str(tmp_path / "out.json")
        incomplete = {"client_id": "", "client_secret": "sec", "base_url": "US1"}
        with (
            patch("femur_cli.cli.load_credentials", return_value=incomplete),
            pytest.raises(SystemExit) as exc_info,
        ):
            main(["--output", out])
        assert exc_info.value.code == 1

    def test_exits_1_when_missing_client_secret(self, tmp_path):
        out = str(tmp_path / "out.json")
        incomplete = {"client_id": "cid", "client_secret": "", "base_url": "US1"}
        with (
            patch("femur_cli.cli.load_credentials", return_value=incomplete),
            pytest.raises(SystemExit) as exc_info,
        ):
            main(["--output", out])
        assert exc_info.value.code == 1

    def test_exits_1_when_all_fetches_fail(self, tmp_path):
        out = str(tmp_path / "out.json")
        from femur._exceptions import FalconAPIError

        err = FalconAPIError("op", 403, [])
        with (
            patch("femur_cli.cli.load_credentials", return_value=CREDS),
            patch(
                "femur_cli._fetchers.iter_applications", side_effect=err
            ),
            patch(
                "femur_cli._fetchers.iter_vulnerabilities", side_effect=err
            ),
            patch(
                "femur_cli._fetchers.iter_assessments_by_severity", side_effect=err
            ),
            pytest.raises(SystemExit) as exc_info,
        ):
            main(["--output", out])
        assert exc_info.value.code == 1

    def test_exits_1_on_unwritable_output(self, tmp_path):
        out = str(tmp_path / "nonexistent_dir" / "out.json")
        with (
            patch("femur_cli.cli.load_credentials", return_value=CREDS),
            patch("femur_cli._fetchers.iter_applications", return_value=[]),
            patch("femur_cli._fetchers.iter_vulnerabilities", return_value=[]),
            patch("femur_cli._fetchers.iter_assessments_by_severity", return_value=[]),
            pytest.raises(SystemExit) as exc_info,
        ):
            main(["--output", out])
        assert exc_info.value.code == 1


class TestLoggingFlags:
    def test_verbose_flag_calls_setup_logging_with_verbose_true(self, tmp_path):
        import logging
        out = str(tmp_path / "out.json")
        # _suppress_logging_setup fixture patches _setup_logging; we inspect it.
        with (
            patch("femur_cli.cli._setup_logging") as mock_setup,
            patch("femur_cli.cli.load_credentials", return_value=CREDS),
            patch("femur_cli._fetchers.iter_applications", return_value=[]),
            patch("femur_cli._fetchers.iter_vulnerabilities", return_value=[]),
            patch("femur_cli._fetchers.iter_assessments_by_severity", return_value=[]),
        ):
            main(["--output", out, "--verbose"])

        _, kwargs = mock_setup.call_args
        # --verbose raises console + file to DEBUG and enables tracebacks,
        # but must NOT enable per-request HTTP tracing.
        assert kwargs["console_level"] == logging.DEBUG
        assert kwargs["file_level"] == logging.DEBUG
        assert kwargs["verbose_tracebacks"] is True
        assert kwargs["trace_http"] is False

    def test_log_file_flag_calls_setup_logging_with_path(self, tmp_path):
        import logging
        out = str(tmp_path / "out.json")
        log_path = str(tmp_path / "run.log")
        with (
            patch("femur_cli.cli._setup_logging") as mock_setup,
            patch("femur_cli.cli.load_credentials", return_value=CREDS),
            patch("femur_cli._fetchers.iter_applications", return_value=[]),
            patch("femur_cli._fetchers.iter_vulnerabilities", return_value=[]),
            patch("femur_cli._fetchers.iter_assessments_by_severity", return_value=[]),
        ):
            main(["--output", out, "--log-file", log_path])

        _, kwargs = mock_setup.call_args
        # Defaults: console WARNING, file INFO, no HTTP trace.
        assert kwargs["log_file"] == log_path
        assert kwargs["console_level"] == logging.WARNING
        assert kwargs["file_level"] == logging.INFO
        assert kwargs["trace_http"] is False

    def test_setup_logging_creates_log_file(self, tmp_path):
        """_setup_logging (real, not mocked) writes to the log file."""
        import logging
        log_path = str(tmp_path / "test.log")
        _real_setup_logging(console_level=logging.WARNING, log_file=log_path)

        logging.getLogger("femur").warning("test log entry")

        with open(log_path) as fh:
            content = fh.read()

        assert "test log entry" in content

    def test_file_level_filters_below_threshold(self, tmp_path):
        """The file handler honours file_level: INFO lands, DEBUG does not."""
        import logging
        log_path = str(tmp_path / "lvl.log")
        _real_setup_logging(
            console_level=logging.WARNING,
            log_file=log_path,
            file_level=logging.INFO,
        )
        femur_log = logging.getLogger("femur")
        femur_log.info("info-should-appear")
        femur_log.debug("debug-should-not-appear")
        for h in logging.getLogger().handlers:
            h.flush()

        content = open(log_path).read()
        assert "info-should-appear" in content
        assert "debug-should-not-appear" not in content

    def test_trace_http_off_keeps_falconpy_quiet(self, tmp_path):
        """Without --trace-http, falconpy/urllib3 stay at WARNING even at DEBUG."""
        import logging
        _real_setup_logging(
            console_level=logging.DEBUG,
            log_file=str(tmp_path / "x.log"),
            file_level=logging.DEBUG,
            trace_http=False,
        )
        assert logging.getLogger("falconpy").level == logging.WARNING
        assert logging.getLogger("urllib3").level == logging.WARNING

    def test_trace_http_on_enables_wire_logging(self, tmp_path):
        import logging
        _real_setup_logging(
            console_level=logging.WARNING,
            log_file=str(tmp_path / "x.log"),
            file_level=logging.INFO,
            trace_http=True,
        )
        assert logging.getLogger("falconpy").level == logging.DEBUG
        assert logging.getLogger("urllib3").level == logging.DEBUG

    def test_log_level_flag_sets_console_level(self, tmp_path):
        import logging
        out = str(tmp_path / "out.json")
        with (
            patch("femur_cli.cli._setup_logging") as mock_setup,
            patch("femur_cli.cli.load_credentials", return_value=CREDS),
            patch("femur_cli._fetchers.iter_applications", return_value=[]),
            patch("femur_cli._fetchers.iter_vulnerabilities", return_value=[]),
            patch("femur_cli._fetchers.iter_assessments_by_severity", return_value=[]),
        ):
            main(["--output", out, "--log-level", "DEBUG",
                  "--log-file-level", "ERROR"])

        _, kwargs = mock_setup.call_args
        assert kwargs["console_level"] == logging.DEBUG
        assert kwargs["file_level"] == logging.ERROR

    def test_trace_http_flag_passes_through(self, tmp_path):
        out = str(tmp_path / "out.json")
        with (
            patch("femur_cli.cli._setup_logging") as mock_setup,
            patch("femur_cli.cli.load_credentials", return_value=CREDS),
            patch("femur_cli._fetchers.iter_applications", return_value=[]),
            patch("femur_cli._fetchers.iter_vulnerabilities", return_value=[]),
            patch("femur_cli._fetchers.iter_assessments_by_severity", return_value=[]),
        ):
            main(["--output", out, "--trace-http"])

        _, kwargs = mock_setup.call_args
        assert kwargs["trace_http"] is True

    def test_verbose_error_includes_traceback_panel(self, tmp_path):
        """With --verbose a failed fetch shows a Traceback in addition to the Panel."""
        out = str(tmp_path / "out.json")
        from femur._exceptions import FalconAPIError

        printed = []

        with (
            patch("femur_cli.cli._setup_logging"),
            patch("femur_cli.cli.load_credentials", return_value=CREDS),
            patch(
                "femur_cli._fetchers.iter_applications",
                side_effect=FalconAPIError("op", 403, [{"code": 403, "message": "Forbidden"}]),
            ),
            patch("femur_cli._fetchers.iter_vulnerabilities", return_value=[]),
            patch("femur_cli._fetchers.iter_assessments_by_severity", return_value=[]),
            patch(
                "femur_cli.cli.console.print",
                side_effect=lambda *a, **kw: printed.append(a),
            ),
        ):
            main(["--output", out, "--verbose"])

        # At least one call should have been a Traceback object.
        from rich.traceback import Traceback
        assert any(
            any(isinstance(arg, Traceback) for arg in call) for call in printed
        )

    def test_no_traceback_without_verbose(self, tmp_path):
        """Without --verbose, no Traceback object is printed."""
        out = str(tmp_path / "out.json")
        from femur._exceptions import FalconAPIError

        printed = []

        with (
            patch("femur_cli.cli._setup_logging"),
            patch("femur_cli.cli.load_credentials", return_value=CREDS),
            patch(
                "femur_cli._fetchers.iter_applications",
                side_effect=FalconAPIError("op", 403, [{"code": 403, "message": "Forbidden"}]),
            ),
            patch("femur_cli._fetchers.iter_vulnerabilities", return_value=[]),
            patch("femur_cli._fetchers.iter_assessments_by_severity", return_value=[]),
            patch(
                "femur_cli.cli.console.print",
                side_effect=lambda *a, **kw: printed.append(a),
            ),
        ):
            main(["--output", out])

        from rich.traceback import Traceback
        assert not any(
            any(isinstance(arg, Traceback) for arg in call) for call in printed
        )


class TestScopeFilters:
    """--host-groups / --tags are resolved and applied additively per dataset."""

    def test_tags_applied_to_all_three_datasets(self, tmp_path):
        out = str(tmp_path / "out.json")
        with (
            patch("femur_cli.cli.load_credentials", return_value=CREDS),
            patch("femur_cli._fetchers.iter_applications", return_value=[]) as m_app,
            patch("femur_cli._fetchers.iter_vulnerabilities", return_value=[]) as m_vuln,
            patch(
                "femur_cli._fetchers.iter_assessments_by_severity", return_value=[]
            ) as m_asmt,
        ):
            main(["--output", out, "--tags", "Monkey,heartbeat"])

        # Applications + Assessments use host.tags; Spotlight uses host_info.tags.
        assert m_app.call_args[1]["fql_filter"] == (
            "host.tags:['FalconGroupingTags/Monkey','FalconGroupingTags/heartbeat']"
        )
        assert m_asmt.call_args[1]["fql_filter"] == (
            "created_timestamp:>='2000-01-01T00:00:00Z'"
            "+host.tags:['FalconGroupingTags/Monkey','FalconGroupingTags/heartbeat']"
        )
        assert m_vuln.call_args[1]["fql_filter"] == (
            "status:['open','reopen']"
            "+host_info.tags:['FalconGroupingTags/Monkey','FalconGroupingTags/heartbeat']"
        )

    def test_host_groups_resolved_to_ids_for_vuln_and_assessment(self, tmp_path):
        out = str(tmp_path / "out.json")
        resolved = {"Cloud Lab": "dfba0b1b823e46409f069711d151be0c"}
        with (
            patch("femur_cli.cli.load_credentials", return_value=CREDS),
            patch(
                "femur_cli.cli.resolve_group_names_to_ids",
                return_value=(resolved, []),
            ) as m_resolve,
            patch("femur_cli._fetchers.iter_applications", return_value=[]) as m_app,
            patch("femur_cli._fetchers.iter_vulnerabilities", return_value=[]) as m_vuln,
            patch(
                "femur_cli._fetchers.iter_assessments_by_severity", return_value=[]
            ) as m_asmt,
        ):
            main(["--output", out, "--host-groups", "Cloud Lab"])

        m_resolve.assert_called_once()
        # Discover filters by NAME.
        assert m_app.call_args[1]["fql_filter"] == "host.groups:['Cloud Lab']"
        # Spotlight + Assessment filter by resolved ID.
        assert m_vuln.call_args[1]["fql_filter"] == (
            "status:['open','reopen']"
            "+host_info.groups:['dfba0b1b823e46409f069711d151be0c']"
        )
        assert m_asmt.call_args[1]["fql_filter"] == (
            "created_timestamp:>='2000-01-01T00:00:00Z'"
            "+host.groups:['dfba0b1b823e46409f069711d151be0c']"
        )

    def test_scope_is_additive_to_user_filter(self, tmp_path):
        out = str(tmp_path / "out.json")
        with (
            patch("femur_cli.cli.load_credentials", return_value=CREDS),
            patch("femur_cli._fetchers.iter_applications", return_value=[]) as m_app,
            patch("femur_cli._fetchers.iter_vulnerabilities", return_value=[]),
            patch("femur_cli._fetchers.iter_assessments_by_severity", return_value=[]),
        ):
            main([
                "--output", out,
                "--app-filter", "host.platform_name:'Linux'",
                "--tags", "Monkey",
            ])

        assert m_app.call_args[1]["fql_filter"] == (
            "host.platform_name:'Linux'+host.tags:['FalconGroupingTags/Monkey']"
        )

    def test_missing_group_name_exits_1(self, tmp_path):
        out = str(tmp_path / "out.json")
        with (
            patch("femur_cli.cli.load_credentials", return_value=CREDS),
            patch(
                "femur_cli.cli.resolve_group_names_to_ids",
                return_value=({}, ["Nonexistent"]),
            ),
            pytest.raises(SystemExit) as exc_info,
        ):
            main(["--output", out, "--host-groups", "Nonexistent"])
        assert exc_info.value.code == 1

    def test_no_resolution_call_when_only_tags(self, tmp_path):
        out = str(tmp_path / "out.json")
        with (
            patch("femur_cli.cli.load_credentials", return_value=CREDS),
            patch(
                "femur_cli.cli.resolve_group_names_to_ids",
                return_value=({}, []),
            ) as m_resolve,
            patch("femur_cli._fetchers.iter_applications", return_value=[]),
            patch("femur_cli._fetchers.iter_vulnerabilities", return_value=[]),
            patch("femur_cli._fetchers.iter_assessments_by_severity", return_value=[]),
        ):
            main(["--output", out, "--tags", "Monkey"])

        m_resolve.assert_not_called()


class TestVulnWorkers:
    def test_default_uses_serial_iter(self, tmp_path):
        """Without --vuln-workers, iter_vulnerabilities is used (not parallel)."""
        out = str(tmp_path / "out.json")
        with (
            patch("femur_cli.cli.load_credentials", return_value=CREDS),
            patch("femur_cli._fetchers.iter_applications", return_value=APPS),
            patch(
                "femur_cli._fetchers.iter_vulnerabilities_parallel",
                return_value=VULNS,
            ) as mock_parallel,
            patch(
                "femur_cli._fetchers.iter_vulnerabilities",
                return_value=VULNS,
            ) as mock_serial,
            patch("femur_cli._fetchers.iter_assessments_by_severity", return_value=ASSESSMENTS),
        ):
            main(["--output", out])

        mock_serial.assert_called_once()
        mock_parallel.assert_not_called()

    def test_vuln_workers_flag_uses_parallel_iter(self, tmp_path):
        """--vuln-workers > 1 routes through iter_vulnerabilities_parallel."""
        out = str(tmp_path / "out.json")
        with (
            patch("femur_cli.cli.load_credentials", return_value=CREDS),
            patch("femur_cli._fetchers.iter_applications", return_value=APPS),
            patch(
                "femur_cli._fetchers.iter_vulnerabilities_parallel",
                return_value=VULNS,
            ) as mock_parallel,
            patch(
                "femur_cli._fetchers.iter_vulnerabilities",
                return_value=VULNS,
            ) as mock_serial,
            patch("femur_cli._fetchers.iter_assessments_by_severity", return_value=ASSESSMENTS),
        ):
            main(["--output", out, "--vuln-workers", "4"])

        mock_parallel.assert_called_once()
        mock_serial.assert_not_called()

    def test_workers_kwarg_passed_to_parallel_iter(self, tmp_path):
        """The workers= kwarg is forwarded correctly to iter_vulnerabilities_parallel."""
        out = str(tmp_path / "out.json")
        with (
            patch("femur_cli.cli.load_credentials", return_value=CREDS),
            patch("femur_cli._fetchers.iter_applications", return_value=[]),
            patch(
                "femur_cli._fetchers.iter_vulnerabilities_parallel",
                return_value=[],
            ) as mock_parallel,
            patch("femur_cli._fetchers.iter_assessments_by_severity", return_value=[]),
        ):
            main(["--output", out, "--vuln-workers", "8"])

        _, kwargs = mock_parallel.call_args
        assert kwargs.get("workers") == 8

    def test_output_includes_vulns_from_parallel_iter(self, tmp_path):
        """Output JSON contains the records returned by parallel iter."""
        out = str(tmp_path / "out.json")
        with (
            patch("femur_cli.cli.load_credentials", return_value=CREDS),
            patch("femur_cli._fetchers.iter_applications", return_value=[]),
            patch(
                "femur_cli._fetchers.iter_vulnerabilities_parallel",
                return_value=VULNS,
            ),
            patch("femur_cli._fetchers.iter_assessments_by_severity", return_value=[]),
        ):
            main(["--output", out, "--vuln-workers", "2"])

        with open(out) as fh:
            payload = json.load(fh)

        assert payload["vulnerabilities"] == VULNS


class TestAssessmentParallel:
    def test_default_uses_by_severity(self, tmp_path):
        """By default, iter_assessments_by_severity is used (not cross_flat)."""
        out = str(tmp_path / "out.json")
        with (
            patch("femur_cli.cli.load_credentials", return_value=CREDS),
            patch("femur_cli._fetchers.iter_applications", return_value=[]),
            patch("femur_cli._fetchers.iter_vulnerabilities", return_value=[]),
            patch(
                "femur_cli._fetchers.iter_assessments_by_severity",
                return_value=ASSESSMENTS,
            ) as mock_by_sev,
            patch(
                "femur_cli._fetchers.iter_assessments_cross_flat",
                return_value=ASSESSMENTS,
            ) as mock_cross,
        ):
            main(["--output", out])

        mock_by_sev.assert_called_once()
        mock_cross.assert_not_called()

    def test_large_env_flag_uses_cross_flat(self, tmp_path):
        """--assessment-large-env routes through iter_assessments_cross_flat."""
        out = str(tmp_path / "out.json")
        with (
            patch("femur_cli.cli.load_credentials", return_value=CREDS),
            patch("femur_cli._fetchers.iter_applications", return_value=[]),
            patch("femur_cli._fetchers.iter_vulnerabilities", return_value=[]),
            patch(
                "femur_cli._fetchers.iter_assessments_by_severity",
                return_value=ASSESSMENTS,
            ) as mock_by_sev,
            patch(
                "femur_cli._fetchers.iter_assessments_cross_flat",
                return_value=ASSESSMENTS,
            ) as mock_cross,
        ):
            main(["--output", out, "--assessment-large-env"])

        mock_cross.assert_called_once()
        mock_by_sev.assert_not_called()

    def test_large_env_output_contains_assessments(self, tmp_path):
        """Output JSON contains the records returned by cross_flat."""
        out = str(tmp_path / "out.json")
        with (
            patch("femur_cli.cli.load_credentials", return_value=CREDS),
            patch("femur_cli._fetchers.iter_applications", return_value=[]),
            patch("femur_cli._fetchers.iter_vulnerabilities", return_value=[]),
            patch(
                "femur_cli._fetchers.iter_assessments_cross_flat",
                return_value=ASSESSMENTS,
            ),
        ):
            main(["--output", out, "--assessment-large-env"])

        with open(out) as fh:
            payload = json.load(fh)

        assert payload["assessments"] == ASSESSMENTS

    def test_assessment_filter_forwarded_in_large_env_mode(self, tmp_path):
        """--assessment-filter is forwarded to iter_assessments_cross_flat."""
        out = str(tmp_path / "out.json")
        with (
            patch("femur_cli.cli.load_credentials", return_value=CREDS),
            patch("femur_cli._fetchers.iter_applications", return_value=[]),
            patch("femur_cli._fetchers.iter_vulnerabilities", return_value=[]),
            patch(
                "femur_cli._fetchers.iter_assessments_cross_flat",
                return_value=[],
            ) as mock_cross,
        ):
            main([
                "--output", out,
                "--assessment-large-env",
                "--assessment-filter", "finding.status:'fail'",
            ])

        _, kwargs = mock_cross.call_args
        assert kwargs.get("fql_filter") == "finding.status:'fail'"


class TestApplicationParallel:
    def test_default_uses_iter_applications(self, tmp_path):
        """By default iter_applications is used (not the parallel offset strategy)."""
        out = str(tmp_path / "out.json")
        with (
            patch("femur_cli.cli.load_credentials", return_value=CREDS),
            patch(
                "femur_cli._fetchers.iter_applications",
                return_value=APPS,
            ) as mock_serial,
            patch(
                "femur_cli._fetchers.iter_applications_mac_buckets",
                return_value=APPS,
            ) as mock_mac_buckets,
            patch("femur_cli._fetchers.iter_vulnerabilities", return_value=[]),
            patch("femur_cli._fetchers.iter_assessments_by_severity", return_value=[]),
        ):
            main(["--output", out])

        mock_serial.assert_called_once()
        mock_mac_buckets.assert_not_called()

    def test_app_large_env_flag_uses_mac_buckets(self, tmp_path):
        """--app-large-env routes through iter_applications_mac_buckets."""
        out = str(tmp_path / "out.json")
        with (
            patch("femur_cli.cli.load_credentials", return_value=CREDS),
            patch(
                "femur_cli._fetchers.iter_applications",
                return_value=APPS,
            ) as mock_serial,
            patch(
                "femur_cli._fetchers.iter_applications_mac_buckets",
                return_value=APPS,
            ) as mock_mac_buckets,
            patch("femur_cli._fetchers.iter_vulnerabilities", return_value=[]),
            patch("femur_cli._fetchers.iter_assessments_by_severity", return_value=[]),
        ):
            main(["--output", out, "--app-large-env"])

        mock_mac_buckets.assert_called_once()
        mock_serial.assert_not_called()

    def test_app_large_env_output_contains_applications(self, tmp_path):
        """Output JSON applications field matches records from MAC-bucket strategy."""
        out = str(tmp_path / "out.json")
        with (
            patch("femur_cli.cli.load_credentials", return_value=CREDS),
            patch(
                "femur_cli._fetchers.iter_applications_mac_buckets",
                return_value=APPS,
            ),
            patch("femur_cli._fetchers.iter_vulnerabilities", return_value=[]),
            patch("femur_cli._fetchers.iter_assessments_by_severity", return_value=[]),
        ):
            main(["--output", out, "--app-large-env"])

        with open(out) as fh:
            payload = json.load(fh)

        assert payload["applications"] == APPS

    def test_app_filter_forwarded_in_large_env_mode(self, tmp_path):
        """--app-filter is forwarded to iter_applications_mac_buckets."""
        out = str(tmp_path / "out.json")
        with (
            patch("femur_cli.cli.load_credentials", return_value=CREDS),
            patch(
                "femur_cli._fetchers.iter_applications_mac_buckets",
                return_value=[],
            ) as mock_mac_buckets,
            patch("femur_cli._fetchers.iter_vulnerabilities", return_value=[]),
            patch("femur_cli._fetchers.iter_assessments_by_severity", return_value=[]),
        ):
            main([
                "--output", out,
                "--app-large-env",
                "--app-filter", "host.platform_name:'Linux'",
            ])

        _, kwargs = mock_mac_buckets.call_args
        assert kwargs.get("fql_filter") == "host.platform_name:'Linux'"


class TestLargeEnv:
    """--large-env promotes the best-practice large-environment recipe."""

    def test_routes_through_all_large_env_strategies(self, tmp_path):
        """--large-env selects MAC-bucket apps, severity-bucket vulns, cross-flat assessments."""
        out_dir = str(tmp_path / "inv")
        with (
            patch("femur_cli.cli.load_credentials", return_value=CREDS),
            patch(
                "femur_cli._fetchers.iter_applications_mac_buckets", return_value=APPS
            ) as m_mac,
            patch(
                "femur_cli._fetchers.iter_applications", return_value=APPS
            ) as m_app_serial,
            patch(
                "femur_cli._fetchers.iter_vulnerabilities_by_severity", return_value=VULNS
            ) as m_vuln_sev,
            patch(
                "femur_cli._fetchers.iter_assessments_cross_flat", return_value=ASSESSMENTS
            ) as m_asmt_cross,
            patch(
                "femur_cli._fetchers.iter_assessments_by_severity", return_value=ASSESSMENTS
            ) as m_asmt_sev,
        ):
            main(["--large-env", "--skip-host-map", "--output-dir", out_dir])

        m_mac.assert_called_once()
        m_app_serial.assert_not_called()
        m_vuln_sev.assert_called_once()
        m_asmt_cross.assert_called_once()
        m_asmt_sev.assert_not_called()

    def test_defaults_to_jsonl_output(self, tmp_path):
        """Without an explicit --output-format, --large-env streams JSONL files."""
        out_dir = str(tmp_path / "inv")
        with (
            patch("femur_cli.cli.load_credentials", return_value=CREDS),
            patch("femur_cli._fetchers.iter_applications_mac_buckets", return_value=APPS),
            patch("femur_cli._fetchers.iter_vulnerabilities_by_severity", return_value=VULNS),
            patch("femur_cli._fetchers.iter_assessments_cross_flat", return_value=ASSESSMENTS),
        ):
            main(["--large-env", "--skip-host-map", "--output-dir", out_dir])

        assert (tmp_path / "inv" / "applications.jsonl").exists()
        assert (tmp_path / "inv" / "vulnerabilities.jsonl").exists()
        assert (tmp_path / "inv" / "assessments.jsonl").exists()

    def test_explicit_output_format_json_is_respected(self, tmp_path):
        """--large-env --output-format json keeps the monolithic JSON path."""
        out = str(tmp_path / "out.json")
        with (
            patch("femur_cli.cli.load_credentials", return_value=CREDS),
            patch("femur_cli._fetchers.iter_applications_mac_buckets", return_value=APPS),
            patch("femur_cli._fetchers.iter_vulnerabilities_by_severity", return_value=VULNS),
            patch("femur_cli._fetchers.iter_assessments_cross_flat", return_value=ASSESSMENTS),
        ):
            main(["--large-env", "--skip-host-map", "--output-format", "json", "--output", out])

        # Monolithic JSON file written, not a JSONL directory.
        with open(out) as fh:
            payload = json.load(fh)
        assert payload["applications"] == APPS

    def test_skip_host_map_disables_implied_decoration(self, tmp_path):
        """--large-env --skip-host-map leaves decorate-aids off (no host map)."""
        from femur_cli.parser import build_parser
        from femur_cli.cli import _expand_large_env

        args = build_parser().parse_args(["--large-env", "--skip-host-map"])
        _expand_large_env(args)
        assert args.decorate_aids is False
        assert args.app_large_env is True
        assert args.worker_by_severity is True
        assert args.assessment_large_env is True
        assert args.output_format == "jsonl"

    def test_enables_decoration_when_host_map_available(self):
        """--large-env alone enables decorate-aids (host map present)."""
        from femur_cli.parser import build_parser
        from femur_cli.cli import _expand_large_env

        args = build_parser().parse_args(["--large-env"])
        _expand_large_env(args)
        assert args.decorate_aids is True


class TestPartialManifest:
    """A streaming dataset that fails mid-stream is flagged partial in the manifest."""

    def test_failed_streaming_dataset_marked_partial(self, tmp_path):
        from femur._exceptions import FalconAPIError

        out_dir = str(tmp_path / "inv")
        with (
            patch("femur_cli.cli.load_credentials", return_value=CREDS),
            patch("femur_cli._fetchers.iter_applications", return_value=APPS),
            patch("femur_cli._fetchers.iter_vulnerabilities", return_value=VULNS),
            patch(
                "femur_cli._fetchers.iter_assessments_by_severity",
                side_effect=FalconAPIError("query_combined_assessments", 204, []),
            ),
        ):
            main(["--output-format", "jsonl", "--skip-host-map", "--output-dir", out_dir])

        with open(tmp_path / "inv" / "manifest.json") as fh:
            manifest = json.load(fh)

        assert manifest["partial"] == ["assessments"]
        assert any(e["dataset"] == "assessments" for e in manifest["errors"])

    def test_no_partial_key_when_all_succeed(self, tmp_path):
        out_dir = str(tmp_path / "inv")
        with (
            patch("femur_cli.cli.load_credentials", return_value=CREDS),
            patch("femur_cli._fetchers.iter_applications", return_value=APPS),
            patch("femur_cli._fetchers.iter_vulnerabilities", return_value=VULNS),
            patch("femur_cli._fetchers.iter_assessments_by_severity", return_value=ASSESSMENTS),
        ):
            main(["--output-format", "jsonl", "--skip-host-map", "--output-dir", out_dir])

        with open(tmp_path / "inv" / "manifest.json") as fh:
            manifest = json.load(fh)

        assert "partial" not in manifest
        assert "errors" not in manifest

    def test_compressed_by_aid_implies_bucket_by_aid(self, tmp_path):
        """--compressed-by-aid alone routes into by_aid/ and produces per-AID zips.

        Regression: previously this flag was silently ignored without an
        explicit --bucket-by-aid, yielding flat uncompressed output.
        """
        out_dir = str(tmp_path / "inv")
        with (
            patch("femur_cli.cli.load_credentials", return_value=CREDS),
            patch("femur_cli._fetchers.iter_applications", return_value=APPS),
            patch("femur_cli._fetchers.iter_vulnerabilities", return_value=VULNS),
            patch("femur_cli._fetchers.iter_assessments_by_severity", return_value=ASSESSMENTS),
        ):
            main([
                "--output-format", "jsonl", "--skip-host-map",
                "--output-dir", out_dir, "--compressed-by-aid",
            ])

        by_aid = tmp_path / "inv" / "by_aid"
        assert by_aid.is_dir(), "by_aid/ directory should exist"
        # Per-AID archives, not flat directories.
        zips = list(by_aid.glob("*.zip"))
        assert zips, "expected at least one per-AID .zip archive"
        # No uncompressed per-AID directories should remain.
        assert not any(p.is_dir() for p in by_aid.iterdir())


class TestWorkspaceDefaults:
    """WORKSPACE=true in .env auto-fills --output-dir and --log-file."""

    @pytest.fixture(autouse=True)
    def _clear_ws_env(self, monkeypatch):
        monkeypatch.delenv("WORKSPACE", raising=False)
        yield

    def _make_workspace(self, tmp_path, workspace=True):
        """Build a workspace dir with .env, data/, logs/ and return its path."""
        ws = tmp_path / "ws"
        ws.mkdir()
        (ws / "data").mkdir()
        (ws / "logs").mkdir()
        flag = "WORKSPACE=true\n" if workspace else ""
        (ws / ".env").write_text(f"CLIENT_ID=x\nCLIENT_SECRET=y\n{flag}")
        return ws

    def test_output_dir_and_log_file_default_into_workspace(self, tmp_path):
        ws = self._make_workspace(tmp_path)
        env_file = str(ws / ".env")
        with (
            patch("femur_cli.cli.load_credentials", return_value=CREDS),
            patch("femur_cli.cli._setup_logging") as mock_logging,
            patch("femur_cli._fetchers.iter_applications", return_value=APPS),
            patch("femur_cli._fetchers.iter_vulnerabilities", return_value=VULNS),
            patch("femur_cli._fetchers.iter_assessments_by_severity", return_value=ASSESSMENTS),
        ):
            main(["--env-file", env_file, "--output-format", "jsonl", "--skip-host-map"])

        # Output landed in the workspace data/ dir.
        assert (ws / "data" / "manifest.json").exists()
        # Logging was configured with a timestamped path under logs/.
        _, kwargs = mock_logging.call_args
        log_file = kwargs["log_file"]
        assert log_file is not None
        assert log_file.startswith(str(ws / "logs"))
        assert os.path.basename(log_file).startswith("femur-")
        assert log_file.endswith(".log")

    def test_explicit_output_dir_overrides_workspace(self, tmp_path):
        ws = self._make_workspace(tmp_path)
        env_file = str(ws / ".env")
        explicit = str(tmp_path / "elsewhere")
        with (
            patch("femur_cli.cli.load_credentials", return_value=CREDS),
            patch("femur_cli._fetchers.iter_applications", return_value=APPS),
            patch("femur_cli._fetchers.iter_vulnerabilities", return_value=VULNS),
            patch("femur_cli._fetchers.iter_assessments_by_severity", return_value=ASSESSMENTS),
        ):
            main([
                "--env-file", env_file, "--output-format", "jsonl",
                "--skip-host-map", "--output-dir", explicit,
            ])

        assert (tmp_path / "elsewhere" / "manifest.json").exists()
        assert not (ws / "data" / "manifest.json").exists()

    def test_no_logs_dir_means_no_auto_log(self, tmp_path):
        ws = self._make_workspace(tmp_path)
        # Remove logs/ so auto-logging must be skipped (never created here).
        (ws / "logs").rmdir()
        env_file = str(ws / ".env")
        with (
            patch("femur_cli.cli.load_credentials", return_value=CREDS),
            patch("femur_cli._fetchers.iter_applications", return_value=APPS),
            patch("femur_cli._fetchers.iter_vulnerabilities", return_value=VULNS),
            patch("femur_cli._fetchers.iter_assessments_by_severity", return_value=ASSESSMENTS),
        ):
            main(["--env-file", env_file, "--output-format", "jsonl", "--skip-host-map"])

        # data/ still used, but logs/ was not resurrected.
        assert (ws / "data" / "manifest.json").exists()
        assert not (ws / "logs").exists()

    def test_non_workspace_env_does_not_default(self, tmp_path):
        ws = self._make_workspace(tmp_path, workspace=False)
        env_file = str(ws / ".env")
        out_dir = str(tmp_path / "explicit_out")
        with (
            patch("femur_cli.cli.load_credentials", return_value=CREDS),
            patch("femur_cli._fetchers.iter_applications", return_value=APPS),
            patch("femur_cli._fetchers.iter_vulnerabilities", return_value=VULNS),
            patch("femur_cli._fetchers.iter_assessments_by_severity", return_value=ASSESSMENTS),
        ):
            main([
                "--env-file", env_file, "--output-format", "jsonl",
                "--skip-host-map", "--output-dir", out_dir,
            ])

        # Without WORKSPACE=true, data/ is untouched and no auto log appears.
        assert not (ws / "data" / "manifest.json").exists()
        assert not list((ws / "logs").glob("femur-*.log"))


class TestParserGrouping:
    """Guard against a botched argument-group refactor."""

    def test_large_env_flag_parses(self):
        from femur_cli.parser import build_parser

        args = build_parser().parse_args(["--large-env"])
        assert args.large_env is True

    def test_output_format_default_is_none_sentinel(self):
        from femur_cli.parser import build_parser

        # Parser leaves output_format as None so the CLI can detect an
        # explicit override; _expand_large_env resolves it.
        args = build_parser().parse_args([])
        assert args.output_format is None

    def test_all_known_flags_still_parse(self):
        from femur_cli.parser import build_parser

        args = build_parser().parse_args([
            "--env-file", "x.env", "--output", "o.json",
            "--output-format", "xml", "--output-dir", "d",
            "--app-filter", "a", "--vuln-filter", "v", "--assessment-filter", "s",
            "--host-groups", "G", "--tags", "T",
            "--large-env", "--app-large-env", "--worker-by-severity",
            "--vuln-workers", "8", "--assessment-large-env",
            "--decorate-aids", "--iavm-file", "i.xml", "--assessment-evidence",
            "--vuln-facet", "cve", "--no-assessment-compliance-mapping",
            "--skip-host-map", "--bucket-by-aid", "--compress",
            "--compressed-by-aid", "--indent", "0", "--verbose",
            "--log-file", "l.log",
        ])
        assert args.output_format == "xml"
        assert args.vuln_workers == 8
        assert args.assessment_compliance_mapping is False
        assert args.compressed is True

