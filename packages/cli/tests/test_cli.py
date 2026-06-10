import json
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

        mock_setup.assert_called_once_with(verbose=True, log_file=None)

    def test_log_file_flag_calls_setup_logging_with_path(self, tmp_path):
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

        mock_setup.assert_called_once_with(verbose=False, log_file=log_path)

    def test_setup_logging_creates_log_file(self, tmp_path):
        """_setup_logging (real, not mocked) writes to the log file."""
        log_path = str(tmp_path / "test.log")
        _real_setup_logging(verbose=False, log_file=log_path)

        import logging
        logging.getLogger("femur").warning("test log entry")

        with open(log_path) as fh:
            content = fh.read()

        assert "test log entry" in content

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
