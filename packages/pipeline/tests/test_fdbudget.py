"""Tests for file-descriptor budget introspection."""

import errno
import os

import pytest

from femur_pipeline.fdbudget import (
    FdExhaustionError,
    describe_fd_exhaustion,
    fd_limits,
    fd_report,
    format_fd_state,
    is_fd_exhaustion,
    open_fd_count,
    raise_soft_limit,
)

resource = pytest.importorskip("resource")


class TestFdLimits:
    def test_returns_soft_and_hard(self):
        soft, hard = fd_limits()
        assert isinstance(soft, int)
        assert soft > 0
        assert hard == resource.RLIM_INFINITY or hard >= soft

    def test_reports_the_in_process_limit(self):
        """The limit that matters is this process's, not the shell's."""
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        resource.setrlimit(resource.RLIMIT_NOFILE, (256, hard))
        try:
            assert fd_limits()[0] == 256
        finally:
            resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))


class TestOpenFdCount:
    def test_counts_open_descriptors(self):
        before = open_fd_count()
        if before is None:
            pytest.skip("no descriptor table exposed on this platform")
        handles = [open(os.devnull) for _ in range(8)]
        try:
            after = open_fd_count()
        finally:
            for fh in handles:
                fh.close()
        assert after - before == 8

    def test_excludes_its_own_listing_descriptor(self):
        """Two consecutive calls must agree — the listdir fd is subtracted."""
        count = open_fd_count()
        if count is None:
            pytest.skip("no descriptor table exposed on this platform")
        assert open_fd_count() == count


class TestRaiseSoftLimit:
    def test_raises_towards_hard_limit(self):
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        resource.setrlimit(resource.RLIMIT_NOFILE, (256, hard))
        try:
            result = raise_soft_limit()
            assert result is not None
            assert result > 256 or hard == 256
        finally:
            resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))

    def test_is_a_noop_when_already_at_hard_limit(self):
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if hard == resource.RLIM_INFINITY:
            pytest.skip("hard limit is unlimited")
        resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
        try:
            assert raise_soft_limit() == hard
        finally:
            resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))


class TestIsFdExhaustion:
    def test_detects_raw_emfile(self):
        assert is_fd_exhaustion(OSError(errno.EMFILE, "Too many open files"))

    def test_detects_enfile(self):
        assert is_fd_exhaustion(OSError(errno.ENFILE, "Too many open files in system"))

    def test_detects_the_stringified_form_from_an_http_client(self):
        wrapped = RuntimeError(
            "HTTPSConnectionPool(...): Failed to establish a new connection: "
            "[Errno 24] Too many open files"
        )
        assert is_fd_exhaustion(wrapped)

    def test_ignores_unrelated_oserror(self):
        assert not is_fd_exhaustion(OSError(errno.ENOENT, "No such file"))

    def test_ignores_unrelated_exception(self):
        assert not is_fd_exhaustion(ValueError("bad value"))


class TestReporting:
    def test_format_names_the_limit(self):
        text = format_fd_state()
        assert "soft limit" in text

    def test_report_shape(self):
        report = fd_report()
        assert set(report) == {"open_fds", "soft_limit", "hard_limit"}

    def test_description_states_it_is_local_not_remote(self):
        text = describe_fd_exhaustion("writing per-AID output")
        assert "writing per-AID output" in text
        assert "local resource limit" in text
        # The whole point: stop the operator blaming the API.
        assert "not an API failure" in text


class TestFdExhaustionError:
    def test_carries_errno_and_accounting(self):
        exc = FdExhaustionError(context="writing output", path="/tmp/x.jsonl")
        assert exc.errno == errno.EMFILE
        assert exc.path == "/tmp/x.jsonl"
        assert set(exc.fd_state) == {"open_fds", "soft_limit", "hard_limit"}

    def test_message_includes_the_failing_path_and_limits(self):
        exc = FdExhaustionError(context="writing output", path="/tmp/x.jsonl")
        message = str(exc)
        assert "/tmp/x.jsonl" in message
        assert "soft limit" in message

    def test_is_recognised_by_the_detector(self):
        assert is_fd_exhaustion(FdExhaustionError())


class TestUnlimitedLimits:
    """RLIM_INFINITY must not leak into output as a 19-digit integer."""

    def test_format_renders_infinity_as_a_word(self):
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if hard != resource.RLIM_INFINITY:
            pytest.skip("hard limit is finite on this platform")
        text = format_fd_state()
        assert "unlimited" in text
        assert str(resource.RLIM_INFINITY) not in text

    def test_report_reports_infinity_as_none(self):
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if hard != resource.RLIM_INFINITY:
            pytest.skip("hard limit is finite on this platform")
        assert fd_report()["hard_limit"] is None

    def test_raise_soft_limit_never_sets_infinity(self):
        """Setting soft to RLIM_INFINITY is rejected on some platforms and is
        meaningless on others, where the real cap is a sysctl."""
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        resource.setrlimit(resource.RLIMIT_NOFILE, (256, hard))
        try:
            raise_soft_limit()
            new_soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
            assert new_soft != resource.RLIM_INFINITY
            assert new_soft >= 256
        finally:
            resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))
