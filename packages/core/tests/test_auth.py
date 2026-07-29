import os

import pytest

from femur._auth import load_credentials, detect_workspace


class TestLoadCredentials:
    def test_reads_values_from_env_file(self, tmp_path, monkeypatch):
        env_file = tmp_path / ".env"
        env_file.write_text("CLIENT_ID=myid\nCLIENT_SECRET=mysecret\nBASE_URL=EU1\n")
        # Isolate from any ambient env so file values are visible.
        monkeypatch.delenv("CLIENT_ID", raising=False)
        monkeypatch.delenv("CLIENT_SECRET", raising=False)
        monkeypatch.delenv("BASE_URL", raising=False)

        creds = load_credentials(env_file=str(env_file))

        assert creds["client_id"] == "myid"
        assert creds["client_secret"] == "mysecret"
        assert creds["base_url"] == "EU1"

    def test_base_url_defaults_to_us1_when_absent(self, tmp_path, monkeypatch):
        env_file = tmp_path / ".env"
        env_file.write_text("CLIENT_ID=x\nCLIENT_SECRET=y\n")
        monkeypatch.delenv("CLIENT_ID", raising=False)
        monkeypatch.delenv("CLIENT_SECRET", raising=False)
        monkeypatch.delenv("BASE_URL", raising=False)

        creds = load_credentials(env_file=str(env_file))

        assert creds["base_url"] == "US1"

    def test_env_var_takes_priority_over_file(self, tmp_path, monkeypatch):
        env_file = tmp_path / ".env"
        env_file.write_text("CLIENT_ID=file_id\nCLIENT_SECRET=file_secret\nBASE_URL=EU1\n")
        monkeypatch.setenv("CLIENT_ID", "env_id")
        monkeypatch.setenv("CLIENT_SECRET", "env_secret")
        monkeypatch.setenv("BASE_URL", "US2")

        creds = load_credentials(env_file=str(env_file))

        assert creds["client_id"] == "env_id"
        assert creds["client_secret"] == "env_secret"
        assert creds["base_url"] == "US2"

    def test_returns_dict_with_required_keys(self, tmp_path, monkeypatch):
        env_file = tmp_path / ".env"
        env_file.write_text("")
        monkeypatch.delenv("CLIENT_ID", raising=False)
        monkeypatch.delenv("CLIENT_SECRET", raising=False)
        monkeypatch.delenv("BASE_URL", raising=False)

        creds = load_credentials(env_file=str(env_file))

        assert set(creds.keys()) == {"client_id", "client_secret", "base_url"}

    def test_works_without_env_file_argument(self, monkeypatch):
        monkeypatch.setenv("CLIENT_ID", "direct_id")
        monkeypatch.setenv("CLIENT_SECRET", "direct_secret")
        monkeypatch.setenv("BASE_URL", "US2")

        creds = load_credentials()

        assert creds["client_id"] == "direct_id"
        assert creds["client_secret"] == "direct_secret"
        assert creds["base_url"] == "US2"


class TestDetectWorkspace:
    @pytest.fixture(autouse=True)
    def _clear_env(self, monkeypatch):
        # Isolate from any ambient WORKSPACE so file values drive the test.
        monkeypatch.delenv("WORKSPACE", raising=False)
        yield

    def test_true_in_env_returns_root(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("CLIENT_ID=x\nCLIENT_SECRET=y\nWORKSPACE=true\n")

        root = detect_workspace(env_file=str(env_file))

        assert root == str(tmp_path)

    def test_root_is_env_dir_when_run_from_subdir(self, tmp_path, monkeypatch):
        """Running from a nested dir still resolves the .env's directory."""
        env_file = tmp_path / ".env"
        env_file.write_text("WORKSPACE=true\n")
        subdir = tmp_path / "sub" / "deeper"
        subdir.mkdir(parents=True)
        monkeypatch.chdir(subdir)

        # No explicit env_file → upward walk from cwd finds tmp_path/.env.
        root = detect_workspace()

        assert root == str(tmp_path)

    def test_false_returns_none(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("WORKSPACE=false\n")

        assert detect_workspace(env_file=str(env_file)) is None

    def test_absent_flag_returns_none(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("CLIENT_ID=x\n")

        assert detect_workspace(env_file=str(env_file)) is None

    def test_missing_file_returns_none(self, tmp_path):
        assert detect_workspace(env_file=str(tmp_path / "nope.env")) is None

    def test_shell_env_overrides_file_false(self, tmp_path, monkeypatch):
        env_file = tmp_path / ".env"
        env_file.write_text("WORKSPACE=false\n")
        monkeypatch.setenv("WORKSPACE", "true")

        assert detect_workspace(env_file=str(env_file)) == str(tmp_path)

    def test_shell_env_false_overrides_file_true(self, tmp_path, monkeypatch):
        env_file = tmp_path / ".env"
        env_file.write_text("WORKSPACE=true\n")
        monkeypatch.setenv("WORKSPACE", "0")

        assert detect_workspace(env_file=str(env_file)) is None

    def test_truthy_variants(self, tmp_path):
        for val in ("1", "yes", "ON", "True"):
            env_file = tmp_path / ".env"
            env_file.write_text(f"WORKSPACE={val}\n")
            assert detect_workspace(env_file=str(env_file)) == str(tmp_path)

