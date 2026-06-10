"""Tests for CPE generation module and CpeDecoratorTransform."""

import pytest

from femur_pipeline.cpe import (
    escape_cpe_component,
    generate_cpe,
    generate_cpe_for_record,
    normalize_product,
    normalize_vendor,
    normalize_version,
)
from femur_pipeline.transforms import CpeDecoratorTransform


# ---------------------------------------------------------------------------
# Vendor normalization
# ---------------------------------------------------------------------------


class TestNormalizeVendor:
    def test_corporate_suffix_stripped(self):
        assert normalize_vendor("Microsoft Corporation") == "microsoft"
        assert normalize_vendor("Rapid7 Inc") == "rapid7"
        assert normalize_vendor("Rapid7, LLC.") == "rapid7"

    def test_alias_resolution(self):
        assert normalize_vendor("Red Hat, Inc.") == "redhat"
        assert normalize_vendor("Oracle America") == "oracle"
        assert normalize_vendor("Adobe Systems Incorporated") == "adobe"
        assert normalize_vendor("Amazon Web Services") == "amazon"

    def test_email_stripped(self):
        assert normalize_vendor("docs-hosted-app-own@google.com") == "google"

    def test_debian_maintainer_returns_empty(self):
        assert normalize_vendor("Joe Dev <joe@ubuntu.com>") == ""
        assert normalize_vendor("Pkg Team <team@lists.ubuntu.com>") == ""

    def test_none_vendor(self):
        assert normalize_vendor("(none)") == ""

    def test_empty_string(self):
        assert normalize_vendor("") == ""

    def test_unknown_vendor_passthrough(self):
        assert normalize_vendor("Acme Corp") == "acme_corp"

    def test_spaces_become_underscores(self):
        assert normalize_vendor("Some Vendor Name") == "some_vendor_name"


# ---------------------------------------------------------------------------
# Product normalization
# ---------------------------------------------------------------------------


class TestNormalizeProduct:
    def test_architecture_paren_stripped(self):
        assert normalize_product("Chrome (x64)", "google") == "chrome"

    def test_version_suffix_stripped(self):
        assert normalize_product("App_v2.1.0", "acme") == "app"
        assert normalize_product("Tool_3.5", "acme") == "tool"

    def test_microsoft_prefix_stripped(self):
        assert normalize_product("Microsoft Edge", "microsoft") == "edge"

    def test_apple_app_suffix_stripped(self):
        assert normalize_product("Safari.app", "apple") == "safari"

    def test_linux_arch_suffix_stripped(self):
        assert normalize_product("openssl-amd64", "redhat") == "openssl"
        assert normalize_product("curl-x86_64", "centos") == "curl"

    def test_linux_package_prefix_stripped(self):
        assert normalize_product("python3-requests", "debian") == "requests"
        assert normalize_product("perl-Net-SSLeay", "redhat") == "net-ssleay"

    def test_linux_package_suffix_stripped(self):
        assert normalize_product("openssh-server", "redhat") == "openssh"
        assert normalize_product("openssl-libs", "centos") == "openssl"

    def test_product_alias(self):
        assert normalize_product("Falcon Sensor", "crowdstrike") == "falcon"
        assert normalize_product("Global Protect", "paloaltonetworks") == "globalprotect"
        assert normalize_product("Chrome Installer", "google") == "chrome"

    def test_empty_string(self):
        assert normalize_product("", "microsoft") == ""

    def test_hash_paren_stripped(self):
        assert normalize_product("App (a1b2c3d4)", "acme") == "app"

    def test_non_linux_vendor_keeps_suffixes(self):
        # Non-Linux vendors don't get package suffix stripping
        assert normalize_product("openssh-server", "acme") == "openssh-server"


# ---------------------------------------------------------------------------
# Version normalization
# ---------------------------------------------------------------------------


class TestNormalizeVersion:
    def test_normal_version(self):
        assert normalize_version("1.2.3") == "1.2.3"

    def test_build_metadata_stripped(self):
        assert normalize_version("1.2.3+build456") == "1.2.3"

    def test_empty_returns_wildcard(self):
        assert normalize_version("") == "*"
        assert normalize_version(None) == "*"

    def test_whitespace_stripped(self):
        assert normalize_version("  3.0.1  ") == "3.0.1"


# ---------------------------------------------------------------------------
# CPE component escaping
# ---------------------------------------------------------------------------


class TestEscapeCpeComponent:
    def test_wildcard_passthrough(self):
        assert escape_cpe_component("*") == "*"

    def test_dash_passthrough(self):
        assert escape_cpe_component("-") == "-"

    def test_empty_becomes_wildcard(self):
        assert escape_cpe_component("") == "*"

    def test_special_chars_escaped(self):
        assert escape_cpe_component("c++") == "c\\+\\+"
        assert escape_cpe_component("a:b") == "a\\:b"

    def test_normal_chars_unescaped(self):
        assert escape_cpe_component("openssl") == "openssl"
        assert escape_cpe_component("python3.11") == "python3.11"


# ---------------------------------------------------------------------------
# CPE URI generation
# ---------------------------------------------------------------------------


class TestGenerateCpe:
    def test_basic_application_cpe(self):
        cpe = generate_cpe("microsoft", "edge", "120.0.1")
        assert cpe == "cpe:2.3:a:microsoft:edge:120.0.1:*:*:*:*:*:*:*"

    def test_wildcard_version(self):
        cpe = generate_cpe("google", "chrome", "*")
        assert cpe == "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*"

    def test_empty_vendor_becomes_wildcard(self):
        cpe = generate_cpe("", "curl", "7.88.1")
        assert cpe == "cpe:2.3:a:*:curl:7.88.1:*:*:*:*:*:*:*"

    def test_special_chars_escaped(self):
        cpe = generate_cpe("don_ho", "notepad\\+\\+", "8.5.1")
        assert "notepad" in cpe

    def test_os_part(self):
        cpe = generate_cpe("microsoft", "windows_10", "21H2", part="o")
        assert cpe.startswith("cpe:2.3:o:")


# ---------------------------------------------------------------------------
# generate_cpe_for_record (high-level)
# ---------------------------------------------------------------------------


class TestGenerateCpeForRecord:
    def test_normalized_mode(self):
        record = {"vendor": "Microsoft Corporation", "name": "Edge", "version": "120.0.1"}
        result = generate_cpe_for_record(record, normalize=True)
        assert result["cpe"] == "cpe:2.3:a:microsoft:edge:120.0.1:*:*:*:*:*:*:*"
        assert result["cpe_match_type"] == "generated"

    def test_raw_mode(self):
        record = {"vendor": "Acme Inc", "name": "My Tool", "version": "2.0"}
        result = generate_cpe_for_record(record, normalize=False)
        assert result["cpe"] == "cpe:2.3:a:acme_inc:my_tool:2.0:*:*:*:*:*:*:*"

    def test_vendor_override_applied(self):
        record = {"vendor": "Microsoft Corporation", "name": "Chrome", "version": "120.0"}
        result = generate_cpe_for_record(record, normalize=True)
        # Microsoft + Chrome → vendor overridden to google
        assert "google" in result["cpe"]
        assert "chrome" in result["cpe"]

    def test_no_vendor_no_product_returns_none(self):
        record = {"vendor": "", "name": "", "version": "1.0"}
        result = generate_cpe_for_record(record, normalize=True)
        assert result is None

    def test_missing_version_uses_wildcard(self):
        record = {"vendor": "Google", "name": "Chrome"}
        result = generate_cpe_for_record(record, normalize=False)
        assert ":*:*:*:*:*:*:*:*" in result["cpe"]

    def test_product_alias_applied(self):
        record = {"vendor": "CrowdStrike", "name": "Falcon Sensor", "version": "7.0"}
        result = generate_cpe_for_record(record, normalize=True)
        assert "falcon" in result["cpe"]
        assert "falcon_sensor" not in result["cpe"]


# ---------------------------------------------------------------------------
# CpeDecoratorTransform
# ---------------------------------------------------------------------------


class TestCpeDecoratorTransform:
    def test_decorates_application_record(self):
        t = CpeDecoratorTransform(normalize=True)
        rec = {"vendor": "Google", "name": "Chrome", "version": "120.0.1"}
        result = t(rec, "applications")
        assert "cpe" in result
        assert result["cpe_match_type"] == "generated"
        assert "google" in result["cpe"]
        assert "chrome" in result["cpe"]

    def test_passthrough_non_application(self):
        t = CpeDecoratorTransform()
        rec = {"id": "vuln-1", "cve": "CVE-2024-1234"}
        result = t(rec, "vulnerabilities")
        assert result == rec
        assert "cpe" not in result

    def test_record_without_vendor_product_still_returned(self):
        """Records with no vendor/product should still pass through (not dropped)."""
        t = CpeDecoratorTransform()
        rec = {"vendor": "", "name": "", "version": "1.0"}
        result = t(rec, "applications")
        # Record is returned (not None) but without CPE since there's nothing to generate
        assert result is not None
        assert "cpe" not in result

    def test_normalize_false(self):
        t = CpeDecoratorTransform(normalize=False)
        rec = {"vendor": "My Vendor", "name": "My App", "version": "3.0"}
        result = t(rec, "applications")
        assert result["cpe"] == "cpe:2.3:a:my_vendor:my_app:3.0:*:*:*:*:*:*:*"

    def test_existing_fields_preserved(self):
        t = CpeDecoratorTransform()
        rec = {"vendor": "Google", "name": "Chrome", "version": "120.0", "host": {"id": "h1"}}
        result = t(rec, "applications")
        assert result["host"] == {"id": "h1"}
        assert "cpe" in result
