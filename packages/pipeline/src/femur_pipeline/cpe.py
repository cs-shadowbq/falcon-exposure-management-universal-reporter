"""CPE 2.3 URI generation from Falcon Discover application records.

Pure normalization and generation — no database, no fuzzy matching, no NVD
index.  Normalizes vendor/product/version strings and builds well-formed CPE
2.3 URIs suitable for downstream compliance systems.

The normalization tables and regex patterns are extracted from the standalone
``cpe-gen.py`` prototype and represent CrowdStrike-specific vendor/product
quirks observed across real Falcon Discover inventory data.
"""

import re
from typing import Dict, FrozenSet, Optional, Tuple

# ---------------------------------------------------------------------------
# Vendor normalization
# ---------------------------------------------------------------------------

_VENDOR_SUFFIX_RE = re.compile(
    r",?\s*(?:Corporation|Inc\.?|LLC\.?|Ltd\.?|and/or its affiliates)\s*$",
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(r"\s*<[^>]+>\s*")
_MAINTAINER_RE = re.compile(
    r"^[\w\s.-]+<[\w.+-]+@(?:ubuntu|debian|lists\.ubuntu)\.(?:com|org)>$"
)

VENDOR_ALIASES: Dict[str, str] = {
    "microsoft_corporation": "microsoft",
    "oracle_and/or_its_affiliates": "oracle",
    "oracle_america": "oracle",
    "rapid7_inc": "rapid7",
    "rapid7,_llc.": "rapid7",
    "red_hat,_inc.": "redhat",
    "red_hat": "redhat",
    "mozilla.org": "mozilla",
    "screenconnect_software": "connectwise",
    "shining_light_productions": "openssl",
    "palo_alto_networks": "paloaltonetworks",
    "docs-hosted-app-own@google.com": "google",
    "notepad++": "don_ho",
    "apple_(signed)": "apple",
    "amazon_linux": "amazon",
    "amazon.com": "amazon",
    "amazon_web_services": "amazon",
    "rocky_enterprise_software_foundation": "rockylinux",
    "python_software_foundation": "python",
    "azure_container_upstream": "microsoft",
    "blobfuse_v-team": "microsoft",
    "azure_storage_xnfs_team": "microsoft",
    "rocky": "rockylinux",
    "fedora_project": "fedoraproject",
    "sun_microsystems": "sun",
    "adobe_systems_incorporated": "adobe",
    "(none)": "",
}

# Some products are reported under the wrong vendor in Falcon Discover.
# Maps (normalized_vendor, normalized_product) -> corrected vendor.
VENDOR_OVERRIDES: Dict[Tuple[str, str], str] = {
    ("microsoft", "chrome"): "google",
    ("microsoft", "chrome_installer"): "google",
    ("microsoft", "google_updater"): "google",
    ("microsoft", "google_installer"): "google",
}


def normalize_vendor(raw: str) -> str:
    """Normalize a raw vendor string to a CPE-friendly form."""
    if not raw:
        return ""
    if _MAINTAINER_RE.match(raw.strip()):
        return ""
    v = _EMAIL_RE.sub("", raw).strip()
    v = _VENDOR_SUFFIX_RE.sub("", v).strip()
    v = v.lower().replace(" ", "_")
    v = v.rstrip("_").rstrip(",").rstrip("_")
    return VENDOR_ALIASES.get(v, v)


# ---------------------------------------------------------------------------
# Product normalization
# ---------------------------------------------------------------------------

_VERSION_PREFIX_RE = re.compile(r"\s*-\s*[\d.].*$")
_PRODUCT_VERSION_SUFFIX_RE = re.compile(r"_v?\d+(?:\.\d+)*(?:_\(.*\))?$")
_PAREN_ARCH_RE = re.compile(r"\s*\([^)]*\b(?:x64|x86|arm64|amd64)\b[^)]*\)\s*")
_PAREN_HASH_RE = re.compile(r"\s*\([0-9a-f]+\)\s*$")
_MICROSOFT_PREFIX_RE = re.compile(r"^microsoft_")
_APP_SUFFIX_RE = re.compile(r"\.app$")
_ARCH_SUFFIX_RE = re.compile(
    r"-(?:amd64|x86_64|arm64|aarch64|i386|i686|noarch|ppc64le|s390x)$"
)
_LINUX_PKG_PREFIX_RE = re.compile(r"^(?:python3?(?:\.\d+)?|perl|rubygem)-")
_LINUX_PKG_SUFFIX_RE = re.compile(
    r"-(?:server|client|libs|lib|libelf|common|dev|devel|utils|tools|bin|data|doc"
    r"|modules|headers|image|cloud-tools|runtime|event|extra|extras|base|plugins"
    r"|minimal|core|firmware|whence)$"
)

_IS_LINUX_VENDOR: FrozenSet[str] = frozenset((
    "redhat", "centos", "rockylinux", "amazon", "",
    "debian", "ubuntu", "suse", "fedora", "fedoraproject",
    "oracle", "sun", "docker",
))

PRODUCT_ALIASES: Dict[Tuple[str, str], str] = {
    ("microsoft", "defender_signature"): "windows_defender_security_intelligence_updates",
    ("microsoft", "defender_engine"): "windows_defender",
    ("microsoft", "malware_protection"): "windows_defender",
    ("crowdstrike", "falcon_sensor"): "falcon",
    ("paloaltonetworks", "global_protect"): "globalprotect",
    ("google", "chrome_installer"): "chrome",
    ("google", "google_updater"): "chrome",
    ("google", "google_installer"): "chrome",
}


def normalize_product(raw: str, vendor: str) -> str:
    """Normalize a raw product name using vendor-specific rules."""
    if not raw:
        return ""
    p = _PAREN_ARCH_RE.sub("", raw).strip()
    p = _PAREN_HASH_RE.sub("", p).strip()
    p = _VERSION_PREFIX_RE.sub("", p).strip()
    p = p.lower().replace(" ", "_")
    if vendor == "apple":
        p = _APP_SUFFIX_RE.sub("", p)
    if vendor == "microsoft":
        p = _MICROSOFT_PREFIX_RE.sub("", p)
    if vendor in _IS_LINUX_VENDOR:
        # Strip arch suffix BEFORE version suffix to avoid _64 in x86_64
        # being misidentified as a version number.
        p = _ARCH_SUFFIX_RE.sub("", p)
        p = _LINUX_PKG_PREFIX_RE.sub("", p)
        p = _LINUX_PKG_SUFFIX_RE.sub("", p)
    p = _PRODUCT_VERSION_SUFFIX_RE.sub("", p)
    alias = PRODUCT_ALIASES.get((vendor, p))
    return alias if alias else p


# ---------------------------------------------------------------------------
# Version normalization
# ---------------------------------------------------------------------------


def normalize_version(raw: str) -> str:
    """Normalize a version string, stripping build metadata."""
    if not raw:
        return "*"
    v = raw.strip()
    if "+" in v:
        v = v.split("+")[0]
    return v if v else "*"


# ---------------------------------------------------------------------------
# CPE 2.3 URI construction
# ---------------------------------------------------------------------------

# Characters that must be escaped in a CPE 2.3 formatted string component.
_CPE_SPECIAL_CHARS = frozenset(
    "\\!\"#$%&'()+,/:;<=>@[]^`{|}~"
)


def escape_cpe_component(value: str) -> str:
    """Escape special characters in a CPE 2.3 component per the spec."""
    if value in ("*", "-", ""):
        return value if value else "*"
    out = []
    for ch in value:
        if ch in _CPE_SPECIAL_CHARS:
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


def generate_cpe(
    vendor: str,
    product: str,
    version: str,
    part: str = "a",
) -> str:
    """Build a CPE 2.3 URI from normalized components.

    Parameters
    ----------
    vendor : str
        Normalized vendor name.
    product : str
        Normalized product name.
    version : str
        Normalized version string (``"*"`` if unknown).
    part : str
        CPE part indicator: ``"a"`` (application), ``"o"`` (OS), ``"h"`` (HW).
    """
    return ":".join([
        "cpe", "2.3", part,
        escape_cpe_component(vendor or "*"),
        escape_cpe_component(product or "*"),
        escape_cpe_component(version),
        "*", "*", "*", "*", "*", "*", "*",
    ])


# ---------------------------------------------------------------------------
# High-level record processing
# ---------------------------------------------------------------------------


def generate_cpe_for_record(
    record: dict,
    normalize: bool = True,
) -> Optional[dict]:
    """Compute CPE fields for an application record.

    Returns a dict with ``cpe`` and ``cpe_match_type`` keys, or ``None``
    if the record lacks both vendor and product name.

    Parameters
    ----------
    record : dict
        A Falcon Discover application record containing ``vendor``,
        ``name``, and ``version`` fields.
    normalize : bool
        When ``True`` (default), applies alias resolution, suffix stripping,
        and vendor override corrections.  When ``False``, uses raw values
        lowercased with spaces replaced by underscores.
    """
    raw_vendor = record.get("vendor", "")
    raw_name = record.get("name", "")
    raw_version = record.get("version", "")

    if normalize:
        vendor = normalize_vendor(raw_vendor)
        product = normalize_product(raw_name, vendor)
        vendor = VENDOR_OVERRIDES.get((vendor, product), vendor)
        version = normalize_version(raw_version)
    else:
        vendor = raw_vendor.strip().lower().replace(" ", "_") if raw_vendor else ""
        product = raw_name.strip().lower().replace(" ", "_") if raw_name else ""
        version = raw_version.strip() if raw_version else "*"
        if not version:
            version = "*"

    # Skip records with no meaningful product information
    if not vendor and not product:
        return None

    return {
        "cpe": generate_cpe(vendor, product, version),
        "cpe_match_type": "generated",
    }
