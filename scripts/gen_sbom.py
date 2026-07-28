#!/usr/bin/env python3
"""Generate a CycloneDX 1.5 SBOM from a directory of bundled wheels.

Used by scripts/build-airgap.sh. Reads each wheel's METADATA to build the
component list, then emits a CycloneDX document describing the application and
all bundled dependencies.

By default every .whl in <wheels_dir> is included. Pass --only with a
comma-separated list of wheel filenames to restrict the SBOM to a subset (e.g.
the CLI-only install closure), so the SBOM reflects what is actually deployed
rather than everything present in the bundle.

Usage:
    gen_sbom.py <wheels_dir> <output_sbom_json> <app_version> [--only a.whl,b.whl]
"""
import datetime
import email.parser
import json
import os
import sys
import zipfile


def build_components(wheels_dir: str, only: set = None) -> list:
    components = []
    for fname in sorted(os.listdir(wheels_dir)):
        if not fname.endswith(".whl"):
            continue
        if only is not None and fname not in only:
            continue
        whl_path = os.path.join(wheels_dir, fname)
        with zipfile.ZipFile(whl_path) as zf:
            metadata_files = [n for n in zf.namelist() if n.endswith("/METADATA")]
            if not metadata_files:
                continue
            with zf.open(metadata_files[0]) as mf:
                meta = email.parser.BytesParser().parsebytes(mf.read())
        # email.parser may return Header objects (RFC 2047) rather than str for
        # some fields; coerce everything to str so the SBOM stays JSON-serializable.
        name = str(meta.get("Name", ""))
        version = str(meta.get("Version", ""))
        purl = f"pkg:pypi/{name.lower()}@{version}"
        component = {
            "type": "library",
            "name": name,
            "version": version,
            "purl": purl,
            "bom-ref": purl,
        }
        license_val = str(meta.get("License-Expression") or "")
        if not license_val or len(license_val) > 80:
            # Fallback: try Classifier for SPDX-style short identifiers
            classifiers = meta.get_all("Classifier") or []
            for c in classifiers:
                c = str(c)
                if c.startswith("License :: OSI Approved ::"):
                    license_val = c.split("::")[-1].strip()
                    break
        if not license_val:
            license_val = str(meta.get("License", ""))
        if license_val and license_val.strip() and license_val.strip() != "UNKNOWN":
            # Truncate full license texts to just the first line (likely the name)
            short = license_val.strip().split("\n")[0].strip()
            if len(short) <= 80:
                component["licenses"] = [{"expression": short}]
            else:
                component["licenses"] = [{"license": {"name": short[:200]}}]
        author = str(meta.get("Author") or meta.get("Author-email", "") or "")
        if author:
            component["author"] = author
        # Add the wheel filename as evidence of what's bundled
        component["evidence"] = {
            "identity": {
                "field": "filename",
                "methods": [{"technique": "filename", "value": fname}],
            }
        }
        components.append(component)
    return components


def main(wheels_dir: str, out_path: str, app_version: str, only: set = None) -> int:
    components = build_components(wheels_dir, only=only)
    sbom = {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "component": {
                "type": "application",
                "name": "femur",
                "version": app_version,
                "purl": f"pkg:pypi/femur-cli@{app_version}",
                "bom-ref": f"pkg:pypi/femur-cli@{app_version}",
            },
            "tools": [{"name": "build-airgap.sh", "version": app_version}],
        },
        "components": components,
    }
    with open(out_path, "w") as f:
        json.dump(sbom, f, indent=2)
    print(f"  {len(components)} components in {os.path.basename(out_path)}")
    return 0


if __name__ == "__main__":
    args = sys.argv[1:]
    only_set = None
    if "--only" in args:
        i = args.index("--only")
        try:
            only_val = args[i + 1]
        except IndexError:
            sys.exit("--only requires a comma-separated list of wheel filenames")
        only_set = {w.strip() for w in only_val.split(",") if w.strip()}
        del args[i:i + 2]
    if len(args) != 3:
        sys.exit("usage: gen_sbom.py <wheels_dir> <output_sbom_json> <app_version> "
                 "[--only a.whl,b.whl]")
    sys.exit(main(args[0], args[1], args[2], only=only_set))
