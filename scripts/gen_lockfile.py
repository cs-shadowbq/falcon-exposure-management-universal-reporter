#!/usr/bin/env python3
"""Generate a hash-pinned pip requirements lockfile from a directory of wheels.

Used by scripts/build-airgap.sh so the offline install can run with
`pip install --require-hashes`. Groups wheels by (name, version) and emits all
SHA256 hashes for each so pip can pick the best-matching file. Covers the
project wheels and every transitive dependency.

By default every .whl in <wheels_dir> is pinned. Pass --only with a
comma-separated list of wheel filenames to restrict the lockfile to a subset
(e.g. the CLI-only install closure), so a reporter-only host installs and
hash-verifies just the wheels it actually needs.

Usage:
    gen_lockfile.py <wheels_dir> <output_lockfile> [--only a.whl,b.whl]
"""
import hashlib
import os
import sys
from collections import defaultdict


def main(wheels_dir: str, out_path: str, only: set = None) -> int:
    groups = defaultdict(list)  # (name, version) -> [sha256, ...]
    for fname in sorted(os.listdir(wheels_dir)):
        if not fname.endswith(".whl"):
            continue
        if only is not None and fname not in only:
            continue
        # Wheel filename: {name}-{version}-{pytag}-{abitag}-{plat}.whl
        parts = fname[:-4].split("-")
        if len(parts) < 2:
            continue
        name, version = parts[0], parts[1]
        with open(os.path.join(wheels_dir, fname), "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        groups[(name, version)].append(digest)

    lines = [
        "# Auto-generated hash-pinned lockfile for airgap install. DO NOT EDIT.",
        "# Install with: pip install --no-index --find-links=wheels \\",
        "#   --require-hashes -r <this-file>",
        "",
    ]
    for (name, version), digests in sorted(groups.items()):
        hash_args = " \\\n    ".join(f"--hash=sha256:{d}" for d in digests)
        lines.append(f"{name}=={version} \\\n    {hash_args}")
    with open(out_path, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"  {len(groups)} pinned packages in {os.path.basename(out_path)}")
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
    if len(args) != 2:
        sys.exit("usage: gen_lockfile.py <wheels_dir> <output_lockfile> "
                 "[--only a.whl,b.whl]")
    sys.exit(main(args[0], args[1], only=only_set))
