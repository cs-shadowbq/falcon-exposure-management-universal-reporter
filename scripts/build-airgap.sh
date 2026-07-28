#!/bin/bash
# Build airgap deployment bundle for FEMUR (monorepo)
# Run on a machine WITH internet to produce a transferable bundle.
#
# Each bundle is a self-contained offline install kit: all project + dependency
# wheels, a hash-pinned lockfile, a CycloneDX SBOM, the man pages, and the full
# install/upgrade/uninstall lifecycle scripts from dist-templates/.
#
# Usage:
#   ./scripts/build-airgap.sh                  # defaults: Python 3.9, RHEL 9 x86_64
#   ./scripts/build-airgap.sh --python 312     # Python 3.12 target
#   ./scripts/build-airgap.sh --python 39,311,312  # all versions
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TEMPLATES_DIR="$PROJECT_DIR/dist-templates"
BUILD_DIR="$PROJECT_DIR/build"

# Defaults
PYTHON_VERSIONS="39"
PLATFORM="manylinux_2_28_x86_64"
DIST_BASE="$PROJECT_DIR/dist"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --python|-p)
            PYTHON_VERSIONS="$2"
            shift 2
            ;;
        --platform)
            PLATFORM="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [--python VERSION] [--platform PLATFORM]"
            echo ""
            echo "Options:"
            echo "  --python, -p    Python version(s): 39, 311, 312, or 39,311,312 (default: 39)"
            echo "  --platform      Wheel platform tag (default: manylinux_2_28_x86_64)"
            echo ""
            echo "Examples:"
            echo "  $0                            # Python 3.9, RHEL 9 x86_64"
            echo "  $0 --python 312               # Python 3.12"
            echo "  $0 --python 39,311,312        # All versions"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Read version from root pyproject.toml
VERSION=$(python3 -c "
try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib
print(tomllib.load(open('$PROJECT_DIR/pyproject.toml', 'rb'))['project']['version'])
")

# Version-scoped output directory so different versions never mingle and the
# generated SHA256SUMS only ever covers a single release.
DIST_DIR="$DIST_BASE/$VERSION"

echo "=== Building FEMUR v${VERSION} airgap bundles ==="
echo "Target platform: ${PLATFORM}"
echo "Python versions: ${PYTHON_VERSIONS}"
echo ""

# Build all package wheels if not already present
echo "--- Building package wheels ---"
cd "$PROJECT_DIR"
mkdir -p "$DIST_DIR"

PACKAGES=(packages/core packages/pipeline packages/cli packages/server)
WHEEL_COUNT=$(find "$DIST_DIR" -maxdepth 1 -name '*.whl' -print 2>/dev/null | wc -l | tr -d ' ')

if [[ "$WHEEL_COUNT" -lt 4 ]]; then
    echo "Building wheels for all packages..."
    python3 -m pip install --quiet build 2>/dev/null || true
    for pkg in "${PACKAGES[@]}"; do
        echo "  Building $(basename "$pkg")..."
        python3 -m build --wheel --outdir "$DIST_DIR" "$pkg" 2>&1 | grep -E "^Successfully" || true
    done
fi

echo "Wheels in dist/:"
find "$DIST_DIR" -maxdepth 1 -name '*.whl' -exec basename {} \; | sort
echo ""

# Runtime deps are resolved from the actual project wheels (below), so version
# floors always come from the packages' pyproject.toml. femur-server pulls
# uvicorn[standard], so its extra (httptools, uvloop, websockets, watchgod,
# pyyaml, ...) is resolved automatically. The [standard] extra is requested
# explicitly alongside the project wheels so pip includes it.
PROJECT_REQS="femur-cli femur-server uvicorn[standard]"

# Templates and generated artifacts copied verbatim into every bundle.
LIFECYCLE_FILES=(install.sh uninstall.sh upgrade.sh merge_env.py femur-server.service)
MAN_PAGES=(femur.1 femurd.1)

# Build bundles for each Python version
IFS=',' read -ra VERSIONS <<< "$PYTHON_VERSIONS"
for PYVER in "${VERSIONS[@]}"; do
    PYVER_DOT="${PYVER:0:1}.${PYVER:1}"
    BUNDLE_NAME="femur-${VERSION}-airgap-rhel9-cp${PYVER}-x86_64"
    BUNDLE_DIR="$DIST_DIR/$BUNDLE_NAME"

    echo "--- Building bundle for Python ${PYVER_DOT} ---"

    rm -rf "$BUNDLE_DIR"
    mkdir -p "$BUNDLE_DIR/wheels"

    # Copy all project wheels
    find "$DIST_DIR" -maxdepth 1 -name '*.whl' -exec cp {} "$BUNDLE_DIR/wheels/" \;

    # Download every runtime dependency in a SINGLE resolver pass. Splitting the
    # platform-specific and pure-python downloads across two `pip download` runs
    # breaks resolution (each run sees only a partial graph and backtracks to
    # wrong/old versions, or drops env-marker deps like exceptiongroup). Passing
    # multiple --platform/--abi tags to one invocation lets pip pick manylinux
    # AND pure-python (none/any) wheels together against the full graph.
    #
    # --platform matches wheel tags EXACTLY (pip does not infer that a 2_28 host
    # runs older manylinux wheels), so the full compatible manylinux lineage must
    # be listed: some deps (e.g. watchfiles, a Rust abi3 package) only publish
    # manylinux_2_17/2014 wheels. Newest baseline first so pip prefers it.
    #
    # Resolving against the project wheels (--find-links to the bundle's own
    # wheels/) means transitive deps + version floors come from the packages'
    # pyproject.toml rather than a hand-maintained list.
    echo "Downloading dependencies for cp${PYVER} / ${PLATFORM} lineage..."
    # Fail loudly if resolution fails: a swallowed error would ship a bundle
    # missing its dependencies (the offline install would then fail on the
    # airgapped host, far from where the problem can be diagnosed). PIPESTATUS[0]
    # is pip's exit code (not grep's, which is always 0 with `|| true`).
    # shellcheck disable=SC2086  # PROJECT_REQS must word-split into separate args
    pip download \
        --platform "$PLATFORM" \
        --platform manylinux_2_17_x86_64 \
        --platform manylinux2014_x86_64 \
        --platform manylinux_2_5_x86_64 \
        --platform manylinux1_x86_64 \
        --platform any \
        --python-version "$PYVER" \
        --implementation cp \
        --abi "cp${PYVER}" \
        --abi abi3 \
        --abi none \
        --only-binary=:all: \
        --find-links "$BUNDLE_DIR/wheels/" \
        --dest "$BUNDLE_DIR/wheels/" \
        $PROJECT_REQS \
        2>&1 | grep -E "^(Downloading|Saved|File was already)" || true
    DL_RC="${PIPESTATUS[0]}"
    if [ "$DL_RC" -ne 0 ]; then
        echo "ERROR: dependency download failed for cp${PYVER} (pip exit $DL_RC)." >&2
        echo "       Re-run the pip download above without the grep filter to see the" >&2
        echo "       full resolver error. Aborting so no incomplete bundle is shipped." >&2
        exit 1
    fi

    # Supplemental marker-conditional deps. pip evaluates environment markers
    # (python_version < "3.11", ...) against the BUILD host's interpreter, NOT
    # --python-version, so deps gated behind an older-Python marker are silently
    # skipped when building on a newer Python. Fetch them explicitly for the
    # target version. (The reference tool works around the same pip limitation
    # by hand-adding tomli for py<311.) For cp39/cp310, anyio needs
    # exceptiongroup; without it the offline install fails on the target.
    SUPPLEMENTAL=""
    if [ "$PYVER" -lt 311 ]; then
        SUPPLEMENTAL="exceptiongroup"
    fi
    if [ -n "$SUPPLEMENTAL" ]; then
        echo "Fetching marker-conditional deps for cp${PYVER}: $SUPPLEMENTAL"
        # shellcheck disable=SC2086
        pip download \
            --platform "$PLATFORM" \
            --platform manylinux_2_17_x86_64 \
            --platform manylinux2014_x86_64 \
            --platform manylinux_2_5_x86_64 \
            --platform manylinux1_x86_64 \
            --platform any \
            --python-version "$PYVER" \
            --implementation cp \
            --abi "cp${PYVER}" \
            --abi abi3 \
            --abi none \
            --only-binary=:all: \
            --no-deps \
            --dest "$BUNDLE_DIR/wheels/" \
            $SUPPLEMENTAL \
            2>&1 | grep -E "^(Downloading|Saved|File was already)" || true
        if [ "${PIPESTATUS[0]}" -ne 0 ]; then
            echo "ERROR: supplemental dep download failed for cp${PYVER}. Aborting." >&2
            exit 1
        fi
    fi

    # Generate hash-pinned lockfile so the offline install can use --require-hashes.
    echo "Generating hash-pinned lockfile..."
    python3 "$SCRIPT_DIR/gen_lockfile.py" "$BUNDLE_DIR/wheels" "$BUNDLE_DIR/requirements.lock"

    # Generate CycloneDX SBOM from the bundled wheels (full install closure).
    echo "Generating SBOM (CycloneDX)..."
    python3 "$SCRIPT_DIR/gen_sbom.py" "$BUNDLE_DIR/wheels" "$BUNDLE_DIR/sbom.cdx.json" "$VERSION"

    # --- CLI-only (reporter) closure -------------------------------------------
    # A --no-server install ships femur (CLI) but not femurd (server). Resolve the
    # femur-cli closure OFFLINE against the bundle's own wheels to get the exact
    # subset (pulls pipeline + core, excludes fastapi/uvicorn/starlette/...), then
    # emit a matching lockfile and SBOM so the reporter-only path stays
    # hash-verified and its SBOM reflects only what is deployed.
    echo "Resolving CLI-only closure for reporter installs..."
    CLI_CLOSURE_DIR="$(mktemp -d)"
    if pip download \
        --no-index \
        --find-links "$BUNDLE_DIR/wheels/" \
        --platform "$PLATFORM" \
        --platform manylinux_2_17_x86_64 \
        --platform manylinux2014_x86_64 \
        --platform manylinux_2_5_x86_64 \
        --platform manylinux1_x86_64 \
        --platform any \
        --python-version "$PYVER" \
        --implementation cp \
        --abi "cp${PYVER}" \
        --abi abi3 \
        --abi none \
        --only-binary=:all: \
        --dest "$CLI_CLOSURE_DIR" \
        femur-cli \
        >/dev/null 2>&1; then
        # Comma-separated list of the wheel filenames in the CLI closure.
        CLI_ONLY="$(find "$CLI_CLOSURE_DIR" -maxdepth 1 -name '*.whl' -exec basename {} \; | sort | paste -sd, -)"
        rm -rf "$CLI_CLOSURE_DIR"
        if [ -n "$CLI_ONLY" ]; then
            echo "Generating CLI-only lockfile + SBOM..."
            python3 "$SCRIPT_DIR/gen_lockfile.py" "$BUNDLE_DIR/wheels" \
                "$BUNDLE_DIR/requirements-cli.lock" --only "$CLI_ONLY"
            python3 "$SCRIPT_DIR/gen_sbom.py" "$BUNDLE_DIR/wheels" \
                "$BUNDLE_DIR/sbom-cli.cdx.json" "$VERSION" --only "$CLI_ONLY"
        else
            echo "WARNING: CLI closure resolved to nothing; --no-server install will" >&2
            echo "         fall back to a non-hash-verified install on the target." >&2
        fi
    else
        rm -rf "$CLI_CLOSURE_DIR"
        echo "WARNING: could not resolve CLI-only closure offline; skipping" >&2
        echo "         requirements-cli.lock / sbom-cli.cdx.json. --no-server will" >&2
        echo "         still work but without hash verification." >&2
    fi

    # Copy the install lifecycle scripts + systemd unit from dist-templates/.
    for f in "${LIFECYCLE_FILES[@]}"; do
        if [ -f "$TEMPLATES_DIR/$f" ]; then
            cp "$TEMPLATES_DIR/$f" "$BUNDLE_DIR/$f"
        else
            echo "WARNING: dist-templates/$f not found; bundle will be missing it." >&2
        fi
    done
    chmod +x "$BUNDLE_DIR/install.sh" "$BUNDLE_DIR/uninstall.sh" "$BUNDLE_DIR/upgrade.sh" 2>/dev/null || true

    # Copy the generated man pages (built by `make man` into build/).
    for page in "${MAN_PAGES[@]}"; do
        if [ -f "$BUILD_DIR/$page" ]; then
            cp "$BUILD_DIR/$page" "$BUNDLE_DIR/$page"
        else
            echo "WARNING: build/$page not found; run 'make man' first. Bundle will lack it." >&2
        fi
    done

    # Seed config template for install.sh (WORKSPACE/service seeding).
    if [ -f "$PROJECT_DIR/example.env" ]; then
        cp "$PROJECT_DIR/example.env" "$BUNDLE_DIR/example.env"
    fi

    # Ship the human-facing install guide alongside the scripts.
    [ -f "$PROJECT_DIR/INSTALL.md" ] && cp "$PROJECT_DIR/INSTALL.md" "$BUNDLE_DIR/INSTALL.md"

    # Create the per-bundle README.
    cat > "$BUNDLE_DIR/README.md" << EOF
# FEMUR v${VERSION} — Airgap Bundle

**Target:** RHEL 9 x86_64, Python ${PYVER_DOT}

## Install

\`\`\`bash
chmod +x install.sh
./install.sh                                   # install both binaries (femur, femurd)
./install.sh --no-server                       # reporter only: femur CLI, no femurd
./install.sh --workspace-path /opt/femur       # + prepare a run directory
sudo ./install.sh --service -y                 # + hardened femurd systemd service
\`\`\`

Installs the \`femur\` CLI and \`femurd\` server offline from \`wheels/\` (hash-verified
against \`requirements.lock\`), the man pages, and records install state to a manifest
under \`~/.config/femur\` (or \`/var/log/femur\` for a service install).

**Reporter-only (\`--no-server\`):** installs just the \`femur\` CLI (which still
pulls in the pipeline + core it needs), hash-verified against
\`requirements-cli.lock\`. Skips the \`femurd\` binary, its man page, and the
systemd service. The matching \`sbom-cli.cdx.json\` (not the full SBOM) is
recorded so a reporter host's SBOM reflects only what is deployed.

## Upgrade / Uninstall (from a matching or newer bundle)

\`\`\`bash
./upgrade.sh --check-install     # inspect current install, no changes
./upgrade.sh                     # upgrade packages, refresh man pages, merge .env
./uninstall.sh                   # remove packages/wrappers/man/service (keeps config+data)
./uninstall.sh --purge           # also delete .env, data, logs
\`\`\`

Upgrade and uninstall are manifest-driven: a reporter-only install is upgraded
and removed as a CLI-only deployment automatically.

## Selective / manual install

\`\`\`bash
pip install --no-index --find-links=./wheels/ femur-cli          # CLI only
# no pip, no root:
mkdir -p ~/pylibs && for whl in wheels/*.whl; do unzip -q -o "\$whl" -d ~/pylibs/; done
export PYTHONPATH=~/pylibs:\$PYTHONPATH && python3 -m femur_cli --help
\`\`\`

## Bundle contents

- \`wheels/\` — all project + dependency wheels
- \`requirements.lock\` — hash-pinned lockfile for the full install (\`--require-hashes\`)
- \`requirements-cli.lock\` — hash-pinned lockfile for the \`--no-server\` (reporter) install
- \`sbom.cdx.json\` — CycloneDX 1.5 SBOM for the full install (CLI + server)
- \`sbom-cli.cdx.json\` — CycloneDX 1.5 SBOM for the reporter-only install
- \`install.sh\`, \`upgrade.sh\`, \`uninstall.sh\`, \`merge_env.py\` — install lifecycle
- \`femur-server.service\` — hardened systemd unit template (femurd)
- \`femur.1\`, \`femurd.1\` — man pages
- \`example.env\` — credentials template (CLIENT_ID / CLIENT_SECRET / BASE_URL)

## Verify

\`\`\`bash
femur --version
femurd --version
man femur
\`\`\`
EOF

    # Create tarball
    cd "$DIST_DIR"
    tar -czf "${BUNDLE_NAME}.tar.gz" "$BUNDLE_NAME"/
    rm -rf "$BUNDLE_DIR"

    BUNDLE_SIZE=$(du -h "${BUNDLE_NAME}.tar.gz" | cut -f1)
    echo "Created: dist/${VERSION}/${BUNDLE_NAME}.tar.gz (${BUNDLE_SIZE})"
    echo ""
done

echo "=== Build complete ==="
echo ""

# Generate SHA256 checksums for all dist artifacts
echo "--- Generating checksums ---"
cd "$DIST_DIR"
shasum -a 256 ./*.whl ./*.tar.gz 2>/dev/null > SHA256SUMS
cat SHA256SUMS
echo ""

# Optional GPG signing of the checksum file. Warns (does not fail) if no key is
# available, so unsigned builds still succeed on hosts without a signing key.
if command -v gpg &>/dev/null; then
    GPG_ARGS=()
    if [ -n "${GPG_SIGNING_KEY:-}" ]; then
        GPG_ARGS=(--local-user "$GPG_SIGNING_KEY")
    fi
    # Expand the array in a way that is safe when empty under `set -u` (macOS bash 3.2).
    if gpg ${GPG_ARGS[@]+"${GPG_ARGS[@]}"} --armor --detach-sign --output SHA256SUMS.asc SHA256SUMS 2>/dev/null; then
        echo "Signed checksums: dist/${VERSION}/SHA256SUMS.asc"
        echo "Verify with: gpg --verify SHA256SUMS.asc SHA256SUMS"
    else
        echo "NOTE: gpg present but signing failed (no default/usable key?); SHA256SUMS left unsigned."
        echo "      Set GPG_SIGNING_KEY=<keyid> to sign, or sign manually later."
    fi
else
    echo "NOTE: gpg not found; SHA256SUMS left unsigned."
fi
echo ""

echo "Artifacts in: $DIST_DIR/"
ls -lh "$DIST_DIR"/*.tar.gz "$DIST_DIR"/*.whl "$DIST_DIR"/SHA256SUMS 2>/dev/null
echo ""
echo "Upload to GitHub release or transfer to airgapped host."
