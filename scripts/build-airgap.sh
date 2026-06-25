#!/bin/bash
# Build airgap deployment bundle for FEMUR (monorepo)
# Run on a machine WITH internet to produce a transferable bundle.
#
# Usage:
#   ./scripts/build-airgap.sh                  # defaults: Python 3.9, RHEL 9 x86_64
#   ./scripts/build-airgap.sh --python 312     # Python 3.12 target
#   ./scripts/build-airgap.sh --python 39,311,312  # all versions
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Defaults
PYTHON_VERSIONS="39"
PLATFORM="manylinux_2_28_x86_64"
DIST_DIR="$PROJECT_DIR/dist"

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

# Collect all runtime deps from all packages
ALL_DEPS="crowdstrike-falconpy rich python-dotenv defusedxml fastapi uvicorn"

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

    # Download platform-specific dependencies
    echo "Downloading dependencies for cp${PYVER} / ${PLATFORM}..."
    pip download \
        --platform "$PLATFORM" \
        --python-version "$PYVER" \
        --implementation cp \
        --abi "cp${PYVER}" \
        --only-binary=:all: \
        --dest "$BUNDLE_DIR/wheels/" \
        $ALL_DEPS \
        2>&1 | grep -E "^(Downloading|Saved|File was already)" || true

    # Also grab pure-python fallbacks
    pip download \
        --platform any \
        --python-version "$PYVER" \
        --implementation cp \
        --abi none \
        --only-binary=:all: \
        --dest "$BUNDLE_DIR/wheels/" \
        $ALL_DEPS \
        2>/dev/null || true

    # Generate CycloneDX SBOM from bundled wheels
    echo "Generating SBOM (CycloneDX)..."
    python3 -c "
import json, zipfile, email.parser, os, datetime

wheels_dir = '$BUNDLE_DIR/wheels'
components = []
for fname in sorted(os.listdir(wheels_dir)):
    if not fname.endswith('.whl'):
        continue
    whl_path = os.path.join(wheels_dir, fname)
    with zipfile.ZipFile(whl_path) as zf:
        metadata_files = [n for n in zf.namelist() if n.endswith('/METADATA')]
        if not metadata_files:
            continue
        with zf.open(metadata_files[0]) as mf:
            meta = email.parser.BytesParser().parsebytes(mf.read())
    name = str(meta.get('Name', ''))
    version = str(meta.get('Version', ''))
    purl = f'pkg:pypi/{name.lower().replace(\"-\", \"-\")}@{version}'
    component = {
        'type': 'library',
        'name': name,
        'version': version,
        'purl': purl,
        'bom-ref': purl,
    }
    license_val = str(meta.get('License-Expression') or '')
    if not license_val or len(license_val) > 80:
        classifiers = meta.get_all('Classifier') or []
        for c in classifiers:
            if str(c).startswith('License :: OSI Approved ::'):
                license_val = str(c).split('::')[-1].strip()
                break
    if not license_val:
        license_val = str(meta.get('License', ''))
    if license_val and license_val.strip() and license_val.strip() != 'UNKNOWN':
        short = license_val.strip().split('\\n')[0].strip()
        if len(short) <= 80:
            component['licenses'] = [{'expression': short}]
        else:
            component['licenses'] = [{'license': {'name': short[:200]}}]
    author = str(meta.get('Author') or meta.get('Author-email') or '')
    if author:
        component['author'] = author
    component['evidence'] = {'identity': {'field': 'filename', 'methods': [{'technique': 'filename', 'value': fname}]}}
    components.append(component)

sbom = {
    '\$schema': 'http://cyclonedx.org/schema/bom-1.5.schema.json',
    'bomFormat': 'CycloneDX',
    'specVersion': '1.5',
    'version': 1,
    'metadata': {
        'timestamp': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'component': {
            'type': 'application',
            'name': 'femur',
            'version': '$VERSION',
            'purl': 'pkg:pypi/femur-cli@$VERSION',
            'bom-ref': 'pkg:pypi/femur-cli@$VERSION',
        },
        'tools': [{'name': 'build-airgap.sh', 'version': '$VERSION'}],
    },
    'components': components,
}

with open('$BUNDLE_DIR/sbom.cdx.json', 'w') as f:
    json.dump(sbom, f, indent=2)
print(f'  {len(components)} components in sbom.cdx.json')
"

    # Create install script
    cat > "$BUNDLE_DIR/install.sh" << 'INSTALL_EOF'
#!/bin/bash
# FEMUR airgap installer
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WHEEL_DIR="$SCRIPT_DIR/wheels"

echo "=== FEMUR Airgap Installer ==="
echo ""
echo "Available packages:"
echo "  femur-cli    — CLI tool (command: femur)"
echo "  femur-server — REST API server (command: femurd)"
echo ""

# Detect Python
PYTHON=""
for candidate in python3.12 python3.11 python3.9 python3; do
    if command -v "$candidate" &>/dev/null; then
        PYTHON="$candidate"
        break
    fi
done

if [ -z "$PYTHON" ]; then
    echo "ERROR: No python3 found in PATH"
    exit 1
fi

PYVER=$($PYTHON -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "Using: $PYTHON (Python $PYVER)"
echo ""

# Check if pip is available
if $PYTHON -m pip --version &>/dev/null; then
    echo "Installing with pip (--no-index)..."
    $PYTHON -m pip install --no-index --find-links="$WHEEL_DIR" femur-cli femur-server
    echo ""
    echo "Done!"
    echo "  CLI:    femur --help"
    echo "  Server: femurd --help"
elif $PYTHON -m ensurepip --help &>/dev/null; then
    echo "Bootstrapping pip via ensurepip..."
    $PYTHON -m ensurepip --user 2>/dev/null || $PYTHON -m ensurepip
    $PYTHON -m pip install --no-index --find-links="$WHEEL_DIR" femur-cli femur-server
    echo ""
    echo "Done!"
    echo "  CLI:    femur --help"
    echo "  Server: femurd --help"
else
    echo "pip not available. Installing via manual extraction..."
    echo ""

    INSTALL_DIR="$HOME/.local/lib/python${PYVER}/site-packages"
    mkdir -p "$INSTALL_DIR"

    echo "Extracting wheels to: $INSTALL_DIR"
    for whl in "$WHEEL_DIR"/*.whl; do
        echo "  $(basename "$whl")"
        unzip -q -o "$whl" -d "$INSTALL_DIR"
    done

    BIN_DIR="$HOME/.local/bin"
    mkdir -p "$BIN_DIR"
    cat > "$BIN_DIR/femur" << EOF
#!/bin/bash
export PYTHONPATH="$INSTALL_DIR:\$PYTHONPATH"
exec $PYTHON -m femur_cli "\$@"
EOF
    cat > "$BIN_DIR/femurd" << EOF
#!/bin/bash
export PYTHONPATH="$INSTALL_DIR:\$PYTHONPATH"
exec $PYTHON -m femur_server.server "\$@"
EOF
    chmod +x "$BIN_DIR/femur" "$BIN_DIR/femurd"

    echo ""
    echo "Done!"
    echo "Ensure ~/.local/bin is in PATH:  export PATH=\$HOME/.local/bin:\$PATH"
    echo "  CLI:    femur --help"
    echo "  Server: femurd --help"
fi
INSTALL_EOF
    chmod +x "$BUNDLE_DIR/install.sh"

    # Create README
    cat > "$BUNDLE_DIR/README.md" << EOF
# FEMUR v${VERSION} — Airgap Bundle

**Target:** RHEL 9 x86_64, Python ${PYVER_DOT}

## Quick Install

\`\`\`bash
chmod +x install.sh
./install.sh
\`\`\`

## Selective Install (CLI only, no server)

\`\`\`bash
pip install --no-index --find-links=./wheels/ femur-cli
\`\`\`

## Manual Install (no pip, no root)

\`\`\`bash
mkdir -p ~/pylibs
for whl in wheels/*.whl; do unzip -q -o "\$whl" -d ~/pylibs/; done
export PYTHONPATH=~/pylibs:\$PYTHONPATH
python3 -m femur_cli --help
\`\`\`

## Packages Included

- \`falcon-exposure-management-universal-reporter\` — Core API library
- \`femur-pipeline\` — Data pipeline and output sinks
- \`femur-cli\` — CLI tool (\`femur\` command)
- \`femur-server\` — REST API server (\`femurd\` command)
- All runtime dependencies

## Verify

\`\`\`bash
femur --version
femurd --version
\`\`\`
EOF

    # Create tarball
    cd "$DIST_DIR"
    tar -czf "${BUNDLE_NAME}.tar.gz" "$BUNDLE_NAME"/
    rm -rf "$BUNDLE_DIR"

    BUNDLE_SIZE=$(du -h "${BUNDLE_NAME}.tar.gz" | cut -f1)
    echo "Created: dist/${BUNDLE_NAME}.tar.gz (${BUNDLE_SIZE})"
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

echo "Artifacts in: $DIST_DIR/"
ls -lh "$DIST_DIR"/*.tar.gz "$DIST_DIR"/*.whl "$DIST_DIR"/SHA256SUMS 2>/dev/null
echo ""
echo "Upload to GitHub release or transfer to airgapped host."
