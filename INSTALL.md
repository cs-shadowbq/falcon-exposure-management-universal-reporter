# Installation Guide

## Standard Install (from GitHub Release)

Download wheels from the latest
[GitHub release](https://github.com/cs-shadowbq/falcon-exposure-management-universal-reporter/releases):

```bash
pip install femur_cli-2.0.0-py3-none-any.whl
pip install femur_server-2.0.0-py3-none-any.whl
```

Or install directly from git:

```bash
pip install "femur-cli @ git+https://github.com/cs-shadowbq/falcon-exposure-management-universal-reporter.git#subdirectory=packages/cli"
pip install "femur-server @ git+https://github.com/cs-shadowbq/falcon-exposure-management-universal-reporter.git#subdirectory=packages/server"
```

## Development Install

Clone the repo and install all packages in editable mode:

```bash
git clone https://github.com/cs-shadowbq/falcon-exposure-management-universal-reporter.git
cd falcon-exposure-management-universal-reporter
make install-dev
```

This installs all 4 packages (core, pipeline, cli, server) in development mode
with test dependencies.

## Airgapped Install (RHEL 9 x86_64)

For disconnected environments without internet access.

### 1. Transfer the bundle

Copy the appropriate tarball to the target host:

| Bundle | Python Version | RHEL 9 Source |
|--------|---------------|---------------|
| `femur-2.0.0-airgap-rhel9-cp39-x86_64.tar.gz` | 3.9 | Default (RHEL 9.0-9.3) |
| `femur-2.0.0-airgap-rhel9-cp311-x86_64.tar.gz` | 3.11 | AppStream |
| `femur-2.0.0-airgap-rhel9-cp312-x86_64.tar.gz` | 3.12 | AppStream (RHEL 9.4+) |

### 2. Extract and install

```bash
tar -xzf femur-2.0.0-airgap-rhel9-cp39-x86_64.tar.gz
cd femur-2.0.0-airgap-rhel9-cp39-x86_64/
chmod +x install.sh
./install.sh
```

### 3. Selective install (CLI only, no server)

```bash
pip install --no-index --find-links=./wheels/ femur-cli
```

### 4. Manual install (no pip, no root)

```bash
mkdir -p ~/pylibs
for whl in wheels/*.whl; do unzip -q -o "$whl" -d ~/pylibs/; done
export PYTHONPATH=~/pylibs:$PYTHONPATH
python3 -m femur_cli --help
```

### Bundle contents

Each airgap tarball contains:

- `wheels/` — All package wheels + all runtime dependencies
- `install.sh` — Auto-detecting installer script
- `sbom.cdx.json` — CycloneDX 1.5 SBOM listing all bundled components
- `README.md` — Quick reference

## Building Bundles

Requirements: Python 3.9+, pip, internet access (for dependency download).

```bash
# Build all wheels
make dist

# Build airgap bundles (default: Python 3.9, 3.11, 3.12)
make airgap

# Build for a specific Python version
make airgap AIRGAP_PYTHON=39

# Build for all supported versions
make airgap AIRGAP_PYTHON=39,311,312
```

Output lands in `dist/`:

```
dist/
  falcon_exposure_management_universal_reporter-2.0.0-py3-none-any.whl
  femur_pipeline-2.0.0-py3-none-any.whl
  femur_cli-2.0.0-py3-none-any.whl
  femur_server-2.0.0-py3-none-any.whl
  femur-2.0.0-airgap-rhel9-cp39-x86_64.tar.gz
  femur-2.0.0-airgap-rhel9-cp311-x86_64.tar.gz
  femur-2.0.0-airgap-rhel9-cp312-x86_64.tar.gz
  SHA256SUMS
```

## Creating a Release

With `gh` CLI installed:

```bash
make release
```

Without `gh` CLI, `make release` prints step-by-step manual instructions for
creating the release on GitHub with all required attachments.

## Verifying Integrity

Each build produces a `dist/SHA256SUMS` file:

```bash
cd dist/
shasum -a 256 -c SHA256SUMS
```
