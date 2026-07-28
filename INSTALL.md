# Installation Guide

FEMUR ships two console binaries:

- **`femur`** — the CLI that downloads Falcon application inventory, vulnerabilities, and configuration assessments.
- **`femurd`** — the REST API server that serves the data `femur` produces.

## Standard Install (from GitHub Release)

Download wheels from the latest
[GitHub release](https://github.com/cs-shadowbq/falcon-exposure-management-universal-reporter/releases):

```bash
pip install femur_cli-2.1.0-py3-none-any.whl
pip install femur_server-2.1.0-py3-none-any.whl
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

For disconnected environments without internet access. Each bundle is a
self-contained offline install kit with a full install → upgrade → uninstall
lifecycle, a hash-pinned lockfile, a CycloneDX SBOM, and man pages.

### 1. Transfer the bundle

Copy the appropriate tarball to the target host:

| Bundle | Python Version | RHEL 9 Source |
|--------|---------------|---------------|
| `femur-2.1.0-airgap-rhel9-cp39-x86_64.tar.gz` | 3.9 | Default (RHEL 9.0-9.3) |
| `femur-2.1.0-airgap-rhel9-cp311-x86_64.tar.gz` | 3.11 | AppStream |
| `femur-2.1.0-airgap-rhel9-cp312-x86_64.tar.gz` | 3.12 | AppStream (RHEL 9.4+) |

### 2. Extract and install

```bash
tar -xzf femur-2.1.0-airgap-rhel9-cp39-x86_64.tar.gz
cd femur-2.1.0-airgap-rhel9-cp39-x86_64/
chmod +x install.sh

./install.sh                                 # install both binaries (femur, femurd)
./install.sh --no-server                     # reporter only: femur CLI, no femurd
./install.sh --workspace-path /opt/femur     # + prepare a self-contained run directory
sudo ./install.sh --service -y               # + install the hardened femurd systemd service
```

`install.sh` installs the wheels offline (hash-verified against
`requirements.lock`), installs the `femur.1` / `femurd.1` man pages, and records
install state to a manifest so it can be cleanly upgraded or removed later. The
manifest and an append-only activity log live under `~/.config/femur` (or
`/var/log/femur` for a `--service` install); pass `--state-dir DIR` to relocate
them. See `./install.sh --help` for `--type SYSTEM|WORKSPACE`, `--service-user`,
`--service-host`, and `--service-port`.

### Reporter-only install (`--no-server`)

Customers who want FEMUR only as a **reporter** (run `femur`, export the data)
and not as an API server can skip `femurd`:

```bash
./install.sh --no-server                     # or --cli-only
```

This installs just the `femur` CLI — which still pulls in the pipeline and core
it depends on — and skips the `femurd` server, its man page, and the systemd
service (`--no-server` + `--service` is rejected as contradictory). It is
hash-verified against `requirements-cli.lock`, and the CLI-only SBOM
(`sbom-cli.cdx.json`) is recorded in the state dir so the host's SBOM reflects
only what is deployed — no server components. The install profile is stored in
the manifest, so `upgrade.sh` and `uninstall.sh` automatically act on the
reporter-only set.

### 3. Upgrade (from a matching or newer bundle)

```bash
./upgrade.sh --check-install     # inspect current install + version transition, no changes
./upgrade.sh --dry-run           # preview every action
./upgrade.sh                     # upgrade packages, refresh man pages, produce merged .env
```

The package upgrade is offline and hash-verified. Runtime data, output, and logs
are never touched. Your live `.env` is never overwritten — a merged candidate
`.env.upgraded` is written that keeps your values and comments and appends only
new keys; adopt it with `--force-config` (backs up the old file as `.env.bak`).

### 4. Uninstall

```bash
./uninstall.sh                   # remove packages, wrappers, man pages, service (keeps config + data)
./uninstall.sh --purge           # also delete .env, data, output, and logs
```

The state manifest and activity log are retained for audit even with `--purge`.

### 5. Selective install (CLI only, no server)

```bash
pip install --no-index --find-links=./wheels/ femur-cli
```

### 6. Manual install (no pip, no root)

```bash
mkdir -p ~/pylibs
for whl in wheels/*.whl; do unzip -q -o "$whl" -d ~/pylibs/; done
export PYTHONPATH=~/pylibs:$PYTHONPATH
python3 -m femur_cli --help
```

### Bundle contents

Each airgap tarball contains:

- `wheels/` — All package wheels + all runtime dependencies
- `requirements.lock` — Hash-pinned lockfile for the full install (`pip --require-hashes`)
- `requirements-cli.lock` — Hash-pinned lockfile for the `--no-server` (reporter) install
- `sbom.cdx.json` — CycloneDX 1.5 SBOM for the full install (CLI + server)
- `sbom-cli.cdx.json` — CycloneDX 1.5 SBOM for the reporter-only install
- `install.sh`, `upgrade.sh`, `uninstall.sh`, `merge_env.py` — install lifecycle
- `femur-server.service` — Hardened systemd unit template for `femurd`
- `femur.1`, `femurd.1` — Man pages
- `example.env` — Credentials template (`CLIENT_ID` / `CLIENT_SECRET` / `BASE_URL`)
- `README.md`, `INSTALL.md` — Reference docs

## Building Bundles

Requirements: Python 3.9+, pip, internet access (for dependency download).

```bash
# Build all wheels
make dist

# Generate the man pages (build/femur.1, build/femurd.1)
make man

# Build wheels + man pages together
make build

# Build airgap bundles (default: Python 3.9, 3.11, 3.12) — depends on `build`
make airgap

# Build for a specific Python version
make airgap AIRGAP_PYTHON=39
```

Output lands in a version-scoped directory `dist/<version>/`:

```
dist/2.1.0/
  falcon_exposure_management_universal_reporter-2.1.0-py3-none-any.whl
  femur_pipeline-2.1.0-py3-none-any.whl
  femur_cli-2.1.0-py3-none-any.whl
  femur_server-2.1.0-py3-none-any.whl
  femur-2.1.0-airgap-rhel9-cp39-x86_64.tar.gz
  femur-2.1.0-airgap-rhel9-cp311-x86_64.tar.gz
  femur-2.1.0-airgap-rhel9-cp312-x86_64.tar.gz
  SHA256SUMS
  SHA256SUMS.asc          # present only when GPG signing is available
```

## Creating a Release

With `gh` CLI installed:

```bash
make release
```

`make release` runs `airgap` first, then creates the GitHub release attaching all
wheels, airgap tarballs, `SHA256SUMS`, and `SHA256SUMS.asc` (when present).
Without `gh` CLI, it prints step-by-step manual instructions with the exact files
to attach.

## Verifying Integrity

Each build produces a `dist/<version>/SHA256SUMS` file:

```bash
cd dist/2.1.0/
shasum -a 256 -c SHA256SUMS
```

When the build host has a GPG signing key, a detached signature
`SHA256SUMS.asc` is also produced (set `GPG_SIGNING_KEY=<keyid>` to select a
specific key). Verify it with:

```bash
gpg --verify SHA256SUMS.asc SHA256SUMS
```
