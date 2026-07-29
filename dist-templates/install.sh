#!/bin/bash
# FEMUR airgap installer
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WHEEL_DIR="$SCRIPT_DIR/wheels"

# Project identifier used for system paths, the state manifest, and the log.
# Keep in sync with the systemd unit name and /etc,/var/lib,/var/log/<APP_NAME>.
APP_NAME="femur"

# Schema version of the state manifest (CATEGORY | KEY | VALUE, first line is
# 'manifest-schema | - | X.Y.Z'). Bump the MAJOR when the manifest shape changes
# incompatibly so future uninstall/upgrade scripts can detect and refuse to
# misparse an old-shaped manifest.
MANIFEST_SCHEMA="1.0.0"

# Distribution names (pip) and their console scripts. FEMUR ships two binaries.
# The set actually installed depends on the profile (see --no-server): a
# reporter-only install ships just the femur CLI (which still pulls in
# femur-pipeline + core), no femurd server.
PIP_PACKAGES_FULL="femur-cli femur-server"
CONSOLE_SCRIPTS_FULL="femur femurd"
MAN_PAGES_FULL="femur.1 femurd.1"
PIP_PACKAGES_CLI="femur-cli"
CONSOLE_SCRIPTS_CLI="femur"
MAN_PAGES_CLI="femur.1"

# Two files, two jobs (resolved after arg parsing, under STATE_DIR):
#   MANIFEST  - mutable STATE: what is installed now (paths, hashes, layout).
#               Upserted freely; uninstall.sh/upgrade.sh read it back.
#   LOGFILE   - append-only AUDIT trail of install/upgrade/uninstall activity,
#               syslog-style and tagged with the script that wrote each line.
STATE_DIR=""
MANIFEST=""
LOGFILE=""

# --- Argument parsing -------------------------------------------------------
# Behavior is driven entirely by flags. The only interactive moment is a single
# confirmation before installing the systemd service, which -y/--yes skips.
ASSUME_YES="no"          # -y/--yes: auto-confirm the service install
TYPE="SYSTEM"            # deployment layout: SYSTEM (FHS dirs) | WORKSPACE (a dir)
TYPE_SET="no"            # was --type given explicitly?
WORKSPACE_PATH=""        # -w/--workspace-path; defaults to ./ when TYPE=WORKSPACE
WANT_SERVICE="no"        # --service: install the hardened systemd service
SVC_USER="femur"         # --service-user: account to run the service as
SVC_HOST="127.0.0.1"     # --service-host: bind address for femurd
SVC_PORT="8000"          # --service-port: bind port for femurd
STATE_DIR_ARG=""         # --state-dir/--log-dir: where manifest + log live
PROFILE="full"           # --no-server/--cli-only -> "cli": reporter-only (no femurd)

usage() {
    cat << USAGE
FEMUR airgap installer

Usage: ./install.sh [OPTIONS]

Installs FEMUR (the 'femur' CLI and 'femurd' server) from the bundled offline
wheels, then optionally prepares a run location and/or installs a hardened
systemd service for femurd. Everything is driven by flags — the only prompt is a
confirmation before the service install, which -y skips.

Options:
  -h, --help              Show this help and exit.

      --type TYPE         Deployment layout (default: SYSTEM):
                            SYSTEM     - system-wide paths:
                                         /etc/femur (config/.env),
                                         /var/lib/femur (data),
                                         /var/log/femur (logs).
                                         Requires root.
                            WORKSPACE  - a single self-contained directory
                                         (see --workspace-path).

  -w, --workspace-path PATH
                          Directory to prepare and run from (implies
                          --type WORKSPACE). Created with 'mkdir -p'; gets
                          data/, logs/ and a seeded .env (mode 0600). Defaults
                          to ./ when --type WORKSPACE is used without this flag.
                          Example:
                            --workspace-path /opt/crowdstrike-oss/femur

      --no-server         Reporter-only install: install just the 'femur' CLI
                          (which still pulls in the pipeline + core it needs).
                          Skips the 'femurd' server, its man page, and the
                          systemd service. Hash-verified against
                          requirements-cli.lock; records the CLI-only SBOM.
                          (--cli-only is accepted as an alias.)

      --service           Install the hardened systemd service for femurd
                          (requires root). Not valid with --no-server.
      --service-user NAME Service account to run as (default: femur).
      --service-host ADDR Bind address for femurd (default: 127.0.0.1).
      --service-port PORT Bind port for femurd (default: 8000).

      --state-dir DIR     Where the state manifest ($APP_NAME.manifest) and the
                          append-only installation log ($APP_NAME-installation.log)
                          live. Default: /var/log/$APP_NAME for a --service
                          install, otherwise \${XDG_CONFIG_HOME:-~/.config}/$APP_NAME.
                          Give the same --state-dir to uninstall.sh / upgrade.sh.
                          (--log-dir is accepted as an alias.)

  -y, --yes               Auto-confirm the service install (no prompt).

Steps performed:
  1. Install wheels offline (pip --require-hashes against requirements.lock,
     or manual extraction if pip is unavailable).
  2. Install the man pages (best effort).
  3. Prepare a WORKSPACE run directory (only when --type WORKSPACE or -w given).
  4. Install a hardened systemd service for femurd (only when --service given).
  5. Record install state to the manifest and actions to the installation log.

Examples:
  ./install.sh                                        # install both binaries
  ./install.sh --no-server                            # reporter only (femur CLI)
  ./install.sh --workspace-path /opt/crowdstrike-oss/femur
  sudo ./install.sh --service -y                      # SYSTEM femurd service
  sudo ./install.sh --type WORKSPACE -w /opt/femur --service -y

Uninstall with ./uninstall.sh (add --purge to also remove config/data).
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        --type)
            if [ $# -lt 2 ]; then echo "Error: --type requires SYSTEM|WORKSPACE" >&2; exit 2; fi
            case "$2" in
                SYSTEM|WORKSPACE) TYPE="$2"; TYPE_SET="yes" ;;
                system|workspace) TYPE="$(echo "$2" | tr '[:lower:]' '[:upper:]')"; TYPE_SET="yes" ;;
                *) echo "Error: --type must be SYSTEM or WORKSPACE (got '$2')" >&2; exit 2 ;;
            esac
            shift 2 ;;
        -w|--workspace-path)
            if [ $# -lt 2 ]; then echo "Error: $1 requires a PATH argument" >&2; exit 2; fi
            WORKSPACE_PATH="$2"; shift 2 ;;
        --no-server|--cli-only) PROFILE="cli"; shift ;;
        --service) WANT_SERVICE="yes"; shift ;;
        --service-user)
            if [ $# -lt 2 ]; then echo "Error: --service-user requires a NAME" >&2; exit 2; fi
            SVC_USER="$2"; shift 2 ;;
        --service-host)
            if [ $# -lt 2 ]; then echo "Error: --service-host requires an ADDR" >&2; exit 2; fi
            SVC_HOST="$2"; shift 2 ;;
        --service-port)
            if [ $# -lt 2 ]; then echo "Error: --service-port requires a PORT" >&2; exit 2; fi
            SVC_PORT="$2"; shift 2 ;;
        --state-dir|--log-dir)
            if [ $# -lt 2 ]; then echo "Error: $1 requires a DIR" >&2; exit 2; fi
            STATE_DIR_ARG="$2"; shift 2 ;;
        -y|--yes) ASSUME_YES="yes"; shift ;;
        *) echo "Unknown option: $1" >&2; echo "Try './install.sh --help'." >&2; exit 2 ;;
    esac
done

# --- Resolve the install profile --------------------------------------------
# A reporter-only (--no-server) install ships just the femur CLI. The systemd
# service IS the server, so --service + --no-server is contradictory.
if [ "$PROFILE" = "cli" ] && [ "$WANT_SERVICE" = "yes" ]; then
    echo "Error: --service installs the femurd server, which --no-server excludes." >&2
    echo "       Choose one: --no-server (reporter only) OR --service." >&2
    exit 2
fi

if [ "$PROFILE" = "cli" ]; then
    PIP_PACKAGES="$PIP_PACKAGES_CLI"
    CONSOLE_SCRIPTS="$CONSOLE_SCRIPTS_CLI"
    MAN_PAGES="$MAN_PAGES_CLI"
    LOCKFILE="requirements-cli.lock"
    SBOM_FILE="sbom-cli.cdx.json"
else
    PIP_PACKAGES="$PIP_PACKAGES_FULL"
    CONSOLE_SCRIPTS="$CONSOLE_SCRIPTS_FULL"
    MAN_PAGES="$MAN_PAGES_FULL"
    LOCKFILE="requirements.lock"
    SBOM_FILE="sbom.cdx.json"
fi

# Providing a workspace path implies the WORKSPACE type.
if [ -n "$WORKSPACE_PATH" ]; then
    if [ "$TYPE_SET" = "yes" ] && [ "$TYPE" = "SYSTEM" ]; then
        echo "NOTE: --workspace-path given; overriding --type SYSTEM with WORKSPACE."
    fi
    TYPE="WORKSPACE"
fi

# WORKSPACE type defaults its path to the current directory.
if [ "$TYPE" = "WORKSPACE" ] && [ -z "$WORKSPACE_PATH" ]; then
    WORKSPACE_PATH="./"
fi

# Expand a leading ~ up front (re-resolved to absolute once the dir exists).
if [ -n "$WORKSPACE_PATH" ]; then
    WORKSPACE_PATH="${WORKSPACE_PATH/#\~/$HOME}"
fi

# --- Resolve the state directory (manifest + log live here) -----------------
# Never leave them in SCRIPT_DIR (the transient extracted tarball). An explicit
# --state-dir wins; otherwise a --service install uses /var/log, and everything
# else uses the user's XDG config dir.
if [ -n "$STATE_DIR_ARG" ]; then
    STATE_DIR="${STATE_DIR_ARG/#\~/$HOME}"
elif [ "$WANT_SERVICE" = "yes" ]; then
    STATE_DIR="/var/log/$APP_NAME"
else
    STATE_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/$APP_NAME"
fi
if ! mkdir -p "$STATE_DIR" 2>/dev/null; then
    echo "WARNING: cannot create state dir $STATE_DIR; falling back to \$HOME/.config/$APP_NAME" >&2
    STATE_DIR="$HOME/.config/$APP_NAME"
    mkdir -p "$STATE_DIR"
fi
MANIFEST="$STATE_DIR/$APP_NAME.manifest"
LOGFILE="$STATE_DIR/$APP_NAME-installation.log"

echo "=== FEMUR Airgap Installer ==="
echo "State manifest: $MANIFEST"
echo "Activity log:   $LOGFILE"
echo ""

# --- Append-only activity log (syslog-style, never rewritten) ---------------
# Format:  <ISO8601> <host> <app>/<script>[<pid>]: <message>
LOG_HOST="${HOSTNAME:-$(uname -n 2>/dev/null || echo localhost)}"
logline() {
    printf '%s %s %s/install.sh[%s]: %s\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$LOG_HOST" "$APP_NAME" "$$" "$1" >> "$LOGFILE"
}

# --- Mutable state manifest -------------------------------------------------
# Upsert a state entry keyed by (CATEGORY, KEY). The manifest is a state file
# (current install), NOT an audit log, so replacing a stale line is correct.
# Format:  CATEGORY | KEY | VALUE
mset() {
    # $1=category  $2=key(path or '-')  $3=value
    local cat="$1" key="$2" val="${3:-}"
    if [ -f "$MANIFEST" ]; then
        awk -F' \\| ' -v c="$cat" -v k="$key" '!($1==c && $2==k)' "$MANIFEST" \
            > "$MANIFEST.tmp" && mv "$MANIFEST.tmp" "$MANIFEST"
    fi
    printf '%s | %s | %s\n' "$cat" "$key" "$val" >> "$MANIFEST"
}

# Ensure the manifest exists with the schema version as its FIRST line.
if [ ! -f "$MANIFEST" ]; then
    printf 'manifest-schema | - | %s\n' "$MANIFEST_SCHEMA" > "$MANIFEST"
else
    mset manifest-schema - "$MANIFEST_SCHEMA"
fi

# Portable sha256 of a file (RHEL: sha256sum, macOS build host: shasum -a 256).
sha256_of() {
    if command -v sha256sum &>/dev/null; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

logline "install started (type=$TYPE profile=$PROFILE service=$WANT_SERVICE user=$(id -un) root=$([ "$(id -u)" -eq 0 ] && echo yes || echo no))"
mset type - "$TYPE"
# Record the install profile so upgrade.sh/uninstall.sh act on the right set of
# packages (full = femur + femurd; cli = reporter-only, femur CLI only).
mset profile - "$PROFILE"

IS_ROOT="no"
[ "$(id -u)" -eq 0 ] && IS_ROOT="yes"

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
    logline "ERROR: no python3 found in PATH; aborting"
    exit 1
fi

PYVER=$($PYTHON -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "Using: $PYTHON (Python $PYVER)"
logline "using interpreter $(command -v "$PYTHON") (Python $PYVER)"
echo ""

INSTALL_MODE=""
# Primary CLI path (femur) used for service/help hints; both scripts are recorded.
CLI_PATH=""

# Prefer a hash-pinned install when the profile's lockfile is present
# (supply-chain integrity for the offline bundle); fall back to a plain
# --no-index install by package name. LOCKFILE is requirements.lock for a full
# install, requirements-cli.lock for --no-server.
pip_install() {
    if [ -f "$SCRIPT_DIR/$LOCKFILE" ]; then
        echo "Installing with pip (--no-index, hash-verified from $LOCKFILE)..."
        if $PYTHON -m pip install --no-index --find-links="$WHEEL_DIR" \
            --require-hashes -r "$SCRIPT_DIR/$LOCKFILE"; then
            logline "pip install (hash-verified) from $LOCKFILE"
            return 0
        fi
        echo "Hash-verified install failed; retrying without --require-hashes..."
        logline "hash-verified install failed; retrying without --require-hashes"
    fi
    echo "Installing with pip (--no-index)..."
    # shellcheck disable=SC2086
    $PYTHON -m pip install --no-index --find-links="$WHEEL_DIR" $PIP_PACKAGES
}

# Resolve the install path of a console script. Deliberately robust because the
# script dir is frequently NOT on PATH (e.g. root's PATH lacks /usr/local/bin on
# RHEL). Try, in order: `pip show -f` RECORD, command -v, well-known bindirs.
resolve_script_path() {
    # $1=console-script name  $2=pip package that provides it -> prints path or ""
    local name="$1" pkg="$2" loc rel path
    loc=$($PYTHON -m pip show "$pkg" 2>/dev/null | awk -F': ' '/^Location:/ {print $2}')
    path=""
    if [ -n "$loc" ]; then
        rel=$($PYTHON -m pip show -f "$pkg" 2>/dev/null \
            | awk '/^ / {sub(/^ +/,""); print}' \
            | grep -E "(^|/)bin/$name\$" | head -1)
        if [ -n "$rel" ]; then
            path=$($PYTHON -c "import os,sys; print(os.path.realpath(os.path.join(sys.argv[1], sys.argv[2])))" "$loc" "$rel" 2>/dev/null || true)
            [ -x "$path" ] || path=""
        fi
    fi
    [ -z "$path" ] && path=$(command -v "$name" 2>/dev/null || true)
    if [ -z "$path" ]; then
        local d
        for d in \
            "$($PYTHON -c 'import sysconfig; print(sysconfig.get_path("scripts") or "")' 2>/dev/null)" \
            /usr/local/bin /usr/bin "$HOME/.local/bin"; do
            if [ -n "$d" ] && [ -x "$d/$name" ]; then path="$d/$name"; break; fi
        done
    fi
    printf '%s' "$path"
}

# Record where pip placed each console script (into the manifest so uninstall/
# upgrade know exactly what to act on). Sets CLI_PATH to the 'femur' path.
record_pip_layout() {
    local loc name pkg path
    loc=$($PYTHON -m pip show femur-cli 2>/dev/null \
        | awk -F': ' '/^Location:/ {print $2}')
    [ -n "$loc" ] && mset package "$loc/femur_cli" "pip"

    for name in $CONSOLE_SCRIPTS; do
        case "$name" in
            femur)  pkg="femur-cli" ;;
            femurd) pkg="femur-server" ;;
            *)      pkg="femur-cli" ;;
        esac
        path="$(resolve_script_path "$name" "$pkg")"
        if [ -n "$path" ]; then
            mset cli "$path" "pip"
            [ "$name" = "femur" ] && CLI_PATH="$path"
            case ":$PATH:" in
                *":$(dirname "$path"):"*) : ;;
                *)
                    echo "NOTE: $name installed to $(dirname "$path") which is NOT on your PATH."
                    echo "      Add it:  export PATH=\"$(dirname "$path"):\$PATH\""
                    logline "console script $name at $path is not on PATH"
                    ;;
            esac
        else
            echo "WARNING: could not locate the $name console script."
            logline "WARNING: console script path for $name not resolved"
        fi
    done
    # Explicit success: a falsy last statement would abort under `set -e`.
    return 0
}

# Check if pip is available
if $PYTHON -m pip --version &>/dev/null; then
    INSTALL_MODE="pip"
    pip_install
    record_pip_layout
    echo ""
    echo "Done!"
    echo "  CLI:    ${CLI_PATH:-femur} --help"
    [ "$PROFILE" = "full" ] && echo "  Server: femurd --help"
elif $PYTHON -m ensurepip --help &>/dev/null; then
    INSTALL_MODE="ensurepip"
    echo "Bootstrapping pip via ensurepip..."
    $PYTHON -m ensurepip --user 2>/dev/null || $PYTHON -m ensurepip
    pip_install
    record_pip_layout
    echo ""
    echo "Done!"
    echo "  CLI:    ${CLI_PATH:-femur} --help"
    [ "$PROFILE" = "full" ] && echo "  Server: femurd --help"
else
    INSTALL_MODE="manual"
    echo "pip not available. Installing via manual extraction..."
    echo ""

    INSTALL_DIR="$HOME/.local/lib/python${PYVER}/site-packages"
    mkdir -p "$INSTALL_DIR"

    # In cli-only mode, extract the CLI closure recorded in requirements-cli.lock
    # (falls back to all wheels if the lock is absent). This keeps a reporter-only
    # manual install from unpacking the server + its deps into site-packages.
    echo "Extracting wheels to: $INSTALL_DIR"
    if [ "$PROFILE" = "cli" ] && [ -f "$SCRIPT_DIR/$LOCKFILE" ]; then
        # Pin names come from the lock ('name==version'); match wheel files by name.
        CLI_NAMES="$(awk '/^[A-Za-z0-9._-]+==/{sub(/==.*/,""); gsub(/-/,"_"); print tolower($0)}' "$SCRIPT_DIR/$LOCKFILE")"
        for whl in "$WHEEL_DIR"/*.whl; do
            wname="$(basename "$whl" | sed 's/-[0-9].*//' | tr '[:upper:]' '[:lower:]' | tr '-' '_')"
            for want in $CLI_NAMES; do
                if [ "$wname" = "$want" ]; then
                    echo "  $(basename "$whl")"
                    unzip -q -o "$whl" -d "$INSTALL_DIR"
                    break
                fi
            done
        done
    else
        for whl in "$WHEEL_DIR"/*.whl; do
            echo "  $(basename "$whl")"
            unzip -q -o "$whl" -d "$INSTALL_DIR"
        done
    fi
    mset package "$INSTALL_DIR" "manual"

    # Create CLI wrappers (femur always; femurd only for a full install).
    BIN_DIR="$HOME/.local/bin"
    mkdir -p "$BIN_DIR"
    cat > "$BIN_DIR/femur" << EOF
#!/bin/bash
export PYTHONPATH="$INSTALL_DIR:\$PYTHONPATH"
exec $PYTHON -m femur_cli "\$@"
EOF
    chmod +x "$BIN_DIR/femur"
    CLI_PATH="$BIN_DIR/femur"
    mset cli "$BIN_DIR/femur" "manual"
    if [ "$PROFILE" = "full" ]; then
        cat > "$BIN_DIR/femurd" << EOF
#!/bin/bash
export PYTHONPATH="$INSTALL_DIR:\$PYTHONPATH"
exec $PYTHON -m femur_server.server "\$@"
EOF
        chmod +x "$BIN_DIR/femurd"
        mset cli "$BIN_DIR/femurd" "manual"
    fi

    echo ""
    echo "Done!"
    echo "Ensure ~/.local/bin is in PATH:  export PATH=\$HOME/.local/bin:\$PATH"
    echo "  CLI:    femur --help"
    [ "$PROFILE" = "full" ] && echo "  Server: femurd --help"
fi
mset mode - "$INSTALL_MODE"
# Record the installed version so upgrade.sh/--check-install can report it.
INSTALLED_VER="$($PYTHON -m pip show femur-cli 2>/dev/null | awk -F': ' '/^Version:/ {print $2}')"
[ -n "$INSTALLED_VER" ] && mset version - "$INSTALLED_VER"
logline "packages installed (mode=$INSTALL_MODE version=${INSTALLED_VER:-unknown} profile=$PROFILE)"

# --- Record the SBOM that matches what was installed ------------------------
# Copy the profile's SBOM (full: sbom.cdx.json, cli: sbom-cli.cdx.json) into the
# state dir and record its path, so a reporter-only host's SBOM reflects only the
# deployed components (no server attack surface). Best effort.
if [ -f "$SCRIPT_DIR/$SBOM_FILE" ]; then
    if cp "$SCRIPT_DIR/$SBOM_FILE" "$STATE_DIR/$SBOM_FILE" 2>/dev/null; then
        mset sbom "$STATE_DIR/$SBOM_FILE" "$PROFILE"
        logline "recorded SBOM $STATE_DIR/$SBOM_FILE (profile=$PROFILE)"
    else
        # Could not copy (e.g. read-only state dir); still record the bundle path.
        mset sbom "$SCRIPT_DIR/$SBOM_FILE" "$PROFILE"
        logline "recorded SBOM at bundle path $SCRIPT_DIR/$SBOM_FILE (copy failed)"
    fi
fi

# --- Install the man pages (best effort) ------------------------------------
# Install femur.1 / femurd.1 into the first writable man1 directory so
# `man femur` works offline. Skips gracefully if none is writable.
if [ "$IS_ROOT" = "yes" ]; then
    MAN_DIR="/usr/local/share/man/man1"
else
    MAN_DIR="$HOME/.local/share/man/man1"
fi
MAN_INSTALLED="no"
for page in $MAN_PAGES; do
    [ -f "$SCRIPT_DIR/$page" ] || continue
    if mkdir -p "$MAN_DIR" 2>/dev/null && [ -w "$MAN_DIR" ]; then
        cp "$SCRIPT_DIR/$page" "$MAN_DIR/$page"
        chmod 644 "$MAN_DIR/$page" 2>/dev/null || true
        mset man "$MAN_DIR/$page" -
        logline "man page installed at $MAN_DIR/$page"
        MAN_INSTALLED="yes"
    fi
done
if [ "$MAN_INSTALLED" = "yes" ]; then
    echo "Installed man pages in $MAN_DIR  (try: man femur / man femurd)"
    if [ "$IS_ROOT" != "yes" ]; then
        echo "  If 'man femur' isn't found, add to MANPATH:"
        echo "    export MANPATH=\"\$HOME/.local/share/man:\$MANPATH\""
    fi
elif [ -f "$SCRIPT_DIR/femur.1" ]; then
    echo "NOTE: no writable man1 dir; skipping man page install."
    echo "      View directly with:  man $SCRIPT_DIR/femur.1"
fi

# --- Workspace preparation (TYPE=WORKSPACE) --------------------------------
# Prepare a single self-contained directory to run from. femur writes inventory
# into data/, femurd serves it from there, and .env holds credentials.
WORKSPACE=""
echo ""
if [ "$TYPE" = "WORKSPACE" ]; then
    WORKSPACE="$WORKSPACE_PATH"
    echo "Preparing workspace at: $WORKSPACE"
    mkdir -p "$WORKSPACE" "$WORKSPACE/data" "$WORKSPACE/logs"
    WORKSPACE="$(cd "$WORKSPACE" && pwd)"
    mset workspace "$WORKSPACE" -
    mset data "$WORKSPACE/data" -
    mset logs "$WORKSPACE/logs" -
    logline "workspace prepared at $WORKSPACE"

    # Seed .env from the bundled example if absent; it holds API credentials, so
    # lock it to owner-only (0600).
    if [ -f "$SCRIPT_DIR/example.env" ]; then
        if [ -f "$WORKSPACE/.env" ]; then
            echo "Existing $WORKSPACE/.env left untouched."
        else
            cp "$SCRIPT_DIR/example.env" "$WORKSPACE/.env"
            chmod 600 "$WORKSPACE/.env"
            # Mark this .env as a workspace root so `femur` defaults
            # --output-dir to data/ and --log-file to logs/ automatically.
            # (The repo's example.env keeps this commented, so a bare
            # git-clone never triggers workspace behaviour.) Append before
            # the config-hash below so the recorded hash matches contents.
            if ! grep -qE '^[[:space:]]*WORKSPACE[[:space:]]*=' "$WORKSPACE/.env"; then
                printf '\n# Workspace root marker (added by install.sh --type WORKSPACE).\nWORKSPACE=true\n' >> "$WORKSPACE/.env"
            fi
            mset config "$WORKSPACE/.env" -
            mset config-hash "$WORKSPACE/.env" "$(sha256_of "$WORKSPACE/.env")"
            logline "seeded .env (0600) at $WORKSPACE/.env"
        fi
    fi

    echo ""
    echo "Workspace ready:"
    echo "  $WORKSPACE/.env      (edit with your CLIENT_ID/CLIENT_SECRET/BASE_URL, mode 0600)"
    echo "  $WORKSPACE/data/     (inventory output; femurd serves from here)"
    echo "  $WORKSPACE/logs/     (logs)"
    echo ""
    echo "Fetch inventory, then serve it:"
    echo "  femur -e $WORKSPACE/.env --output-dir $WORKSPACE/data"
    echo "  femurd --data-dir $WORKSPACE/data -e $WORKSPACE/.env"
fi

# --- Optional systemd service install (femurd) ------------------------------
# Install femurd as a sandboxed systemd service on a hardened RHEL9 host.
# Renders the bundled femur-server.service template with concrete paths.
UNIT_TEMPLATE="$SCRIPT_DIR/femur-server.service"
echo ""
INSTALL_SVC="n"
if [ "$WANT_SERVICE" != "yes" ]; then
    :
elif [ ! -f "$UNIT_TEMPLATE" ]; then
    echo "--service given but unit template not found next to installer; skipping."
elif ! command -v systemctl &>/dev/null; then
    echo "--service given but systemctl not found; skipping service install."
elif [ "$IS_ROOT" != "yes" ]; then
    echo "--service requires root. Re-run with sudo, or render the unit by hand:"
    echo "  $UNIT_TEMPLATE"
elif [ "$ASSUME_YES" = "yes" ]; then
    INSTALL_SVC="y"
elif [ -t 0 ]; then
    read -r -p "Install the hardened femurd systemd service (--type $TYPE)? [y/N] " CONFIRM
    [[ "$CONFIRM" =~ ^[Yy] ]] && INSTALL_SVC="y"
else
    echo "--service given without a TTY; re-run with -y to confirm. Skipping."
fi

if [ "$INSTALL_SVC" = "y" ]; then
    # Resolve the femurd path (use an `if`, not `test && cmd`, so a non-empty
    # value doesn't become the last, falsy command under `set -e`).
    SVC_EXEC="$(command -v femurd 2>/dev/null || true)"
    if [ -z "$SVC_EXEC" ]; then
        SVC_EXEC="$(resolve_script_path femurd femur-server)"
    fi
    [ -z "$SVC_EXEC" ] && SVC_EXEC="/usr/local/bin/femurd"

    # Service paths follow the deployment --type. WORKSPACE was already prepared
    # above (its path is resolved to absolute); SYSTEM uses FHS locations.
    if [ "$TYPE" = "WORKSPACE" ]; then
        SVC_CONFIG="$WORKSPACE/.env"
        SVC_DATA="$WORKSPACE/data"
        SVC_LOGS="$WORKSPACE/logs"
    else
        SVC_CONFIG="/etc/femur/.env"
        SVC_DATA="/var/lib/femur"
        SVC_LOGS="/var/log/femur"
    fi

    SVC_GROUP="$SVC_USER"

    # Create the service account if it doesn't exist.
    if ! id "$SVC_USER" &>/dev/null; then
        useradd -r -s /sbin/nologin -c "FEMUR Inventory API" "$SVC_USER"
        mset user "$SVC_USER" "created"
        logline "created system user $SVC_USER"
        echo "Created system user: $SVC_USER"
    else
        mset user "$SVC_USER" "preexisting"
        logline "service user $SVC_USER already existed (not created)"
    fi

    # Create dirs and seed config.
    mkdir -p "$(dirname "$SVC_CONFIG")" "$SVC_DATA" "$SVC_LOGS"
    mset data "$SVC_DATA" -
    mset logs "$SVC_LOGS" -

    if [ ! -f "$SVC_CONFIG" ]; then
        if [ -f "$SCRIPT_DIR/example.env" ]; then
            cp "$SCRIPT_DIR/example.env" "$SVC_CONFIG"
        fi
        chmod 600 "$SVC_CONFIG" 2>/dev/null || true
        mset config "$SVC_CONFIG" -
        mset config-hash "$SVC_CONFIG" "$(sha256_of "$SVC_CONFIG")"
        logline "seeded .env (0600) at $SVC_CONFIG"
    fi

    chown -R "$SVC_USER:$SVC_GROUP" "$SVC_DATA" "$SVC_LOGS"
    chown "$SVC_USER:$SVC_GROUP" "$SVC_CONFIG" 2>/dev/null || true

    # Render the unit template.
    UNIT_DEST="/etc/systemd/system/femur.service"
    sed -e "s|@EXEC@|$SVC_EXEC|g" \
        -e "s|@CONFIG@|$SVC_CONFIG|g" \
        -e "s|@DATA@|$SVC_DATA|g" \
        -e "s|@LOGS@|$SVC_LOGS|g" \
        -e "s|@HOST@|$SVC_HOST|g" \
        -e "s|@PORT@|$SVC_PORT|g" \
        -e "s|@USER@|$SVC_USER|g" \
        -e "s|@GROUP@|$SVC_GROUP|g" \
        "$UNIT_TEMPLATE" > "$UNIT_DEST"
    chmod 644 "$UNIT_DEST"
    mset systemd-unit "$UNIT_DEST" -
    logline "systemd unit rendered at $UNIT_DEST (service-user=$SVC_USER)"

    systemctl daemon-reload
    echo ""
    echo "Service installed: $UNIT_DEST"
    echo ""
    echo "=== IMPORTANT: populate data + validate BEFORE enabling the daemon ==="
    echo ""
    echo "1. Edit credentials in:"
    echo "     $SVC_CONFIG"
    echo ""
    echo "2. Fetch inventory AS THE SERVICE USER ($SVC_USER) so femurd has data to"
    echo "   serve and no root-owned files are left in $SVC_DATA:"
    echo ""
    echo "     sudo -u $SVC_USER femur -e $SVC_CONFIG --output-dir $SVC_DATA"
    echo ""
    echo "3. Enable the service:"
    echo ""
    echo "     sudo systemctl enable --now femur"
    echo ""
    echo "4. Verify health and sandboxing:"
    echo "     systemctl status femur"
    echo "     journalctl -u femur -f"
    echo "     systemd-analyze security femur"
fi

logline "install complete (type=$TYPE service=$INSTALL_SVC)"
echo ""
echo "State manifest:  $MANIFEST"
echo "Activity log:    $LOGFILE"
echo "To remove later:  ./uninstall.sh --state-dir $STATE_DIR   (add --purge to also delete config/data)"
echo "To upgrade later: ./upgrade.sh   --state-dir $STATE_DIR   (from a newer bundle)"
