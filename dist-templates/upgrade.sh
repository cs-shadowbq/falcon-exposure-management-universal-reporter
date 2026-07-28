#!/bin/bash
# FEMUR airgap upgrader
#
# Upgrades an existing airgap install to the version in THIS bundle. It reuses
# the layout recorded in the state manifest (<app>.manifest) written by
# install.sh, so paths are not re-guessed.
#
#   Packages : pip --upgrade from the bundled wheels (hash-verified). Replaced.
#   Runtime  : data/, logs/, output/ are NEVER touched.
#   config   : never overwritten. A merged candidate (.env.upgraded) is produced
#              via merge_env.py (keeps your values + comments, appends new keys),
#              plus example.env is refreshed as the reference.
#
# State (paths, baseline hash) is read from and written to <app>.manifest.
# Human-readable activity is appended to the shared <app>-installation.log.
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WHEEL_DIR="$SCRIPT_DIR/wheels"
APP_NAME="femur"
# Manifest schema this script understands. It compares MAJOR against the
# manifest's 'manifest-schema' entry and refuses on mismatch.
MANIFEST_SCHEMA="1.0.0"
MANIFEST=""   # resolved after arg parsing
LOGFILE=""
# Package set + lockfile are chosen from the manifest's install profile after it
# is read (full = femur + femurd; cli = reporter-only). Defaults cover a manifest
# with no profile recorded (older installs) = full.
PIP_PACKAGES="femur-cli femur-server"
LOCKFILE="requirements.lock"

ASSUME_YES="no"
DRY_RUN="no"
FORCE_CONFIG="no"
STATE_DIR_ARG=""
CHECK_ONLY="no"

usage() {
    cat << USAGE
FEMUR airgap upgrader

Usage: ./upgrade.sh [OPTIONS]

Upgrades an existing install to this bundle's version. Reads the state manifest
($APP_NAME.manifest) to reuse the original layout. Never touches your data,
logs, or output.

Options:
  -h, --help          Show this help and exit.
      --check-install Print the current install state (version, layout, paths,
                      service) and the version this bundle would upgrade to, then
                      exit WITHOUT changing anything.
  -y, --yes           Confirm the upgrade non-interactively (required to apply
                      changes without a TTY).
      --dry-run       Show every action but change nothing (no confirm).
      --force-config  Adopt the merged config candidate as the live .env,
                      backing up the current one as .env.bak.
      --state-dir DIR Directory holding $APP_NAME.manifest (else searched:
                      /var/log/$APP_NAME, then ~/.config/$APP_NAME, then here).
                      --log-dir is accepted as an alias.

Before applying, upgrade.sh shows the current install state and the version
transition (e.g. 2.1.0 -> 2.3.0) and asks to confirm (skip the prompt with -y).
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        --check-install) CHECK_ONLY="yes"; shift ;;
        -y|--yes) ASSUME_YES="yes"; shift ;;
        --dry-run) DRY_RUN="yes"; shift ;;
        --force-config) FORCE_CONFIG="yes"; shift ;;
        --state-dir|--log-dir)
            if [ $# -lt 2 ]; then echo "Error: $1 requires a DIR" >&2; exit 2; fi
            STATE_DIR_ARG="$2"; shift 2 ;;
        --state-dir=*|--log-dir=*) STATE_DIR_ARG="${1#*=}"; shift ;;
        *) echo "Unknown option: $1" >&2; echo "Try './upgrade.sh --help'." >&2; exit 2 ;;
    esac
done
[ -n "$STATE_DIR_ARG" ] && STATE_DIR_ARG="${STATE_DIR_ARG/#\~/$HOME}"

echo "=== FEMUR Airgap Upgrader ==="
echo ""

# --- Locate the state manifest ----------------------------------------------
STATE_DIR=""
for d in \
    "${STATE_DIR_ARG:-}" \
    "/var/log/$APP_NAME" \
    "${XDG_CONFIG_HOME:-$HOME/.config}/$APP_NAME" \
    "$SCRIPT_DIR"; do
    [ -n "$d" ] || continue
    if [ -f "$d/$APP_NAME.manifest" ]; then
        STATE_DIR="$d"
        MANIFEST="$d/$APP_NAME.manifest"
        break
    fi
done

if [ -z "$MANIFEST" ]; then
    echo "ERROR: no $APP_NAME.manifest found (searched --state-dir, /var/log/$APP_NAME," >&2
    echo "       ~/.config/$APP_NAME, and this script's dir). upgrade.sh needs the state" >&2
    echo "       manifest written by install.sh. If this is a fresh host, run" >&2
    echo "       ./install.sh instead, or pass --state-dir DIR." >&2
    exit 1
fi
LOGFILE="$STATE_DIR/$APP_NAME-installation.log"
echo "Using state manifest: $MANIFEST"

# --- Append-only activity log (syslog-style, tagged, never rewritten) -------
LOG_HOST="${HOSTNAME:-$(uname -n 2>/dev/null || echo localhost)}"
logline() {
    printf '%s %s %s/upgrade.sh[%s]: %s\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$LOG_HOST" "$APP_NAME" "$$" "$1" >> "$LOGFILE"
}

sha256_of() {
    if command -v sha256sum &>/dev/null; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

# Manifest state accessors: CATEGORY | KEY | VALUE.
mval() {
    # $1=category -> KEY column of the last matching line (path-keyed entries)
    awk -F' \\| ' -v c="$1" '$1==c {v=$2} END {if (v) print v}' "$MANIFEST"
}
mvalue() {
    # $1=category -> VALUE column of the last matching line (singleton entries)
    awk -F' \\| ' -v c="$1" '$1==c {v=$3} END {if (v) print v}' "$MANIFEST"
}
mall() {
    # $1=category -> KEY column of every matching line
    awk -F' \\| ' -v c="$1" '$1==c {print $2}' "$MANIFEST"
}
# Upsert a (category,key)=value into the manifest (advances baselines etc.).
mset() {
    local cat="$1" key="$2" val="${3:-}"
    awk -F' \\| ' -v c="$cat" -v k="$key" '!($1==c && $2==k)' "$MANIFEST" \
        > "$MANIFEST.tmp" && mv "$MANIFEST.tmp" "$MANIFEST"
    printf '%s | %s | %s\n' "$cat" "$key" "$val" >> "$MANIFEST"
}

# --- Manifest schema compatibility ------------------------------------------
FOUND_SCHEMA="$(mvalue manifest-schema)"
[ -z "$FOUND_SCHEMA" ] && FOUND_SCHEMA="1.0.0"
if [ "${FOUND_SCHEMA%%.*}" != "${MANIFEST_SCHEMA%%.*}" ]; then
    echo "ERROR: manifest schema $FOUND_SCHEMA is incompatible with this upgrader" >&2
    echo "       (understands ${MANIFEST_SCHEMA%%.*}.x). Use the upgrade.sh from a" >&2
    echo "       bundle matching the installed major version." >&2
    logline "aborted: incompatible manifest schema $FOUND_SCHEMA (want ${MANIFEST_SCHEMA%%.*}.x)"
    exit 4
fi

# --- Detect Python (same probe order as install.sh) ------------------------
PYTHON=""
for candidate in python3.12 python3.11 python3.9 python3; do
    command -v "$candidate" &>/dev/null && { PYTHON="$candidate"; break; }
done
[ -z "$PYTHON" ] && { echo "ERROR: no python3 found in PATH" >&2; exit 1; }

# --- Discover the existing install from the manifest ------------------------
CONFIG_FILE="$(mval config)"
SVC_UNIT="$(mval systemd-unit)"
SVC_USER="$(mval user)"
INSTALL_TYPE="$(mvalue type)"
MANIFEST_VER="$(mvalue version)"

# Install profile (full = femur + femurd; cli = reporter-only). Absent on
# pre-profile manifests -> treat as full. Selects the package set + lockfile so
# a reporter-only install is upgraded as CLI-only (never pulls in the server).
INSTALL_PROFILE="$(mvalue profile)"
[ -z "$INSTALL_PROFILE" ] && INSTALL_PROFILE="full"
if [ "$INSTALL_PROFILE" = "cli" ]; then
    PIP_PACKAGES="femur-cli"
    LOCKFILE="requirements-cli.lock"
else
    PIP_PACKAGES="femur-cli femur-server"
    LOCKFILE="requirements.lock"
fi

# --- Version resolution -----------------------------------------------------
# CUR_VER is the AUTHORITATIVE installed version (pip). NEW_VER is what THIS
# bundle would install (from the bundled femur_cli wheel filename).
NEW_WHEEL="$(find "$WHEEL_DIR" -maxdepth 1 -name 'femur_cli-*.whl' -print 2>/dev/null | head -1)"
NEW_VER="unknown"
if [ -n "$NEW_WHEEL" ]; then
    NEW_VER="$(basename "$NEW_WHEEL" | awk -F- '{print $2}')"
fi
CUR_VER="$($PYTHON -m pip show femur-cli 2>/dev/null | awk -F': ' '/^Version:/ {print $2}')"

# Human-readable summary of the CURRENT install. Safe to call read-only.
print_install_state() {
    echo "Current install (from manifest: $MANIFEST):"
    local ver_note=""
    if [ -n "$MANIFEST_VER" ] && [ "$MANIFEST_VER" != "$CUR_VER" ]; then
        ver_note="   (manifest recorded: $MANIFEST_VER)"
    fi
    echo "  installed version : ${CUR_VER:-<not installed>}${ver_note}"
    echo "  deployment type   : ${INSTALL_TYPE:-<unknown>}"
    echo "  install profile   : $INSTALL_PROFILE$([ "$INSTALL_PROFILE" = "cli" ] && echo "  (reporter only, no femurd)")"
    echo "  config (.env)     : ${CONFIG_FILE:-<unknown>}"
    for c in $(mall cli); do echo "  CLI               : $c"; done
    for m in $(mall man); do echo "  man page          : $m"; done
    if [ -n "$SVC_UNIT" ]; then
        local act="unknown" ena="unknown"
        if command -v systemctl &>/dev/null; then
            act="$(systemctl is-active femur 2>/dev/null || echo inactive)"
            ena="$(systemctl is-enabled femur 2>/dev/null || echo disabled)"
        fi
        echo "  systemd service   : $SVC_UNIT (user=${SVC_USER:-?}, active=$act, enabled=$ena)"
    fi
    echo "  state dir         : $STATE_DIR"
    echo "  manifest schema   : ${FOUND_SCHEMA:-1.0.0}"
    echo ""
    echo "This bundle would upgrade:  ${CUR_VER:-<none>}  ->  ${NEW_VER}"
    if [ -z "$CUR_VER" ]; then
        echo "NOTE: package not currently installed; upgrade would install it fresh."
    fi
}

print_install_state
echo ""

# --check-install: report state and exit without changing anything.
if [ "$CHECK_ONLY" = "yes" ]; then
    logline "check-install: installed=${CUR_VER:-none} bundle=${NEW_VER} type=${INSTALL_TYPE:-unknown}"
    echo "(--check-install) No changes made."
    exit 0
fi

logline "upgrade invoked (${CUR_VER:-none} -> ${NEW_VER}, dry_run=$DRY_RUN, manifest=$MANIFEST)"

# --- Confirmation gate ------------------------------------------------------
if [ "$DRY_RUN" = "yes" ]; then
    echo "[dry-run] No changes will be made."
    echo ""
elif [ "$ASSUME_YES" = "yes" ]; then
    echo "Proceeding with upgrade ${CUR_VER:-<none>} -> ${NEW_VER} (-y given)."
    logline "upgrade confirmed via -y"
    echo ""
elif [ -t 0 ]; then
    read -r -p "Proceed with upgrade ${CUR_VER:-<none>} -> ${NEW_VER}? [y/N] " CONFIRM
    if [[ ! "$CONFIRM" =~ ^[Yy] ]]; then
        echo "Aborted. (Use --check-install to inspect, or --dry-run to preview.)"
        logline "upgrade aborted at confirmation prompt"
        exit 0
    fi
    logline "upgrade confirmed interactively"
    echo ""
else
    echo "ERROR: refusing to upgrade non-interactively without -y." >&2
    echo "       Re-run with -y to confirm, --dry-run to preview, or" >&2
    echo "       --check-install to just inspect the current install." >&2
    logline "upgrade aborted (non-interactive, no -y)"
    exit 2
fi

# --- 1. Stop the service if it is active (SYSTEM/service installs) ----------
SVC_WAS_ACTIVE="no"
if [ -n "$SVC_UNIT" ] && command -v systemctl &>/dev/null; then
    if systemctl is-active --quiet femur 2>/dev/null; then
        SVC_WAS_ACTIVE="yes"
        if [ "$DRY_RUN" = "yes" ]; then
            echo "[dry-run] would stop service femur"
        else
            echo "Stopping service femur ..."
            systemctl stop femur || true
            logline "stopped service femur for upgrade"
        fi
    fi
fi

# --- 2. Upgrade the Python packages (hash-verified, offline) ----------------
# Uses the profile's lockfile (requirements.lock for full, requirements-cli.lock
# for reporter-only), so a CLI-only install is never upgraded into a server one.
if [ "$DRY_RUN" = "yes" ]; then
    echo "[dry-run] would: pip install --upgrade --no-index --find-links=wheels --require-hashes -r $LOCKFILE"
else
    echo "Upgrading Python packages (offline, hash-verified, profile=$INSTALL_PROFILE)..."
    if [ -f "$SCRIPT_DIR/$LOCKFILE" ]; then
        $PYTHON -m pip install --upgrade --no-index --find-links="$WHEEL_DIR" \
            --require-hashes -r "$SCRIPT_DIR/$LOCKFILE"
    else
        # shellcheck disable=SC2086
        $PYTHON -m pip install --upgrade --no-index --find-links="$WHEEL_DIR" $PIP_PACKAGES
    fi
    logline "packages upgraded ${CUR_VER:-none} -> ${NEW_VER} (profile=$INSTALL_PROFILE)"
    mset version - "$NEW_VER"
fi
echo ""

# --- 3. Man pages (best effort, idempotent) ---------------------------------
# Refresh every recorded man page from the bundle.
for target in $(mall man); do
    base="$(basename "$target")"
    [ -f "$SCRIPT_DIR/$base" ] || continue
    if [ "$DRY_RUN" = "yes" ]; then
        echo "[dry-run] would refresh man page at $target"
    else
        if cp "$SCRIPT_DIR/$base" "$target" 2>/dev/null; then
            echo "Refreshed man page: $target"
            logline "refreshed man page $target"
        fi
    fi
done
echo ""

# --- 3c. SBOM refresh (best effort) -----------------------------------------
# Refresh the recorded SBOM from this bundle so it reflects the upgraded version.
# Uses the SBOM matching the recorded profile (sbom-cli.cdx.json for reporter).
SBOM_TARGET="$(mval sbom)"
if [ -n "$SBOM_TARGET" ]; then
    SBOM_BASE="$(basename "$SBOM_TARGET")"
    if [ -f "$SCRIPT_DIR/$SBOM_BASE" ]; then
        if [ "$DRY_RUN" = "yes" ]; then
            echo "[dry-run] would refresh SBOM at $SBOM_TARGET"
        else
            if cp "$SCRIPT_DIR/$SBOM_BASE" "$SBOM_TARGET" 2>/dev/null; then
                echo "Refreshed SBOM: $SBOM_TARGET"
                logline "refreshed SBOM $SBOM_TARGET"
            fi
        fi
    fi
fi
echo ""

# --- 4. Config merge candidate (never overwrite live .env) ------------------
NEW_EXAMPLE="$SCRIPT_DIR/example.env"
if [ -n "$CONFIG_FILE" ] && [ -f "$CONFIG_FILE" ] && [ -f "$NEW_EXAMPLE" ]; then
    CONFIG_DIR="$(dirname "$CONFIG_FILE")"
    CANDIDATE="$CONFIG_DIR/.env.upgraded"
    echo "Building merged config candidate (your values + new keys, comments kept)..."
    if [ "$DRY_RUN" = "yes" ]; then
        tmp="$(mktemp)"
        ADDED="$($PYTHON "$SCRIPT_DIR/merge_env.py" "$CONFIG_FILE" "$NEW_EXAMPLE" "$tmp" || true)"
        rm -f "$tmp"
        if [ -n "$ADDED" ]; then
            echo "  [dry-run] keys that would be added:"; echo "$ADDED" | sed 's/^/    + /'
        else
            echo "  [dry-run] no new config keys."
        fi
    else
        ADDED="$($PYTHON "$SCRIPT_DIR/merge_env.py" "$CONFIG_FILE" "$NEW_EXAMPLE" "$CANDIDATE")"
        chmod 600 "$CANDIDATE" 2>/dev/null || true
        # Refresh the reference example alongside the config.
        cp "$NEW_EXAMPLE" "$CONFIG_DIR/example.env"
        logline "wrote merged config candidate $CANDIDATE"
        if [ -n "$ADDED" ]; then
            echo "  New config keys in $NEW_VER:"; echo "$ADDED" | sed 's/^/    + /'
        else
            echo "  No new config keys."
        fi

        if [ "$FORCE_CONFIG" = "yes" ]; then
            cp "$CONFIG_FILE" "$CONFIG_FILE.bak"
            mv "$CANDIDATE" "$CONFIG_FILE"
            chmod 600 "$CONFIG_FILE" 2>/dev/null || true
            mset config-hash "$CONFIG_FILE" "$(sha256_of "$CONFIG_FILE")"   # advance baseline
            logline "adopted merged config $CONFIG_FILE (--force-config; backup $CONFIG_FILE.bak)"
            echo "  Adopted merged config (previous saved as $(basename "$CONFIG_FILE").bak)."
        else
            echo "  Review and adopt with:"
            echo "    diff $CONFIG_FILE $CANDIDATE"
            echo "    mv $CANDIDATE $CONFIG_FILE   # when satisfied"
        fi
    fi
else
    echo "No live config recorded/found; skipping config merge."
fi
echo ""

# --- 5. Restart the service if we stopped it --------------------------------
if [ "$SVC_WAS_ACTIVE" = "yes" ]; then
    if [ "$DRY_RUN" = "yes" ]; then
        echo "[dry-run] would restart service femur"
    else
        echo "Restarting service femur ..."
        systemctl start femur || true
        logline "restarted service femur"
    fi
fi

# --- 6. Post-upgrade guidance ----------------------------------------------
echo ""
echo "=== Upgrade complete (${CUR_VER:-none} -> ${NEW_VER}) ==="
logline "upgrade complete (${CUR_VER:-none} -> ${NEW_VER})"
echo "State manifest: $MANIFEST"
echo "Activity log:   $LOGFILE"
