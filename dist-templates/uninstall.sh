#!/bin/bash
# FEMUR airgap uninstaller
#
# Default: removes the Python packages (femur-cli, femur-server), CLI wrappers,
#          man pages, systemd unit, and the service account (only if this
#          deployment's installer created it). Leaves config (.env), data, logs,
#          and the state manifest intact.
# --purge: additionally deletes config (.env), data, output, and logs.
# --yes:   don't prompt for confirmation.
#
# Reads the mutable state manifest (<app>.manifest) written by install.sh, and
# appends its actions to the shared append-only log (<app>-installation.log).
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_NAME="femur"
# Manifest schema this script understands (MAJOR checked against the manifest).
MANIFEST_SCHEMA="1.0.0"
PIP_PACKAGES="femur-cli femur-server"

PURGE="no"
ASSUME_YES="no"
STATE_DIR_ARG=""
while [ $# -gt 0 ]; do
    case "$1" in
        --purge) PURGE="yes"; shift ;;
        --yes|-y) ASSUME_YES="yes"; shift ;;
        --state-dir|--log-dir)
            if [ $# -lt 2 ]; then echo "Error: $1 requires a DIR" >&2; exit 1; fi
            STATE_DIR_ARG="$2"; shift 2 ;;
        --state-dir=*|--log-dir=*) STATE_DIR_ARG="${1#*=}"; shift ;;
        --help|-h)
            echo "Usage: $0 [--purge] [--yes] [--state-dir DIR]"
            echo "  --purge         also delete config (.env), data, output, and logs"
            echo "  --yes           skip confirmation prompt"
            echo "  --state-dir DIR directory holding $APP_NAME.manifest (else searched:"
            echo "                  /var/log/$APP_NAME, then ~/.config/$APP_NAME,"
            echo "                  then next to this script). --log-dir is an alias."
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done
[ -n "$STATE_DIR_ARG" ] && STATE_DIR_ARG="${STATE_DIR_ARG/#\~/$HOME}"

# --- Locate the state manifest ----------------------------------------------
# Search order: explicit --state-dir, then the SYSTEM state dir, then the
# per-user XDG dir, then next to this script (back-compat).
MANIFEST=""
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

# The shared append-only activity log lives next to the manifest when found,
# else in the explicit/XDG state dir so the uninstall is still recorded.
if [ -n "$STATE_DIR" ]; then
    LOGFILE="$STATE_DIR/$APP_NAME-installation.log"
else
    STATE_DIR="${STATE_DIR_ARG:-${XDG_CONFIG_HOME:-$HOME/.config}/$APP_NAME}"
    mkdir -p "$STATE_DIR" 2>/dev/null || STATE_DIR="$SCRIPT_DIR"
    LOGFILE="$STATE_DIR/$APP_NAME-installation.log"
fi

# Append-only, syslog-style, tagged with this script. Never rewrites a line.
LOG_HOST="${HOSTNAME:-$(uname -n 2>/dev/null || echo localhost)}"
logline() {
    printf '%s %s %s/uninstall.sh[%s]: %s\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$LOG_HOST" "$APP_NAME" "$$" "$1" >> "$LOGFILE"
}

# Manifest is a state file: CATEGORY | KEY | VALUE  (paths live in KEY).
mval() {
    # $1=category -> KEY column of the last matching line
    [ -f "$MANIFEST" ] || return 0
    awk -F' \\| ' -v c="$1" '$1==c {v=$2} END {if (v) print v}' "$MANIFEST"
}
mnote() {
    # $1=category -> VALUE column of the last matching line
    [ -f "$MANIFEST" ] || return 0
    awk -F' \\| ' -v c="$1" '$1==c {v=$3} END {if (v) print v}' "$MANIFEST"
}
mall() {
    # $1=category -> KEY column of every matching line
    [ -f "$MANIFEST" ] || return 0
    awk -F' \\| ' -v c="$1" '$1==c {print $2}' "$MANIFEST"
}

echo "=== FEMUR Uninstaller ==="
if [ -n "$MANIFEST" ]; then
    echo "Reading state manifest: $MANIFEST"
    # Refuse on incompatible MAJOR schema rather than misparsing (which could
    # target the wrong paths for removal). Missing entry = pre-schema 1.0.
    FOUND_SCHEMA="$(mnote manifest-schema)"
    [ -z "$FOUND_SCHEMA" ] && FOUND_SCHEMA="1.0.0"
    if [ "${FOUND_SCHEMA%%.*}" != "${MANIFEST_SCHEMA%%.*}" ]; then
        echo "ERROR: manifest schema $FOUND_SCHEMA is incompatible with this uninstaller" >&2
        echo "       (understands ${MANIFEST_SCHEMA%%.*}.x). Use the uninstall.sh from a" >&2
        echo "       bundle matching the installed major version." >&2
        logline "aborted: incompatible manifest schema $FOUND_SCHEMA (want ${MANIFEST_SCHEMA%%.*}.x)"
        exit 4
    fi
    logline "uninstall started (purge=$PURGE manifest=$MANIFEST schema=$FOUND_SCHEMA)"
else
    echo "No $APP_NAME.manifest found (searched --state-dir, /var/log/$APP_NAME,"
    echo "~/.config/$APP_NAME, and this script's dir); falling back to pip uninstall + defaults."
    logline "uninstall started (purge=$PURGE, no manifest found)"
fi
echo ""

SVC_UNIT="$(mval systemd-unit)"
SVC_USER="$(mval user)"
SVC_USER_NOTE="$(mnote user)"
CLI_PATHS="$(mall cli)"
MAN_PATHS="$(mall man)"
PKG_PATH="$(mval package)"
CONFIG_FILE="$(mval config)"
DATA_DIRS="$(mall data)"
OUTPUT_DIRS="$(mall output)"
LOG_DIRS="$(mall logs)"
SBOM_PATH="$(mval sbom)"

# Honor the recorded install profile so pip uninstall targets only what was
# installed (a reporter-only install never had femur-server). Absent profile
# (pre-profile manifest) or no manifest -> default to both.
INSTALL_PROFILE="$(mnote profile)"
if [ "$INSTALL_PROFILE" = "cli" ]; then
    PIP_PACKAGES="femur-cli"
fi

echo "Will remove:"
[ -n "$SVC_UNIT" ] && echo "  systemd unit : $SVC_UNIT"
for c in $CLI_PATHS; do echo "  CLI wrapper  : $c"; done
for m in $MAN_PATHS; do echo "  man page     : $m"; done
echo "  Python packages (pip uninstall $PIP_PACKAGES, or $PKG_PATH)"
if [ "$SVC_USER_NOTE" = "created" ] && [ -n "$SVC_USER" ]; then
    echo "  service user : $SVC_USER"
fi
if [ "$PURGE" = "yes" ]; then
    echo "Will PURGE (delete):"
    [ -n "$CONFIG_FILE" ] && echo "  config (.env): $CONFIG_FILE"
    [ -n "$DATA_DIRS" ]   && echo "  data dirs    : $DATA_DIRS"
    [ -n "$OUTPUT_DIRS" ] && echo "  output dirs  : $OUTPUT_DIRS"
    [ -n "$LOG_DIRS" ]    && echo "  log dirs     : $LOG_DIRS"
    echo "  (state manifest + activity log are kept for audit)"
else
    echo "Config (.env), data, and logs will be LEFT IN PLACE (use --purge to delete)."
fi
echo ""

if [ "$ASSUME_YES" != "yes" ]; then
    if [ -t 0 ]; then
        read -r -p "Proceed? [y/N] " CONFIRM
        [[ "$CONFIRM" =~ ^[Yy] ]] || { echo "Aborted."; logline "uninstall aborted by user"; exit 0; }
    else
        echo "Non-interactive and --yes not given; aborting."
        logline "uninstall aborted (non-interactive, no --yes)"
        exit 1
    fi
fi

# Detect python for pip uninstall.
PYTHON=""
for candidate in python3.12 python3.11 python3.9 python3; do
    command -v "$candidate" &>/dev/null && { PYTHON="$candidate"; break; }
done

# 1. Stop + remove systemd unit.
if [ -n "$SVC_UNIT" ] && command -v systemctl &>/dev/null; then
    systemctl disable --now femur 2>/dev/null || true
    if rm -f "$SVC_UNIT" 2>/dev/null; then
        systemctl daemon-reload 2>/dev/null || true
        echo "Removed systemd unit: $SVC_UNIT"
        logline "removed systemd unit $SVC_UNIT"
    else
        logline "systemd unit $SVC_UNIT not removed (missing or no permission)"
    fi
fi

# 2. Uninstall Python packages.
if [ -n "$PYTHON" ] && $PYTHON -m pip show femur-cli &>/dev/null; then
    # shellcheck disable=SC2086
    $PYTHON -m pip uninstall -y $PIP_PACKAGES 2>/dev/null \
        && logline "pip uninstalled $PIP_PACKAGES" \
        || logline "pip uninstall failed"
    echo "Uninstalled Python packages via pip."
elif [ -n "$PKG_PATH" ] && [ -d "$PKG_PATH" ]; then
    # Manual extraction mode: remove only our package trees, not all of site-packages.
    for tree in femur femur_cli femur_pipeline femur_server; do
        rm -rf "$PKG_PATH/$tree" 2>/dev/null || true
    done
    echo "Removed extracted packages under: $PKG_PATH"
    logline "removed extracted packages under $PKG_PATH"
fi

# 3. Remove CLI wrappers.
for c in $CLI_PATHS; do
    if [ -f "$c" ]; then
        rm -f "$c" 2>/dev/null \
            && { echo "Removed CLI wrapper: $c"; logline "removed CLI wrapper $c"; } \
            || logline "CLI wrapper $c not removed"
    fi
done

# 3b. Remove man pages.
for m in $MAN_PATHS; do
    if [ -f "$m" ]; then
        rm -f "$m" 2>/dev/null \
            && { echo "Removed man page: $m"; logline "removed man page $m"; } \
            || logline "man page $m not removed"
    fi
done

# 3c. Remove the recorded SBOM copy (install-created metadata in the state dir).
if [ -n "$SBOM_PATH" ] && [ -f "$SBOM_PATH" ]; then
    rm -f "$SBOM_PATH" 2>/dev/null \
        && { echo "Removed SBOM: $SBOM_PATH"; logline "removed SBOM $SBOM_PATH"; } \
        || logline "SBOM $SBOM_PATH not removed"
fi

# 4. Remove the service account only if this deployment created it.
if [ "$SVC_USER_NOTE" = "created" ] && [ -n "$SVC_USER" ]; then
    if id "$SVC_USER" &>/dev/null && command -v userdel &>/dev/null; then
        userdel "$SVC_USER" 2>/dev/null \
            && { echo "Removed service user: $SVC_USER"; logline "removed service user $SVC_USER"; } \
            || logline "service user $SVC_USER not removed (may need root)"
    fi
fi

# 5. Purge config/data/output/logs if requested.
if [ "$PURGE" = "yes" ]; then
    purge_path() {
        [ -z "$1" ] && return 0
        if [ -e "$1" ]; then
            rm -rf "$1" 2>/dev/null \
                && { echo "Purged: $1"; logline "purged $1"; } \
                || logline "purge failed for $1"
        fi
    }
    purge_path "$CONFIG_FILE"
    for d in $DATA_DIRS;   do purge_path "$d"; done
    for d in $OUTPUT_DIRS; do purge_path "$d"; done
    for d in $LOG_DIRS;    do purge_path "$d"; done
    echo ""
    echo "Purge complete. Config, data, output, and logs removed."
    echo "State manifest + activity log kept at: $STATE_DIR"
else
    echo ""
    echo "Uninstall complete. Config (.env), data, and logs were left in place."
fi

logline "uninstall complete (purge=$PURGE)"
echo "Activity recorded in: $LOGFILE"
