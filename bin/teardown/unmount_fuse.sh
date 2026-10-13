#!/usr/bin/env bash
# Safely detach the Vaulthalla FUSE mount.
#
# Do not kill by command-line substring, project path, generic FUSE name, or mount users.
# Remote IDEs and shells often mention the repository path and may legitimately touch
# the mount while inspecting files.

set -euo pipefail

UNIT="${VH_UNIT_CORE:-vaulthalla.service}"  # make dev: vaulthalla-dev.service (bin/lib/platform.sh)
MOUNT="${VH_MOUNTPOINT:-/mnt/vaulthalla}"
FORCE_VAULTHALLA_PIDS=false
SYSTEMCTL_STOP_TIMEOUT="${VH_SYSTEMCTL_STOP_TIMEOUT:-35s}"

log(){ printf '[vh-unmount] %s\n' "$*"; }

usage() {
  cat <<EOF
Usage: $0 [--force-vaulthalla-pids]

Options:
  --force-vaulthalla-pids  After graceful systemd stop fails, SIGTERM/SIGKILL only
                           the verified Vaulthalla service MainPID.
  -h, --help               Show this help.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --force-vaulthalla-pids)
      FORCE_VAULTHALLA_PIDS=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

canon_mount() {
  readlink -f "$MOUNT" 2>/dev/null || echo "$MOUNT"
}

is_mounted() {
  local mp
  mp="$(canon_mount)"

  if command -v findmnt >/dev/null 2>&1; then
    findmnt -rn -M "$mp" >/dev/null 2>&1 && return 0
  fi

  grep -Fq " $mp " /proc/self/mountinfo 2>/dev/null
}

unit_exists() {
  local unit="$1"
  systemctl list-unit-files "$unit" >/dev/null 2>&1 || systemctl status "$unit" >/dev/null 2>&1
}

unit_main_pid() {
  local unit="$1"
  systemctl show -p MainPID --value "$unit" 2>/dev/null | awk '$1>0{print $1}'
}

pid_exe() {
  local pid="$1"
  readlink -f "/proc/$pid/exe" 2>/dev/null || true
}

is_vaulthalla_pid() {
  local pid="$1" exe
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  [[ -d "/proc/$pid" ]] || return 1

  exe="$(pid_exe "$pid")"
  case "$exe" in
    /usr/bin/vaulthalla-server|/usr/local/bin/vaulthalla-server)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

safe_stop_unit() {
  local unit="$1"
  if ! unit_exists "$unit"; then
    log "$unit is not installed/loaded"
    return 0
  fi

  log "Stopping $unit"
  if command -v timeout >/dev/null 2>&1; then
    if ! sudo timeout "$SYSTEMCTL_STOP_TIMEOUT" systemctl stop --job-mode=replace "$unit"; then
      log "⚠️  systemctl stop $unit failed or exceeded $SYSTEMCTL_STOP_TIMEOUT"
      return 1
    fi
  elif ! sudo systemctl stop --job-mode=replace "$unit"; then
    log "⚠️  systemctl stop $unit failed"
    return 1
  fi

  if [[ "$(systemctl show -p ActiveState --value "$unit" 2>/dev/null || true)" == "deactivating" ]]; then
    log "⚠️  $unit is still deactivating after stop"
    return 1
  fi
}

force_verified_main_pid() {
  local unit="$1" pid
  pid="$(unit_main_pid "$unit")"
  if [[ -z "$pid" ]]; then
    log "No active MainPID for $unit"
    return 0
  fi

  if ! is_vaulthalla_pid "$pid"; then
    log "Refusing to kill unverified $unit MainPID $pid ($(pid_exe "$pid"))"
    return 1
  fi

  log "Terminating verified Vaulthalla MainPID $pid"
  sudo kill -TERM "$pid"
  sleep 2

  if kill -0 "$pid" 2>/dev/null; then
    log "Killing verified Vaulthalla MainPID $pid"
    sudo kill -KILL "$pid"
  fi
}

try_unmount() {
  local mp
  mp="$(canon_mount)"

  if ! is_mounted; then
    log "$mp is not mounted"
    return 0
  fi

  if command -v fusermount3 >/dev/null 2>&1; then
    log "Unmount: sudo fusermount3 -uz $mp"
    if ! sudo fusermount3 -uz "$mp" 2>/dev/null; then
      log "fusermount3 could not unmount $mp"
    fi
  elif command -v fusermount >/dev/null 2>&1; then
    log "Unmount: sudo fusermount -uz $mp"
    if ! sudo fusermount -uz "$mp" 2>/dev/null; then
      log "fusermount could not unmount $mp"
    fi
  fi

  if is_mounted; then
    log "Unmount: sudo umount -l $mp"
    if ! sudo umount -l "$mp" 2>/dev/null; then
      log "umount could not unmount $mp"
    fi
  fi
}

report_busy_mount() {
  local mp
  mp="$(canon_mount)"

  log "Mount is still busy: $mp"
  log "Not killing unrelated processes. Close shells, editors, terminals, or indexers using this mount and retry."

  if command -v lsof >/dev/null 2>&1; then
    log "Processes reported by lsof:"
    if ! sudo lsof +f -- "$mp" 2>/dev/null; then
      log "lsof reported no holders or could not inspect $mp"
    fi
  fi

  if command -v fuser >/dev/null 2>&1; then
    log "Processes reported by fuser -vm:"
    if ! sudo fuser -vm "$mp" 2>/dev/null; then
      log "fuser reported no holders or could not inspect $mp"
    fi
  fi
}

remove_mount_dir_if_empty() {
  local mp
  mp="$(canon_mount)"

  if is_mounted; then
    log "Refusing to remove live mountpoint: $mp"
    return 1
  fi

  if [[ -d "$mp" ]]; then
    log "Removing empty mount dir: $mp"
    sudo rmdir "$mp" 2>/dev/null || log "Mount dir not empty or not removable; leaving it in place: $mp"
  fi
}

main() {
  local mp stop_failed=false
  mp="$(canon_mount)"

  log "Target mount: $mp"
  safe_stop_unit "$UNIT" || stop_failed=true

  if [[ "$stop_failed" == true && "$FORCE_VAULTHALLA_PIDS" == true ]]; then
    force_verified_main_pid "$UNIT"
  elif [[ "$stop_failed" == true ]]; then
    log "Use --force-vaulthalla-pids to terminate only the verified $UNIT MainPID."
  fi

  try_unmount

  if is_mounted; then
    report_busy_mount
    exit 1
  fi

  remove_mount_dir_if_empty
  if ! sudo systemctl reset-failed "$UNIT" >/dev/null 2>&1; then
    log "Could not reset failed state for $UNIT"
  fi
  log "✅ Vaulthalla FUSE mount detached safely."
}

main "$@"
