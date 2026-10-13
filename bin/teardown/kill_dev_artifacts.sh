#!/usr/bin/env bash
# Dev-only cleanup for stale Vaulthalla-owned services and protocol listeners.
#
# This script deliberately avoids repo-path, mount-user, generic command substring,
# and port-only killing. A PID is eligible only when it has an exact Vaulthalla
# identity, and JetBrains/RemoteDev tooling is denied before allow rules are used.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# The install this cleans up. Defaults: production's names (the dev install used to be production's). `make dev` now
# installs an isolated instance and passes its own (bin/lib/platform.sh): unit stem vaulthalla-dev, its binaries under
# /opt/vaulthalla-dev, /mnt/vh_dev; then nothing that belongs to a production install beside it is ever eligible.
VH_UNIT_STEM="${VH_UNIT_STEM:-vaulthalla}"
VH_INSTANCE_BINDIRS="${VH_INSTANCE_BINDIRS:-/usr/bin /usr/local/bin}"
VH_CONFIG_PATH="${VH_CONFIG_PATH:-/etc/vaulthalla/config.yaml}"
VH_MOUNTPOINT="${VH_MOUNTPOINT:-/mnt/vaulthalla}"
VH_WEB_SERVER_PATH="${VH_WEB_SERVER_PATH:-/usr/share/vaulthalla-web/server.js}"
VH_SWTPM_STATE_DIR="${VH_SWTPM_STATE_DIR:-/var/lib/swtpm/vaulthalla}"
VH_SYSTEMCTL_STOP_TIMEOUT="${VH_SYSTEMCTL_STOP_TIMEOUT:-35s}"
VH_PID_GRACE_SECONDS="${VH_PID_GRACE_SECONDS:-2}"

# vaulthalla-cli.{socket,service} are retired (#110) but still cleaned up on older dev installs.
VH_DEV_CLEANUP_UNITS=(
  "$VH_UNIT_STEM-web.service"
  "$VH_UNIT_STEM-cli.socket"
  "$VH_UNIT_STEM-cli.service"
  "$VH_UNIT_STEM.service"
  "$VH_UNIT_STEM-swtpm.service"
)

vh_log() {
  printf '[vh-dev-cleanup] %s\n' "$*"
}

vh_is_dry_run() {
  [[ "${VH_DEV_CLEANUP_DRY_RUN:-false}" == "true" ]]
}

vh_canon_path() {
  local path="$1"
  readlink -f "$path" 2>/dev/null || printf '%s\n' "$path"
}

vh_is_exact_vaulthalla_unit() {
  local unit
  for unit in "${VH_DEV_CLEANUP_UNITS[@]}"; do
    [[ "$1" == "$unit" ]] && return 0
  done
  return 1
}

vh_is_instance_binary() {
  local dir
  for dir in $VH_INSTANCE_BINDIRS; do
    case "$1" in
      "$dir/vaulthalla-server"|"$dir/vaulthalla-cli") return 0 ;;
    esac
  done
  return 1
}

vh_unit_exists() {
  local unit="$1"
  vh_is_exact_vaulthalla_unit "$unit" || return 1
  systemctl list-unit-files "$unit" >/dev/null 2>&1 || systemctl status "$unit" >/dev/null 2>&1
}

vh_systemctl() {
  if vh_is_dry_run; then
    vh_log "DRY RUN: would run systemctl $*"
    return 0
  fi

  if command -v timeout >/dev/null 2>&1; then
    sudo timeout "$VH_SYSTEMCTL_STOP_TIMEOUT" systemctl "$@"
  else
    sudo systemctl "$@"
  fi
}

vh_unit_state() {
  local unit="$1"
  systemctl show -p ActiveState --value "$unit" 2>/dev/null || true
}

vh_unit_active_or_deactivating() {
  local unit="$1" state
  state="$(vh_unit_state "$unit")"
  [[ "$state" == "active" || "$state" == "activating" || "$state" == "deactivating" || "$state" == "reloading" ]]
}

vh_stop_unit() {
  local unit="$1"
  vh_is_exact_vaulthalla_unit "$unit" || {
    vh_log "Refusing to stop non-Vaulthalla unit: $unit"
    return 1
  }

  if ! vh_unit_exists "$unit"; then
    vh_log "$unit is not installed/loaded"
    return 0
  fi

  if vh_is_dry_run; then
    vh_log "DRY RUN: would stop exact unit $unit"
    return 0
  fi

  vh_log "Stopping exact unit $unit"
  if ! vh_systemctl stop --job-mode=replace "$unit"; then
    vh_log "systemctl stop $unit failed or exceeded $VH_SYSTEMCTL_STOP_TIMEOUT"
    return 1
  fi

  if vh_unit_active_or_deactivating "$unit"; then
    vh_log "$unit is still $(vh_unit_state "$unit")"
    return 1
  fi
}

vh_kill_unit_cgroup_if_needed() {
  local unit="$1"
  vh_is_exact_vaulthalla_unit "$unit" || {
    vh_log "Refusing to kill non-Vaulthalla unit: $unit"
    return 1
  }

  vh_unit_exists "$unit" || return 0
  vh_unit_active_or_deactivating "$unit" || return 0

  if vh_is_dry_run; then
    vh_log "DRY RUN: would terminate exact unit cgroup $unit"
    return 0
  fi

  vh_log "Terminating exact unit cgroup $unit"
  if ! sudo systemctl kill --kill-who=all --signal=SIGTERM "$unit"; then
    vh_log "systemctl kill SIGTERM failed for $unit"
  fi

  sleep "$VH_PID_GRACE_SECONDS"
  vh_unit_active_or_deactivating "$unit" || return 0

  vh_log "Killing exact unit cgroup $unit"
  if ! sudo systemctl kill --kill-who=all --signal=SIGKILL "$unit"; then
    vh_log "systemctl kill SIGKILL failed for $unit"
  fi
}

vh_stop_dev_units() {
  local unit
  for unit in "${VH_DEV_CLEANUP_UNITS[@]}"; do
    vh_stop_unit "$unit" || true
  done

  for unit in "${VH_DEV_CLEANUP_UNITS[@]}"; do
    vh_kill_unit_cgroup_if_needed "$unit" || true
  done
}

vh_is_mounted() {
  local mp
  mp="$(vh_canon_path "$VH_MOUNTPOINT")"

  if command -v findmnt >/dev/null 2>&1; then
    findmnt -rn -M "$mp" >/dev/null 2>&1 && return 0
  fi

  grep -Fq " $mp " /proc/self/mountinfo 2>/dev/null
}

vh_lazy_unmount() {
  local mp
  mp="$(vh_canon_path "$VH_MOUNTPOINT")"

  if ! vh_is_mounted; then
    vh_log "$mp is not mounted"
    return 0
  fi

  if vh_is_dry_run; then
    vh_log "DRY RUN: would lazy-unmount $mp"
    return 0
  fi

  if command -v fusermount3 >/dev/null 2>&1; then
    vh_log "Lazy unmount with fusermount3: $mp"
    sudo fusermount3 -uz "$mp" 2>/dev/null || vh_log "fusermount3 could not unmount $mp"
  elif command -v fusermount >/dev/null 2>&1; then
    vh_log "Lazy unmount with fusermount: $mp"
    sudo fusermount -uz "$mp" 2>/dev/null || vh_log "fusermount could not unmount $mp"
  fi

  if vh_is_mounted; then
    vh_log "Lazy unmount with umount -l: $mp"
    sudo umount -l "$mp" 2>/dev/null || vh_log "umount could not unmount $mp"
  fi
}

vh_identity_is_forbidden() {
  local exe="$1" cmdline="$2" comm="$3" cgroup="$4"
  local haystack
  haystack="${exe} ${cmdline} ${comm} ${cgroup}"
  haystack="${haystack,,}"

  case "$haystack" in
    *jetbrains*|*remotedev*|*remote-dev*|*rider.backend*|*fsnotifier*|*clangd*|*copilot*|*semantic-search*)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

vh_cgroup_has_exact_vaulthalla_unit() {
  local cgroup="$1" line path part
  local -a parts=()

  while IFS= read -r line; do
    path="${line#*:*:}"
    IFS='/' read -r -a parts <<< "$path" || true
    for part in "${parts[@]}"; do
      if vh_is_exact_vaulthalla_unit "$part"; then
        return 0
      fi
    done
  done <<< "$cgroup"

  return 1
}

vh_cmdline_args_match_node_web() {
  local cmdline="$1"
  local -a args=()
  read -r -a args <<< "$cmdline" || true

  [[ "${#args[@]}" -eq 2 ]] || return 1
  [[ "${args[0]##*/}" == "node" ]] || return 1
  [[ "${args[1]}" == "$VH_WEB_SERVER_PATH" ]]
}

vh_cmdline_uses_swtpm_state_dir() {
  local cmdline="$1"
  local arg
  local -a args=()
  read -r -a args <<< "$cmdline" || true

  for arg in "${args[@]}"; do
    case "$arg" in
      "dir=$VH_SWTPM_STATE_DIR"|"--tpmstate=dir=$VH_SWTPM_STATE_DIR")
        return 0
        ;;
    esac
  done

  return 1
}

vh_cmdline_targets_mountpoint() {
  local cmdline="$1" mount_raw mount_canon arg
  local -a args=()
  mount_raw="$VH_MOUNTPOINT"
  mount_canon="$(vh_canon_path "$VH_MOUNTPOINT")"
  read -r -a args <<< "$cmdline" || true

  for arg in "${args[@]}"; do
    [[ "$arg" == "$mount_raw" || "$arg" == "$mount_canon" ]] && return 0
  done

  return 1
}

vh_identity_is_kill_eligible() {
  local exe="$1" cmdline="$2" comm="$3" cgroup="$4"
  local exe_base
  exe_base="${exe##*/}"

  if vh_identity_is_forbidden "$exe" "$cmdline" "$comm" "$cgroup"; then
    return 1
  fi

  if vh_is_instance_binary "$exe"; then
    return 0
  fi

  if vh_cgroup_has_exact_vaulthalla_unit "$cgroup"; then
    return 0
  fi

  if [[ "$exe_base" == "node" || "$comm" == "node" ]] && vh_cmdline_args_match_node_web "$cmdline"; then
    return 0
  fi

  if [[ "$exe_base" == "swtpm" || "$comm" == "swtpm" ]] && vh_cmdline_uses_swtpm_state_dir "$cmdline"; then
    return 0
  fi

  if [[ "$exe_base" == "fusermount3" || "$comm" == "fusermount3" ]] && vh_cmdline_targets_mountpoint "$cmdline"; then
    return 0
  fi

  return 1
}

vh_pid_exe() {
  local pid="$1"
  readlink -f "/proc/$pid/exe" 2>/dev/null || true
}

vh_pid_cmdline() {
  local pid="$1"
  if [[ -r "/proc/$pid/cmdline" ]]; then
    tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | sed 's/[[:space:]]*$//' || true
  fi
  return 0
}

vh_pid_comm() {
  local pid="$1"
  if [[ -r "/proc/$pid/comm" ]]; then
    tr -d '\n' < "/proc/$pid/comm" 2>/dev/null || true
  fi
  return 0
}

vh_pid_cgroup() {
  local pid="$1"
  if [[ -r "/proc/$pid/cgroup" ]]; then
    cat "/proc/$pid/cgroup" 2>/dev/null || true
  fi
  return 0
}

vh_task_status_field() {
  local pid="$1" tid="$2" field="$3"
  local status="/proc/$pid/task/$tid/status"

  [[ -r "$status" ]] || return 0
  awk -v field="$field" '$1 == field ":" { sub(/^[^:]+:[[:space:]]*/, ""); print; exit }' "$status" 2>/dev/null || true
}

vh_task_state_code() {
  local pid="$1" tid="${2:-$1}" state
  state="$(vh_task_status_field "$pid" "$tid" State)"
  [[ -n "$state" ]] || return 0
  printf '%s\n' "${state%%[[:space:]]*}"
}

vh_pid_is_zombie() {
  [[ "$(vh_task_state_code "$1" "$1")" == "Z" ]]
}

vh_task_wchan() {
  local pid="$1" tid="${2:-$1}"
  if [[ -r "/proc/$pid/task/$tid/wchan" ]]; then
    cat "/proc/$pid/task/$tid/wchan" 2>/dev/null || true
  fi
}

vh_task_cgroup() {
  local pid="$1" tid="${2:-$1}"
  if [[ -r "/proc/$pid/task/$tid/cgroup" ]]; then
    cat "/proc/$pid/task/$tid/cgroup" 2>/dev/null || true
  else
    vh_pid_cgroup "$pid"
  fi
}

vh_pid_is_kill_eligible() {
  local pid="$1"
  local exe cmdline comm cgroup

  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  [[ -d "/proc/$pid" ]] || return 1

  exe="$(vh_pid_exe "$pid")"
  cmdline="$(vh_pid_cmdline "$pid")"
  comm="$(vh_pid_comm "$pid")"
  cgroup="$(vh_pid_cgroup "$pid")"

  vh_identity_is_kill_eligible "$exe" "$cmdline" "$comm" "$cgroup"
}

vh_process_label() {
  local pid="$1" exe cmdline
  exe="$(vh_pid_exe "$pid")"
  cmdline="$(vh_pid_cmdline "$pid")"
  printf '%s :: %s' "${exe:-unknown-exe}" "${cmdline:-unknown-cmdline}"
}

vh_skip_own_pid() {
  local pid="$1"
  [[ "$pid" == "$$" || "$pid" == "${BASHPID:-}" || "$pid" == "${PPID:-}" ]]
}

vh_kill_pid() {
  local pid="$1" reason="$2"

  if vh_skip_own_pid "$pid"; then
    return 0
  fi

  if ! vh_pid_is_kill_eligible "$pid"; then
    vh_log "Refusing to kill unverified PID $pid ($(vh_process_label "$pid"))"
    return 1
  fi

  if vh_pid_is_zombie "$pid"; then
    vh_log "Skipping zombie PID $pid for $reason ($(vh_process_label "$pid"))"
    return 0
  fi

  if vh_is_dry_run; then
    vh_log "DRY RUN: would terminate verified PID $pid for $reason ($(vh_process_label "$pid"))"
    return 0
  fi

  vh_log "Terminating verified PID $pid for $reason ($(vh_process_label "$pid"))"
  sudo kill -TERM "$pid" 2>/dev/null || return 0
  sleep "$VH_PID_GRACE_SECONDS"

  if sudo kill -0 "$pid" 2>/dev/null; then
    vh_log "Killing verified PID $pid for $reason"
    sudo kill -KILL "$pid" 2>/dev/null || true
  fi
}

vh_cleanup_verified_orphans() {
  local proc pid

  vh_log "Scanning for verified Vaulthalla orphan processes"
  for proc in /proc/[0-9]*; do
    [[ -d "$proc" ]] || continue
    pid="${proc##*/}"
    vh_skip_own_pid "$pid" && continue
    if vh_pid_is_kill_eligible "$pid"; then
      vh_kill_pid "$pid" "dev orphan cleanup" || true
    fi
  done
}

vh_active_config_path() {
  local candidate
  for candidate in \
    "${VH_PATH_TO_CONFIG:-}" \
    "$VH_CONFIG_PATH" \
    "$REPO_ROOT/config.yaml" \
    "$REPO_ROOT/deploy/config/config.yaml"; do
    [[ -n "$candidate" && -r "$candidate" ]] || continue
    # An instance's ports are only in its own config: the repo's carry production's.
    if [[ "$VH_UNIT_STEM" != vaulthalla && "$candidate" != "${VH_PATH_TO_CONFIG:-}" && "$candidate" != "$VH_CONFIG_PATH" ]]; then
      continue
    fi
    printf '%s\n' "$candidate"
    return 0
  done

  return 1
}

vh_config_section_port() {
  local path="$1" section="$2" default="$3"

  awk -v section="$section" -v fallback="$default" '
    BEGIN { in_section = 0; found = 0 }
    $0 ~ "^[[:space:]]*" section ":[[:space:]]*($|#)" {
      in_section = 1
      next
    }
    in_section && $0 ~ "^[^[:space:]#][^:]*:" {
      in_section = 0
    }
    in_section && $0 ~ "^[[:space:]]*port:[[:space:]]*" {
      line = $0
      sub(/[[:space:]]*#.*/, "", line)
      sub(/^.*port:[[:space:]]*/, "", line)
      gsub(/[[:space:]]/, "", line)
      if (line ~ /^[0-9]+$/) {
        print line
        found = 1
        exit
      }
    }
    END {
      if (!found) {
        print fallback
      }
    }
  ' "$path"
}

vh_protocol_ports() {
  local config ws_port preview_port

  if config="$(vh_active_config_path 2>/dev/null)"; then
    ws_port="$(vh_config_section_port "$config" websocket_server 36969)"
    preview_port="$(vh_config_section_port "$config" http_preview_server 36970)"
    vh_log "Protocol port source: $config (websocket=$ws_port, preview=$preview_port)" >&2
  else
    ws_port=36969
    preview_port=36970
    vh_log "Protocol config not found; using defaults $ws_port/$preview_port" >&2
  fi

  printf '%s\n%s\n' "$ws_port" "$preview_port" | awk '!seen[$0]++'
}

vh_listener_pids_for_port() {
  local port="$1" output

  command -v ss >/dev/null 2>&1 || {
    vh_log "ss is unavailable; cannot inspect port $port"
    return 0
  }

  output="$(sudo ss -H -ltnp "( sport = :$port )" 2>/dev/null || true)"
  [[ -n "$output" ]] || return 0

  printf '%s\n' "$output" \
    | grep -oE 'pid=[0-9]+' \
    | cut -d= -f2 \
    | awk '!seen[$0]++' || true
}

vh_port_hex() {
  local port="$1"
  printf '%04X\n' "$port"
}

vh_listener_inodes_for_port() {
  local port="$1" port_hex
  port_hex="$(vh_port_hex "$port")"

  awk -v port_hex="$port_hex" '
    $1 == "sl" { next }
    $4 == "0A" {
      split($2, local_addr, ":")
      if (toupper(local_addr[2]) == port_hex && $10 != "0")
        print $10
    }
  ' /proc/net/tcp /proc/net/tcp6 2>/dev/null | awk '!seen[$0]++'
}

vh_thread_owners_for_inode() {
  local inode="$1"

  sudo find /proc/[0-9]*/task/[0-9]*/fd -lname "socket:[$inode]" -printf '%p\n' 2>/dev/null \
    | sed -E 's#^/proc/([0-9]+)/task/([0-9]+)/fd/.*#\1 \2#' \
    | awk '!seen[$0]++' || true
}

vh_listener_owners_for_port() {
  local port="$1" pid inode owner owner_pid owner_tid
  local -a pids=()
  local -a inodes=()

  {
    mapfile -t pids < <(vh_listener_pids_for_port "$port")
    for pid in "${pids[@]}"; do
      [[ -n "$pid" ]] || continue
      printf '%s %s ss\n' "$pid" "$pid"
    done

    mapfile -t inodes < <(vh_listener_inodes_for_port "$port")
    for inode in "${inodes[@]}"; do
      [[ -n "$inode" ]] || continue
      while IFS= read -r owner; do
        [[ -n "$owner" ]] || continue
        read -r owner_pid owner_tid <<< "$owner"
        printf '%s %s %s\n' "$owner_pid" "$owner_tid" "$inode"
      done < <(vh_thread_owners_for_inode "$inode")
    done
  } | awk '!seen[$1 " " $2]++'
}

vh_report_stuck_kernel_thread() {
  local port="$1" pid="$2" tid="$3" inode="$4"
  local state wchan cgroup

  state="$(vh_task_state_code "$pid" "$tid")"
  wchan="$(vh_task_wchan "$pid" "$tid")"
  cgroup="$(vh_task_cgroup "$pid" "$tid" | tr '\n' ' ')"

  vh_log "Stuck Vaulthalla thread holds protocol port $port: TGID=$pid TID=$tid state=${state:-unknown} wchan=${wchan:-unknown} inode=$inode"
  vh_log "  process: $(vh_process_label "$pid")"
  vh_log "  cgroup: ${cgroup:-unknown}"
  vh_log "Cannot kill a D-state kernel-blocked thread from userland; reboot or clear the underlying FUSE/kernel blockage before restarting Vaulthalla."
  VH_STUCK_KERNEL_THREADS=1
}

vh_cleanup_protocol_ports() {
  local port owner pid tid source state key
  local -a owners=()
  local -A seen_owner=()
  VH_STUCK_KERNEL_THREADS=0

  for port in "$@"; do
    [[ "$port" =~ ^[0-9]+$ ]] || continue
    vh_log "Inspecting protocol listener port $port"
    mapfile -t owners < <(vh_listener_owners_for_port "$port")

    for owner in "${owners[@]}"; do
      read -r pid tid source <<< "$owner"
      [[ -n "$pid" ]] || continue
      tid="${tid:-$pid}"
      source="${source:-unknown}"
      key="$pid:$tid:$source"
      [[ -z "${seen_owner[$key]:-}" ]] || continue
      seen_owner[$key]=1

      if vh_pid_is_kill_eligible "$pid"; then
        state="$(vh_task_state_code "$pid" "$tid")"
        if [[ "$state" == "D" ]]; then
          vh_report_stuck_kernel_thread "$port" "$pid" "$tid" "$source"
          continue
        fi

        vh_kill_pid "$pid" "verified listener on port $port" || true
      else
        vh_log "Refusing to kill unverified listener on port $port: PID $pid TID $tid ($(vh_process_label "$pid"))"
      fi
    done
  done

  [[ "$VH_STUCK_KERNEL_THREADS" != 1 ]]
}

main() {
  local -a ports=()

  vh_log "Starting dev-only harsh cleanup"
  vh_stop_dev_units
  vh_lazy_unmount
  vh_cleanup_verified_orphans
  mapfile -t ports < <(vh_protocol_ports)
  vh_cleanup_protocol_ports "${ports[@]}"
  vh_lazy_unmount

  if vh_is_mounted; then
    vh_log "Mount is still live after verified cleanup: $(vh_canon_path "$VH_MOUNTPOINT")"
    vh_log "Refusing to continue dev teardown while the mount remains attached."
    exit 1
  fi

  vh_log "Dev-only cleanup complete"
}

if [[ "${VH_DEV_CLEANUP_LIB_ONLY:-false}" != "true" ]]; then
  main "$@"
fi
