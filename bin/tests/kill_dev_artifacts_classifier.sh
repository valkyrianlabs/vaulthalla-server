#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

export VH_DEV_CLEANUP_LIB_ONLY=true
export VH_MOUNTPOINT=/mnt/vaulthalla
source "$REPO_ROOT/bin/teardown/kill_dev_artifacts.sh"

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

assert_allowed() {
  local name="$1" exe="$2" cmdline="$3" comm="$4" cgroup="$5"
  if ! vh_identity_is_kill_eligible "$exe" "$cmdline" "$comm" "$cgroup"; then
    fail "expected allowed: $name"
  fi
}

assert_refused() {
  local name="$1" exe="$2" cmdline="$3" comm="$4" cgroup="$5"
  if vh_identity_is_kill_eligible "$exe" "$cmdline" "$comm" "$cgroup"; then
    fail "expected refused: $name"
  fi
}

assert_allowed \
  "installed server exe" \
  "/usr/bin/vaulthalla-server" \
  "/usr/bin/vaulthalla-server" \
  "vaulthalla-server" \
  "0::/user.slice/user-1000.slice/session-2.scope"

assert_allowed \
  "installed cli exe" \
  "/usr/local/bin/vaulthalla-cli" \
  "/usr/local/bin/vaulthalla-cli --systemd" \
  "vaulthalla-cli" \
  "0::/user.slice/user-1000.slice/session-2.scope"

assert_allowed \
  "exact core cgroup" \
  "/bin/sh" \
  "/bin/sh -c true" \
  "sh" \
  "0::/system.slice/vaulthalla.service"

assert_allowed \
  "packaged web node" \
  "/usr/bin/node" \
  "/usr/bin/node /usr/share/vaulthalla-web/server.js" \
  "node" \
  "0::/user.slice/user-1000.slice/session-2.scope"

assert_allowed \
  "managed swtpm" \
  "/usr/bin/swtpm" \
  "/usr/bin/swtpm socket --tpm2 --tpmstate dir=/var/lib/swtpm/vaulthalla --server type=tcp,port=2321" \
  "swtpm" \
  "0::/user.slice/user-1000.slice/session-2.scope"

assert_allowed \
  "managed fusermount3" \
  "/usr/bin/fusermount3" \
  "/usr/bin/fusermount3 -uz /mnt/vaulthalla" \
  "fusermount3" \
  "0::/user.slice/user-1000.slice/session-2.scope"

assert_refused \
  "JetBrains RemoteDev" \
  "/home/coop/.cache/JetBrains/RemoteDev/dist/bin/remote-dev-serv" \
  "/home/coop/.cache/JetBrains/RemoteDev/dist/bin/remote-dev-serv /srv/vaulthalla" \
  "remote-dev-serv" \
  "0::/user.slice/user-1000.slice/session-2.scope"

assert_refused \
  "Rider backend" \
  "/home/coop/.cache/JetBrains/RemoteDev/dist/Rider.Backend" \
  "Rider.Backend /srv/vaulthalla" \
  "Rider.Backend" \
  "0::/user.slice/user-1000.slice/session-2.scope"

assert_refused \
  "jetbrainsd" \
  "/usr/bin/jetbrainsd" \
  "/usr/bin/jetbrainsd" \
  "jetbrainsd" \
  "0::/user.slice/user-1000.slice/session-2.scope"

assert_refused \
  "fsnotifier" \
  "/opt/JetBrains/fsnotifier" \
  "/opt/JetBrains/fsnotifier /srv/vaulthalla" \
  "fsnotifier" \
  "0::/user.slice/user-1000.slice/session-2.scope"

assert_refused \
  "clangd" \
  "/usr/bin/clangd" \
  "/usr/bin/clangd --compile-commands-dir=/srv/vaulthalla/build" \
  "clangd" \
  "0::/user.slice/user-1000.slice/session-2.scope"

assert_refused \
  "Copilot language server" \
  "/home/coop/.vscode/extensions/github.copilot/chat/copilot-language-server" \
  "copilot-language-server --stdio" \
  "copilot-language" \
  "0::/user.slice/user-1000.slice/session-2.scope"

assert_refused \
  "JetBrains semantic search" \
  "/opt/JetBrains/semantic-search" \
  "semantic-search /srv/vaulthalla" \
  "semantic-search" \
  "0::/user.slice/user-1000.slice/session-2.scope"

assert_refused \
  "JetBrains denied before cgroup allow" \
  "/opt/JetBrains/fsnotifier" \
  "/opt/JetBrains/fsnotifier" \
  "fsnotifier" \
  "0::/system.slice/vaulthalla.service"

assert_refused \
  "lookalike cgroup" \
  "/bin/sh" \
  "/bin/sh -c true" \
  "sh" \
  "0::/system.slice/vaulthalla-dev.service"

assert_refused \
  "generic node" \
  "/usr/bin/node" \
  "/usr/bin/node /srv/vaulthalla/web/server.js" \
  "node" \
  "0::/user.slice/user-1000.slice/session-2.scope"

assert_refused \
  "generic next" \
  "/usr/bin/node" \
  "/usr/bin/node /srv/vaulthalla/web/node_modules/.bin/next dev" \
  "node" \
  "0::/user.slice/user-1000.slice/session-2.scope"

assert_refused \
  "arbitrary process mentioning default port" \
  "/usr/bin/python3" \
  "/usr/bin/python3 -m http.server 36969" \
  "python3" \
  "0::/user.slice/user-1000.slice/session-2.scope"

(
  export VH_DEV_CLEANUP_DRY_RUN=true
  vh_unit_exists() { return 0; }
  vh_unit_active_or_deactivating() { return 0; }
  vh_is_mounted() { return 0; }
  sudo() { fail "dry run attempted sudo $*"; }

  vh_stop_unit vaulthalla.service
  vh_kill_unit_cgroup_if_needed vaulthalla.service
  vh_lazy_unmount
)

declare -A TEST_EXE=(
  [9101]="/usr/bin/python3"
  [9102]="/home/coop/.cache/JetBrains/RemoteDev/dist/bin/remote-dev-serv"
  [9103]="/usr/bin/node"
  [9201]="/usr/bin/vaulthalla-server"
)
declare -A TEST_CMDLINE=(
  [9101]="/usr/bin/python3 -m http.server 36969"
  [9102]="remote-dev-serv --port 36969 /srv/vaulthalla"
  [9103]="/usr/bin/node /usr/share/vaulthalla-web/server.js"
  [9201]="/usr/bin/vaulthalla-server"
)
declare -A TEST_COMM=(
  [9101]="python3"
  [9102]="remote-dev-serv"
  [9103]="node"
  [9201]="vaulthalla-serv"
)
declare -A TEST_CGROUP=(
  [9101]="0::/user.slice/user-1000.slice/session-2.scope"
  [9102]="0::/user.slice/user-1000.slice/session-2.scope"
  [9103]="0::/user.slice/user-1000.slice/session-2.scope"
  [9201]="0::/system.slice/vaulthalla.service"
)

vh_pid_exe() { printf '%s\n' "${TEST_EXE[$1]:-}"; }
vh_pid_cmdline() { printf '%s\n' "${TEST_CMDLINE[$1]:-}"; }
vh_pid_comm() { printf '%s\n' "${TEST_COMM[$1]:-}"; }
vh_pid_cgroup() { printf '%s\n' "${TEST_CGROUP[$1]:-}"; }
vh_pid_is_kill_eligible() {
  vh_identity_is_kill_eligible \
    "$(vh_pid_exe "$1")" \
    "$(vh_pid_cmdline "$1")" \
    "$(vh_pid_comm "$1")" \
    "$(vh_pid_cgroup "$1")"
}
vh_process_label() { printf '%s :: %s' "$(vh_pid_exe "$1")" "$(vh_pid_cmdline "$1")"; }

killed=()
vh_kill_pid() {
  killed+=("$1:$2")
}

vh_listener_pids_for_port() {
  case "$1" in
    36969)
      printf '9101\n9102\n'
      ;;
    36970)
      printf '9103\n'
      ;;
  esac
}
vh_listener_inodes_for_port() { :; }

vh_cleanup_protocol_ports 36969
[[ "${#killed[@]}" -eq 0 ]] || fail "unverified listeners on 36969 should not be killed"

vh_cleanup_protocol_ports 36970
[[ "${#killed[@]}" -eq 1 && "${killed[0]}" == "9103:verified listener on port 36970" ]] \
  || fail "verified packaged web listener should be killed"

tmp_config="$(mktemp)"
trap 'rm -f "$tmp_config"' EXIT
cat > "$tmp_config" <<'YAML'
websocket_server:
  enabled: true
  host: 127.0.0.1
  port: 41111
http_preview_server:
  enabled: true
  host: 127.0.0.1
  port: 42222
YAML

export VH_PATH_TO_CONFIG="$tmp_config"
mapfile -t configured_ports < <(vh_protocol_ports)
[[ "${configured_ports[*]}" == "41111 42222" ]] || fail "configured protocol ports were not read"

killed=()
vh_listener_pids_for_port() {
  case "$1" in
    41111)
      printf '9101\n'
      ;;
    42222)
      printf '9103\n'
      ;;
  esac
}

vh_cleanup_protocol_ports "${configured_ports[@]}"
[[ "${#killed[@]}" -eq 1 && "${killed[0]}" == "9103:verified listener on port 42222" ]] \
  || fail "configured-port cleanup should kill only verified listeners"

killed=()
vh_listener_pids_for_port() { :; }
vh_listener_inodes_for_port() {
  [[ "$1" == "36969" ]] && printf '7777\n'
}
vh_thread_owners_for_inode() {
  [[ "$1" == "7777" ]] && printf '9201 9202\n'
}
vh_task_state_code() {
  if [[ "$1" == "9201" && "${2:-$1}" == "9202" ]]; then
    printf 'D\n'
  else
    printf 'S\n'
  fi
}
vh_task_wchan() { printf 'fuse_simple_request\n'; }
vh_task_cgroup() { printf '0::/system.slice/vaulthalla.service\n'; }

if vh_cleanup_protocol_ports 36969; then
  fail "D-state Vaulthalla listener thread should make port cleanup fail"
fi
[[ "${#killed[@]}" -eq 0 ]] || fail "D-state listener thread should not be killed"

# `make dev` installs the isolated dev instance beside production: only the instance's identities are eligible.
(
  export VH_UNIT_STEM=vaulthalla-dev VH_INSTANCE_BINDIRS=/opt/vaulthalla-dev/bin VH_MOUNTPOINT=/mnt/vh_dev
  export VH_WEB_SERVER_PATH=/opt/vaulthalla-dev/share/vaulthalla-web/server.js
  export VH_SWTPM_STATE_DIR=/var/lib/swtpm/vaulthalla-dev VH_CONFIG_PATH=/etc/vaulthalla-dev/config.yaml
  # shellcheck source=bin/teardown/kill_dev_artifacts.sh
  source "$REPO_ROOT/bin/teardown/kill_dev_artifacts.sh"
  user_scope="0::/user.slice/user-1000.slice/session-2.scope"
  assert_allowed "dev server exe" /opt/vaulthalla-dev/bin/vaulthalla-server /opt/vaulthalla-dev/bin/vaulthalla-server \
    vaulthalla-server "$user_scope"
  assert_allowed "dev core cgroup" /bin/sh "/bin/sh -c true" sh "0::/system.slice/vaulthalla-dev.service"
  assert_allowed "dev web node" /usr/bin/node "/usr/bin/node /opt/vaulthalla-dev/share/vaulthalla-web/server.js" node \
    "$user_scope"
  assert_refused "production server exe" /usr/bin/vaulthalla-server /usr/bin/vaulthalla-server vaulthalla-server \
    "$user_scope"
  assert_refused "production core cgroup" /bin/sh "/bin/sh -c true" sh "0::/system.slice/vaulthalla.service"
  assert_refused "production web cgroup" /usr/bin/node "/usr/bin/node /usr/share/vaulthalla-web/server.js" node \
    "0::/system.slice/vaulthalla-web.service"
  assert_refused "production swtpm" /usr/bin/swtpm \
    "/usr/bin/swtpm socket --tpm2 --tpmstate dir=/var/lib/swtpm/vaulthalla --server type=tcp,port=2321" swtpm \
    "0::/system.slice/vaulthalla-swtpm.service"
  assert_refused "production fusermount" /usr/bin/fusermount3 "/usr/bin/fusermount3 -uz /mnt/vaulthalla" fusermount3 \
    "$user_scope"
)

printf 'PASS: kill_dev_artifacts classifier\n'
