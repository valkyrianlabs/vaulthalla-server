#!/usr/bin/env bash
set -euo pipefail

# Vaulthalla is published to the Valkyrian Labs APT repository, signed by the Valkyrian Labs LLC key.
# apt.vaulthalla.sh serves the same index (an alias), so either URL installs the same packages.
readonly KEY_URL="${VH_APT_KEY_URL:-https://apt.valkyrianlabs.com/pubkey.asc}"
readonly REPO_URL="${VH_APT_REPO_URL:-https://apt.valkyrianlabs.com}"
readonly REPO_DIST="${VH_APT_DIST:-stable}"
readonly REPO_COMPONENT="${VH_APT_COMPONENT:-main}"
readonly REPO_ARCH="${VH_APT_ARCH:-$(dpkg --print-architecture 2>/dev/null || echo amd64)}"

# Owned by valkyrianlabs-archive-keyring once vaulthalla pulls it in (same bytes), which keeps it current.
readonly KEY_FILE="/usr/share/keyrings/valkyrianlabs.gpg"
readonly SOURCE_FILE="/etc/apt/sources.list.d/valkyrianlabs.list"
readonly SOURCE_LINE="deb [arch=${REPO_ARCH} signed-by=${KEY_FILE}] ${REPO_URL} ${REPO_DIST} ${REPO_COMPONENT}"
# What earlier versions of this script wrote. apt.vaulthalla.sh now serves the index above, so a byte-identical
# copy is retired in favor of SOURCE_FILE; anything else there is the admin's and is left alone.
readonly LEGACY_SOURCE_FILE="/etc/apt/sources.list.d/vaulthalla.list"
readonly LEGACY_SOURCE_LINE="deb [arch=${REPO_ARCH} signed-by=/usr/share/keyrings/vaulthalla.gpg] https://apt.vaulthalla.sh ${REPO_DIST} ${REPO_COMPONENT}"

readonly VH_GROUP="vaulthalla"
readonly DEFAULT_PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
readonly ADMIN_ASSIGN_TIMEOUT_SECONDS="${VH_ADMIN_ASSIGN_TIMEOUT_SECONDS:-20}"

INTERACTIVE_MODE=0
PROFILE="standard"
PROFILE_LOCKED=0
ADMIN_MODE="current"
ASSIGN_TARGET_USER=""

REPO_KEY_STATUS="unknown"
REPO_SOURCE_STATUS="unknown"
GROUP_STATUS_LINES=()
ADMIN_STATUS="not attempted"
ADMIN_DETAIL=""
SESSION_STATUS="not evaluated"
SESSION_NEXT_STEP=""
SESSION_NOTE=""

log() { printf '[vh install] %s\n' "$*"; }
warn() { printf '[vh install] WARN: %s\n' "$*" >&2; }
die() { printf '[vh install] ERROR: %s\n' "$*" >&2; exit 1; }

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

run_priv() {
    if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
        "$@"
        return
    fi
    need_cmd sudo
    sudo "$@"
}

run_as_user() {
    local user="$1"
    shift

    if [[ "$(id -un)" == "$user" && "${EUID:-$(id -u)}" -ne 0 ]]; then
        "$@"
        return
    fi

    if [[ "${EUID:-$(id -u)}" -eq 0 ]] && command -v runuser >/dev/null 2>&1; then
        runuser -u "$user" -- "$@"
        return
    fi

    need_cmd sudo
    sudo -u "$user" "$@"
}

usage() {
    cat <<'EOF'
Usage: ./install.sh [options]

Default (no prompts):
  ./install.sh

Advanced interactive mode (arrow-key menus):
  ./install.sh --interactive
  ./install.sh --advanced

Deterministic profile flags (non-interactive):
  --lean       Install with --no-install-recommends
  --no-db      Set VH_SKIP_DB_BOOTSTRAP=1 for package install
  --no-nginx   Set VH_SKIP_NGINX_CONFIG=1 for package install

Deterministic onboarding flags:
  --assign-user <linux-user>   Attempt explicit admin claim as this user
  --skip-admin-assign          Skip explicit admin claim
EOF
}

supports_interactive_ui() {
    [[ -t 0 && -t 1 ]]
}

menu_select() {
    local prompt="$1"
    shift
    local -a options=("$@")
    local selected=0

    while true; do
        printf '%s\n' "$prompt"
        for i in "${!options[@]}"; do
            if [[ "$i" -eq "$selected" ]]; then
                printf '  ◉ %s\n' "${options[$i]}"
            else
                printf '  ◯ %s\n' "${options[$i]}"
            fi
        done
        printf '  Use ↑/↓ and Enter.\n'

        local key=""
        IFS= read -rsn1 key || true
        if [[ "$key" == $'\x1b' ]]; then
            local rest=""
            IFS= read -rsn2 rest || true
            key+="$rest"
        fi

        case "$key" in
            $'\x1b[A'|k|K)
                selected=$(( (selected - 1 + ${#options[@]}) % ${#options[@]} ))
                ;;
            $'\x1b[B'|j|J)
                selected=$(( (selected + 1) % ${#options[@]} ))
                ;;
            ""|$'\n')
                printf '\n'
                printf '%s\n' "$selected"
                return 0
                ;;
            *)
                ;;
        esac

        printf '\033[%dA\033[J' "$(( ${#options[@]} + 2 ))"
    done
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --interactive|--advanced)
                INTERACTIVE_MODE=1
                shift
                ;;
            --lean)
                [[ "$PROFILE_LOCKED" -eq 0 ]] || die "Install profile already selected. Use only one of --lean/--no-db/--no-nginx."
                PROFILE="lean"
                PROFILE_LOCKED=1
                shift
                ;;
            --no-db)
                [[ "$PROFILE_LOCKED" -eq 0 ]] || die "Install profile already selected. Use only one of --lean/--no-db/--no-nginx."
                PROFILE="no-db"
                PROFILE_LOCKED=1
                shift
                ;;
            --no-nginx)
                [[ "$PROFILE_LOCKED" -eq 0 ]] || die "Install profile already selected. Use only one of --lean/--no-db/--no-nginx."
                PROFILE="no-nginx"
                PROFILE_LOCKED=1
                shift
                ;;
            --assign-user)
                [[ $# -ge 2 ]] || die "--assign-user requires a username argument."
                ASSIGN_TARGET_USER="$2"
                ADMIN_MODE="other"
                shift 2
                ;;
            --skip-admin-assign)
                ADMIN_MODE="skip"
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                die "Unknown argument: $1"
                ;;
        esac
    done

    if [[ "$INTERACTIVE_MODE" -eq 1 && "$PROFILE_LOCKED" -eq 1 ]]; then
        die "Do not combine --interactive/--advanced with --lean/--no-db/--no-nginx."
    fi
}

ensure_supported_environment() {
    [[ "$(uname -s)" == "Linux" ]] || die "Unsupported OS: $(uname -s). This installer supports Debian/Ubuntu Linux only."
    [[ -r /etc/os-release ]] || die "Missing /etc/os-release. Cannot determine distribution."
    [[ -r /etc/debian_version ]] || die "Unsupported distro: /etc/debian_version is missing."

    # shellcheck source=/dev/null
    . /etc/os-release

    local id="${ID:-unknown}"
    local id_like="${ID_LIKE:-}"
    case "$id" in
        debian|ubuntu) ;;
        *)
            [[ "$id_like" == *debian* ]] || die "Unsupported distro: ${id}. This installer supports Debian/Ubuntu apt environments only."
            ;;
    esac

    need_cmd apt-get
    need_cmd curl
    need_cmd cmp
    need_cmd install
    need_cmd tee
    need_cmd getent
    need_cmd id
}

resolve_operator_user() {
    if [[ -n "${ASSIGN_TARGET_USER:-}" && "$ADMIN_MODE" == "other" ]]; then
        id "$ASSIGN_TARGET_USER" >/dev/null 2>&1 || die "User '${ASSIGN_TARGET_USER}' does not exist."
    fi

    if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
        printf '%s\n' "$SUDO_USER"
        return
    fi
    id -un
}

ensure_repo_bootstrap() {
    need_cmd gpg

    local tmp_key
    tmp_key="$(mktemp)"
    local tmp_keyring
    tmp_keyring="$(mktemp)"
    local tmp_source
    tmp_source="$(mktemp)"
    # Expanded now on purpose: the locals are gone by the time the EXIT trap runs.
    # shellcheck disable=SC2064
    trap "rm -f '$tmp_key' '$tmp_keyring' '$tmp_source'" EXIT

    log "Ensuring the Valkyrian Labs apt key and source are configured."
    curl -fsSL "$KEY_URL" -o "$tmp_key"
    [[ -s "$tmp_key" ]] || die "Downloaded key is empty: ${KEY_URL}"

    gpg --dearmor < "$tmp_key" > "$tmp_keyring"

    run_priv install -d -m 0755 /usr/share/keyrings /etc/apt/sources.list.d

    if [[ -f "$KEY_FILE" ]] && cmp -s "$tmp_keyring" "$KEY_FILE"; then
        REPO_KEY_STATUS="already configured"
    else
        run_priv install -m 0644 -o root -g root "$tmp_keyring" "$KEY_FILE"
        REPO_KEY_STATUS="updated"
    fi

    printf '%s\n' "$SOURCE_LINE" > "$tmp_source"

    local other
    other="$(other_source_for "$REPO_URL")"
    if [[ -f "$SOURCE_FILE" ]] && cmp -s "$tmp_source" "$SOURCE_FILE"; then
        REPO_SOURCE_STATUS="already configured"
    elif [[ -n "$other" ]]; then
        # A second entry for the same URI with another signed-by= makes apt refuse every source.
        REPO_SOURCE_STATUS="already configured (${other})"
    else
        run_priv install -m 0644 -o root -g root "$tmp_source" "$SOURCE_FILE"
        REPO_SOURCE_STATUS="updated"
    fi

    printf '%s\n' "$LEGACY_SOURCE_LINE" > "$tmp_source"
    if [[ -f "$LEGACY_SOURCE_FILE" ]] && cmp -s "$tmp_source" "$LEGACY_SOURCE_FILE"; then
        run_priv rm -f "$LEGACY_SOURCE_FILE"
        REPO_SOURCE_STATUS+="; retired ${LEGACY_SOURCE_FILE} (apt.vaulthalla.sh serves the same index)"
    elif [[ -f "$LEGACY_SOURCE_FILE" ]]; then
        warn "${LEGACY_SOURCE_FILE} was edited by hand; left unchanged. apt.vaulthalla.sh serves the same index as ${REPO_URL}."
    fi
}

# Print the first APT source file other than SOURCE_FILE that already names URL (one-line or deb822).
other_source_for() {
    local url="${1%/}" f
    for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
        [[ -f "$f" && "$f" != "$SOURCE_FILE" ]] || continue
        if grep -Eq "^[^#]*[[:space:]]${url//./\\.}/?([[:space:]]|$)" "$f"; then
            printf '%s\n' "$f"
            return
        fi
    done
}

interactive_select_profile() {
    supports_interactive_ui || die "--interactive/--advanced requires a TTY."
    local -a opts=(
        "Standard (apt install vaulthalla)"
        "Lean (apt install --no-install-recommends vaulthalla)"
        "No DB bootstrap (VH_SKIP_DB_BOOTSTRAP=1)"
        "No nginx setup (VH_SKIP_NGINX_CONFIG=1)"
    )
    local selected
    selected="$(menu_select "Select install profile:" "${opts[@]}")"
    case "$selected" in
        0) PROFILE="standard" ;;
        1) PROFILE="lean" ;;
        2) PROFILE="no-db" ;;
        3) PROFILE="no-nginx" ;;
        *) die "Invalid profile selection: ${selected}" ;;
    esac
}

interactive_select_admin_mode() {
    supports_interactive_ui || die "--interactive/--advanced requires a TTY."
    local operator_user="$1"

    local -a opts=(
        "Assign current user (${operator_user}) as Vaulthalla CLI super-admin"
        "Assign a different local user as Vaulthalla CLI super-admin"
        "Skip admin assignment for now"
    )

    local selected
    selected="$(menu_select "Select post-install admin assignment behavior:" "${opts[@]}")"
    case "$selected" in
        0)
            ADMIN_MODE="current"
            ASSIGN_TARGET_USER="$operator_user"
            ;;
        1)
            ADMIN_MODE="other"
            ASSIGN_TARGET_USER="$(interactive_select_local_user "$operator_user")"
            ;;
        2)
            ADMIN_MODE="skip"
            ASSIGN_TARGET_USER=""
            ;;
        *)
            die "Invalid admin selection: ${selected}"
            ;;
    esac
}

interactive_select_local_user() {
    local operator_user="$1"
    local -a users=()

    if command -v getent >/dev/null 2>&1; then
        while IFS=: read -r user _ uid _ _ _ shell; do
            [[ -n "$user" ]] || continue
            [[ "$uid" -ge 1000 ]] || continue
            [[ "$user" == "nobody" ]] && continue
            [[ "$shell" =~ (false|nologin)$ ]] && continue
            users+=("$user")
        done < <(getent passwd)
    fi

    if [[ "$operator_user" != "root" ]]; then
        users+=("$operator_user")
    fi

    if [[ ${#users[@]} -eq 0 ]]; then
        die "No eligible local users were found for admin assignment."
    fi

    mapfile -t users < <(printf '%s\n' "${users[@]}" | awk '!seen[$0]++' | sort)

    local selected
    selected="$(menu_select "Select local user for admin assignment:" "${users[@]}")"
    printf '%s\n' "${users[$selected]}"
}

run_apt_install_flow() {
    local -a apt_opts=()
    local -a install_env=(
        "DEBIAN_FRONTEND=noninteractive"
        "NEEDRESTART_SUSPEND=1"
    )

    case "$PROFILE" in
        lean)
            apt_opts+=("--no-install-recommends")
            ;;
        no-db)
            install_env+=("VH_SKIP_DB_BOOTSTRAP=1")
            ;;
        no-nginx)
            install_env+=("VH_SKIP_NGINX_CONFIG=1")
            ;;
        standard)
            ;;
        *)
            die "Unknown install profile: ${PROFILE}"
            ;;
    esac

    log "Running apt-get update."
    run_priv env "${install_env[@]}" apt-get update

    log "Installing vaulthalla package (profile: ${PROFILE})."
    run_priv env "${install_env[@]}" apt-get install -y "${apt_opts[@]}" vaulthalla
}

user_in_group_configured() {
    local user="$1"
    id -nG "$user" 2>/dev/null | tr ' ' '\n' | grep -Fxq "$VH_GROUP"
}

current_shell_in_group() {
    id -nG 2>/dev/null | tr ' ' '\n' | grep -Fxq "$VH_GROUP"
}

ensure_user_group_membership() {
    local user="$1"
    [[ -n "$user" ]] || return
    if [[ "$user" == "root" ]]; then
        GROUP_STATUS_LINES+=("group ${VH_GROUP}: skipped for root")
        return
    fi
    if user_in_group_configured "$user"; then
        GROUP_STATUS_LINES+=("group ${VH_GROUP}: ${user} already enrolled")
        return
    fi
    run_priv usermod -aG "$VH_GROUP" "$user"
    GROUP_STATUS_LINES+=("group ${VH_GROUP}: added ${user}")
}

attempt_admin_assignment() {
    local user="$1"
    [[ -n "$user" ]] || {
        ADMIN_STATUS="skipped by operator choice"
        return
    }

    log "Starting admin assignment check for user '${user}' (timeout: ${ADMIN_ASSIGN_TIMEOUT_SECONDS}s)."

    local vh_bin="/usr/bin/vh"
    if [[ ! -x "$vh_bin" ]]; then
        vh_bin="$(command -v vh || true)"
    fi
    [[ -n "$vh_bin" ]] || {
        ADMIN_STATUS="pending (vh binary not found)"
        ADMIN_DETAIL="Install appears complete but 'vh' is not in PATH."
        return
    }

    if ! command -v timeout >/dev/null 2>&1; then
        ADMIN_STATUS="pending (timeout utility not available)"
        ADMIN_DETAIL="Skipped automatic admin assignment to avoid unbounded wait. Run manually: vh setup assign-admin"
        return
    fi

    local timeout_status=124
    local output=""
    if output="$(run_as_user "$user" env PATH="$DEFAULT_PATH" timeout "${ADMIN_ASSIGN_TIMEOUT_SECONDS}" "$vh_bin" setup assign-admin 2>&1)"; then
        ADMIN_STATUS="completed (user: ${user})"
        ADMIN_DETAIL="$(printf '%s\n' "$output" | head -n 1)"
        return
    fi
    timeout_status=$?

    if [[ "$timeout_status" -eq 124 ]]; then
        ADMIN_STATUS="pending (timed out, user: ${user})"
        ADMIN_DETAIL="vh setup assign-admin exceeded ${ADMIN_ASSIGN_TIMEOUT_SECONDS}s; run manually after service health check."
        return
    fi

    if command -v sg >/dev/null 2>&1; then
        local sg_cmd
        printf -v sg_cmd '%q %q %q' "$vh_bin" "setup" "assign-admin"
        if output="$(run_as_user "$user" env PATH="$DEFAULT_PATH" timeout "${ADMIN_ASSIGN_TIMEOUT_SECONDS}" sg "$VH_GROUP" -c "$sg_cmd" 2>&1)"; then
            ADMIN_STATUS="completed via sg handoff (user: ${user})"
            ADMIN_DETAIL="$(printf '%s\n' "$output" | head -n 1)"
            return
        fi
        timeout_status=$?
        if [[ "$timeout_status" -eq 124 ]]; then
            ADMIN_STATUS="pending (timed out via sg handoff, user: ${user})"
            ADMIN_DETAIL="sg vh setup assign-admin exceeded ${ADMIN_ASSIGN_TIMEOUT_SECONDS}s; run manually after service health check."
            return
        fi
    fi

    ADMIN_STATUS="pending (user: ${user})"
    ADMIN_DETAIL="$(printf '%s\n' "$output" | head -n 1)"
    if [[ "$output" == *"Unknown setup subcommand"* ]]; then
        ADMIN_DETAIL="This build does not provide 'vh setup assign-admin'; first non-root user to run 'vh'/'vaulthalla' will claim super-admin."
    fi
}

compute_session_handoff_summary() {
    local operator_user="$1"
    local invoking_user
    invoking_user="$(id -un)"

    if [[ "$operator_user" != "$invoking_user" ]]; then
        SESSION_STATUS="not applied (installer was invoked by '${invoking_user}', operator '${operator_user}')"
        SESSION_NOTE="Group refresh must be done in the operator's own shell."
        return
    fi

    if current_shell_in_group; then
        SESSION_STATUS="current shell already has '${VH_GROUP}' group"
        return
    fi

    SESSION_STATUS="current shell may not yet have '${VH_GROUP}' group"
    if command -v newgrp >/dev/null 2>&1; then
        SESSION_NEXT_STEP="newgrp ${VH_GROUP}"
    else
        SESSION_NEXT_STEP="log out and log back in"
    fi
    SESSION_NOTE="A full new login shell/session may still be required to refresh parent-shell group membership."
}

INITIAL_PASSWORD_FILE="/var/lib/vaulthalla/super_admin_initial_password"

# The web console has no universal default password: each install generates one for 'admin' and writes it once to
# INITIAL_PASSWORD_FILE when the service first starts with a new database.
print_web_console_sign_in() {
    log "Web console sign-in:"
    log "  user: admin"
    if run_priv test -f "$INITIAL_PASSWORD_FILE" 2>/dev/null; then
        log "  initial password (generated for this install): sudo cat ${INITIAL_PASSWORD_FILE}"
    else
        log "  initial password: ${INITIAL_PASSWORD_FILE} (written when the service first starts with a new database;"
        log "    if it is absent on an existing install, the password was already changed or the file deleted)"
    fi
    log "  change it: vh setup set-super-admin-password (as the super-admin Linux user, without sudo; removes the file)"
    log "  keeping the generated password is fine; delete the file before exposing the console to a network"
    log "  HTTPS through nginx is optional ('vh setup nginx' below); it offers to do either first"
}

print_summary() {
    local operator_user="$1"
    local profile_label="$PROFILE"
    case "$PROFILE" in
        standard) profile_label="standard" ;;
        lean) profile_label="lean (--no-install-recommends)" ;;
        no-db) profile_label="no-db (VH_SKIP_DB_BOOTSTRAP=1)" ;;
        no-nginx) profile_label="no-nginx (VH_SKIP_NGINX_CONFIG=1)" ;;
    esac

    log "Install summary:"
    log "  repo key: ${REPO_KEY_STATUS}"
    log "  repo source: ${REPO_SOURCE_STATUS}"
    log "  profile: ${profile_label}"
    log "  operator user: ${operator_user}"

    if [[ ${#GROUP_STATUS_LINES[@]} -eq 0 ]]; then
        log "  group handling: no changes"
    else
        for line in "${GROUP_STATUS_LINES[@]}"; do
            log "  ${line}"
        done
    fi

    log "  session handoff: ${SESSION_STATUS}"
    [[ -n "$SESSION_NEXT_STEP" ]] && log "  session next step: run '${SESSION_NEXT_STEP}'"
    [[ -n "$SESSION_NOTE" ]] && log "  note: ${SESSION_NOTE}"

    log "  admin assignment: ${ADMIN_STATUS}"
    [[ -n "$ADMIN_DETAIL" ]] && log "  admin detail: ${ADMIN_DETAIL}"

    if [[ "$ADMIN_MODE" == "skip" ]]; then
        warn "Admin assignment was skipped."
        warn "First non-root user to call 'vh' or 'vaulthalla' will claim super-admin ownership for their Linux UID."
    fi

    print_web_console_sign_in

    log "Recommended next commands:"
    log "  vh setup assign-admin"
    log "  vh setup set-super-admin-password"
    log "  vh setup db"
    log "  vh setup remote-db"
    log "  vh setup nginx"
    log "  vh setup nginx --certbot --domain <domain>"
    log "  vh setup nginx --domain vaulthalla.dev --s3-domain s3.vaulthalla.dev --certbot-dns-cloudflare /etc/vaulthalla/certbot/cloudflare.ini"
}

main() {
    parse_args "$@"
    ensure_supported_environment

    local operator_user
    operator_user="$(resolve_operator_user)"
    id "$operator_user" >/dev/null 2>&1 || die "Operator user does not exist: ${operator_user}"

    if [[ "$INTERACTIVE_MODE" -eq 1 ]]; then
        interactive_select_profile
    fi

    ensure_repo_bootstrap
    run_apt_install_flow
    log "apt install flow completed."

    getent group "$VH_GROUP" >/dev/null 2>&1 || die "Group '${VH_GROUP}' was not created by package install."

    ensure_user_group_membership "$operator_user"

    if [[ "$INTERACTIVE_MODE" -eq 1 ]]; then
        interactive_select_admin_mode "$operator_user"
    elif [[ "$ADMIN_MODE" == "current" && -z "$ASSIGN_TARGET_USER" ]]; then
        ASSIGN_TARGET_USER="$operator_user"
    fi

    if [[ "$ADMIN_MODE" == "other" ]]; then
        ensure_user_group_membership "$ASSIGN_TARGET_USER"
    fi

    if [[ "$ADMIN_MODE" == "skip" ]]; then
        ADMIN_STATUS="skipped by operator choice"
    else
        log "Beginning optional admin assignment step."
        attempt_admin_assignment "$ASSIGN_TARGET_USER"
    fi

    compute_session_handoff_summary "$operator_user"
    print_summary "$operator_user"
}

main "$@"
