#!/usr/bin/env bash
# Surface-aware verification for the vaulthalla monorepo.
# Shared by contributors and agents (.claude/skills/verify wraps it).
# Usage: tools/dev/verify.sh <profile> [...more profiles]
#   doctor      toolchain + repo sanity (no builds)
#   changed     infer profiles from `git diff` + untracked files vs HEAD (default)
#   core        meson compile + meson test in build/ (configures build/ if missing)
#   web         pnpm typecheck + lint (VERIFY_STRICT_LINT=0 downgrades lint failures to warnings);
#               VERIFY_WEB_BUILD=1 also builds and enforces the first-load JS budgets (web/perf-budgets.json)
#   release     vl-release contract: vlr check + vlr version check (release.toml, staged .release/ docs)
#   packaging   product contracts (tools/contracts: Debian packaging, maintainer scripts, migrations,
#               release workflow) + tools/lab and tools/project tests, each with a minimum test count
#   lifecycle   deploy/lifecycle unit tests (minimum test count)
#   docs        payload-markdown checker on changed docs (or all docs) + pmdocs validate
#   shell       bash -n on changed/all bin/ and debian maintainer scripts
#   harness     integration engine unit + self tests (tools/harness, no daemon; Python 3.14 with `websockets`:
#               the tools/harness/.venv from bootstrap.sh, or VERIFY_HARNESS_PYTHON)
#   integration make itest: Tier A proofs as an isolated private instance (sudo; never touches the dev install)
#   all         core web release packaging lifecycle docs shell harness
set -euo pipefail

ROOT_DIR="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)"
cd "$ROOT_DIR"

log()  { printf '[verify] %s\n' "$*"; }
warn() { printf '[verify] WARN: %s\n' "$*" >&2; }
die()  { printf '[verify] ERROR: %s\n' "$*" >&2; exit 1; }

changed_files() {
  { git diff --name-only --diff-filter=ACMRTUXB HEAD; git ls-files --others --exclude-standard; } | sort -u
}

run_doctor() {
  local c want have
  for c in git python3 meson ninja node pnpm; do
    if command -v "$c" >/dev/null; then log "$c: $("$c" --version 2>&1 | head -n1)"; else warn "$c missing"; fi
  done
  for c in pmdocs shellcheck dpkg-buildpackage; do command -v "$c" >/dev/null || warn "$c missing (optional)"; done
  want="$(tr -d '[:space:]' < web/.nvmrc)"; have="$(node -v 2>/dev/null | sed 's/^v//')"
  [[ "$have" == "$want"* ]] || warn "node ${have:-none} does not match web/.nvmrc $want"
  want="$(python3 -c 'import json;print(json.load(open("web/package.json"))["packageManager"].split("@")[1])')"
  have="$(pnpm -v 2>/dev/null || true)"
  [[ "$have" == "$want" ]] || warn "pnpm ${have:-none} does not match packageManager $want"
  [[ -d web/node_modules ]] || warn "web/node_modules missing: pnpm --dir web install --frozen-lockfile"
  [[ -f build/build.ninja ]] || warn "build/ not configured: meson setup build -Dbuild_unit_tests=true"
  [[ -d web/public/icons/fa ]] || warn "private web icons missing (web build will fail); see docs/contributors/development-setup.md"
  [[ -z "$(git status --porcelain)" ]] || warn "working tree is dirty"
  if command -v vlr >/dev/null; then
    vlr version check >/dev/null && log "release-managed versions in sync ($(cat VERSION))" || warn "vlr version check failed"
  else
    warn "vlr (vl-release) missing: the release profile needs it"
  fi
}

run_core() {
  if [[ ! -f build/build.ninja ]]; then
    log "configuring build/ (-Dbuild_unit_tests=true)"
    meson setup build -Dbuild_unit_tests=true
  fi
  log "meson compile -C build"
  meson compile -C build
  # No env file is sourced: DB-backed suites skip here and run under 'make test' (bin/tests/run_unit.sh: a per-run
  # database and its own environment), and live provider tests are opt-in only (never enabled here).
  log "meson test -C build (DB-backed suites skip here: run 'make test' for them; live tests are opt-in)"
  meson test -C build --print-errorlogs
}

run_web() {
  local want have
  want="$(tr -d '[:space:]' < web/.nvmrc)"; have="$(node -v 2>/dev/null | sed 's/^v//')"
  [[ "$have" == "$want"* ]] || warn "node $have does not match web/.nvmrc $want"
  log "web typecheck"; pnpm --dir web typecheck
  log "web lint"
  if ! pnpm --dir web lint; then
    [[ "${VERIFY_STRICT_LINT:-1}" == "1" ]] && die "web lint failed"
    warn "web lint failed (VERIFY_STRICT_LINT=0, continuing)"
  fi
  # Performance budgets need a production build (slow): VERIFY_WEB_BUILD=1 builds and enforces them, as CI does.
  if [[ "${VERIFY_WEB_BUILD:-0}" == "1" ]]; then
    log "web production build"; pnpm --dir web build
    log "web performance budgets"; pnpm --dir web budgets
  else
    log "web budgets skipped (set VERIFY_WEB_BUILD=1 to build and enforce them)"
  fi
}

# Runs a unittest suite and fails when fewer than <min> tests ran, so a suite silently dropped from discovery
# (a missing __init__.py, a moved directory) can't pass as "OK". Raise the floors when adding tests.
run_suite() {
  local label="$1" min="$2" output rc=0 ran
  shift 2
  output="$(python3 -m unittest "$@" 2>&1)" || rc=$?
  printf '%s\n' "$output" | tail -n 3
  [[ "$rc" -eq 0 ]] || { printf '%s\n' "$output" | tail -n 40 >&2; die "$label failed"; }
  ran="$(printf '%s\n' "$output" | sed -nE 's/^Ran ([0-9]+) tests?.*/\1/p' | tail -n1)"
  (( ${ran:-0} >= min )) || die "$label: only ${ran:-0} test(s) ran, expected at least $min"
}

run_release() {
  command -v vlr >/dev/null || die "vlr (vl-release) is not installed: apt install vl-release (apt.valkyrianlabs.com)"
  log "vlr check"; vlr check
  log "vlr version check"; vlr version check
}

run_packaging() {
  log "product contracts (tools/contracts)"
  run_suite "tools/contracts" 177 discover -s tools/contracts -t .
  log "lab tooling tests (tools/lab/tests)"
  run_suite "tools/lab/tests" 34 discover -s tools/lab/tests -t .
  log "project board tooling tests (tools/project/tests)"
  python3 -c 'import yaml' 2>/dev/null || die "tools/project needs PyYAML: apt install python3-yaml"
  run_suite "tools/project/tests" 22 discover -s tools/project/tests -t .
}

run_lifecycle() {
  log "deploy/lifecycle tests"
  run_suite "deploy/lifecycle" 29 deploy.lifecycle.tests.test_main
}

run_docs() {
  local checker=.claude/skills/payload-markdown/scripts/check_payload_markdown_doc.py files=()
  mapfile -t files < <(changed_files | grep -E '^docs/.*\.md$' || true)
  if [[ "${#files[@]}" -eq 0 ]]; then mapfile -t files < <(find docs -name '*.md' | LC_ALL=C sort); fi
  log "payload-markdown checker on ${#files[@]} file(s)"
  python3 "$checker" "${files[@]}"
  if command -v pmdocs >/dev/null; then log "pmdocs validate --source docs"; pmdocs validate --source docs
  else warn "pmdocs not installed; skipped package validation"; fi
}

run_shell() {
  local files=() f
  mapfile -t files < <(changed_files | grep -E '^(bin/.*\.sh|web/bin/.*\.sh|tools/.*\.sh|debian/(postinst|prerm|postrm|preinst))$' || true)
  if [[ "${#files[@]}" -eq 0 ]]; then
    mapfile -t files < <( { find bin web/bin tools -name '*.sh'; ls debian/{postinst,prerm,postrm,preinst} 2>/dev/null; } | LC_ALL=C sort)
  fi
  log "bash -n on ${#files[@]} script(s)"
  for f in "${files[@]}"; do [[ -f "$f" ]] && bash -n "$f"; done
  if command -v shellcheck >/dev/null; then shellcheck -S warning "${files[@]}" || warn "shellcheck findings (non-blocking)"
  else warn "shellcheck not installed; syntax check only"; fi
}

run_harness() {
  local py="${VERIFY_HARNESS_PYTHON:-}"
  [[ -z "$py" && -x tools/harness/.venv/bin/python ]] && py="$ROOT_DIR/tools/harness/.venv/bin/python"
  py="${py:-python3.14}"
  [[ "$py" == */* && "$py" != /* ]] && py="$ROOT_DIR/$py"
  "$py" -c 'import sys; sys.exit(sys.version_info < (3, 14))' 2>/dev/null || die "tools/harness needs Python 3.14 ($py): sudo tools/harness/bootstrap.sh (or VERIFY_HARNESS_PYTHON)"
  "$py" -c 'import websockets' 2>/dev/null || die "tools/harness needs websockets: sudo tools/harness/bootstrap.sh (or VERIFY_HARNESS_PYTHON)"
  log "integration engine tests (tools/harness/tests, $py)"
  local output rc=0 ran
  output="$(cd tools/harness && "$py" -m unittest discover -s tests -t . 2>&1)" || rc=$?
  [[ "$rc" -eq 0 ]] || { printf '%s\n' "$output" | tail -n 40 >&2; die "harness tests failed"; }
  ran="$(grep -oE '^Ran [0-9]+' <<<"$output" | grep -oE '[0-9]+' || true)"
  (( ${ran:-0} >= 119 )) || die "harness: only ${ran:-0} test(s) ran, expected at least 119"
  log "harness: $ran tests passed"
}

run_integration() {
  log "make itest (isolated private instance: per-run DB, private paths, nothing installed)"
  make --no-print-directory itest
}

infer_profiles() {
  local files; files="$(changed_files)"
  [[ -z "$files" ]] && { log "no changes vs HEAD"; return; }
  grep -qE '^core/|^meson\.build$|^meson\.options$'            <<<"$files" && echo core
  grep -qE '^web/'                                              <<<"$files" && echo web
  grep -qE '^release\.toml$|^\.release/|^VERSION$|^meson\.build$|^web/package\.json$|^debian/changelog$|^RELEASE_NOTES\.md$|^\.github/' <<<"$files" && echo release
  grep -qE '^debian/|^deploy/(systemd|psql|nginx)/|^core/seed/shipped_migrations\.lock$|^tools/(contracts|lab|project)/|^\.github/' <<<"$files" && echo packaging
  grep -qE '^deploy/lifecycle/'                                 <<<"$files" && echo lifecycle
  grep -qE '^docs/|^debian/README'                              <<<"$files" && echo docs
  grep -qE '^bin/|^web/bin/|^tools/.*\.sh$|^debian/(postinst|prerm|postrm)$'   <<<"$files" && echo shell
  grep -qE '^tools/harness/|^tools/lab/pentest/'                <<<"$files" && echo harness
  return 0
}

profiles=("$@"); [[ "${#profiles[@]}" -eq 0 ]] && profiles=(changed)
expanded=()
for p in "${profiles[@]}"; do
  case "$p" in
    changed) mapfile -t -O "${#expanded[@]}" expanded < <(infer_profiles) ;;
    all) expanded+=(core web release packaging lifecycle docs shell harness) ;;
    doctor|core|web|release|packaging|lifecycle|docs|shell|harness|integration) expanded+=("$p") ;;
    *) die "unknown profile '$p'" ;;
  esac
done
[[ "${#expanded[@]}" -eq 0 ]] && { log "nothing to verify"; exit 0; }

log "profiles: ${expanded[*]}"
for p in "${expanded[@]}"; do log "== $p"; "run_$p"; done
log "verification passed: ${expanded[*]}"
