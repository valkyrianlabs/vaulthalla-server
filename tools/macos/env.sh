# shellcheck shell=bash
# Build environment for macOS (Apple Silicon + Homebrew). Source it, from bash or zsh:
#
#   source tools/macos/env.sh
#
# - PKG_CONFIG_PATH: openssl@3 FIRST (Homebrew's unversioned `openssl` can be openssl@4; Linux builds against OpenSSL 3),
#   then the deps prefix (pdfium.pc, libpqxx-vh.pc from tools/macos/bootstrap.sh), then the keg-only libpq and curl
#   (without curl's, Meson picks the SDK's older libcurl).
# - PATH: postgresql@16 (initdb/pg_ctl/psql for tools/macos/test-db.sh) and python@3.12's unversioned python3.
# - VH_MACOS_DEPS: where fetch-pdfium.sh / make-pc-aliases.sh install (default ~/.cache/vaulthalla-macos-deps).
# Safe to source more than once.

if ! command -v brew >/dev/null 2>&1; then
  echo "tools/macos/env.sh: Homebrew (brew) not found on PATH" >&2
  # shellcheck disable=SC2317  # exit only runs when the file is executed instead of sourced
  return 1 2>/dev/null || exit 1
fi

VH_BREW_PREFIX="$(brew --prefix)"
export VH_BREW_PREFIX
export VH_MACOS_DEPS="${VH_MACOS_DEPS:-$HOME/.cache/vaulthalla-macos-deps}"

# Prepends $2 to the colon list named by $1 unless already present.
_vh_prepend() {
  eval "_vh_cur=\${$1:-}"
  case ":${_vh_cur}:" in
    *":$2:"*) ;;
    *) if [ -n "${_vh_cur}" ]; then eval "export $1=\"\$2:\${_vh_cur}\""; else eval "export $1=\"\$2\""; fi ;;
  esac
  unset _vh_cur
}

# Prepended in reverse so the final order is: openssl@3, deps prefix, libpq, curl, then whatever was there.
_vh_prepend PKG_CONFIG_PATH "$VH_BREW_PREFIX/opt/curl/lib/pkgconfig"
_vh_prepend PKG_CONFIG_PATH "$VH_BREW_PREFIX/opt/libpq/lib/pkgconfig"
_vh_prepend PKG_CONFIG_PATH "$VH_MACOS_DEPS/lib/pkgconfig"
_vh_prepend PKG_CONFIG_PATH "$VH_BREW_PREFIX/opt/openssl@3/lib/pkgconfig"

_vh_prepend PATH "$VH_BREW_PREFIX/opt/python@3.12/libexec/bin"
_vh_prepend PATH "$VH_BREW_PREFIX/opt/postgresql@16/bin"

# Boost is found through BOOST_ROOT (Meson's boost finder does not consult pkg-config).
export BOOST_ROOT="${BOOST_ROOT:-$VH_BREW_PREFIX/opt/boost}"

# -L/-I entries in the caller's LDFLAGS/CPPFLAGS/CXXFLAGS that point at directories that don't exist (a removed
# Homebrew keg, e.g. llvm@17) only make the linker print "search path ... not found" on every link: dropped. Everything
# else in those variables is kept as given.
_vh_drop_missing_dirs() {
  eval "_vh_in=\${$1:-}"
  [ -n "${_vh_in}" ] || return 0
  _vh_out=""
  # Split through a command substitution: zsh (unlike bash) doesn't word-split an unquoted parameter.
  # shellcheck disable=SC2046
  for _vh_w in $(printf '%s\n' "${_vh_in}"); do
    case "${_vh_w}" in
      -L*|-I*) [ -d "${_vh_w#-?}" ] || continue ;;
    esac
    _vh_out="${_vh_out:+${_vh_out} }${_vh_w}"
  done
  eval "export $1=\"\${_vh_out}\""
  unset _vh_in _vh_out _vh_w
}
# CPATH is searched like -I: with Homebrew's include dir there (a common shell setup), every Homebrew header counts as
# project code and its warnings land in our build (spdlog's fmt 12 deprecations: thousands of lines). The same
# directories as C_INCLUDE_PATH/CPLUS_INCLUDE_PATH are searched as system headers: same lookup, their warnings stay theirs.
if [ -n "${CPATH:-}" ]; then
  export C_INCLUDE_PATH="${CPATH}${C_INCLUDE_PATH:+:${C_INCLUDE_PATH}}"
  export CPLUS_INCLUDE_PATH="${CPATH}${CPLUS_INCLUDE_PATH:+:${CPLUS_INCLUDE_PATH}}"
  unset CPATH
fi
_vh_drop_missing_dirs LDFLAGS
_vh_drop_missing_dirs CPPFLAGS
_vh_drop_missing_dirs CXXFLAGS

unset -f _vh_prepend _vh_drop_missing_dirs
