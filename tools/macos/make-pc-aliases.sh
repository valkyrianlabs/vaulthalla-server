#!/bin/bash
# Writes pkg-config aliases that map Linux SDK names onto Homebrew packages, into <prefix>/lib/pkgconfig.
#
#   tools/macos/make-pc-aliases.sh <prefix>
#
# core/meson.build requires `libpqxx-vh >= 8.0.2` on every OS (on Linux: the static libpqxx SDK from
# apt.vaulthalla.sh; tools/contracts pins the name). On macOS, libpqxx-vh.pc wraps Homebrew's shared libpqxx
# (+ libpq) for development builds; a static SDK is a distribution-time concern. Rerun after `brew upgrade libpqxx`
# (bootstrap does).
# Bash 3.2 compatible.
set -euo pipefail

die() { printf 'make-pc-aliases: error: %s\n' "$*" >&2; exit 1; }

[ $# -eq 1 ] && [ -n "$1" ] || die "usage: $0 <prefix>"
command -v brew >/dev/null 2>&1 || die "Homebrew is required"
command -v pkg-config >/dev/null 2>&1 || die "pkg-config is required (brew install pkgconf)"

brew_prefix="$(brew --prefix)"
pqxx_pc_dir="$brew_prefix/opt/libpqxx/lib/pkgconfig"
[ -f "$pqxx_pc_dir/libpqxx.pc" ] || die "Homebrew libpqxx is not installed (brew bundle --file tools/macos/Brewfile)"
# libpqxx.pc has Requires.private: libpq, which is keg-only.
pqxx_version="$(PKG_CONFIG_PATH="$pqxx_pc_dir:$brew_prefix/opt/libpq/lib/pkgconfig" pkg-config --modversion libpqxx)"
[ -n "$pqxx_version" ] || die "could not read the Homebrew libpqxx version"

mkdir -p "$1/lib/pkgconfig"
pc_dir="$(cd "$1/lib/pkgconfig" && pwd -P)"
pc="$pc_dir/libpqxx-vh.pc"

# Absolute .dylib paths and no Requires on purpose: core/meson.build asks for libpqxx-vh with static: true, and a
# `Requires: libpqxx` chain makes Meson resolve libpq's Requires.private statically (libpq.a, libcurl.a, and Homebrew
# curl's openssl@4 libssl.a/libcrypto.a ahead of openssl@3), so the binary would embed OpenSSL 4 while compiling
# against OpenSSL 3 headers. Linking the two shared libraries keeps each one bound to the OpenSSL it was built with.
pqxx_lib="$brew_prefix/opt/libpqxx/lib/libpqxx.dylib"
pq_lib="$brew_prefix/opt/libpq/lib/libpq.dylib"
[ -f "$pqxx_lib" ] || die "missing $pqxx_lib"
[ -f "$pq_lib" ] || die "missing $pq_lib"

cat > "$pc.tmp" <<EOF
Name: libpqxx-vh
Description: Alias for Homebrew's shared libpqxx $pqxx_version + libpq (macOS development builds; Linux uses the static libpqxx-vh-dev SDK)
Version: $pqxx_version
Libs: $pqxx_lib $pq_lib
Cflags: -I$brew_prefix/opt/libpqxx/include -I$brew_prefix/opt/libpq/include
EOF
mv -f "$pc.tmp" "$pc"
printf 'make-pc-aliases: libpqxx-vh %s -> Homebrew libpqxx (%s)\n' "$pqxx_version" "$pc"
