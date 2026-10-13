#!/bin/bash
# The web console for the macOS package, from the release's web bundle (vaulthalla-web_<v>_next-standalone.tar.gz,
# built by web/bin/build_release_payload.sh on the Linux runner, which has the licensed icon set; GitHub's macOS
# runners don't, so the console is never built there).
#
#   tools/macos/pkg/web-for-macos.sh TARBALL DESTDIR    # -> DESTDIR/usr/local/share/vaulthalla-web
#
# The standalone build is JavaScript except sharp (next/image): its linux-x64 addon and libvips are swapped for the
# darwin-arm64 ones of the same versions, fetched with `npm pack` (npm checks the registry's integrity hashes). The
# result is refused if any other native binary is left in it. Bash 3.2 compatible.
set -euo pipefail

TARBALL="${1:?usage: web-for-macos.sh TARBALL DESTDIR}"
DEST="${2:?usage: web-for-macos.sh TARBALL DESTDIR}"
WEB="$DEST/usr/local/share/vaulthalla-web"

log() { printf 'web-for-macos: %s\n' "$*" >&2; }
die() { printf 'web-for-macos: error: %s\n' "$*" >&2; exit 1; }

[ -f "$TARBALL" ] || die "no web bundle at $TARBALL"
command -v npm >/dev/null || die "npm is not on PATH"
work=$(mktemp -d "${TMPDIR:-/tmp}/vh-web.XXXXXX")
trap 'rm -rf "$work"' EXIT

tar -xzf "$TARBALL" -C "$work"
[ -f "$work/vaulthalla-web/server.js" ] || die "$TARBALL has no vaulthalla-web/server.js"
pnpm_dir="$work/vaulthalla-web/node_modules/.pnpm"

# The sharp the build resolved, and the libvips its darwin-arm64 addon expects.
sharp_dirs=$(cd "$pnpm_dir" && ls -d sharp@* 2>/dev/null || true)
[ "$(printf '%s\n' "$sharp_dirs" | grep -c .)" = 1 ] || die "expected exactly one sharp in the bundle, found: ${sharp_dirs:-none}"
sharp_version=${sharp_dirs#sharp@}
img="$pnpm_dir/$sharp_dirs/node_modules/@img"
libvips_version=$(node -e 'const p=require(process.argv[1]); process.stdout.write((p.optionalDependencies||{})["@img/sharp-libvips-darwin-arm64"]||"")' \
  "$pnpm_dir/$sharp_dirs/node_modules/sharp/package.json")
[ -n "$libvips_version" ] || die "sharp $sharp_version names no @img/sharp-libvips-darwin-arm64"

# Out with every other platform's sharp binaries (links next to sharp, and their .pnpm entries).
for link in "$img"/sharp-*; do
  [ -e "$link" ] || [ -L "$link" ] || continue
  case "$(basename "$link")" in sharp-darwin-arm64|sharp-libvips-darwin-arm64) ;; *) rm -rf "$link" ;; esac
done
for entry in "$pnpm_dir"/@img+sharp-*; do
  [ -e "$entry" ] || continue
  case "$(basename "$entry")" in @img+sharp-darwin-arm64@*|@img+sharp-libvips-darwin-arm64@*) ;; *) rm -rf "$entry" ;; esac
done

# In with darwin-arm64's, as siblings of sharp's other @img dependencies: the addon's rpath
# (@loader_path/../../sharp-libvips-darwin-arm64/lib) finds libvips there.
mkdir -p "$work/npm"
(cd "$work/npm" && npm pack --silent "@img/sharp-darwin-arm64@$sharp_version" \
  "@img/sharp-libvips-darwin-arm64@$libvips_version" >/dev/null) || die "npm pack of the darwin-arm64 sharp failed"
for pkg in sharp-darwin-arm64 sharp-libvips-darwin-arm64; do
  t=$(ls "$work/npm/img-$pkg-"*.tgz)
  mkdir -p "$work/npm/$pkg" && tar -xzf "$t" -C "$work/npm/$pkg"
  rm -rf "${img:?}/$pkg" && cp -R "$work/npm/$pkg/package" "$img/$pkg"
done

# Nothing native may be left that isn't darwin-arm64's sharp.
leftover=$(find "$work/vaulthalla-web" -type f \( -name '*.node' -o -name '*.so' -o -name '*.so.*' -o -name '*.dylib' \) |
           grep -v '/@img/sharp-darwin-arm64/\|/@img/sharp-libvips-darwin-arm64/' || true)
[ -z "$leftover" ] || die "native files for another platform remain: $leftover"

# The bundle was built in a CI container with a restrictive umask: the installed console must be readable by the
# service account (it runs as _vaulthalla), and writable by nobody but root.
chmod -R u+rwX,go+rX,go-w "$work/vaulthalla-web"
mkdir -p "$(dirname "$WEB")"
rm -rf "$WEB"
mv "$work/vaulthalla-web" "$WEB"
log "web console from $(basename "$TARBALL") with sharp $sharp_version / libvips $libvips_version for darwin-arm64"
