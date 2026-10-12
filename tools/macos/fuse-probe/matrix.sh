#!/bin/bash
# macOS FUSE proof matrix (roadmap #200 / #221): runs vh_fuse_probe and checks, from the probe's own request log,
# (1) which uid the kernel reports for each caller and (2) whether any answer reached a caller WITHOUT the daemon
# being asked (a cache hit). Vaulthalla's per-uid RBAC needs both: correct caller identity and no cross-uid caching.
#
# Needs macFUSE installed (FSKit module enabled) and two local accounts: the invoking user (A) and a second uid (B),
# run through `sudo -u`. Nothing here changes system configuration; it mounts under $WORK and unmounts on exit.
#
#   tools/macos/fuse-probe/matrix.sh [--other-user USER] [--backend fskit|kext] [--work DIR] [-- extra -o options]
#
# Output: one PASS/FAIL line per check plus the log path. A FAIL is evidence, not a crash: keep the log.
set -u

OTHER_USER=nobody
BACKEND=fskit
WORK="${TMPDIR:-/tmp}/vh-fuse-matrix.$$"
EXTRA=()
while [ $# -gt 0 ]; do
  case "$1" in
    --other-user) OTHER_USER="$2"; shift 2 ;;
    --backend) BACKEND="$2"; shift 2 ;;
    --work) WORK="$2"; shift 2 ;;
    --) shift; EXTRA=("$@"); break ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

HERE="$(cd "$(dirname "$0")" && pwd)"
PROBE="${VH_FUSE_PROBE:-$HERE/vh_fuse_probe}"
[ -x "$PROBE" ] || { echo "build the probe first (see vh_fuse_probe.c header) or set VH_FUSE_PROBE" >&2; exit 2; }

A_UID="$(id -u)"
B_UID="$(id -u "$OTHER_USER")" || exit 2
MNT="$WORK/mnt"
LOG="$WORK/probe.log"
POLICY="$WORK/policy"
mkdir -p "$MNT"
chmod 0755 "$WORK" "$MNT"
: > "$LOG"
echo "$A_UID" > "$POLICY"     # A may see /secret, B may not
chmod 0644 "$POLICY"

pass=0; fail=0
check() {  # check <name> <0|1 ok> <detail>
  if [ "$2" = 0 ]; then echo "PASS $1${3:+: $3}"; pass=$((pass + 1)); else echo "FAIL $1${3:+: $3}"; fail=$((fail + 1)); fi
}
lines() { wc -l < "$LOG" | tr -d ' '; }
since() { tail -n +"$(( $1 + 1 ))" "$LOG"; }
asB() { sudo -n -u "$OTHER_USER" "$@"; }

cleanup() {
  umount "$MNT" 2>/dev/null || diskutil unmount force "$MNT" >/dev/null 2>&1
  [ -n "${PID:-}" ] && kill "$PID" 2>/dev/null
}
trap cleanup EXIT

opts=(-o allow_other -o volname=vh-probe -o noappledouble -o noapplexattr)
[ "$BACKEND" = fskit ] && opts+=(-o backend=fskit)
"$PROBE" "$MNT" --log "$LOG" --policy "$POLICY" -- "${opts[@]}" "${EXTRA[@]}" &
PID=$!
for _ in $(seq 1 50); do grep -q " mounted " "$LOG" && break; sleep 0.2; done
mount | grep -q " $MNT " ; check "mount ($BACKEND, ${opts[*]} ${EXTRA[*]})" $? "$(mount | grep " $MNT " | head -1)"

# 1. Caller identity: each caller's own request carries its own uid.
n=$(lines); stat "$MNT/public" >/dev/null 2>&1
since "$n" | grep -q "uid=$A_UID " ; check "identity: A's stat arrives as uid $A_UID" $?
n=$(lines); asB stat "$MNT/public" >/dev/null 2>&1
since "$n" | grep -q "uid=$B_UID " ; check "identity: B's stat arrives as uid $B_UID" $?
n=$(lines); sudo -n stat "$MNT/public" >/dev/null 2>&1
since "$n" | grep -q "uid=0 " ; check "identity: root's stat arrives as uid 0" $?

# 2. Deny means hidden, per caller, with no cross-uid cache: A resolves /secret, then B must be asked and refused.
stat "$MNT/secret" >/dev/null 2>&1; check "A sees /secret" $?
n=$(lines); asB stat "$MNT/secret" >/dev/null 2>&1; rc=$?
[ $rc -ne 0 ] ; check "B gets ENOENT for /secret right after A resolved it" $?
since "$n" | grep -qE "(lookup|getattr).* uid=$B_UID .*secret|uid=$B_UID .*ino=3" ; check "B's request reached the daemon (not answered from A's cache)" $?
n=$(lines); asB cat "$MNT/secret" >/dev/null 2>&1; [ $? -ne 0 ] ; check "B cannot read /secret" $?
asB ls "$MNT" 2>/dev/null | grep -qx secret; [ $? -ne 0 ] ; check "B's listing hides /secret after A listed it" $?

# 3. Grants and revocations apply on the next request.
echo "$B_UID" >> "$POLICY"; asB stat "$MNT/secret" >/dev/null 2>&1 ; check "grant to B applies immediately" $?
echo "$A_UID" > "$POLICY";  n=$(lines); asB stat "$MNT/secret" >/dev/null 2>&1; [ $? -ne 0 ] ; check "revocation from B applies immediately" $?
since "$n" | grep -q "uid=$B_UID" ; check "post-revocation request reached the daemon" $?

# 4. Open handle survives policy change only as the daemon decides (probe: read after revoke is refused).
exec 9<"$MNT/secret" && { echo "" > "$POLICY"; head -c 1 <&9 >/dev/null 2>&1; [ $? -ne 0 ]; check "read on an open handle after revocation is refused" $?; exec 9<&-; echo "$A_UID" > "$POLICY"; } || check "open /secret as A" 1

# 5. Rename flags: exclusive rename refuses an existing target; swap is refused (never a plain overwrite).
echo one > "$MNT/scratch/a"; echo two > "$MNT/scratch/b"
python3 - "$MNT/scratch" <<'PY'
import ctypes, os, sys
libc = ctypes.CDLL(None, use_errno=True)
d = sys.argv[1]
RENAME_SWAP, RENAME_EXCL = 0x2, 0x4
def rx(flag):
    r = libc.renamex_np(os.path.join(d, "a").encode(), os.path.join(d, "b").encode(), flag)
    return 0 if r == 0 else ctypes.get_errno()
print("excl", rx(RENAME_EXCL)); print("swap", rx(RENAME_SWAP))
PY
grep -q "flags=0x4 -> File exists" "$LOG" ; check "renamex_np(RENAME_EXCL) onto an existing name -> EEXIST" $?
grep -q "flags=0x2 -> Invalid argument" "$LOG" || ! grep -q "flags=0x2 -> ok" "$LOG" ; check "renamex_np(RENAME_SWAP) refused (or never reached the daemon)" $?

# 6. Data integrity: 32 MiB random through the mount and back.
head -c $((32 * 1024 * 1024)) /dev/urandom > "$WORK/blob"
cp "$WORK/blob" "$MNT/scratch/blob" && cmp -s "$WORK/blob" "$MNT/scratch/blob" ; check "32 MiB write/read-back is byte-identical" $?

# 7. Finder metadata pollution (with noappledouble): no ._* or .DS_Store creates reached the daemon.
grep -qE "create .*name=(\._|\.DS_Store)" "$LOG"; [ $? -ne 0 ] ; check "no AppleDouble/.DS_Store creates" $?

# 8. Forced unmount while busy returns and the daemon exits.
exec 8<"$MNT/public"
diskutil unmount force "$MNT" >/dev/null 2>&1 || umount -f "$MNT" 2>/dev/null
exec 8<&-
for _ in $(seq 1 25); do kill -0 "$PID" 2>/dev/null || break; sleep 0.2; done
kill -0 "$PID" 2>/dev/null; [ $? -ne 0 ] ; check "forced unmount with an open handle ends the daemon" $?

echo "matrix: $pass passed, $fail failed; log: $LOG"
[ "$fail" -eq 0 ]
