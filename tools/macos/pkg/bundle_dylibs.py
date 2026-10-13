#!/usr/bin/env python3
"""Make a staged macOS install self-contained: every non-system library its executables load is copied into one
private directory, given an absolute install name there, and every reference (including transitive ones) rewritten to
it. Homebrew rpaths are dropped. Each changed Mach-O is re-signed (ad hoc, or with VH_PKG_CODESIGN_IDENTITY).

  bundle_dylibs.py STAGE_ROOT [--libdir /usr/local/lib/vaulthalla] [--scan PATH ...]

--scan lists installed paths (files or directories, as they will be installed) whose Mach-O files are processed;
by default the Vaulthalla binaries under /usr/local/bin and the libraries already in --libdir. The Node runtime and
the bundled PostgreSQL are left alone (official, signed / built against the OS only). Exits non-zero if anything
still references a path outside the OS and the install after bundling.
"""
import argparse
import os
import shutil
import subprocess
import sys

SYSTEM = ("/usr/lib/", "/System/")


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def is_macho(path):
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
    except OSError:
        return False
    return magic in (b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xfe\xed\xfa\xcf", b"\xbe\xba\xfe\xca")


def deps(path):
    lines = run("otool", "-L", path).splitlines()[1:]
    out = [l.strip().split(" (")[0] for l in lines if l.strip()]
    # A dylib lists its own install name first.
    if path.endswith(".dylib") and out:
        own = run("otool", "-D", path).splitlines()[1:]
        if own and out[0] == own[0].strip():
            out = out[1:]
    return out


def rpaths(path):
    out, lines = [], run("otool", "-l", path).splitlines()
    for i, l in enumerate(lines):
        if l.strip() == "cmd LC_RPATH":
            out.append(lines[i + 2].strip().split()[1])
    return out


def resolve(ref, referrer_real, referrer_rpaths):
    if ref.startswith("@rpath/"):
        for rp in referrer_rpaths:
            rp = rp.replace("@loader_path", os.path.dirname(referrer_real))
            cand = os.path.join(rp, ref[len("@rpath/"):])
            if os.path.exists(cand):
                return os.path.realpath(cand)
        return None
    if ref.startswith("@loader_path/"):
        cand = os.path.join(os.path.dirname(referrer_real), ref[len("@loader_path/"):])
        return os.path.realpath(cand) if os.path.exists(cand) else None
    return os.path.realpath(ref) if os.path.exists(ref) else None


def sign(path):
    identity = os.environ.get("VH_PKG_CODESIGN_IDENTITY", "-")
    args = ["codesign", "-f", "-s", identity]
    if identity != "-":
        args += ["--options", "runtime", "--timestamp"]
    subprocess.run(args + [path], check=True, capture_output=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("stage")
    ap.add_argument("--libdir", default="/usr/local/lib/vaulthalla")
    ap.add_argument("--scan", action="append")
    a = ap.parse_args()
    stage = os.path.abspath(a.stage)
    libdir = a.libdir
    scan = a.scan or ["/usr/local/bin", libdir]

    def staged(p):
        return stage + p

    targets = []
    for s in scan:
        p = staged(s)
        if os.path.isfile(p) and not os.path.islink(p):
            targets.append(p)
        elif os.path.isdir(p):
            for n in sorted(os.listdir(p)):
                q = os.path.join(p, n)
                if os.path.isfile(q) and not os.path.islink(q):
                    targets.append(q)
    targets = [t for t in targets if is_macho(t)]
    os.makedirs(staged(libdir), exist_ok=True)

    bundled = {}  # real source path -> installed path
    queue = list(targets)
    seen = set()
    while queue:
        f = queue.pop()
        if f in seen:
            continue
        seen.add(f)
        os.chmod(f, os.stat(f).st_mode | 0o200)
        # The original's rpaths resolve @rpath refs; a copied lib's original location tells where it came from.
        origin = getattr(main, "origins", {}).get(f, f)
        rps = rpaths(f)
        changes = []
        for ref in deps(f):
            if ref.startswith(SYSTEM) or ref.startswith(libdir + "/"):
                continue
            src = resolve(ref, origin, rps)
            if src is None:
                sys.exit(f"bundle_dylibs: {os.path.relpath(f, stage)} needs {ref}, which doesn't resolve")
            name = os.path.basename(ref)
            dest = f"{libdir}/{name}"
            if src not in bundled:
                if os.path.exists(staged(dest)) and os.path.realpath(staged(dest)) != src:
                    if run("shasum", "-a", "256", staged(dest)).split()[0] != run("shasum", "-a", "256", src).split()[0]:
                        sys.exit(f"bundle_dylibs: two different libraries named {name}")
                else:
                    shutil.copy2(src, staged(dest))
                    os.chmod(staged(dest), 0o755)
                    main.origins = getattr(main, "origins", {})
                    main.origins[staged(dest)] = src
                    subprocess.run(["install_name_tool", "-id", dest, staged(dest)], check=True, capture_output=True)
                    queue.append(staged(dest))
                bundled[src] = dest
            changes += ["-change", ref, bundled[src]]
        for rp in rps:
            if not rp.startswith(("@", libdir)):
                changes += ["-delete_rpath", rp]
        if changes:
            subprocess.run(["install_name_tool", *changes, f], check=True, capture_output=True)
        sign(f)

    # Proof: every processed file now references only the OS and the private libdir.
    bad = []
    for f in sorted(seen):
        for ref in deps(f):
            if not (ref.startswith(SYSTEM) or ref.startswith(libdir + "/")):
                bad.append(f"{os.path.relpath(f, stage)} -> {ref}")
        for rp in rpaths(f):
            if not rp.startswith(("@", libdir)):
                bad.append(f"{os.path.relpath(f, stage)} rpath {rp}")
    if bad:
        sys.exit("bundle_dylibs: still outside the install:\n  " + "\n  ".join(bad))
    print(f"bundle_dylibs: {len(seen)} Mach-O files, {len(bundled)} libraries bundled into {libdir}")


if __name__ == "__main__":
    main()
