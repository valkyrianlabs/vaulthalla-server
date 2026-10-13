# Agent instructions

`CLAUDE.md` is the full project guide (map, commands, hard rules, conventions); every rule there applies to any agent
working in this repository. This file states the rule that is checked on every push.

## Builds are silent

**Any code pushed to GitHub, to a branch or a pull request, must compile with zero output other than the build
progress.** On Linux (GCC) and macOS (Apple clang), `meson setup` prints no WARNING/DEPRECATION lines and the
build prints nothing but ninja's `[n/N]` progress lines: no compiler or linker warnings, no notes, no script chatter.

- Check before pushing: `meson setup <dir> -Dwerror=true … 2>&1 | tee setup.log` then
  `bash tools/dev/quiet-build.sh <dir> setup.log`. CI runs the same script on both platforms and fails on any other
  line (`.github/actions/build/action.yml`, `.github/workflows/macos.yml`).
- On macOS, `source tools/macos/env.sh` first: it keeps Homebrew headers out of the warning set the way Linux's
  `/usr/include` already is.
- Fix the cause. Never silence a warning in our code with a pragma, a weaker `-W` set, or by dropping `-Werror`; a
  third-party header is the only thing that may be treated as a system header (`include_type: 'system'`).
- A warning you didn't introduce is still yours to fix if your change is the first to see it.
