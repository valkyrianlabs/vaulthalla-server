# Historical shared-libmagic race campaign

The magic scenario provisions pentest-v1 in a new private daemon. Half the sessions upload
through the console's authenticated HTTP lane; half write through independent FUSE actors.
Every round releases all writes together, waits for sealing/upload completion, then reads
each file through the opposite surface. Pathnames are unique per writer and round. The
normal oracle, canary and integrity judges run, and this workload additionally requires
every operation to succeed and every transfer to provide a hash.

The trace records the seed, setup operation, canonical operations, measured intervals and
barriers. The report counts batches with observed HTTP/FUSE request overlap. Request overlap
does not prove simultaneous entry into libmagic. Sanitizer findings, crashes, missing
operations, incorrect bytes, and incomplete teardown fail the scenario.

## Fixed build baseline

Build the current branch with integration targets and ASan/UBSan (or a supported TSan
toolchain). Do not install the build. From a bootstrapped harness checkout:

    sudo tools/harness/vhh.sh scenario magic --build build-fixed --seed 0x197 \
      --sessions 12 --rounds 100 --out /tmp/vhh-magic-fixed-01

Repeat with fresh output directories. The launcher creates fresh databases and runtime
directories; no published fixture or running development daemon is reused. Save each
scenario.json and instance/magic/trace.jsonl along with sanitizer logs.

## Disposable historical fault build

Opus owns the fault-injected campaign. Create a separate scratch worktree/branch from the
exact fixed commit, with its own build directory. In that scratch worktree only, remove the
two scoped_lock statements guarding the shared cookie calls in
core/src/fs/metadata/Magic.cpp. Preserve the static Magic instances and all other code.
That recreates concurrent use of the same cookie and the returned libmagic-owned buffer.

Do not commit or push that patch, add a production runtime fault switch, modify the fixed
build, or disable sanitizer diagnostics to make the campaign pass. Record the base commit,
the scratch-only diff and sanitizer flags with the campaign artifacts. ASan can expose
memory corruption even when the system libmagic is not instrumented; reliable TSan analysis
of accesses inside libmagic may require a separately instrumented scratch dependency build.

Run the same scenario/seed against the scratch binary. A nonzero run is only a candidate
reproduction: inspect the sanitizer stack for libmagic/Magic/Filesystem sealing involvement.
A provisioning error, unrelated timeout, or startup failure is not evidence of the race.

## Replay and measured success rate

Use a failing run's complete trace (including setup):

    sudo tools/harness/vhh.sh replay --target launch --build build-magic-fault \
      --trace /tmp/vhh-magic-fault-01/instance/magic/trace.jsonl \
      --schedule barrier --repeat 20 --predicate 'sanitizer|integrity|liveness' \
      --artifacts /tmp/vhh-magic-fault-replays

Replay creates a fresh instance per attempt, preserves recorded barriers, and checks the
daemon's sanitizer reports after teardown, including reports from a surviving daemon.
Its JSON reports reproduced/repeat and the diagnostic path for each attempt. Record the
actual fraction and inspect stacks; replay preserves operation overlap, not internal
thread interleavings. Do not assume a success rate before executing this campaign.

Repeat the exact trace against the fixed build with the same repeat count and predicate.
For this negative control, zero reproductions is expected: the replay CLI deliberately
returns exit 1 when no failure is reproduced. Verify each attempt's diagnostics and clean
teardown rather than treating an invocation/setup failure as a clean negative control.
Normal repeated fixed scenarios must return zero and pass all integrity checks.

## Implementer validation versus final acceptance

The focused tests inject corrupted reads, a simulated crash, and a surviving sanitizer
report to prove the recording and replay failure paths. These are plumbing tests, not a
reproduction of the C++ libmagic race. A small real fixed-build workload and replay are
recorded in the implementation handoff. The full scratch fault campaign, repeat counts
and historical-race success rate remain Opus's acceptance work.
