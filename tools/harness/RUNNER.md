# Dedicated integration runner

The manual harness workflow uses the self-hosted, Linux, X64, vaulthalla-harness labels.
Use a dedicated development/CI host, never vh-storage. Administrators must restrict
dispatch and branch selection to trusted code: this workflow runs the checkout with sudo.

Provision the host once, outside the job:

- Install the C++23/Meson/Ninja toolchain and Vaulthalla build dependencies used by the
  existing CI image, Python 3.12+ with venv, PostgreSQL, FUSE3 and its development headers.
- Provide working TPM access (hardware TPM or the development swtpm configuration),
  /dev/fuse, fusectl and allow_other support.
- Have the vaulthalla group and run sudo tools/harness/bootstrap.sh once to provision
  the dedicated vh_harness role, root-only /var/lib/vaulthalla-harness/db.env, and
  vhh-actor-01..16. The workflow never rotates those credentials or changes host accounts.
- Allow passwordless sudo for the trusted runner. The launcher uses postgres to create
  one vh_harness_<run> database per instance and drops only that database.
- Reserve sufficient disk/RAM for sanitizer builds. TSan additionally needs a kernel/address
  layout supported by the toolchain; select none or address,undefined otherwise.

Each dispatch allocates a fresh build, Python venv and artifact directory under
RUNNER_TEMP. Nothing is installed. The launcher supplies fresh loopback ports, private
/tmp/vhh_<run> runtime paths and per-run databases. There is no shared build cleanup,
service restart, or dependency on the shared development daemon.

Controls are profile, seed, session count, magic rounds and sanitizer. Smoke includes the
live revoke scenario. Pressure includes the HTTP/FUSE magic workload. A failed command,
scenario, teardown or sanitizer check makes the job fail. A 60-minute workload timeout
first sends SIGINT so Python's scoped teardown runs; the entire job is bounded to 120 minutes.

The artifact upload runs on failure and includes the workload log, redacted trace, verdicts,
scenario and teardown reports, build logs, sanitizer reports and available diagnostic
evidence. Private backing data, generated credentials and runtime keys are not uploaded.
Regress/replay attempt directories are placed beneath the job artifact directory.
No workflow has been dispatched merely by adding this configuration.
