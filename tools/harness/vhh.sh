#!/usr/bin/env bash
# Entry point for the integration engine: tools/harness/vhh.sh <world|run|replay|shrink|verify|agent> ...
# Launched runs need root (sudo): the engine starts a private daemon instance and actors under test uids.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="$HERE/.venv/bin/python"
[[ -x "$PY" ]] || { echo "run 'sudo $HERE/bootstrap.sh' first" >&2; exit 1; }
export PYTHONPATH="$HERE${PYTHONPATH:+:$PYTHONPATH}"
exec "$PY" -m vhh "$@"
