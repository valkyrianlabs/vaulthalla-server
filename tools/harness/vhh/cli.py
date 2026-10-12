"""vhh: `python -m vhh {world,run,replay,shrink,verify,agent} ...`

Exit codes: 0 pass, 1 fail (a verdict, a broken input, a harness defect), 2 refused (target or usage).
Destructive commands accept only `--target sim` or a target descriptor written by the launcher for a private local
instance (see vhh/targets.py); vh-storage and unknown hosts fail closed.
"""
from __future__ import annotations

import argparse
import asyncio
import importlib
import json
import os
import sys
from pathlib import Path

from vhh import fixture_v1, oracle, replay as R, run as RUN, sim, targets, world as W, worldgen
from vhh.broker import IdentityBroker
from vhh.catalog import load as load_catalog
from vhh.engine import Engine, Session
from vhh.model import Op, Result
from vhh.recorder import TraceError, read_trace
from vhh.redact import Redactor
from vhh.seeds import fmt_seed, parse_seed

PASS, FAIL, REFUSED = 0, 1, 2


def say(verdict: str, msg: str) -> None:
    print(f"vhh: {verdict}: {msg}", flush=True)


# ------------------------------------------------------------------------------------------------ worlds

def load_world(spec: str) -> W.World:
    """'pentest-v1' | 'gen:<seed>[:<profile>]' | path to a world.json. Raises WorldError."""
    if spec in W.WORLDS:
        return W.WORLDS[spec]()
    if spec.startswith("gen:"):
        _, seed, *rest = spec.split(":")
        return worldgen.generate(parse_seed(seed), rest[0] if rest else "smoke")
    p = Path(spec)
    if not p.is_file():
        raise W.WorldError(f"unknown world {spec!r}")
    try:
        return W.load(json.loads(p.read_text()))
    except json.JSONDecodeError as e:
        raise W.WorldError(f"{p}: not JSON ({e.msg})") from e


def world_from_header(h: dict) -> W.World:
    wh = h.get("world") or {}
    if wh.get("seed") and wh.get("name", "").startswith("gen-"):
        w = worldgen.generate(parse_seed(wh["seed"]), wh.get("profile") or "smoke")
    else:
        w = load_world(wh.get("name", ""))
    if wh.get("world_hash") and w.world_hash() != wh["world_hash"]:
        raise W.WorldError("the trace's world hash does not match the rebuilt world")
    return w


def cmd_world(a) -> int:
    try:
        w = load_world(a.world)
    except W.WorldError as e:
        say("FAIL", str(e))
        return FAIL
    errs = w.validate()
    if errs:
        say("FAIL", "invalid world: " + "; ".join(errs))
        return FAIL
    if a.action == "show":
        print(json.dumps({"name": w.name, "seed": w.seed, "world_hash": w.world_hash(),
                          "principals": len(w.principals), "groups": len(w.groups), "vaults": len(w.vaults),
                          "grants": len(w.grants), "overrides": len(w.overrides), "shares": len(w.shares),
                          "objects": len(w.objects), "expectations": len(w.expectations)}, indent=2))
        return PASS
    if a.action == "fixture":
        out = Path(a.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / "manifest.json").write_text(json.dumps(fixture_v1.manifest(w, build_version=a.build_version,
                                                                          git_commit=a.git_commit), indent=2))
        (out / "canaries.json").write_text(json.dumps(fixture_v1.canaries(w), indent=2))
        say("PASS", f"fixture v1 written to {out}")
        return PASS
    # oracle-check: the model against every hand-written expectation
    if not w.expectations:
        say("FAIL", f"{w.name} has no hand-written expectations to cross-check")
        return FAIL
    bad = []
    for e in w.expectations:
        d = oracle.decide_fixture(w, e.principal, e.resource, e.operation, e.path)
        if d.expect != e.expect:
            bad.append(f"{e.principal} {e.operation} {e.resource}:{e.path}: expectation {e.expect}, model "
                       f"{d.expect} ({d.reason})")
    for line in bad:
        print("  MISMATCH " + line)
    say("FAIL" if bad else "PASS", f"{len(w.expectations) - len(bad)}/{len(w.expectations)} expectations agree")
    return FAIL if bad else PASS


# ------------------------------------------------------------------------------------------------ targets

def _target(a):
    try:
        return targets.resolve(a.target)
    except targets.TargetRefused as e:
        say("REFUSED", str(e))
        return None


def _sim_factory(w, broker):
    daemon = sim.SimDaemon(w)
    daemon.register_credentials(broker)
    return lambda surface, principal: sim.SimDriver(surface, daemon, broker)


def _real_factory(target, broker):
    def make(surface, principal):
        mod = importlib.import_module(f"vhh.drivers.{surface}")
        return mod.create(target, principal, broker)
    return make


def _broker(w, kind, target, creds: str | None):
    red = Redactor()
    broker = IdentityBroker(red)
    broker.register_canaries(w.canaries)
    if kind == "private":
        path = creds or os.path.join(getattr(target, "artifacts", ""), "credentials.json")
        if os.path.exists(path):
            broker.load_private_file(path)
    return red, broker


def _run_launched(a) -> int:
    """--target launch: start a private instance from --build, provision the world into it, run, tear down."""
    from vhh.drivers import real
    from vhh.instance import Instance, InstanceError
    try:
        from vhh import provision
    except ImportError:
        say("FAIL", "vhh/provision.py is missing: launched runs need the provisioning module")
        return FAIL
    if not a.build:
        say("REFUSED", "--target launch needs --build <meson build dir>")
        return REFUSED
    try:
        w = load_world(a.world)
    except W.WorldError as e:
        say("FAIL", f"broken world: {e}")
        return FAIL
    seed = parse_seed(a.seed)
    print(f"vhh: seed {fmt_seed(seed)} world {w.name} schedule {a.schedule} (launching {a.build})", flush=True)
    red, broker = _broker(w, "launch", None, None)
    out = Path(a.out) if a.out else RUN.new_run_dir()
    cfg = RUN.RunConfig(seed=seed, profile=a.profile, schedule=a.schedule, sessions=a.sessions,
                        ops_per_session=a.ops, surfaces=tuple(a.surfaces.split(",")), kill_file=a.kill_file)
    try:
        inst = Instance(Path(a.build), artifacts=out / "instance", redactor=red)
        inst.start()
    except InstanceError as e:
        say("FAIL", f"instance: {e}")
        return FAIL
    died = None
    try:
        binding = asyncio.run(provision.provision(inst.target, w, broker, red))
        catalog = load_catalog(a.catalog).restricted(real.SUPPORTED)
        if a.weights:
            catalog = catalog.weighted({k: float(v) for k, v in (kv.split("=", 1) for kv in a.weights.split(","))})
        hard = 120 + 30 * cfg.sessions * cfg.ops_per_session   # far beyond any per-op deadline sum
        with inst.watchdog(hard) as dog:
            res = RUN.run(w, cfg, broker, red, real.factory(inst, binding, w, broker, red), out,
                          catalog, {"kind": "launched", "run_id": inst.run_id})
        if dog.fired:
            died = {"watchdog": f"run exceeded {hard}s; FUSE connection aborted"}
        if not inst.alive():
            died = inst.health()
            inst.capture_evidence("daemon-died")
    finally:
        report = inst.stop()
        sanitizers = inst.sanitizer_reports()
        (out / "instance.json").write_text(json.dumps({"stop": report, "died": died, "sanitizers": sanitizers},
                                                      indent=2, default=str))
    for v in res.engine.failures[:20]:
        print(f"  [{v.judge}/{v.classification}] seq={v.seq} {v.message}")
    ok = res.passed and died is None and report.get("stop") == "clean" and not sanitizers
    reasons = list(res.summary["reasons"]) + ([f"daemon died: {died}"] if died else []) + \
        ([f"sanitizer report(s): {', '.join(sanitizers)}"] if sanitizers else []) + \
        ([f"daemon stop: {report.get('stop')}"] if report.get("stop") not in (None, "clean") else [])
    say("PASS" if ok else "FAIL", f"{res.summary['executed']} ops, {'; '.join(reasons) or 'clean'} "
        f"(seed {fmt_seed(seed)}, trace {res.trace_path}, artifacts {out})")
    print(f"vhh: reproduce with: sudo tools/harness/vhh.sh run --target launch --build {a.build} --world {a.world} "
          f"--seed {fmt_seed(seed)} --schedule {a.schedule} --sessions {a.sessions} --ops {a.ops} "
          f"--surfaces {a.surfaces}" + (f" --weights {a.weights}" if a.weights else ""))
    return PASS if ok else FAIL


def cmd_scenario(a) -> int:
    from vhh import scenarios
    out = Path(a.out) if a.out else RUN.new_run_dir()
    ok, report = scenarios.run(a.kind, a.build, out)
    for k in ("outcome", "after", "wedge", "took_s", "grant_latency_s", "revoke_latency_s", "steps", "died",
              "mount_gone", "db_dropped", "why"):
        if k in report:
            print(f"  {k}: {report[k]}")
    say("PASS" if ok else "FAIL", f"scenario {a.kind}: {'detected and contained' if ok else 'NOT contained'} "
        f"(artifacts {out})")
    return PASS if ok else FAIL


def cmd_run(a) -> int:
    if a.target == "launch":
        return _run_launched(a)
    resolved = _target(a)
    if resolved is None:
        return REFUSED
    kind, target = resolved
    try:
        w = load_world(a.world)
    except W.WorldError as e:
        say("FAIL", f"broken world: {e}")
        return FAIL
    seed = parse_seed(a.seed)
    print(f"vhh: seed {fmt_seed(seed)} world {w.name} schedule {a.schedule}", flush=True)
    red, broker = _broker(w, kind, target, a.credentials)
    factory = _sim_factory(w, broker) if kind == "sim" else _real_factory(target, broker)
    out = Path(a.out) if a.out else RUN.new_run_dir()
    cfg = RUN.RunConfig(seed=seed, profile=a.profile, schedule=a.schedule, sessions=a.sessions,
                        ops_per_session=a.ops, surfaces=tuple(a.surfaces.split(",")), kill_file=a.kill_file)
    res = RUN.run(w, cfg, broker, red, factory, out, load_catalog(a.catalog),
                  {"kind": kind, **({"run_id": getattr(target, "run_id", None)} if target else {})})
    for v in res.engine.failures[:20]:
        print(f"  [{v.judge}/{v.classification}] seq={v.seq} {v.message}")
    say(res.summary["verdict"], f"{res.summary['executed']} ops, {'; '.join(res.summary['reasons']) or 'clean'} "
        f"(seed {fmt_seed(seed)}, trace {res.trace_path})")
    return PASS if res.passed else FAIL


def _engine_factory(w, kind, target, a):
    def factory(ops):
        red, broker = _broker(w, kind, target, a.credentials)
        make = _sim_factory(w, broker) if kind == "sim" else _real_factory(target, broker)
        engine = Engine(w, load_catalog(a.catalog), broker, red)
        for sid in sorted({o.session for o in ops}):
            o = next(x for x in ops if x.session == sid)
            engine.add_session(Session(sid, o.principal, o.surface, make(o.surface, o.principal), intent="replay"))
        return engine
    return factory


def _launched_engine_factory(w, a):
    """Each replay/shrink attempt gets a fresh private instance (launch, provision, engine); the engine's teardown
    stops it. Replay assumes a freshly provisioned world, so nothing is reused between attempts."""
    import concurrent.futures
    from vhh import provision
    from vhh.drivers import real
    from vhh.instance import Instance

    def factory(ops):
        red, broker = _broker(w, "launch", None, None)
        inst = Instance(Path(a.build), redactor=red)
        inst.start()
        try:
            with concurrent.futures.ThreadPoolExecutor(1) as pool:   # provision is async; we are inside a loop
                binding = pool.submit(asyncio.run, provision.provision(inst.target, w, broker, red)).result()
        except BaseException:
            inst.stop()
            raise
        make = real.factory(inst, binding, w, broker, red)
        engine = Engine(w, load_catalog(a.catalog), broker, red)
        for sid in sorted({o.session for o in ops}):
            o = next(x for x in ops if x.session == sid)
            engine.add_session(Session(sid, o.principal, o.surface, make(o.surface, o.principal), intent="replay"))
        engine.teardown = inst.stop
        return engine
    return factory


def _replay_factory(a, w):
    if a.target == "launch":
        if not a.build:
            raise ValueError("--target launch needs --build")
        return _launched_engine_factory(w, a)
    resolved = _target(a)
    return None if resolved is None else _engine_factory(w, *resolved, a)


def _load_trace_and_world(a):
    trace = read_trace(a.trace)
    return trace, world_from_header(trace.header)


def cmd_replay(a) -> int:
    try:
        trace, w = _load_trace_and_world(a)
        factory = _replay_factory(a, w)
    except (TraceError, W.WorldError, OSError, ValueError) as e:
        say("FAIL", str(e))
        return FAIL
    if factory is None:
        return REFUSED
    lo, hi = R.parse_window(a.window)
    pairs = R.window(trace, lo, hi)
    rep = asyncio.run(R.replay(factory, pairs, a.schedule, a.repeat, R.predicate(a.predicate)))
    print(json.dumps(rep.to_json(), indent=2))
    print(f"vhh: note: {R.NOTE}")
    ok = rep.ops > 0 and rep.reproduced > 0
    say("REPRODUCED" if ok else "NOT REPRODUCED", f"{rep.reproduced}/{rep.repeat} runs matched '{a.predicate}'")
    return PASS if ok else FAIL


def cmd_regress(a) -> int:
    """Replay every stored regression (tools/harness/regressions/*.jsonl) against a build, each on a fresh private
    instance. A regression file is a header line {"kind":"regression", "world", "predicate", "finding", ...} followed
    by the shrunk ops. PASS means none of them reproduces; any reproduction, or a regression that can't run, fails."""
    files = sorted(Path(a.dir).glob("*.jsonl"))
    if not files:
        say("FAIL", f"no regressions in {a.dir}")
        return FAIL
    failed = 0
    for f in files:
        lines = [json.loads(x) for x in f.read_text().splitlines() if x.strip()]
        head = lines[0] if lines and lines[0].get("kind") == "regression" else {}
        ops = [Op(**{k: v for k, v in o.items() if k in Op.__dataclass_fields__}) for o in lines[1 if head else 0:]]
        try:
            w = load_world(head.get("world", "pentest-v1"))
            a.target = "launch"
            pairs = [(o, Result("ok")) for o in ops]
            rep = asyncio.run(R.replay(_launched_engine_factory(w, a), pairs, "lockstep", a.repeat,
                                       R.predicate(head.get("predicate", "any"))))
        except Exception as e:  # noqa: BLE001 - a regression that cannot run is a failure, never a pass
            print(f"  ERROR {f.name}: {e!r}")
            failed += 1
            continue
        bad = rep.reproduced > 0 or rep.ops == 0
        failed += bad
        print(f"  {'REPRODUCED' if bad else 'ok'} {f.name}: {head.get('finding', '')} "
              f"({rep.reproduced}/{rep.repeat} reproduced, {rep.ops} op(s))")
    say("FAIL" if failed else "PASS", f"{len(files) - failed}/{len(files)} regressions hold against {a.build}")
    return FAIL if failed else PASS


def cmd_shrink(a) -> int:
    try:
        trace, w = _load_trace_and_world(a)
        factory = _replay_factory(a, w)
        if factory is None:
            return REFUSED
        lo, hi = R.parse_window(a.window)
        ops = asyncio.run(R.shrink(factory, R.window(trace, lo, hi), a.schedule, R.predicate(a.predicate),
                                   a.attempts))
    except (TraceError, W.WorldError, OSError, ValueError) as e:
        say("FAIL", str(e))
        return FAIL
    Path(a.out).write_text("".join(json.dumps(o.to_json(), sort_keys=True) + "\n" for o in ops))
    say("SHRUNK", f"{len(ops)} op(s) still match '{a.predicate}' -> {a.out}")
    return PASS


def verify_trace(path: str) -> tuple[bool, list[str]]:
    """Offline check of a finished trace. Any doubt is a failure."""
    problems = []
    try:
        trace = read_trace(path)
    except (TraceError, OSError) as e:
        return False, [str(e)]
    executed = [r for _, r in trace.ops if r.outcome != "blocked"]
    if not executed:
        problems.append("zero ops executed")
    failing = [v for v in trace.verdicts if not v.ok]
    problems += [f"[{v.judge}/{v.classification}] seq={v.seq} {v.message}" for v in failing]
    s = trace.summary
    if s is None:
        problems.append("no summary line: the run did not finish")
    elif not s.get("passed"):
        problems.append(f"run summary says FAIL: {'; '.join(s.get('reasons', []))}")
    elif failing:
        problems.append("summary says PASS but the trace holds failing verdicts")
    try:
        world_from_header(trace.header)
    except W.WorldError as e:
        problems.append(str(e))
    return not problems, problems


def cmd_verify(a) -> int:
    ok, problems = verify_trace(a.trace)
    for p in problems:
        print("  " + p)
    say("PASS" if ok else "FAIL", f"trace {a.trace}")
    return PASS if ok else FAIL


def cmd_agent(a) -> int:
    resolved = _target(a)
    if resolved is None:
        return REFUSED
    kind, target = resolved
    from vhh.gateway import HttpGateway, ToolAPI
    from vhh.recorder import TraceWriter
    w = load_world(a.world)
    red, broker = _broker(w, kind, target, a.credentials)
    make = _sim_factory(w, broker) if kind == "sim" else _real_factory(target, broker)
    out = Path(a.out) if a.out else RUN.new_run_dir()
    rec = TraceWriter(out / "trace.jsonl", red, {"seed": None, "profile": "agent", "schedule": "free",
                                                 "world": {"name": w.name, "seed": w.seed, "profile": w.profile,
                                                           "world_hash": w.world_hash()}, "build": RUN.build_info()})
    engine = Engine(w, load_catalog(a.catalog), broker, red, rec)
    api = ToolAPI(engine)
    token = api.register_agent(a.name, a.principal, a.surface, make(a.surface, a.principal))
    token_file = out / "gateway.token"
    fd = os.open(token_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(token + "\n")

    async def serve():
        gw = HttpGateway(api, asyncio.get_running_loop()).start()
        say("SERVING", f"{gw.url} (bearer token in {token_file}); stop with Ctrl-C or the kill file")
        try:
            while not engine.stopping:
                await asyncio.sleep(0.5)
        finally:
            gw.stop()
    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        pass
    finally:
        rec.summary({"agent": a.name, **engine.summary()})
        rec.close()
    return PASS


# ------------------------------------------------------------------------------------------------ parser

def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="vhh", description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p, target=True):
        if target:
            p.add_argument("--target", required=True, help="'sim', 'launch' (run only; with --build), or a launcher-written target.json / artifacts dir")
            p.add_argument("--credentials", help="private credentials file (0600) for a private target")
        p.add_argument("--catalog", help="usage.json from vh_usage --json (default: built-in catalog)")

    p = sub.add_parser("world", help="inspect a world, emit fixture v1, cross-check the oracle")
    p.add_argument("action", choices=("show", "fixture", "oracle-check"))
    p.add_argument("--world", default="pentest-v1")
    p.add_argument("--out", default="fixture-out")
    p.add_argument("--build-version", default="0.0.0")
    p.add_argument("--git-commit", default="")
    p.set_defaults(fn=cmd_world)

    p = sub.add_parser("run", help="a seeded run")
    common(p)
    p.add_argument("--world", default="pentest-v1")
    p.add_argument("--seed")
    p.add_argument("--profile", default="smoke")
    p.add_argument("--schedule", choices=("lockstep", "barrier", "free"), default="lockstep")
    p.add_argument("--sessions", type=int, default=4)
    p.add_argument("--ops", type=int, default=25, help="ops per session")
    p.add_argument("--surfaces", default="ws")
    p.add_argument("--out")
    p.add_argument("--kill-file")
    p.add_argument("--build", help="with --target launch: meson build dir holding vaulthalla-server")
    p.add_argument("--weights", help="override op weights, e.g. fs.write=20,fs.read=5 (pressure profiles)")
    p.set_defaults(fn=cmd_run)

    for name, fn in (("replay", cmd_replay), ("shrink", cmd_shrink)):
        p = sub.add_parser(name, help=f"{name} a trace window")
        common(p)
        p.add_argument("--trace", required=True)
        p.add_argument("--window", help="SEQ..SEQ")
        p.add_argument("--schedule", choices=("lockstep", "barrier"), default="barrier")
        p.add_argument("--predicate", default="any", help="e.g. 'canary|wedge|oracle|parity|integrity|any'")
        p.add_argument("--build", help="with --target launch: a fresh private instance per attempt from this build")
        if name == "replay":
            p.add_argument("--repeat", type=int, default=1)
        else:
            p.add_argument("--attempts", type=int, default=1)
            p.add_argument("--out", default="shrunk.jsonl")
        p.set_defaults(fn=fn)

    p = sub.add_parser("regress", help="replay stored regressions against a build (fresh instance each; root)")
    p.add_argument("--build", required=True)
    p.add_argument("--dir", default=str(Path(__file__).resolve().parent.parent / "regressions"))
    p.add_argument("--repeat", type=int, default=1)
    p.add_argument("--catalog")
    p.set_defaults(fn=cmd_regress)

    p = sub.add_parser("scenario", help="hang/crash during an in-flight FUSE op, or revoke on live sessions (root)")
    p.add_argument("kind", choices=("hang", "crash", "revoke"))
    p.add_argument("--build", required=True)
    p.add_argument("--out")
    p.set_defaults(fn=cmd_scenario)

    p = sub.add_parser("verify", help="verify a finished trace offline")
    p.add_argument("--trace", required=True)
    p.set_defaults(fn=cmd_verify)

    p = sub.add_parser("agent", help="serve the agent tool gateway on 127.0.0.1")
    common(p)
    p.add_argument("--world", default="pentest-v1")
    p.add_argument("--name", default="a1")
    p.add_argument("--principal", required=True)
    p.add_argument("--surface", default="ws")
    p.add_argument("--out")
    p.set_defaults(fn=cmd_agent)
    return ap


def main(argv: list[str] | None = None) -> int:
    a = parser().parse_args(argv)
    try:
        return a.fn(a)
    except Exception as e:  # noqa: BLE001 - an unexpected error is a failing run, never a pass
        say("FAIL", f"harness error: {type(e).__name__}: {e}")
        return FAIL


if __name__ == "__main__":
    sys.exit(main())
