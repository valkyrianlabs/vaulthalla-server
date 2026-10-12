"""Grant and revoke on persistent, authenticated WS and FUSE sessions of the same fixture principal."""
from __future__ import annotations

import asyncio
import time

from vhh._repo import pentest
from vhh.broker import IdentityBroker
from vhh.drivers import real
from vhh.drivers.cli_sock import CliSockDriver
from vhh.model import REFUSALS, Op
from vhh.provision import provision
from vhh.redact import Redactor
from vhh.world import pentest_v1

PROPAGATION_S = 5.0
POLL_S = 0.05


class _Failed(Exception):
    pass


async def run_revoke(inst) -> dict:
    """Own the temporary grant and sessions; the caller owns the instance and its scoped teardown."""
    red = inst.redactor
    if red is None:
        red = inst.redactor = Redactor()
    report = {"ok": False, "grant_latency_s": None, "revoke_latency_s": None, "steps": [], "why": None}
    drivers = []
    grant_pending = False
    admin = None
    command = None
    seq = 0

    def record(phase, surface, result):
        report["steps"].append({"phase": phase, "surface": surface, "result": red.redact(result.to_json())})

    async def probe(phase, surface, driver, principal="u-eve", deadline=PROPAGATION_S):
        nonlocal seq
        seq += 1
        op = Op(seq, f"revoke-{principal}-{surface}", principal, surface, "fs.list",
                {"vault": "v-team", "path": "/restricted"}, intent="scenario")
        result = await asyncio.wait_for(driver.execute(op, deadline), deadline)
        record(phase, surface, result)
        if result.outcome not in ("ok", *REFUSALS):
            raise _Failed(f"{phase}: {surface} returned {result.outcome}, not an authorization answer")
        return result.outcome

    async def pair(phase, deadline):
        return await asyncio.gather(probe(phase, "ws", ws, deadline=deadline),
                                    probe(phase, "fuse", fuse, deadline=deadline))

    async def observe(phase, allowed):
        start = time.monotonic()
        end = start + PROPAGATION_S
        while True:
            left = end - time.monotonic()
            if left <= 0:
                raise _Failed(f"{phase}: permission did not propagate to both surfaces within five seconds")
            outcomes = await pair(phase, left)
            elapsed = time.monotonic() - start
            if elapsed <= PROPAGATION_S and all((r == "ok") if allowed else (r in REFUSALS) for r in outcomes):
                return elapsed
            await asyncio.sleep(min(POLL_S, max(0, end - time.monotonic())))

    try:
        world = pentest_v1()
        broker = IdentityBroker(red)
        binding = await provision(inst.target, world, broker, red)
        vault = world.vault("v-team")
        if vault is None or vault.owner != "u-alice" or not world.principal("u-eve").active:
            raise _Failed("fixture does not contain the expected active principal and shared vault")
        spec = next(v for v in pentest.fixture.VAULTS if v.opaque_id == vault.id)
        command = ["vault", "role", "unassign", spec.name, "reader", "-u",
                   binding.principals["u-eve"]["username"], "--owner", binding.principals[vault.owner]["username"]]
        make = real.factory(inst, binding, world, broker, red)
        ws, fuse, owner = make("ws", "u-eve"), make("fuse", "u-eve"), make("ws", vault.owner)
        admin = CliSockDriver(inst.target.cli_socket, None, redactor=red)
        drivers.extend((ws, fuse, owner, admin))
        for driver in drivers:
            await driver.open()  # auth/provision errors fail the scenario; they can never stand in for denial
        if await probe("resource-check", "ws", owner, vault.owner) != "ok":
            raise _Failed("the owner's protected directory is not accessible")
        if not all(r in REFUSALS for r in await pair("before-grant", PROPAGATION_S)):
            raise _Failed("Eve already has access before the grant")
        grant_pending = True  # even a timeout can leave a committed grant; always attempt scoped cleanup
        assign = command.copy()
        assign[2] = "assign"
        result = await admin.run_line(assign, PROPAGATION_S)
        record("assign", "cli_sock", result)
        if result.outcome != "ok":
            raise _Failed(f"grant command failed: {result.outcome}")
        report["grant_latency_s"] = await observe("after-grant", True)
        result = await admin.run_line(command, PROPAGATION_S)
        record("unassign", "cli_sock", result)
        if result.outcome != "ok":
            raise _Failed(f"revoke command failed: {result.outcome}")
        grant_pending = False
        report["revoke_latency_s"] = await observe("after-revoke", False)
        for i in range(3):
            await asyncio.sleep(POLL_S)
            if not all(r in REFUSALS for r in await pair(f"stable-revoke-{i + 1}", PROPAGATION_S)):
                raise _Failed("revocation did not remain effective on both surfaces")
        # A disappearing resource must not masquerade as successful revocation.
        if await probe("resource-still-present", "ws", owner, vault.owner) != "ok":
            raise _Failed("protected directory disappeared during revocation")
        report["ok"] = True
    except _Failed as exc:
        report["why"] = str(exc)
    except Exception as exc:  # noqa: BLE001 - never emit transport/provisioning exception text containing secrets
        report["why"] = f"scenario failed ({type(exc).__name__}); see recorded steps"
    finally:
        if grant_pending and admin is not None and command is not None:
            try:
                result = await admin.run_line(command, PROPAGATION_S)
                record("cleanup-unassign", "cli_sock", result)
                if result.outcome not in ("ok", "not_found"):
                    raise _Failed()
            except Exception:  # noqa: BLE001
                report.update(ok=False, why="temporary grant cleanup failed; scoped instance teardown required")
        for driver in reversed(drivers):
            try:
                await driver.close()
            except Exception:  # noqa: BLE001
                report.update(ok=False, why="session cleanup failed; scoped instance teardown required")
    return red.redact(report)
