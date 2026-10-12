"""Driver protocol: a driver executes canonical ops for one session over one surface.

Real drivers live in `vhh/drivers/<surface>.py` (cli_sock, cli_bin, ws, http, fuse; integrator-owned) and expose
`create(target, principal, broker) -> Driver`. Credentials are never passed in an Op: a driver asks the identity
broker at send time (`broker.credential(op.principal).secret()`), so secrets stay in memory and out of traces.
`vhh.sim.SimDriver` is the reference implementation used by the tests.
"""
from __future__ import annotations

from typing import Protocol

from vhh.model import Op, Result


class Driver(Protocol):
    surface: str

    async def open(self) -> None: ...

    async def execute(self, op: Op, deadline_s: float) -> Result:
        """Run one op; must return within deadline_s (outcome 'timeout' otherwise) and never raise for product
        behavior. Raising means a harness defect. Put read/written bytes in `Result.body` (memory only) and their
        sha256 in `bytes_sha256`; set `data["fault"]` to "harness" or "product" when the cause is known."""
        ...

    async def close(self) -> None: ...
