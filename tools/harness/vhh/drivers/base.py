"""Driver protocol: a driver executes canonical ops for one session over one surface."""
from __future__ import annotations

from typing import Protocol

from vhh.model import Op, Result


class Driver(Protocol):
    surface: str

    async def open(self) -> None: ...

    async def execute(self, op: Op, deadline_s: float) -> Result:
        """Run one op; must return within deadline_s (outcome 'timeout' otherwise) and never raise for product
        behavior. Raising means a harness defect."""
        ...

    async def close(self) -> None: ...
