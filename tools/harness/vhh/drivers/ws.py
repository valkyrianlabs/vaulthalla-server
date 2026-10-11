"""The web console's ws surface ("web-CLI"), straight to a private instance's ws port.

Reuses tools/lab/pentest/client.py (Ws) in its plain-loopback mode. Login goes through the identity broker: the
session is given a principal id and a broker that supplies the password at send time; the password never enters an
Op, a Result or the trace. The refresh cookie the handshake sets is what the HTTP driver uses for this principal.
"""

from __future__ import annotations

import asyncio
import json
import math
import time

from websockets.exceptions import ConnectionClosed

import vhh._repo  # noqa: F401  (puts the repo root on sys.path for tools.lab.pentest)
from tools.lab.pentest.client import Target as NetTarget
from tools.lab.pentest.client import Ws
from vhh.model import Op, Result

# Envelope status + data.code (core/include/protocols/ws/core/handler_templates.hpp) -> normalized outcome.
_CODE_OUTCOME = {"denied": "denied", "not_found": "not_found", "invalid": "invalid", "conflict": "conflict"}

# Temporary bindings until the usage export reaches this branch. These follow OperationSpec.ws.field_to_json
# in core/usage/src/contract/operations.cpp (WS-U); the engine Catalog currently exposes no payload renderer.
# The caller resolves opaque world vault ids to numeric ids before dispatch (or supplies vault_id alongside vault).
_FS_BINDINGS = {
    "fs.list": ("fs.dir.list", {"vault": "vault_id", "path": "path"}),
    "fs.delete": ("fs.entry.delete", {"vault": "vault_id", "path": "path"}),
    "fs.rename": ("fs.entry.rename", {"vault": "vault_id", "path": "from", "to": "to"}),
    "fs.mkdir": ("fs.dir.create", {"vault": "vault_id", "path": "path"}),
    "fs.copy": ("fs.entry.copy", {"vault": "vault_id", "path": "from", "to": "to"}),
    "fs.stat": ("fs.metadata", {"vault": "vault_id", "path": "path"}),
}
_LOGIN_TIMEOUT_S = 15.0
_CLOSE_TIMEOUT_S = 5.0


def classify(msg: dict) -> tuple[str, object]:
    status = str(msg.get("status", "")).upper()
    if status in ("OK", "SUCCESS", "READY"):
        return "ok", status
    if status == "UNAUTHORIZED":
        return "denied", "unauthorized"
    data = msg.get("data") or {}
    code = data.get("code") if isinstance(data, dict) else None
    if code in _CODE_OUTCOME:
        return _CODE_OUTCOME[code], code
    if code:  # NeedsConfirmation carries its own code (e.g. "user_delete")
        return "needs_confirmation", code
    err = str(msg.get("error", "")).lower()
    if "permission" in err or "denied" in err or "not authorized" in err or "forbidden" in err:
        return "denied", status or None
    if "not found" in err or "no such" in err or "does not exist" in err:
        return "not_found", status or None
    return "error", status or None


class WsDriver:
    """One broker principal per session; execute accepts resolved vault/vault_id, path, and (for moves) to.

    The broker's redactor is used unless one is supplied explicitly. Anonymous probes without a redactor retain
    only fixed diagnostics and native outcome codes; server data and payload rendering are withheld.
    """

    surface = "ws"

    def __init__(self, ws_port: int, principal: str | None, broker=None, redactor=None, path: str = "/ws"):
        self.target = NetTarget(hostname="127.0.0.1", ws_port=ws_port, http_port=None)
        self.principal = principal
        self.broker = broker
        self.redactor = redactor if redactor is not None else getattr(broker, "redactor", None)
        self.path = path
        self.ws: Ws | None = None
        self.login_result: Result | None = None
        self._requests = asyncio.Lock()  # Ws.send owns recv until its matching requestId arrives.
        self._closing: set[asyncio.Task] = set()

    async def open(self) -> None:
        """Open once and log in through IdentityBroker. Failed opens raise with a safe login_result attached."""
        if self.ws is not None:
            return
        await self.close()
        self.login_result = None
        t0 = time.time_ns()
        rendered = "connect"
        try:
            # Keep the context even if __aenter__ fails after acquiring a connection (e.g. parsing cookies).
            self.ws = Ws(self.target, path=self.path, user_agent="vhh/1")
            await self.ws.__aenter__()
            self._register_session_secrets()
            if self.principal is None:
                return
            rendered = "auth.login"
            if self.broker is None or self.redactor is None:
                raise ValueError("authenticated sessions require an identity broker and redactor")
            credential = self.broker.credential(self.principal)
            if credential.kind != "password" or not credential.username:
                raise ValueError("auth.login requires a named password credential")
            password = credential.secret()
            if not isinstance(password, str) or not password:
                raise ValueError("auth.login requires a nonempty password")
            self.redactor.register_secret(password)
            msg = await asyncio.wait_for(
                self.ws.send("auth.login", {"name": credential.username, "password": password},
                             timeout=_LOGIN_TIMEOUT_S), timeout=_LOGIN_TIMEOUT_S)
            self._register_session_secrets()
            self.login_result = self._response(msg, rendered, t0)
            if self.login_result.outcome == "ok":
                return
        except asyncio.CancelledError:
            self._retire(abort=True)
            await self.close()
            raise
        except Exception as exc:  # noqa: BLE001 - open errors are recorded by the engine; suppress secret text.
            self.login_result = self._failure(exc, rendered, t0)
        await self.close()
        # The engine records repr(exc) on open failure. Never include a transport exception or credentials there.
        raise RuntimeError(f"websocket open failed: {self.login_result.outcome}") from None

    def _register_session_secrets(self) -> None:
        if self.ws is not None and self.redactor is not None:
            self.redactor.register_secret(self.ws.token)
            for value in self.ws.cookies.values():
                self.redactor.register_secret(value)
            self.redactor.register_secret(self.ws.cookie_header())

    def _result(self, outcome: str, rendered: str, t0: int, *, detail: str = "", code=None,
                data: dict | None = None) -> Result:
        fields = {"detail": detail, "code": code, "data": data or {}, "rendered": rendered}
        if self.redactor is not None:
            fields = self.redactor.redact(fields)
        return Result(outcome, detail=fields["detail"][:400], code=fields["code"], data=fields["data"],
                      rendered=fields["rendered"], t0_ns=t0, t1_ns=time.time_ns())

    def _response(self, msg: dict, rendered: str, t0: int) -> Result:
        # Invalid server envelopes are product/transport errors, not successful empty operations.
        if (not isinstance(msg, dict) or not isinstance(msg.get("status"), str)
                or not isinstance(msg.get("data"), (dict, type(None)))):
            raise TypeError("malformed websocket response")
        data = msg.get("data") or {}
        if not isinstance(data.get("code"), (str, int, type(None))):
            raise TypeError("malformed websocket response code")
        outcome, code = classify(msg)
        # Anonymous probes may omit a redactor. In that case do not expose any server-controlled text or data.
        detail = str(msg.get("error") or "") if self.redactor is not None else ""
        if self.redactor is None and code not in {*_CODE_OUTCOME, "OK", "SUCCESS", "READY", "unauthorized"}:
            code = None
        return self._result(outcome, rendered, t0, detail=detail, code=code,
                            data=data if self.redactor is not None else {})

    def _failure(self, exc: Exception, rendered: str, t0: int) -> Result:
        if isinstance(exc, TimeoutError):
            outcome, detail = "timeout", "websocket request deadline exceeded"
        elif isinstance(exc, (ConnectionClosed, OSError, EOFError)):
            outcome, detail = "disconnected", "websocket connection lost"
        else:
            outcome, detail = "error", "websocket request failed"
        # Exception text can contain a password, close-frame reason, HTTP headers, or an entire response body.
        return self._result(outcome, rendered, t0, detail=detail)

    def _render(self, op: Op) -> tuple[str, dict]:
        if op.surface != self.surface or (self.principal is not None and op.principal != self.principal):
            raise ValueError("operation does not belong to this websocket session")
        if op.op not in _FS_BINDINGS:
            raise ValueError("websocket driver has no binding for this operation")
        command, fields = _FS_BINDINGS[op.op]
        args = op.args
        if not isinstance(args, dict) or args.keys() - (fields.keys() | {"vault_id"}):
            raise ValueError("invalid websocket operation arguments")
        vault = args.get("vault_id", args.get("vault"))
        if type(vault) is not int or not 0 < vault < 2 ** 32:
            raise ValueError("websocket operations require a resolved numeric vault id")
        payload = {"vault_id": vault}
        for source, dest in fields.items():
            if source == "vault":
                continue
            value = args.get(source, "/" if op.op in ("fs.list", "fs.stat") else None)
            if not isinstance(value, str) or "\0" in value:
                raise ValueError("websocket operations require string paths without NUL bytes")
            payload[dest] = value
        return command, payload

    async def execute(self, op: Op, deadline_s: float) -> Result:
        t0 = time.time_ns()
        rendered = ""
        try:
            command, payload = self._render(op)
            rendered = command
            if self.redactor is not None:
                rendered += " " + json.dumps(self.redactor.redact(payload), sort_keys=True, ensure_ascii=False)
            if isinstance(deadline_s, bool) or not isinstance(deadline_s, (float, int)) or not math.isfinite(deadline_s):
                raise ValueError("websocket deadline must be finite")
        except (ValueError, TypeError):
            return self._result("invalid", rendered, t0, detail="unsupported or invalid websocket operation")
        if self.ws is None:
            return self._result("disconnected", rendered, t0, detail="websocket session is not open")
        if deadline_s <= 0:
            return self._result("timeout", rendered, t0, detail="websocket request deadline exceeded")

        async def request() -> Result:
            async with self._requests:
                if self.ws is None:
                    return self._result("disconnected", rendered, t0, detail="websocket session is not open")
                msg = await self.ws.send(command, payload, timeout=deadline_s)
                self._register_session_secrets()
                return self._response(msg, rendered, t0)

        try:
            # Bound the entire exchange (send, unsolicited events and waiting for another request), not each recv.
            return await asyncio.wait_for(request(), timeout=deadline_s)
        except asyncio.CancelledError:
            self._retire(abort=True)
            raise
        except Exception as exc:  # noqa: BLE001 - transport/decoding failures must yield a redacted Result.
            result = self._failure(exc, rendered, t0)
            # A timed-out mutation may still finish server-side. Drop the connection; never retry it implicitly.
            # Abort immediately so cleanup does not add a close-handshake timeout to the operation's deadline.
            self._retire(abort=True)
            return result

    def cookie_header(self) -> str:
        """Return the live session cookie only to the HTTP transport; callers must never record this value."""
        if self.ws is None or (self.principal is not None
                               and (self.login_result is None or self.login_result.outcome != "ok")):
            return ""
        self._register_session_secrets()
        return self.ws.cookie_header()

    @staticmethod
    def _abort(ws: Ws) -> None:
        # websockets' connection owns an asyncio transport. This is only a last-resort close, not a second client.
        transport = getattr(ws.conn, "transport", None)
        if transport is not None:
            transport.abort()

    def _retire(self, *, abort: bool = False) -> None:
        ws, self.ws = self.ws, None
        if ws is None:
            return
        if abort:
            self._abort(ws)

        async def finish() -> None:
            try:
                if ws.conn is not None:
                    await asyncio.wait_for(ws.__aexit__(None, None, None), timeout=_CLOSE_TIMEOUT_S)
            except asyncio.CancelledError:
                self._abort(ws)
                raise
            except Exception:  # noqa: BLE001 - cleanup must abort even if the close handshake fails to decode.
                self._abort(ws)
            finally:
                ws.token = ""
                ws.cookies.clear()

        task = asyncio.create_task(finish())
        self._closing.add(task)
        task.add_done_callback(self._closing.discard)

    async def close(self) -> None:
        """Idempotently close even partially entered contexts and drain cleanup from timed-out requests."""
        self._retire()
        if self._closing:
            await asyncio.shield(asyncio.gather(*self._closing))
