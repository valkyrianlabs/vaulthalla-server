"""The console's authenticated HTTP transfer lane, sharing a WsDriver session and the pentest transports."""
from __future__ import annotations

import asyncio
import hashlib
import http.client
import math
import re
import socket
import threading
import time
from urllib.parse import urlencode

import vhh._repo  # noqa: F401 - make tools.lab importable when only tools/harness is on sys.path
from tools.lab.pentest.client import Target as NetTarget
from tools.lab.pentest.client import http_request, upload_files
from vhh.model import Result

_STATUS = {200: "ok", 401: "denied", 403: "denied", 404: "not_found", 409: "conflict", 412: "conflict",
           413: "invalid", 415: "invalid", 422: "invalid"}


class _Transfer:
    """One worker's deadline and socket. Cancellation interrupts I/O and prevents further mutation requests."""

    def __init__(self, end: float, reserve: float):
        self.end, self.data_end = end, end - reserve
        self.lock = threading.Lock()
        self.sock = None
        self.cancelled = False
        self.stopped = False
        self.cleaning = False
        self.upload_id = None
        self.failure_status = None
        self.cleanup_attempted = False

    def abort(self, *, all_requests=False):
        with self.lock:
            self.cancelled = True
            self.stopped |= all_requests
            if self.sock is not None and (all_requests or not self.cleaning):
                try:
                    self.sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                self.sock.close()

    def connected(self, conn):
        with self.lock:
            self.sock = conn.sock
            if self.stopped or (self.cancelled and not self.cleaning):
                conn.close()
                raise TimeoutError

    def request(self, target, method, path, **kwargs):
        self.cleaning = method == "DELETE"
        if self.cleaning:
            self.cleanup_attempted = True
        remaining = (self.end if self.cleaning else self.data_end) - time.monotonic()
        if remaining <= 0 or self.stopped or (self.cancelled and not self.cleaning):
            raise TimeoutError
        try:
            response = http_request(target, method, path, timeout=remaining, on_connection=self.connected, **kwargs)
        finally:
            with self.lock:
                self.sock = None
        if not self.cleaning and response.status != 200:
            self.failure_status = response.status
        if method == "POST" and path == "/upload/session" and response.status == 200:
            upload_id = response.json().get("upload_id")
            if not isinstance(upload_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", upload_id):
                raise ValueError("invalid upload session response")
            self.upload_id = upload_id
        return response


class HttpLane:
    def __init__(self, http_port: int, redactor):
        if type(http_port) is not int or not 0 < http_port < 65536:
            raise ValueError("HTTP lane requires a private daemon port")
        self.target = NetTarget(hostname="127.0.0.1", http_port=http_port)
        self.redactor = redactor
        self._ws = None
        self._pending = set()

    def attach(self, ws_driver) -> None:
        self._ws = None
        if (ws_driver.ws is None or ws_driver.login_result is None or ws_driver.login_result.outcome != "ok"
                or ws_driver.target.hostname != "127.0.0.1"
                or ws_driver.target.connect_ip not in (None, "127.0.0.1")):
            raise ValueError("HTTP lane requires an authenticated private websocket session")
        cookie = ws_driver.cookie_header()
        if not cookie:
            raise ValueError("authenticated websocket session has no HTTP cookie")
        self._register_cookie(cookie)
        self._ws = ws_driver

    def _register_cookie(self, cookie):
        self.redactor.register_secret(cookie)
        for item in cookie.split(";"):
            _, sep, value = item.strip().partition("=")
            if sep:
                self.redactor.register_secret(value)

    def _result(self, outcome, rendered, t0, *, code=None, detail="", body=None):
        return Result(outcome, detail=self.redactor.redact_text(detail), code=code,
                      rendered=self.redactor.redact_text(rendered), body=body,
                      data={"size": len(body)} if body is not None else {},
                      bytes_sha256=hashlib.sha256(body).hexdigest() if body is not None else None,
                      t0_ns=t0, t1_ns=time.time_ns())

    async def download(self, vault_id, path, deadline_s) -> Result:
        return await self._transfer(vault_id, path, None, deadline_s)

    async def upload(self, vault_id, path, data, deadline_s) -> Result:
        if not isinstance(data, bytes):
            now = time.time_ns()
            return self._result("invalid", "POST /upload/session", now, detail="upload data must be bytes")
        return await self._transfer(vault_id, path, data, deadline_s)

    async def _transfer(self, vault_id, path, data, deadline_s):
        t0 = time.time_ns()
        upload = data is not None
        rendered = "POST /upload/session" if upload else "GET /download"
        if (type(vault_id) is not int or not 0 < vault_id < 2 ** 32 or not isinstance(path, str) or "\0" in path
                or not isinstance(deadline_s, (int, float)) or isinstance(deadline_s, bool)
                or not math.isfinite(deadline_s)):
            return self._result("invalid", rendered, t0, detail="invalid HTTP transfer arguments")
        if deadline_s <= 0:
            return self._result("timeout", rendered, t0, detail="HTTP transfer deadline exceeded")
        if self._ws is None:
            return self._result("denied", rendered, t0, detail="HTTP session is not attached")
        cookie = self._ws.cookie_header()
        if not cookie:
            return self._result("denied", rendered, t0, detail="HTTP session is no longer authenticated")
        self._register_cookie(cookie)
        rendered += "?" + urlencode(self.redactor.redact({"vault_id": vault_id, "path": path}))
        # Reserve a small part of an upload's total budget to cancel a partial server upload session.
        reserve = min(0.25, deadline_s / 4) if upload else 0
        context = _Transfer(time.monotonic() + deadline_s, reserve)

        def work():
            try:
                if upload:
                    completed = False
                    try:
                        errors = upload_files(self.target, cookie, vault_id, [(path, data)], request=context.request)
                        completed = path in errors and errors[path] is None
                    finally:
                        if not completed and context.upload_id and not context.cleanup_attempted:
                            try:
                                context.request(self.target, "DELETE", f"/upload/{context.upload_id}", cookie=cookie)
                            except Exception:  # noqa: BLE001, S110 - preserve failure without logging sensitive text.
                                pass
                    if not completed:
                        code = context.failure_status
                        return self._result(_STATUS.get(code, "error"), rendered, t0, code=code,
                                            detail=f"HTTP upload failed ({code or 'invalid response'})")
                    return self._result("ok", rendered, t0, code=200, body=data)
                response = context.request(self.target, "GET", "/download", query={"vault_id": vault_id, "path": path},
                                           cookie=cookie)
                code = response.status
                return self._result(_STATUS.get(code, "error"), rendered, t0, code=code,
                                    detail="" if code == 200 else f"HTTP download failed ({code})",
                                    body=response.body if code == 200 else None)
            except TimeoutError:
                return self._result("timeout", rendered, t0, detail="HTTP transfer deadline exceeded")
            except (OSError, http.client.RemoteDisconnected, http.client.IncompleteRead):
                return self._result("disconnected", rendered, t0, detail="HTTP connection lost")
            except Exception:  # noqa: BLE001 - transport exceptions and server bodies can contain credentials.
                return self._result("error", rendered, t0, detail="HTTP transfer failed")

        task = asyncio.create_task(asyncio.to_thread(work))
        self._pending.add(task)
        task.add_done_callback(self._pending.discard)
        try:
            return await asyncio.wait_for(asyncio.shield(task), max(0, context.data_end - time.monotonic()))
        except TimeoutError:
            context.abort()
            remaining = context.end - time.monotonic()
            if remaining > 0:
                try:
                    await asyncio.wait_for(asyncio.shield(task), remaining)
                except TimeoutError:
                    pass
            context.abort(all_requests=True)
            return self._result("timeout", rendered, t0, detail="HTTP transfer deadline exceeded")
        except asyncio.CancelledError:
            context.abort(all_requests=True)
            raise

    async def close(self):
        """Drain any worker unwinding after its socket was interrupted; contains no authentication state."""
        self._ws = None
        if self._pending:
            await asyncio.gather(*self._pending)
