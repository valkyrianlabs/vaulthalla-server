"""Agent gateway: external agents drive the same engine through a small tool API.

- In-process: `ToolAPI.list_tools()`, `await ToolAPI.call(agent, tool, args)`, `ToolAPI.read_trace(agent)`.
- HTTP (127.0.0.1 only): GET /v1/tools, POST /v1/call {"tool", "args"}, GET /v1/trace, with
  `Authorization: Bearer <gateway token>` naming the agent's session.

Only actor-side catalog ops are tools. There are no provisioning, reset, restart or admin tools, and an agent cannot
pick its principal: each agent session is bound to one principal by the operator when it is registered. Every call
goes through guardrails (scope = the actor tool list, budgets, kill switch), the recorder and the judges.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from vhh.engine import Engine, Session
from vhh.guardrails import Budget, Scope
from vhh.model import Op

PREVIEW_BYTES = 4096


class GatewayError(ValueError):
    pass


class ToolAPI:
    def __init__(self, engine: Engine):
        self.engine = engine
        self._tokens: dict[str, str] = {}          # gateway token -> agent id
        self._log: dict[str, list[dict]] = {}

    # ------------------------------------------------------------------ operator side
    def register_agent(self, agent: str, principal: str, surface: str, driver, *, max_ops: int | None = 500,
                       max_bytes: int | None = 256 * 1024 * 1024, vaults: frozenset[str] = frozenset()) -> str:
        sid = f"agent-{agent}"
        self.engine.add_session(Session(sid, principal, surface, driver, intent="agent"))
        tools = frozenset(t.id for t in self.engine.catalog.actor_tools())
        admin = frozenset(o for o in self.engine.catalog.ops if o not in tools)
        self.engine.guardrails.set_session(sid, Budget(max_ops, max_bytes), Scope(ops=tools, vaults=vaults,
                                                                                    denied_ops=admin))
        token = secrets.token_urlsafe(24)
        self._tokens[token] = agent
        self._log[agent] = []
        return token

    def agent_for_token(self, token: str) -> str | None:
        return self._tokens.get(token)

    # ------------------------------------------------------------------ agent side
    def list_tools(self) -> list[dict]:
        return [{"name": t.id, "description": t.description, "fields": dict(t.fields), "required": list(t.required),
                 "surfaces": list(t.surfaces)} for t in self.engine.catalog.actor_tools()]

    async def call(self, agent: str, tool: str, args: dict | None = None) -> dict:
        sid = f"agent-{agent}"
        session = self.engine.sessions.get(sid)
        if session is None:
            raise GatewayError("unknown agent")
        if tool not in {t.id for t in self.engine.catalog.actor_tools()}:
            return {"error": f"unknown tool {tool!r}"}
        if not isinstance(args, dict):
            return {"error": "args must be an object"}
        args = {k: v for k, v in args.items() if k != "principal"}   # the session's principal is fixed
        op = Op(seq=-1, session=sid, principal=session.principal, surface=session.surface, op=tool, args=args,
                intent="agent")
        r = await self.engine.execute(session, op)
        reply = {"seq": op.seq, "outcome": r.outcome, "detail": r.detail, "code": r.code, "data": r.data,
                 "bytes_sha256": r.bytes_sha256, "size": len(r.body) if r.body is not None else None}
        if r.body is not None:
            reply["preview"] = self.engine.redactor.redact_text(r.body[:PREVIEW_BYTES].decode("utf-8", "replace"))
        reply = self.engine.redactor.redact(reply)
        self._log[agent].append({"tool": tool, "args": self.engine.redactor.redact(args), "reply": reply})
        return reply

    def read_trace(self, agent: str) -> list[dict]:
        if agent not in self._log:
            raise GatewayError("unknown agent")
        return list(self._log[agent])


def _loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == "localhost"


class HttpGateway:
    """Serves a ToolAPI over local HTTP. The engine's event loop runs elsewhere; calls hop onto it."""

    def __init__(self, api: ToolAPI, loop: asyncio.AbstractEventLoop, host: str = "127.0.0.1", port: int = 0,
                 call_timeout_s: float = 120.0):
        if not _loopback(host):
            raise GatewayError(f"the gateway only listens on loopback, not {host!r}")
        self.api, self.loop, self.call_timeout_s = api, loop, call_timeout_s
        gw = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):   # no request logging (headers carry the gateway token)
                pass

            def _agent(self) -> str | None:
                auth = self.headers.get("Authorization", "")
                return gw.api.agent_for_token(auth[7:]) if auth.startswith("Bearer ") else None

            def _send(self, code: int, body) -> None:
                data = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                agent = self._agent()
                if agent is None:
                    return self._send(401, {"error": "unauthorized"})
                if self.path == "/v1/tools":
                    return self._send(200, {"tools": gw.api.list_tools()})
                if self.path == "/v1/trace":
                    return self._send(200, {"trace": gw.api.read_trace(agent)})
                return self._send(404, {"error": "not found"})

            def do_POST(self):
                agent = self._agent()
                if agent is None:
                    return self._send(401, {"error": "unauthorized"})
                if self.path != "/v1/call":
                    return self._send(404, {"error": "not found"})
                try:
                    n = int(self.headers.get("Content-Length", "0"))
                    if n > 1 << 20:
                        return self._send(413, {"error": "request too large"})
                    req = json.loads(self.rfile.read(n) or b"{}")
                    fut = asyncio.run_coroutine_threadsafe(gw.api.call(agent, req.get("tool", ""),
                                                                       req.get("args") or {}), gw.loop)
                    return self._send(200, fut.result(gw.call_timeout_s))
                except (ValueError, json.JSONDecodeError) as e:
                    return self._send(400, {"error": str(e)})

        self.server = ThreadingHTTPServer((host, port), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, name="vhh-gateway", daemon=True)

    @property
    def url(self) -> str:
        host, port = self.server.server_address[:2]
        return f"http://{host}:{port}"

    def start(self) -> "HttpGateway":
        self.thread.start()
        return self

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
