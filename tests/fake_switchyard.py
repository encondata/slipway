"""A fake Switchyard for tests: enough of its REST API to publish, switch and put back hostnames.

Install it with ``install(monkeypatch)`` (or the ``fake_sy`` fixture of a test module), which
routes ``switchyard.SwitchyardClient`` to ``FakeSwitchyard.handle`` through an httpx.MockTransport.

Besides the hosts, it keeps what a real Switchyard reports in ``GET /api/config/preview``: the last
applied version and the number of edits since then, by anyone. Failure seams:

* ``fail_on = {("PUT", 2): 500}`` fails the 2nd PUT (counted per method, from the start);
* ``someone_edits_after("POST /api/hosts")`` makes a foreign, unapplied edit right after that call;
* ``apply_fails`` (every apply) and ``apply_fails_once()`` (the next apply only);
* ``delete_id_then_reuse(id)``: the id now names a host someone else made;
* ``denied``: "METHOD /path" prefixes answered with 403.

``calls`` lists each request as a ``Call`` (a string such as "PUT /api/hosts/3", with ``method``,
``path`` and ``body``), plus a "changed" entry after each edit, so tests can compare either.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx

from slipway.db.session import get_sessionmaker
from slipway.models import AppSetting
from slipway.services import switchyard

KEY = "sy_" + "T3stK3y" * 6 + "x"  # sy_ and 43 characters, like a real key


class Call(str):
    """One request as "METHOD /path", carrying its JSON body (None without one)."""

    method: str
    path: str
    body: Any

    def __new__(cls, text: str, method: str = "", path: str = "", body: Any = None) -> Call:
        call = super().__new__(cls, text)
        call.method, call.path, call.body = method, path, body
        return call


class FakeSwitchyard:
    """Enough of Switchyard's API: hosts with ids, 409 on a used domain, staged changes, preview and apply."""

    def __init__(self) -> None:
        self.hosts: dict[int, dict] = {}
        self.next_id = 1
        self.version: int | None = 1  # last applied config version (None: never applied)
        self.changes = 0  # audit-log edits since that version, by anyone
        self.drift = False
        self.caddy_error = ""
        self.apply_fails = False
        self._apply_fails_once = False
        self.applies: list[str] = []
        self.calls: list[Call] = []
        self.denied: set[str] = set()  # "METHOD /path" prefixes answered with 403
        self.fail_on: dict[tuple[str, int], int] = {}  # (method, n-th call of it) -> status
        self.counts: dict[str, int] = {}  # calls per method so far
        self._after: list[list[Any]] = []  # [call prefix, calls left to skip, action]

    # ------------------------------------------------------------------ seams

    def someone_edits(self) -> None:
        """An edit made in Switchyard's UI and not applied."""
        self.changes += 1

    def someone_edits_after(self, call: str, action: Callable[[FakeSwitchyard], None] | None = None, *,
                            n: int = 1) -> None:
        """After the ``n``-th call starting with ``call`` (such as "PUT /api/hosts"), someone edits Switchyard.

        The edit is ``action(fake)`` when given (it may change a host), else an unapplied edit
        elsewhere. Either way it counts as one more pending change, as an edit in Switchyard's UI does.
        """
        self._after.append([call, n, action])

    def apply_fails_once(self) -> None:
        """The next apply is refused by Caddy; the one after it works."""
        self._apply_fails_once = True

    def delete_id_then_reuse(self, host_id: int, *, pending: bool = False, **fields: Any) -> dict:
        """Someone deletes host ``host_id`` and Switchyard reuses the id for a host of theirs (no marker).

        They applied it in Switchyard, unless ``pending``: then both edits are waiting to be applied.
        """
        self.hosts.pop(host_id, None)
        host = {"id": host_id, "type": "proxy", "enabled": True, "domains": [f"other-{host_id}.example.net"],
                "upstreams": [{"scheme": "http", "skip_tls_verify": False, "host": "10.9.9.9", "port": 80}],
                "tls_mode": "auto", "force_https": True, "notes": "", "policy_ids": [], **fields}
        self.hosts[host_id] = host
        if pending:
            self.changes += 2  # a delete and a create, both someone else's
        return host

    def hosts_by_domain(self) -> dict[str, dict]:
        return {d: h for h in self.hosts.values() for d in h.get("domains") or []}

    def add(self, **host) -> dict:
        host = {"id": self.next_id, "type": "proxy", "enabled": True, "upstreams": [], "tls_mode": "auto",
                "force_https": True, "notes": "", "policy_ids": [], **host}
        self.hosts[self.next_id] = host
        self.next_id += 1
        return host

    def api_calls(self) -> list[Call]:
        """``calls`` without the "changed" entries."""
        return [c for c in self.calls if c.method]

    # ---------------------------------------------------------------- handler

    def handle(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        call = Call(f"{request.method} {request.url.path}", request.method, request.url.path, body)
        self.calls.append(call)
        response = self._answer(request, call, body)
        self._run_after(call)
        return response

    def _answer(self, request: httpx.Request, call: str, body: Any) -> httpx.Response:
        if request.headers.get("Authorization") != f"Bearer {KEY}":
            return httpx.Response(401, json={"error": "invalid_api_key", "message": "The API key is wrong."})
        if any(call.startswith(d) for d in self.denied):
            return httpx.Response(403, json={"error": "missing_permission", "message": "This key lacks the operation."})
        self.counts[request.method] = self.counts.get(request.method, 0) + 1
        status = self.fail_on.get((request.method, self.counts[request.method]))
        if status:
            return httpx.Response(status, json={"error": "failed", "message": f"Switchyard failed this {request.method}."})
        path = request.url.path.removeprefix("/api")
        if path == "/hosts" and request.method == "GET":
            return httpx.Response(200, json=list(self.hosts.values()))
        if path == "/hosts" and request.method == "POST":
            if any(d in h["domains"] for h in self.hosts.values() for d in body["domains"]):
                return httpx.Response(409, json={"error": "conflict", "message": "A domain is already used."})
            self._changed()
            return httpx.Response(201, json=self.add(**body))
        if path.startswith("/hosts/"):
            hid = int(path.split("/")[2])
            if hid not in self.hosts:
                return httpx.Response(404, json={"error": "not_found", "message": "No such host."})
            if request.method == "GET":
                return httpx.Response(200, json=self.hosts[hid])
            if request.method == "PUT":
                if any(d in h["domains"] for i, h in self.hosts.items() if i != hid for d in body.get("domains") or []):
                    return httpx.Response(409, json={"error": "conflict", "message": "A domain is already used."})
                self.hosts[hid] = {**body, "id": hid}
                self._changed()
                return httpx.Response(200, json=self.hosts[hid])
            if request.method == "DELETE":
                del self.hosts[hid]
                self._changed()
                return httpx.Response(204)
        if path == "/config/preview":
            pending = self.changes > 0 or self.version is None
            last = {"n": self.version, "result": "ok"} if self.version else None
            preview = {"pending": pending, "drift": self.drift,
                       "changes": max(self.changes, int(pending)), "last_applied": last}
            if self.caddy_error:
                preview["caddy_error"] = self.caddy_error
            return httpx.Response(200, json=preview)
        if path == "/config/apply":
            if self.apply_fails or self._apply_fails_once:
                self._apply_fails_once = False
                return httpx.Response(422, json={"error": "caddy_rejected", "message": "Caddy said no."})
            self.applies.append(body.get("note", ""))
            self.version = (self.version or 0) + 1
            self.changes = 0
            return httpx.Response(200, json={"n": self.version, "result": "ok", "applied_by": "api:slipway"})
        return httpx.Response(404, json={"error": "not_found", "message": path})

    def _changed(self) -> None:
        self.calls.append(Call("changed"))
        self.changes += 1

    def _run_after(self, call: str) -> None:
        for entry in list(self._after):
            prefix, left, action = entry
            if not call.startswith(prefix):
                continue
            entry[1] = left = left - 1
            if left:
                continue
            self._after.remove(entry)
            if action is not None:
                action(self)
            self.someone_edits()


def install(monkeypatch) -> FakeSwitchyard:
    """A FakeSwitchyard that every SwitchyardClient made from now on talks to."""
    fake = FakeSwitchyard()
    monkeypatch.setattr(switchyard, "transport_factory", lambda: httpx.MockTransport(fake.handle))
    return fake


async def configure(url: str = "https://sy.example.test", key: str = KEY, tls: str = "auto", **value: Any) -> None:
    """Save the Switchyard connection (``value`` adds settings such as ``traffic_address``)."""
    async with get_sessionmaker()() as db:
        db.add(AppSetting(key=switchyard.SETTING_KEY, value={"url": url, "default_tls_mode": tls, **value}, secret=key))
        await db.commit()
