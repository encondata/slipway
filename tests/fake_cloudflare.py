"""Enough of Cloudflare's v4 API for Slipway's DNS code: zones, records, token checks, errors.

Inject it with::

    fake = FakeCloudflare()
    monkeypatch.setattr(cloudflare, "transport_factory", lambda: httpx.MockTransport(fake.handle))
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import httpx

TOKEN = "cf-T3stT0ken-" + "a1B2c3D4e5" * 3  # 43 URL-safe characters, like a real token
ZONE = "example.com"


def _ok(result: Any, status: int = 200, **extra: Any) -> httpx.Response:
    return httpx.Response(status, json={"success": True, "errors": [], "messages": [], "result": result, **extra})


def _fail(status: int, code: int, message: str, headers: dict[str, str] | None = None) -> httpx.Response:
    return httpx.Response(status, headers=headers, json={
        "success": False, "errors": [{"code": code, "message": message}], "messages": [], "result": None})


class FakeCloudflare:
    def __init__(self, token: str = TOKEN) -> None:
        self.token = token
        self.token_status = "active"  # what /user/tokens/verify reports for the right token
        self.zones: list[dict[str, Any]] = []
        self.records: dict[str, dict[str, Any]] = {}  # id -> record (with "zone_id")
        self.calls: list[dict[str, Any]] = []  # {method, path, params, body}
        self.rate_limit_once = False  # the next call answers 429 with Retry-After: 1
        self.deny: bool | set[str] = False  # True, or a set of methods, answered with 403
        self.echo_token_in_errors = False  # a misbehaving API that repeats the token in its message

    # -- set-up helpers

    def add_zone(self, name: str = ZONE, status: str = "active") -> str:
        zid = uuid.uuid4().hex
        self.zones.append({"id": zid, "name": name, "status": status})
        return zid

    def add_record(self, zone_id: str, type: str, name: str, content: str, *, proxied: bool = False,
                   comment: str | None = None, ttl: int = 300) -> dict[str, Any]:
        rid = uuid.uuid4().hex
        rec = {"id": rid, "zone_id": zone_id, "type": type, "name": name, "content": content,
               "proxied": proxied, "comment": comment, "ttl": ttl}
        self.records[rid] = rec
        return dict(rec)

    def named(self, name: str) -> list[dict[str, Any]]:
        return [r for r in self.records.values() if r["name"] == name]

    def writes(self) -> list[dict[str, Any]]:
        return [c for c in self.calls if c["method"] != "GET"]

    # -- the API

    def handle(self, request: httpx.Request) -> httpx.Response:
        params = dict(request.url.params)
        body = json.loads(request.content) if request.content else None
        path = request.url.path.removeprefix("/client/v4")
        self.calls.append({"method": request.method, "path": path, "params": params, "body": body})
        if self.rate_limit_once:
            self.rate_limit_once = False
            return _fail(429, 971, "Please wait and consider throttling your request speed", {"Retry-After": "1"})
        if request.headers.get("Authorization") != f"Bearer {self.token}":
            given = request.headers.get("Authorization", "")
            text = f"Invalid API Token {given}" if self.echo_token_in_errors else "Invalid API Token"
            return _fail(401, 1000, text)
        if self.deny is True or (isinstance(self.deny, set) and request.method in self.deny):
            text = "Unauthorized to access requested resource"
            if self.echo_token_in_errors:
                text += f" for {self.token}"
            return _fail(403, 9109, text)

        parts = [p for p in path.split("/") if p]
        if parts == ["user", "tokens", "verify"]:
            return _ok({"id": "tok", "status": self.token_status})
        if parts == ["zones"] and request.method == "GET":
            zones = [z for z in self.zones if ("name" not in params or z["name"] == params["name"])
                     and ("status" not in params or z["status"] == params["status"])]
            return _ok(zones)
        if len(parts) >= 3 and parts[0] == "zones" and parts[2] == "dns_records":
            zid = parts[1]
            if not any(z["id"] == zid for z in self.zones):
                return _fail(404, 7003, "Could not route to /zones/..., perhaps your object identifier is invalid?")
            if len(parts) == 3:
                return self._collection(request.method, zid, params, body)
            return self._one(request.method, zid, parts[3], body)
        return _fail(404, 7000, "No route for that URI")

    def _collection(self, method: str, zid: str, params: dict[str, str], body: Any) -> httpx.Response:
        if method == "GET":
            recs = [r for r in self.records.values() if r["zone_id"] == zid
                    and ("name" not in params or r["name"] == params["name"])
                    and ("type" not in params or r["type"] == params["type"])]
            per_page = int(params.get("per_page", 100))
            return _ok(recs[:per_page], result_info={"count": min(len(recs), per_page), "total_count": len(recs)})
        if method == "POST":
            here = [r for r in self.records.values() if r["zone_id"] == zid and r["name"] == body["name"]]
            if any(r["type"] == "CNAME" for r in here) or (body["type"] == "CNAME" and here):
                return _fail(400, 81053, "An A, AAAA, or CNAME record with that host already exists.")
            if any(r["type"] == body["type"] and r["content"] == body["content"] for r in here):
                return _fail(400, 81058, "An identical record already exists.")
            rec = self.add_record(zid, body["type"], body["name"], body["content"], proxied=body.get("proxied", False),
                                  comment=body.get("comment"), ttl=body.get("ttl", 1))
            return _ok(rec)
        return _fail(405, 10000, "Method not allowed")

    def _one(self, method: str, zid: str, rid: str, body: Any) -> httpx.Response:
        rec = self.records.get(rid)
        if rec is None or rec["zone_id"] != zid:
            return _fail(404, 81044, "Record does not exist.")
        if method == "GET":
            return _ok(dict(rec))
        if method == "PATCH":
            rec.update({k: v for k, v in body.items() if k in ("content", "proxied", "ttl", "comment", "name", "type")})
            return _ok(dict(rec))
        if method == "DELETE":
            del self.records[rid]
            return _ok({"id": rid})
        return _fail(405, 10000, "Method not allowed")
