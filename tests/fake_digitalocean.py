"""Enough of DigitalOcean's v2 API for Slipway's phase 4 code, in memory.

Inject it with::

    fake = FakeDigitalOcean()
    monkeypatch.setattr(digitalocean, "transport_factory", lambda: httpx.MockTransport(fake.handler))
    monkeypatch.setattr(digitalocean, "sleep", fake.sleep)          # waits move the fake's clock
    monkeypatch.setattr(digitalocean, "monotonic", fake.monotonic)
    monkeypatch.setattr(digitalocean, "clock", fake.time)

(``use_fake(monkeypatch, fake)`` does all four.) What it models:

* the account and its team per token (``add_token``), regions, sizes with ``price_monthly``,
  database options with layouts and versions;
* VPCs (unique names, members, deletes refused while members remain, ``member_linger``);
* droplets (``boot_polls`` GETs before ``active``, IPs ``203.0.113.<n>`` distinct per droplet,
  ``?tag_name=``; the cloud-init ``user_data`` is parsed and its ``ssh_keys.ed25519_public`` kept in
  ``host_keys``), actions (``action_polls``, ``action_errors``, ``action_stall``, resize only when off);
* databases (``db_polls`` to ``online``, trusted sources that refuse unknown droplets,
  ``firewall_wait``, the CA, ``db_resize_polls``, ``?tag_name=``);
* Spaces keys with their grants (the secret shown once);
* certificates (``dns_names`` read from the uploaded leaf; ``cert_in_use_polls``);
* load balancers (full-body PUT, ``lb_apply_polls``, ``droplet_ids`` with ``tag`` refused, an unknown
  ``certificate_id`` refused, a PUT while not ``active`` refused);
* firewalls (full-body PUT; ports ``all`` answered as ``"0"``).

Failure controls: ``fail[(method, path)]``, ``lose_answer[(method, path)]`` (the write lands, the
answer is a timeout), ``lost_visible_after`` (seconds of the fake's clock before a lost object
shows in lists and tag queries), ``forbid`` (a set of kinds answered 403 for every request, as a
custom-scoped token is), ``rate_limit_once``, ``down``. ``requests`` records every request with its
headers; ``writes()`` the ones that aren't GETs. The clock is the fake's own: ``advance(seconds)``.
"""

from __future__ import annotations

import base64
import datetime as dt
import ipaddress
import json
import secrets
import string
import uuid
from typing import Any

import httpx
import yaml

TOKEN = "dop_v1_" + "0123456789abcdef" * 4  # the shape of a real token (64 hex characters)
TEAM = {"uuid": "5df3e3004a5e11e99f1c0a580a020fd2", "name": "Slipway Team"}
BASE = "https://api.digitalocean.com/v2"
START = 1_800_000_000.0  # the fake's clock starts here (a Unix time in 2027)

# Kinds, for ``forbid``: the first path segment, with ``spaces`` as ``spaces_keys``.
KINDS = ("account", "regions", "sizes", "vpcs", "droplets", "databases", "spaces_keys", "certificates",
         "load_balancers", "firewalls")

REGIONS = ["nyc3", "sfo3", "ams3", "fra1", "lon1", "tor1", "sgp1", "syd1"]
SIZES = [
    # slug, vcpus, memory (MiB), disk (GB), price_monthly
    ("s-1vcpu-1gb", 1, 1024, 25, 6.0),
    ("s-1vcpu-2gb", 1, 2048, 50, 12.0),
    ("s-2vcpu-2gb", 2, 2048, 60, 18.0),
    ("s-2vcpu-4gb", 2, 4096, 80, 24.0),
    ("s-4vcpu-8gb", 4, 8192, 160, 48.0),
    ("c-2", 2, 4096, 25, 42.0),
]
DB_SIZES = ["db-s-1vcpu-1gb", "db-s-1vcpu-2gb", "db-s-2vcpu-4gb", "db-s-4vcpu-8gb"]
DB_VERSIONS = ["14", "15", "16", "17"]
FAKE_CA = "-----BEGIN CERTIFICATE-----\nMIIFakeDigitalOceanDatabaseCA\n-----END CERTIFICATE-----\n"
USER_DATA_LIMIT = 64 * 1024


def _error(status: int, error_id: str, message: str, headers: dict[str, str] | None = None) -> httpx.Response:
    return httpx.Response(status, headers=headers, json={"id": error_id, "message": message,
                                                         "request_id": uuid.uuid4().hex})


def _unprocessable(message: str) -> httpx.Response:
    return _error(422, "unprocessable_entity", message)


def _not_found() -> httpx.Response:
    return _error(404, "not_found", "The resource you were accessing could not be found.")


def _ok(body: dict[str, Any], status: int = 200) -> httpx.Response:
    return httpx.Response(status, json=body)


def _empty(status: int = 204) -> httpx.Response:
    return httpx.Response(status)


def make_leaf(names: list[str], not_after: dt.datetime | None = None) -> tuple[str, str]:
    """``(leaf_pem, key_pem)``: a self-signed certificate for ``names`` (tests upload it)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.UTC)
    not_after = not_after or now + dt.timedelta(days=90)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(not_after)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
            .sign(key, hashes.SHA256()))
    leaf = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()).decode()
    return leaf, key_pem


class FakeDigitalOcean:
    def __init__(self, token: str = TOKEN) -> None:
        self.now = START
        self.tokens: dict[str, dict[str, str]] = {token: dict(TEAM)}
        self.account_status = "active"
        self.droplet_limit = 25

        self.regions = [{"slug": r, "name": r.upper(), "available": True, "features": ["private_networking"],
                         "sizes": [s[0] for s in SIZES]} for r in REGIONS]
        self.sizes = [{"slug": slug, "vcpus": vcpus, "memory": memory, "disk": disk, "transfer": 1.0,
                       "price_monthly": price, "price_hourly": round(price / 672, 5), "available": True,
                       "regions": list(REGIONS), "description": "Basic"}
                      for slug, vcpus, memory, disk, price in SIZES]
        self.db_options = {"options": {"pg": {
            "regions": list(REGIONS), "versions": list(DB_VERSIONS),
            "layouts": [{"num_nodes": 1, "sizes": list(DB_SIZES)}, {"num_nodes": 2, "sizes": list(DB_SIZES[1:])},
                        {"num_nodes": 3, "sizes": list(DB_SIZES[1:])}],
        }}, "version_availability": {"pg": [{"version": v} for v in DB_VERSIONS]}}

        self.vpcs: dict[str, dict[str, Any]] = {}
        self.droplets: dict[int, dict[str, Any]] = {}
        self.actions: dict[int, dict[str, Any]] = {}
        self.databases: dict[str, dict[str, Any]] = {}
        self.db_rules: dict[str, list[dict[str, Any]]] = {}
        self.spaces_keys: dict[str, dict[str, Any]] = {}  # access key -> key (with its secret, never listed)
        self.certificates: dict[str, dict[str, Any]] = {}
        self.load_balancers: dict[str, dict[str, Any]] = {}
        self.firewalls: dict[str, dict[str, Any]] = {}

        self.host_keys: dict[int, str] = {}  # droplet id -> ssh_keys.ed25519_public from its user-data
        self.user_data: dict[int, str] = {}  # never answered back, as DigitalOcean never does

        # Behaviour
        self.boot_polls = 1  # GETs of a new droplet that still answer "new"
        self.action_polls = 1  # GETs of an action that still answer "in-progress"
        self.action_errors: set[str] = set()  # action types that end "errored"
        self.action_stall: set[str] = set()  # action types that never finish
        self.db_polls = 1  # GETs of a new cluster that still answer "creating"
        self.db_resize_polls = 1  # GETs of a resizing cluster that still answer "resizing"
        self.db_hide_password = False  # GETs of a cluster leave out connection.password
        self.firewall_wait = 0  # trusted-source PUTs answered 409 "not ready" before one is taken
        self.cert_in_use_polls = 0  # deletes of a new certificate answered "in use" before one works
        self.lb_apply_polls = 1  # GETs of a load balancer that still answer "new" after a create or PUT
        self.member_linger = 0.0  # seconds a deleted droplet/cluster/LB stays a VPC member
        self.max_per_page = 200

        self.fail: dict[tuple[str, str], Any] = {}  # (method, path) -> status | {status,id,message,headers} | [those]
        self.lose_answer: dict[tuple[str, str], Any] = {}  # (method, path) -> True | times left
        self.lost_visible_after = 0.0
        self.forbid: set[str] = set()
        self.rate_limit_once: bool | dict[str, str] = False  # the next request answers 429 (these headers)
        self.down = False

        self.requests: list[dict[str, Any]] = []
        self._next_droplet = 3001
        self._next_action = 9001
        self._ip_n = 0
        self._lb_n = 0
        self._vpc_n = 0
        self._polls: dict[tuple[str, Any], int] = {}  # (kind, id) -> GETs left before the next state
        self._visible_at: dict[tuple[str, Any], float] = {}  # lost objects: hidden from lists until then
        self._gone_members: list[dict[str, Any]] = []  # {vpc, urn, name, until}
        self._cert_in_use: dict[str, int] = {}

    # -- the clock

    def time(self) -> float:
        return self.now

    def monotonic(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds

    async def sleep(self, seconds: float) -> None:
        self.advance(seconds)

    def _stamp(self) -> str:
        return dt.datetime.fromtimestamp(self.now, dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    # -- set-up helpers

    def add_token(self, token: str, team_name: str, team_uuid: str | None = None) -> None:
        self.tokens[token] = {"uuid": team_uuid or uuid.uuid4().hex, "name": team_name}

    def writes(self) -> list[dict[str, Any]]:
        return [r for r in self.requests if r["method"] != "GET"]

    def _must(self, result: Any) -> dict[str, Any]:
        if isinstance(result, httpx.Response):
            raise AssertionError(f"fake refused the set-up: {result.status_code} {result.text}")
        return result

    def add_vpc(self, **body: Any) -> dict[str, Any]:
        body.setdefault("region", "nyc3")
        return dict(self._must(self._create_vpc(body)))

    def add_droplet(self, *, status: str = "active", **body: Any) -> dict[str, Any]:
        body.setdefault("region", "nyc3")
        body.setdefault("size", "s-1vcpu-1gb")
        body.setdefault("image", "ubuntu-24-04-x64")
        droplet = self._must(self._create_droplet(body))
        if status != "new":
            self._polls.pop(("droplet", droplet["id"]), None)
            self._boot(droplet)
            droplet["status"] = status
        return dict(droplet)

    def add_database(self, *, status: str = "online", **body: Any) -> dict[str, Any]:
        body.setdefault("engine", "pg")
        body.setdefault("version", "16")
        body.setdefault("region", "nyc3")
        body.setdefault("size", "db-s-1vcpu-1gb")
        body.setdefault("num_nodes", 1)
        db = self._must(self._create_database(body))
        if status != "creating":
            self._polls.pop(("database", db["id"]), None)
            db["status"] = status
        return dict(db)

    def add_certificate(self, name: str, names: list[str], not_after: dt.datetime | None = None) -> dict[str, Any]:
        leaf, key = make_leaf(names, not_after)
        return dict(self._must(self._create_certificate({
            "name": name, "type": "custom", "private_key": key, "leaf_certificate": leaf})))

    def add_load_balancer(self, *, status: str = "active", **body: Any) -> dict[str, Any]:
        body.setdefault("region", "nyc3")
        body.setdefault("forwarding_rules", [{"entry_protocol": "http", "entry_port": 80,
                                              "target_protocol": "http", "target_port": 80}])
        lb = self._must(self._create_load_balancer(body))
        if status != "new":
            self._polls.pop(("load_balancer", lb["id"]), None)
            self._lb_ready(lb)
            lb["status"] = status
        return dict(lb)

    def add_firewall(self, **body: Any) -> dict[str, Any]:
        return dict(self._must(self._create_firewall(body)))

    def add_spaces_key(self, name: str, grants: list[dict[str, Any]]) -> dict[str, Any]:
        return dict(self._must(self._create_spaces_key({"name": name, "grants": grants})))

    # -- the API

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path.removeprefix("/v2")
        params = dict(request.url.params)
        body = json.loads(request.content) if request.content else None
        self.requests.append({"method": request.method, "path": path, "params": params, "body": body,
                              "headers": dict(request.headers), "url": str(request.url)})
        if self.down:
            raise httpx.ConnectError("DigitalOcean is down (fake)", request=request)
        if self.rate_limit_once:
            headers = self.rate_limit_once if isinstance(self.rate_limit_once, dict) else {"Retry-After": "1"}
            self.rate_limit_once = False
            return _error(429, "too_many_requests", "API Rate limit exceeded.", headers)
        auth = request.headers.get("Authorization", "")
        team = self.tokens.get(auth.removeprefix("Bearer ")) if auth.startswith("Bearer ") else None
        if team is None:
            return _error(401, "Unauthorized", "Unable to authenticate you")
        parts = [p for p in path.split("/") if p]
        kind = "spaces_keys" if parts[:1] == ["spaces"] else (parts[0] if parts else "")
        if kind in self.forbid:
            return _error(403, "forbidden", "You are not authorized to perform this operation")
        key = (request.method, path)
        if key in self.fail:
            spec = self.fail[key]
            if isinstance(spec, list):
                spec = spec.pop(0)
                if not self.fail[key]:
                    del self.fail[key]
            return self._failure(spec)

        lost = self._take_lost(key)
        visible_from = self.now + self.lost_visible_after if lost else None
        resp = self._route(request.method, parts, params, body or {}, team, visible_from)
        if lost:
            raise httpx.ReadTimeout("the answer was lost (fake)", request=request)
        return resp

    def _failure(self, spec: Any) -> httpx.Response:
        if isinstance(spec, int):
            spec = {"status": spec}
        status = spec["status"]
        default_id = {400: "bad_request", 403: "forbidden", 404: "not_found", 409: "conflict",
                      422: "unprocessable_entity", 429: "too_many_requests"}.get(status, "server_error")
        return _error(status, spec.get("id", default_id), spec.get("message", "Something went wrong (fake)"),
                      spec.get("headers"))

    def _take_lost(self, key: tuple[str, str]) -> bool:
        spec = self.lose_answer.get(key)
        if not spec:
            return False
        if spec is not True and isinstance(spec, int):
            if spec <= 1:
                del self.lose_answer[key]
            else:
                self.lose_answer[key] = spec - 1
        return True

    def _hide(self, kind: str, obj_id: Any, visible_from: float | None) -> None:
        if visible_from is not None and visible_from > self.now:
            self._visible_at[(kind, obj_id)] = visible_from

    def _visible(self, kind: str, obj_id: Any) -> bool:
        return self._visible_at.get((kind, obj_id), self.now) <= self.now

    def _page(self, path: str, key: str, items: list[dict[str, Any]], params: dict[str, str],
              null_when_empty: bool = False) -> httpx.Response:
        per_page = max(1, min(int(params.get("per_page", 20)), self.max_per_page))
        page = max(1, int(params.get("page", 1)))
        chunk = items[(page - 1) * per_page: page * per_page]
        pages: dict[str, str] = {}
        extra = "".join(f"&{k}={v}" for k, v in params.items() if k not in ("page", "per_page"))
        if page * per_page < len(items):
            pages["next"] = f"{BASE}{path}?page={page + 1}&per_page={per_page}{extra}"
            pages["last"] = f"{BASE}{path}?page={(len(items) + per_page - 1) // per_page}&per_page={per_page}{extra}"
        if page > 1:
            pages["prev"] = f"{BASE}{path}?page={page - 1}&per_page={per_page}{extra}"
        value: Any = [dict(i) for i in chunk]
        if null_when_empty and not items:
            value = None  # DigitalOcean answers "databases": null when there are none
        return _ok({key: value, "links": {"pages": pages}, "meta": {"total": len(items)}})

    def _route(self, method: str, parts: list[str], params: dict[str, str], body: dict[str, Any],
               team: dict[str, str], visible_from: float | None) -> httpx.Response:
        path = "/" + "/".join(parts)
        n = len(parts)
        head = parts[0] if parts else ""

        if parts == ["account"] and method == "GET":
            return _ok({"account": {"droplet_limit": self.droplet_limit, "floating_ip_limit": 3,
                                    "email": "ops@example.com", "uuid": "acct-" + team["uuid"][:8],
                                    "email_verified": True, "status": self.account_status,
                                    "status_message": "", "team": dict(team)}})
        if parts == ["regions"] and method == "GET":
            return self._page(path, "regions", self.regions, params)
        if parts == ["sizes"] and method == "GET":
            return self._page(path, "sizes", self.sizes, params)
        if parts == ["databases", "options"] and method == "GET":
            return _ok(json.loads(json.dumps(self.db_options)))

        if head == "vpcs":
            return self._vpcs(method, parts, params, body, visible_from)
        if head == "droplets":
            return self._droplets(method, parts, params, body, visible_from)
        if head == "databases":
            return self._databases(method, parts, params, body, visible_from)
        if parts[:2] == ["spaces", "keys"]:
            if n == 2 and method == "GET":
                keys = [self._key_view(k) for k in self.spaces_keys.values() if self._visible("key", k["access_key"])]
                return self._page(path, "keys", keys, params)
            if n == 2 and method == "POST":
                return self._created("key", self._create_spaces_key(body), "key", visible_from, "access_key")
            if n == 3 and method == "DELETE":
                if self.spaces_keys.pop(parts[2], None) is None:
                    return _not_found()
                return _empty()
        if head == "certificates":
            return self._certs(method, parts, params, body, visible_from)
        if head == "load_balancers":
            return self._lbs(method, parts, params, body, visible_from)
        if head == "firewalls":
            return self._fws(method, parts, params, body, visible_from)
        return _not_found()

    def _created(self, kind: str, result: Any, key: str, visible_from: float | None,
                 id_field: str = "id") -> httpx.Response:
        if isinstance(result, httpx.Response):
            return result
        self._hide(kind, result[id_field], visible_from)
        return _ok({key: dict(result)}, 201 if kind != "droplet" else 202)

    # -- VPCs

    def _create_vpc(self, body: dict[str, Any]) -> Any:
        name = body.get("name")
        if not name or not isinstance(name, str):
            return _unprocessable("Name is required.")
        if body.get("region") not in REGIONS:
            return _unprocessable("Region is invalid.")
        if any(v["name"].lower() == name.lower() for v in self.vpcs.values()):
            return _unprocessable("A VPC with this name already exists.")
        self._vpc_n += 1
        ip_range = body.get("ip_range") or f"10.{109 + self._vpc_n}.0.0/20"
        vid = str(uuid.uuid4())
        vpc = {"id": vid, "urn": f"do:vpc:{vid}", "name": name, "description": body.get("description", ""),
               "region": body["region"], "ip_range": ip_range, "default": False, "created_at": self._stamp()}
        self.vpcs[vid] = vpc
        return vpc

    def _members(self, vpc_id: str) -> list[dict[str, Any]]:
        out = [{"urn": f"do:droplet:{d['id']}", "name": d["name"], "created_at": d["created_at"]}
               for d in self.droplets.values() if d.get("vpc_uuid") == vpc_id]
        out += [{"urn": f"do:dbaas:{d['id']}", "name": d["name"], "created_at": d["created_at"]}
                for d in self.databases.values() if d.get("private_network_uuid") == vpc_id]
        out += [{"urn": f"do:loadbalancer:{lb['id']}", "name": lb["name"], "created_at": lb["created_at"]}
                for lb in self.load_balancers.values() if lb.get("vpc_uuid") == vpc_id]
        self._gone_members = [g for g in self._gone_members if g["until"] > self.now]
        out += [{"urn": g["urn"], "name": g["name"], "created_at": ""} for g in self._gone_members
                if g["vpc"] == vpc_id]
        return out

    def _left_vpc(self, vpc_id: str | None, urn: str, name: str) -> None:
        if vpc_id and self.member_linger > 0:
            self._gone_members.append({"vpc": vpc_id, "urn": urn, "name": name, "until": self.now + self.member_linger})

    def _vpcs(self, method: str, parts: list[str], params: dict[str, str], body: dict[str, Any],
              visible_from: float | None) -> httpx.Response:
        path = "/" + "/".join(parts)
        if len(parts) == 1 and method == "GET":
            return self._page(path, "vpcs", [v for v in self.vpcs.values() if self._visible("vpc", v["id"])], params)
        if len(parts) == 1 and method == "POST":
            return self._created("vpc", self._create_vpc(body), "vpc", visible_from)
        vpc = self.vpcs.get(parts[1]) if len(parts) >= 2 else None
        if vpc is None:
            return _not_found()
        if len(parts) == 2 and method == "GET":
            return _ok({"vpc": dict(vpc)})
        if len(parts) == 2 and method == "DELETE":
            if vpc["default"]:
                return _error(403, "forbidden", "Can not delete the default VPC")
            if self._members(vpc["id"]):
                return _error(403, "forbidden", "Can not delete VPC with members")
            del self.vpcs[vpc["id"]]
            return _empty()
        if len(parts) == 3 and parts[2] == "members" and method == "GET":
            return self._page(path, "members", self._members(vpc["id"]), params)
        return _not_found()

    # -- droplets

    def _size(self, slug: Any) -> dict[str, Any] | None:
        return next((s for s in self.sizes if s["slug"] == slug), None)

    def _create_droplet(self, body: dict[str, Any]) -> Any:
        for field in ("name", "region", "size", "image"):
            if not body.get(field):
                return _unprocessable(f"{field} is required.")
        if body["region"] not in REGIONS:
            return _unprocessable("Region is not available.")
        size = self._size(body["size"])
        if size is None:
            return _unprocessable("Size is not available in this region.")
        vpc_id = body.get("vpc_uuid")
        if vpc_id and vpc_id not in self.vpcs:
            return _unprocessable("VPC is not valid.")
        user_data = body.get("user_data") or ""
        if len(user_data.encode()) > USER_DATA_LIMIT:
            return _unprocessable("user_data is limited to 64 KiB.")
        tags = list(body.get("tags") or [])
        droplet_id = self._next_droplet
        self._next_droplet += 1
        droplet = {"id": droplet_id, "name": body["name"], "status": "new", "locked": False,
                   "memory": size["memory"], "vcpus": size["vcpus"], "disk": size["disk"],
                   "size_slug": size["slug"], "size": dict(size),
                   "region": {"slug": body["region"], "name": body["region"].upper()},
                   "image": {"slug": body["image"]}, "vpc_uuid": vpc_id, "tags": tags,
                   "networks": {"v4": [], "v6": []}, "features": ["private_networking"],
                   "monitoring": bool(body.get("monitoring")), "created_at": self._stamp()}
        self.droplets[droplet_id] = droplet
        self._polls[("droplet", droplet_id)] = self.boot_polls
        if user_data:
            self.user_data[droplet_id] = user_data
            try:
                doc = yaml.safe_load(user_data)
            except yaml.YAMLError:
                doc = None
            public = ((doc or {}).get("ssh_keys") or {}).get("ed25519_public") if isinstance(doc, dict) else None
            if public:
                self.host_keys[droplet_id] = str(public)
        return droplet

    def _boot(self, droplet: dict[str, Any]) -> None:
        droplet["status"] = "active"
        if droplet["networks"]["v4"]:
            return
        self._ip_n += 1
        vpc = self.vpcs.get(droplet.get("vpc_uuid") or "")
        net = ipaddress.ip_network(vpc["ip_range"]) if vpc else ipaddress.ip_network("10.10.0.0/16")
        private = str(net.network_address + 1 + self._ip_n)
        droplet["networks"]["v4"] = [
            {"ip_address": f"203.0.113.{self._ip_n}", "netmask": "255.255.255.0", "gateway": "203.0.113.254",
             "type": "public"},
            {"ip_address": private, "netmask": str(net.netmask), "gateway": str(net.network_address + 1),
             "type": "private"},
        ]

    def _tick_droplet(self, droplet: dict[str, Any]) -> None:
        key = ("droplet", droplet["id"])
        if droplet["status"] != "new":
            return
        left = self._polls.get(key, 0)
        if left > 0:
            self._polls[key] = left - 1
            return
        self._polls.pop(key, None)
        self._boot(droplet)

    def _droplets(self, method: str, parts: list[str], params: dict[str, str], body: dict[str, Any],
                  visible_from: float | None) -> httpx.Response:
        path = "/" + "/".join(parts)
        if len(parts) == 1 and method == "GET":
            items = [d for d in self.droplets.values() if self._visible("droplet", d["id"])]
            if "tag_name" in params:
                items = [d for d in items if params["tag_name"] in d["tags"]]
            return self._page(path, "droplets", items, params)
        if len(parts) == 1 and method == "POST":
            return self._created("droplet", self._create_droplet(body), "droplet", visible_from)
        try:
            droplet = self.droplets.get(int(parts[1]))
        except ValueError:
            droplet = None
        if droplet is None:
            return _not_found()
        if len(parts) == 2 and method == "GET":
            self._tick_droplet(droplet)
            return _ok({"droplet": json.loads(json.dumps(droplet))})
        if len(parts) == 2 and method == "DELETE":
            del self.droplets[droplet["id"]]
            for lb in self.load_balancers.values():  # DigitalOcean drops a deleted droplet from its LBs
                lb["droplet_ids"] = [i for i in lb["droplet_ids"] if i != droplet["id"]]
            self._left_vpc(droplet.get("vpc_uuid"), f"do:droplet:{droplet['id']}", droplet["name"])
            return _empty()
        if len(parts) == 3 and parts[2] == "actions" and method == "POST":
            return self._start_action(droplet, body)
        if len(parts) == 4 and parts[2] == "actions" and method == "GET":
            try:
                action = self.actions.get(int(parts[3]))
            except ValueError:
                action = None
            if action is None or action["resource_id"] != droplet["id"]:
                return _not_found()
            self._tick_action(action)
            return _ok({"action": self._action_view(action)})
        return _not_found()

    def _start_action(self, droplet: dict[str, Any], body: dict[str, Any]) -> httpx.Response:
        kind = body.get("type")
        if kind not in ("power_off", "power_on", "shutdown", "reboot", "resize"):
            return _unprocessable("Action type is not valid.")
        if droplet["locked"]:
            return _unprocessable("Droplet already has a pending event.")
        if kind == "resize":
            size = self._size(body.get("size"))
            if size is None:
                return _unprocessable("Size is not valid.")
            if droplet["status"] != "off":
                return _unprocessable("Droplet is currently on. Please power it off to run this event.")
            if body.get("disk") and size["disk"] < droplet["disk"]:
                return _unprocessable("A disk can't be made smaller.")
        action_id = self._next_action
        self._next_action += 1
        action = {"id": action_id, "status": "in-progress", "type": kind, "started_at": self._stamp(),
                  "completed_at": None, "resource_id": droplet["id"], "resource_type": "droplet",
                  "region_slug": droplet["region"]["slug"], "_body": dict(body)}
        self.actions[action_id] = action
        self._polls[("action", action_id)] = self.action_polls
        droplet["locked"] = True
        return _ok({"action": self._action_view(action)}, 201)

    def _tick_action(self, action: dict[str, Any]) -> None:
        if action["status"] != "in-progress" or action["type"] in self.action_stall:
            return
        key = ("action", action["id"])
        left = self._polls.get(key, 0)
        if left > 0:
            self._polls[key] = left - 1
            return
        self._polls.pop(key, None)
        action["completed_at"] = self._stamp()
        droplet = self.droplets.get(action["resource_id"])
        if droplet is not None:
            droplet["locked"] = False
        if action["type"] in self.action_errors:
            action["status"] = "errored"
            return
        action["status"] = "completed"
        if droplet is None:
            return
        kind, body = action["type"], action["_body"]
        if kind in ("power_off", "shutdown"):
            droplet["status"] = "off"
        elif kind in ("power_on", "reboot"):
            droplet["status"] = "active"
        elif kind == "resize":
            size = self._size(body["size"])
            droplet.update(size_slug=size["slug"], size=dict(size), vcpus=size["vcpus"], memory=size["memory"])
            if body.get("disk"):
                droplet["disk"] = size["disk"]

    def _action_view(self, action: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in action.items() if not k.startswith("_")}

    # -- databases

    def _check_rules(self, rules: Any) -> str | None:
        if not isinstance(rules, list):
            return "rules must be a list."
        for rule in rules:
            if not isinstance(rule, dict) or rule.get("type") not in ("droplet", "ip_addr", "tag", "k8s", "app"):
                return "Rule type is invalid."
            if rule["type"] == "droplet":
                try:
                    known = int(rule.get("value")) in self.droplets
                except (TypeError, ValueError):
                    known = False
                if not known:
                    return "Droplet in trusted sources does not exist."
        return None

    def _create_database(self, body: dict[str, Any]) -> Any:
        for field in ("name", "engine", "version", "region", "size", "num_nodes"):
            if not body.get(field):
                return _unprocessable(f"{field} is required.")
        if body["engine"] != "pg":
            return _unprocessable("Engine is not supported here.")
        pg = self.db_options["options"]["pg"]
        if str(body["version"]) not in pg["versions"]:
            return _unprocessable("Version is not available.")
        layout = next((lay for lay in pg["layouts"] if lay["num_nodes"] == body["num_nodes"]), None)
        if layout is None or body["size"] not in layout["sizes"]:
            return _unprocessable("Size is not available for this number of nodes.")
        if any(d["name"] == body["name"] for d in self.databases.values()):
            return _unprocessable("A cluster with this name already exists.")
        vpc_id = body.get("private_network_uuid")
        if vpc_id and vpc_id not in self.vpcs:
            return _unprocessable("VPC is not valid.")
        problem = self._check_rules(body.get("rules") or [])
        if problem:
            return _unprocessable(problem)
        db_id = str(uuid.uuid4())
        password = secrets.token_urlsafe(16)
        host = f"{body['name']}-do-user-1-0.b.db.ondigitalocean.com"

        def conn(h: str) -> dict[str, Any]:
            return {"protocol": "postgresql",
                    "uri": f"postgresql://doadmin:{password}@{h}:25060/defaultdb?sslmode=require",
                    "database": "defaultdb", "host": h, "port": 25060, "user": "doadmin", "password": password,
                    "ssl": True}

        db = {"id": db_id, "name": body["name"], "engine": "pg", "version": str(body["version"]),
              "region": body["region"], "size": body["size"], "num_nodes": body["num_nodes"],
              "status": "creating", "tags": list(body.get("tags") or []), "private_network_uuid": vpc_id,
              "connection": conn(host), "private_connection": conn("private-" + host),
              "db_names": ["defaultdb"], "users": [{"name": "doadmin", "role": "primary"}],
              "created_at": self._stamp()}
        self.databases[db_id] = db
        self.db_rules[db_id] = [self._rule(db_id, r) for r in body.get("rules") or []]
        self._polls[("database", db_id)] = self.db_polls
        return db

    def _rule(self, db_id: str, rule: dict[str, Any]) -> dict[str, Any]:
        return {"uuid": str(uuid.uuid4()), "cluster_uuid": db_id, "type": rule["type"],
                "value": str(rule["value"]), "created_at": self._stamp()}

    def _db_view(self, db: dict[str, Any]) -> dict[str, Any]:
        view = json.loads(json.dumps(db))
        if self.db_hide_password:
            view["connection"].pop("password", None)
            view["private_connection"].pop("password", None)
        return view

    def _tick_db(self, db: dict[str, Any]) -> None:
        if db["status"] not in ("creating", "resizing"):
            return
        key = ("database", db["id"])
        left = self._polls.get(key, 0)
        if left > 0:
            self._polls[key] = left - 1
            return
        self._polls.pop(key, None)
        pending = db.pop("_resize", None)
        if pending:
            db.update(pending)
        db["status"] = "online"

    def _databases(self, method: str, parts: list[str], params: dict[str, str], body: dict[str, Any],
                   visible_from: float | None) -> httpx.Response:
        path = "/" + "/".join(parts)
        if len(parts) == 1 and method == "GET":
            items = [self._db_view(d) for d in self.databases.values() if self._visible("database", d["id"])]
            if "tag_name" in params:
                items = [d for d in items if params["tag_name"] in d["tags"]]
            return self._page(path, "databases", items, params, null_when_empty=True)
        if len(parts) == 1 and method == "POST":
            result = self._create_database(body)
            if isinstance(result, httpx.Response):
                return result
            self._hide("database", result["id"], visible_from)
            return _ok({"database": json.loads(json.dumps(result))}, 201)  # the create answer has the password
        db = self.databases.get(parts[1]) if len(parts) >= 2 else None
        if db is None:
            return _not_found()
        if len(parts) == 2 and method == "GET":
            self._tick_db(db)
            return _ok({"database": self._db_view(db)})
        if len(parts) == 2 and method == "DELETE":
            del self.databases[db["id"]]
            self.db_rules.pop(db["id"], None)
            self._left_vpc(db.get("private_network_uuid"), f"do:dbaas:{db['id']}", db["name"])
            return _empty()
        sub = parts[2] if len(parts) == 3 else None
        if sub == "firewall" and method == "GET":
            return _ok({"rules": [dict(r) for r in self.db_rules.get(db["id"], [])]})
        if sub == "firewall" and method == "PUT":
            if self.firewall_wait > 0:
                self.firewall_wait -= 1
                return _error(409, "conflict", "The cluster is not ready for this change yet.")
            rules = body.get("rules")
            problem = self._check_rules(rules)
            if problem:
                return _unprocessable(problem)
            self.db_rules[db["id"]] = [self._rule(db["id"], r) for r in rules]
            return _empty()
        if sub == "ca" and method == "GET":
            return _ok({"ca": {"certificate": base64.b64encode(FAKE_CA.encode()).decode()}})
        if sub == "resize" and method == "PUT":
            if db["status"] != "online":
                return _unprocessable("The cluster must be online to resize.")
            num_nodes, size = body.get("num_nodes"), body.get("size")
            layout = next((lay for lay in self.db_options["options"]["pg"]["layouts"]
                           if lay["num_nodes"] == num_nodes), None)
            if layout is None or size not in layout["sizes"]:
                return _unprocessable("Size is not available for this number of nodes.")
            db["status"] = "resizing"
            db["_resize"] = {"size": size, "num_nodes": num_nodes}
            self._polls[("database", db["id"])] = self.db_resize_polls
            return _empty(202)
        return _not_found()

    # -- Spaces keys

    def _key_view(self, key: dict[str, Any]) -> dict[str, Any]:
        return {k: (json.loads(json.dumps(v)) if isinstance(v, list) else v)
                for k, v in key.items() if k != "secret_key"}

    def _create_spaces_key(self, body: dict[str, Any]) -> Any:
        name, grants = body.get("name"), body.get("grants")
        if not name or not isinstance(grants, list) or not grants:
            return _unprocessable("A name and at least one grant are required.")
        for grant in grants:
            if not isinstance(grant, dict) or grant.get("permission") not in ("read", "readwrite", "fullaccess"):
                return _unprocessable("Grant permission is invalid.")
            if grant["permission"] == "fullaccess" and grant.get("bucket", "") != "":
                return _unprocessable("Full access is granted on every bucket (bucket must be empty).")
        alphabet = string.ascii_uppercase + string.digits
        access = "DO" + "".join(secrets.choice(alphabet) for _ in range(18))
        key = {"name": name, "access_key": access, "secret_key": secrets.token_urlsafe(32),
               "grants": [{"bucket": g.get("bucket", ""), "permission": g["permission"]} for g in grants],
               "created_at": self._stamp()}
        self.spaces_keys[access] = key
        return key

    # -- certificates

    def _create_certificate(self, body: dict[str, Any]) -> Any:
        name = body.get("name")
        if not name:
            return _unprocessable("Name is required.")
        if any(c["name"] == name for c in self.certificates.values()):
            return _unprocessable("A certificate with this name already exists.")
        kind = body.get("type", "custom")
        if kind == "custom":
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes

            if not body.get("private_key"):
                return _unprocessable("private_key is required.")
            try:
                leaf = x509.load_pem_x509_certificate(str(body.get("leaf_certificate", "")).encode())
            except ValueError:
                return _unprocessable("The leaf certificate could not be parsed.")
            try:
                san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                names = san.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                names = []
            not_after = leaf.not_valid_after_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
            fingerprint = leaf.fingerprint(hashes.SHA1()).hex()
        elif kind == "lets_encrypt":
            names = list(body.get("dns_names") or [])
            not_after = dt.datetime.fromtimestamp(self.now + 90 * 86400, dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
            fingerprint = secrets.token_hex(20)
        else:
            return _unprocessable("Type is invalid.")
        cert_id = str(uuid.uuid4())
        cert = {"id": cert_id, "name": name, "not_after": not_after, "sha1_fingerprint": fingerprint,
                "created_at": self._stamp(), "dns_names": names, "state": "verified", "type": kind}
        self.certificates[cert_id] = cert
        self._cert_in_use[cert_id] = self.cert_in_use_polls
        return cert

    def _certs(self, method: str, parts: list[str], params: dict[str, str], body: dict[str, Any],
               visible_from: float | None) -> httpx.Response:
        path = "/" + "/".join(parts)
        if len(parts) == 1 and method == "GET":
            items = [c for c in self.certificates.values() if self._visible("certificate", c["id"])]
            return self._page(path, "certificates", items, params)
        if len(parts) == 1 and method == "POST":
            return self._created("certificate", self._create_certificate(body), "certificate", visible_from)
        cert = self.certificates.get(parts[1]) if len(parts) == 2 else None
        if cert is None:
            return _not_found()
        if method == "GET":
            return _ok({"certificate": dict(cert)})
        if method == "DELETE":
            used = any(rule.get("certificate_id") == cert["id"]
                       for lb in self.load_balancers.values() for rule in lb["forwarding_rules"])
            if used or self._cert_in_use.get(cert["id"], 0) > 0:
                if not used:
                    self._cert_in_use[cert["id"]] -= 1
                return _error(403, "forbidden", "Certificate is in use by a load balancer and can't be deleted.")
            del self.certificates[cert["id"]]
            return _empty()
        return _not_found()

    # -- load balancers

    def _check_lb(self, body: dict[str, Any]) -> str | None:
        if not body.get("name"):
            return "Name is required."
        if not isinstance(body.get("region"), str) or body["region"] not in REGIONS:
            return "Region must be given as a slug."
        if body.get("size") and body.get("size_unit"):
            return "Only one of size and size_unit may be given."
        rules = body.get("forwarding_rules")
        if not isinstance(rules, list) or not rules:
            return "At least one forwarding rule is required."
        for rule in rules:
            cert_id = rule.get("certificate_id")
            if cert_id and cert_id not in self.certificates:
                return "The certificate in the forwarding rule does not exist."
        if body.get("tag") and body.get("droplet_ids"):
            return "Specify either a tag or droplet IDs, not both."
        for droplet_id in body.get("droplet_ids") or []:
            if droplet_id not in self.droplets:
                return "A droplet in droplet_ids does not exist."
        if body.get("vpc_uuid") and body["vpc_uuid"] not in self.vpcs:
            return "VPC is not valid."
        return None

    def _lb_fields(self, body: dict[str, Any]) -> dict[str, Any]:
        rules = [{"entry_protocol": r.get("entry_protocol"), "entry_port": r.get("entry_port"),
                  "target_protocol": r.get("target_protocol"), "target_port": r.get("target_port"),
                  "certificate_id": r.get("certificate_id") or "", "tls_passthrough": bool(r.get("tls_passthrough"))}
                 for r in body["forwarding_rules"]]
        health = {"protocol": "http", "port": 80, "path": "/", "check_interval_seconds": 10,
                  "response_timeout_seconds": 5, "healthy_threshold": 5, "unhealthy_threshold": 3}
        health.update(body.get("health_check") or {})
        return {"name": body["name"], "forwarding_rules": rules, "health_check": health,
                "sticky_sessions": body.get("sticky_sessions") or {"type": "none"},
                "size_unit": body.get("size_unit") or 1,
                "redirect_http_to_https": bool(body.get("redirect_http_to_https")),
                "enable_proxy_protocol": bool(body.get("enable_proxy_protocol")),
                "enable_backend_keepalive": bool(body.get("enable_backend_keepalive")),
                "http_idle_timeout_seconds": body.get("http_idle_timeout_seconds") or 60,
                "tag": body.get("tag") or "", "droplet_ids": list(body.get("droplet_ids") or []),
                "region": {"slug": body["region"], "name": body["region"].upper()}}

    def _create_load_balancer(self, body: dict[str, Any]) -> Any:
        problem = self._check_lb(body)
        if problem:
            return _unprocessable(problem)
        lb_id = str(uuid.uuid4())
        lb = {"id": lb_id, "ip": "", "ipv6": "", "status": "new", "created_at": self._stamp(),
              "algorithm": "round_robin", "size": "lb-small", "vpc_uuid": body.get("vpc_uuid") or None,
              **self._lb_fields(body)}
        self.load_balancers[lb_id] = lb
        self._polls[("load_balancer", lb_id)] = self.lb_apply_polls
        return lb

    def _lb_ready(self, lb: dict[str, Any]) -> None:
        lb["status"] = "active"
        if not lb["ip"]:
            self._lb_n += 1
            lb["ip"] = f"192.0.2.{self._lb_n}"

    def _tick_lb(self, lb: dict[str, Any]) -> None:
        if lb["status"] != "new":
            return
        key = ("load_balancer", lb["id"])
        left = self._polls.get(key, 0)
        if left > 0:
            self._polls[key] = left - 1
            return
        self._polls.pop(key, None)
        self._lb_ready(lb)

    def _lbs(self, method: str, parts: list[str], params: dict[str, str], body: dict[str, Any],
             visible_from: float | None) -> httpx.Response:
        path = "/" + "/".join(parts)
        if len(parts) == 1 and method == "GET":
            items = [lb for lb in self.load_balancers.values() if self._visible("load_balancer", lb["id"])]
            return self._page(path, "load_balancers", [json.loads(json.dumps(i)) for i in items], params)
        if len(parts) == 1 and method == "POST":
            result = self._create_load_balancer(body)
            if isinstance(result, httpx.Response):
                return result
            self._hide("load_balancer", result["id"], visible_from)
            return _ok({"load_balancer": json.loads(json.dumps(result))}, 202)
        lb = self.load_balancers.get(parts[1]) if len(parts) == 2 else None
        if lb is None:
            return _not_found()
        if method == "GET":
            self._tick_lb(lb)
            return _ok({"load_balancer": json.loads(json.dumps(lb))})
        if method == "PUT":
            if lb["status"] != "active":
                return _unprocessable("The load balancer is applying a change; wait until it is active.")
            problem = self._check_lb(body)
            if problem:
                return _unprocessable(problem)
            if (body.get("vpc_uuid") or lb["vpc_uuid"]) != lb["vpc_uuid"]:
                return _unprocessable("A load balancer can't move to another VPC.")
            lb.update(self._lb_fields(body))  # the whole body: what it leaves out goes back to the default
            lb["status"] = "new"
            self._polls[("load_balancer", lb["id"])] = self.lb_apply_polls
            return _ok({"load_balancer": json.loads(json.dumps(lb))})
        if method == "DELETE":
            del self.load_balancers[lb["id"]]
            self._left_vpc(lb.get("vpc_uuid"), f"do:loadbalancer:{lb['id']}", lb["name"])
            return _empty()
        return _not_found()

    # -- firewalls

    def _fw_rules(self, rules: Any, side: str) -> list[dict[str, Any]] | str:
        out = []
        for rule in rules or []:
            proto = rule.get("protocol")
            if proto not in ("tcp", "udp", "icmp"):
                return "Protocol is invalid."
            ports = rule.get("ports")
            if proto != "icmp" and not ports:
                return "Ports are required for tcp and udp."
            where = dict(rule.get(side) or {})
            for lb_id in where.get("load_balancer_uids") or []:
                if lb_id not in self.load_balancers:
                    return "A load balancer in the rule does not exist."
            entry: dict[str, Any] = {"protocol": proto, side: {
                k: list(where.get(k) or []) for k in ("addresses", "droplet_ids", "load_balancer_uids", "tags")
                if where.get(k)}}
            if proto != "icmp":
                entry["ports"] = "0" if str(ports) == "all" else str(ports)
            else:
                entry["ports"] = "0"
            out.append(entry)
        return out

    def _fw_fields(self, body: dict[str, Any]) -> dict[str, Any] | str:
        if not body.get("name"):
            return "Name is required."
        inbound = self._fw_rules(body.get("inbound_rules"), "sources")
        if isinstance(inbound, str):
            return inbound
        outbound = self._fw_rules(body.get("outbound_rules"), "destinations")
        if isinstance(outbound, str):
            return outbound
        return {"name": body["name"], "inbound_rules": inbound, "outbound_rules": outbound,
                "droplet_ids": list(body.get("droplet_ids") or []), "tags": list(body.get("tags") or [])}

    def _create_firewall(self, body: dict[str, Any]) -> Any:
        fields = self._fw_fields(body)
        if isinstance(fields, str):
            return _unprocessable(fields)
        fw_id = str(uuid.uuid4())
        fw = {"id": fw_id, "status": "succeeded", "created_at": self._stamp(), "pending_changes": [], **fields}
        self.firewalls[fw_id] = fw
        return fw

    def _fws(self, method: str, parts: list[str], params: dict[str, str], body: dict[str, Any],
             visible_from: float | None) -> httpx.Response:
        path = "/" + "/".join(parts)
        if len(parts) == 1 and method == "GET":
            items = [f for f in self.firewalls.values() if self._visible("firewall", f["id"])]
            return self._page(path, "firewalls", [json.loads(json.dumps(i)) for i in items], params)
        if len(parts) == 1 and method == "POST":
            result = self._create_firewall(body)
            if isinstance(result, httpx.Response):
                return result
            self._hide("firewall", result["id"], visible_from)
            return _ok({"firewall": json.loads(json.dumps(result))}, 202)
        fw = self.firewalls.get(parts[1]) if len(parts) == 2 else None
        if fw is None:
            return _not_found()
        if method == "GET":
            return _ok({"firewall": json.loads(json.dumps(fw))})
        if method == "PUT":
            fields = self._fw_fields(body)
            if isinstance(fields, str):
                return _unprocessable(fields)
            fw.update(fields)
            return _ok({"firewall": json.loads(json.dumps(fw))})
        if method == "DELETE":
            del self.firewalls[fw["id"]]
            return _empty()
        return _not_found()

    # httpx.MockTransport takes any callable; ``handle`` matches FakeCloudflare's name.
    handle = handler


def use_fake(monkeypatch: Any, fake: FakeDigitalOcean) -> FakeDigitalOcean:
    """Point the client at ``fake`` and its clock."""
    from slipway.services import digitalocean

    monkeypatch.setattr(digitalocean, "transport_factory", lambda: httpx.MockTransport(fake.handler))
    monkeypatch.setattr(digitalocean, "sleep", fake.sleep)
    monkeypatch.setattr(digitalocean, "monotonic", fake.monotonic)
    monkeypatch.setattr(digitalocean, "clock", fake.time)
    return fake
