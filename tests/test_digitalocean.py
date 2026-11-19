"""The DigitalOcean client (phase 4 §7) and its fake: tests 1-6."""

from __future__ import annotations

import datetime as dt
import json
from typing import Any

import httpx
import pytest

from slipway.services import digitalocean
from slipway.services.digitalocean import (
    DigitalOceanClient, DigitalOceanError, Forbidden, NotFound, Unauthorized, Unreachable, droplet_ips, poll,
)
from slipway.services.ssh import Redactor
from tests.fake_digitalocean import TEAM, TOKEN, FakeDigitalOcean, make_leaf, use_fake

SECRET_MESSAGE = "do-not-repeat-me-0xC0FFEE"  # put in DigitalOcean's ``message``; must never show up


@pytest.fixture
def fake(monkeypatch) -> FakeDigitalOcean:
    return use_fake(monkeypatch, FakeDigitalOcean())


@pytest.fixture
def waits(monkeypatch) -> list[float]:
    """The client's sleeps, recorded instead of waited."""
    seen: list[float] = []

    async def no_wait(seconds: float) -> None:
        seen.append(seconds)

    monkeypatch.setattr(digitalocean, "sleep", no_wait)
    return seen


class Recorder:
    """A transport that answers every request with ``answer`` (or the next of ``answers``) and records it."""

    SINGULAR = ("account", "vpc", "droplet", "action", "database", "key", "certificate", "load_balancer",
                "firewall", "ca")
    PLURAL = ("regions", "sizes", "vpcs", "members", "droplets", "databases", "keys", "certificates",
              "load_balancers", "firewalls", "rules")

    def __init__(self, answers: list[httpx.Response] | None = None) -> None:
        self.requests: list[httpx.Request] = []
        self.answers = list(answers or [])

    def default(self) -> httpx.Response:
        body: dict[str, Any] = {k: {"id": "x1", "certificate": "Q0E="} for k in self.SINGULAR}
        body.update({k: [] for k in self.PLURAL})
        body["links"] = {}
        return httpx.Response(200, json=body)

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.answers:
            return self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        return self.default()


def recorded(monkeypatch, answers: list[httpx.Response] | None = None) -> Recorder:
    rec = Recorder(answers)
    monkeypatch.setattr(digitalocean, "transport_factory", lambda: httpx.MockTransport(rec))
    return rec


def err(status: int, error_id: Any = "some_error", message: str = SECRET_MESSAGE,
        headers: dict[str, str] | None = None) -> httpx.Response:
    return httpx.Response(status, headers=headers, json={"id": error_id, "message": message})


def body_of(request: httpx.Request) -> Any:
    return json.loads(request.content) if request.content else None


# ---------------------------------------------------------------------- 1: every method's path and body


LB_BODY = {"name": "slipway-prod-lb", "region": "nyc3", "forwarding_rules": [], "droplet_ids": []}
FW_BODY = {"name": "slipway-prod-fw", "tags": ["slipway-env-1"], "inbound_rules": [], "outbound_rules": []}

CALLS: list[tuple[str, tuple, dict, str, str, dict[str, Any], Any]] = [
    # method name, args, kwargs, HTTP method, path, query, body
    ("account", (), {}, "GET", "/v2/account", {}, None),
    ("regions", (), {}, "GET", "/v2/regions", {"per_page": "200", "page": "1"}, None),
    ("sizes", (), {}, "GET", "/v2/sizes", {"per_page": "200", "page": "1"}, None),
    ("database_options", (), {}, "GET", "/v2/databases/options", {}, None),
    ("vpcs", (), {}, "GET", "/v2/vpcs", {"per_page": "200", "page": "1"}, None),
    ("vpc", ("v-1",), {}, "GET", "/v2/vpcs/v-1", {}, None),
    ("create_vpc", ({"name": "slipway-prod", "region": "nyc3", "description": "d"},), {}, "POST", "/v2/vpcs", {},
     {"name": "slipway-prod", "region": "nyc3", "description": "d"}),
    ("delete_vpc", ("v-1",), {}, "DELETE", "/v2/vpcs/v-1", {}, None),
    ("vpc_members", ("v-1",), {}, "GET", "/v2/vpcs/v-1/members", {"per_page": "200", "page": "1"}, None),
    ("droplet", (4001,), {}, "GET", "/v2/droplets/4001", {}, None),
    ("droplets_tagged", ("slipway-req:0123456789abcdef",), {}, "GET", "/v2/droplets",
     {"tag_name": "slipway-req:0123456789abcdef", "per_page": "200", "page": "1"}, None),
    ("create_droplet", ({"name": "slipway-prod-blue", "user_data": "#cloud-config\n"},), {}, "POST", "/v2/droplets",
     {}, {"name": "slipway-prod-blue", "user_data": "#cloud-config\n"}),
    ("delete_droplet", (4001,), {}, "DELETE", "/v2/droplets/4001", {}, None),
    ("droplet_action", (4001, "resize"), {"size": "s-2vcpu-4gb", "disk": True}, "POST", "/v2/droplets/4001/actions",
     {}, {"type": "resize", "size": "s-2vcpu-4gb", "disk": True}),
    ("get_action", (4001, 9001), {}, "GET", "/v2/droplets/4001/actions/9001", {}, None),
    ("database", ("db-1",), {}, "GET", "/v2/databases/db-1", {}, None),
    ("databases_tagged", ("slipway-env-1",), {}, "GET", "/v2/databases",
     {"tag_name": "slipway-env-1", "per_page": "200", "page": "1"}, None),
    ("create_database", ({"name": "slipway-prod-db", "rules": [{"type": "droplet", "value": "4001"}]},), {},
     "POST", "/v2/databases", {}, {"name": "slipway-prod-db", "rules": [{"type": "droplet", "value": "4001"}]}),
    ("database_firewall", ("db-1",), {}, "GET", "/v2/databases/db-1/firewall", {}, None),
    ("set_database_firewall", ("db-1", [{"type": "droplet", "value": "4001"}]), {}, "PUT",
     "/v2/databases/db-1/firewall", {}, {"rules": [{"type": "droplet", "value": "4001"}]}),
    ("database_ca", ("db-1",), {}, "GET", "/v2/databases/db-1/ca", {}, None),
    ("resize_database", ("db-1", "db-s-2vcpu-4gb", 2), {}, "PUT", "/v2/databases/db-1/resize", {},
     {"size": "db-s-2vcpu-4gb", "num_nodes": 2}),
    ("delete_database", ("db-1",), {}, "DELETE", "/v2/databases/db-1", {}, None),
    ("spaces_keys", (), {}, "GET", "/v2/spaces/keys", {"per_page": "200", "page": "1"}, None),
    ("create_spaces_key", ("slipway-prod-1a2b3c4d-0123456789abcdef", [{"bucket": "b", "permission": "readwrite"}]),
     {}, "POST", "/v2/spaces/keys", {},
     {"name": "slipway-prod-1a2b3c4d-0123456789abcdef", "grants": [{"bucket": "b", "permission": "readwrite"}]}),
    ("delete_spaces_key", ("DOABCDEF0123456789XY",), {}, "DELETE", "/v2/spaces/keys/DOABCDEF0123456789XY", {}, None),
    ("certificates", (), {}, "GET", "/v2/certificates", {"per_page": "200", "page": "1"}, None),
    ("certificate", ("c-1",), {}, "GET", "/v2/certificates/c-1", {}, None),
    ("create_certificate", ({"name": "slipway-prod-202611150000", "type": "custom"},), {}, "POST",
     "/v2/certificates", {}, {"name": "slipway-prod-202611150000", "type": "custom"}),
    ("delete_certificate", ("c-1",), {}, "DELETE", "/v2/certificates/c-1", {}, None),
    ("load_balancers", (), {}, "GET", "/v2/load_balancers", {"per_page": "200", "page": "1"}, None),
    ("load_balancer", ("lb-1",), {}, "GET", "/v2/load_balancers/lb-1", {}, None),
    ("create_load_balancer", (LB_BODY,), {}, "POST", "/v2/load_balancers", {}, LB_BODY),
    ("update_load_balancer", ("lb-1", LB_BODY), {}, "PUT", "/v2/load_balancers/lb-1", {}, LB_BODY),
    ("delete_load_balancer", ("lb-1",), {}, "DELETE", "/v2/load_balancers/lb-1", {}, None),
    ("firewalls", (), {}, "GET", "/v2/firewalls", {"per_page": "200", "page": "1"}, None),
    ("firewall", ("fw-1",), {}, "GET", "/v2/firewalls/fw-1", {}, None),
    ("create_firewall", (FW_BODY,), {}, "POST", "/v2/firewalls", {}, FW_BODY),
    ("update_firewall", ("fw-1", FW_BODY), {}, "PUT", "/v2/firewalls/fw-1", {}, FW_BODY),
    ("delete_firewall", ("fw-1",), {}, "DELETE", "/v2/firewalls/fw-1", {}, None),
]


@pytest.mark.parametrize(("name", "args", "kwargs", "method", "path", "query", "body"), CALLS,
                         ids=[c[0] for c in CALLS])
async def test_every_method_path_and_body(monkeypatch, name, args, kwargs, method, path, query, body):
    rec = recorded(monkeypatch)
    async with DigitalOceanClient(TOKEN) as do:
        await getattr(do, name)(*args, **kwargs)
    assert len(rec.requests) == 1
    req = rec.requests[0]
    assert (req.method, req.url.host, req.url.path) == (method, "api.digitalocean.com", path)
    assert dict(req.url.params) == query
    assert body_of(req) == body
    assert req.headers["Authorization"] == f"Bearer {TOKEN}"
    assert req.headers["User-Agent"] == "Slipway"


def test_every_listed_method_is_tested():
    names = {"account", "regions", "sizes", "database_options", "vpcs", "vpc", "create_vpc", "delete_vpc",
             "vpc_members", "droplet", "droplets_tagged", "create_droplet", "delete_droplet", "droplet_action",
             "get_action", "database", "databases_tagged", "create_database", "database_firewall",
             "set_database_firewall", "database_ca", "resize_database", "delete_database", "spaces_keys",
             "create_spaces_key", "delete_spaces_key", "certificates", "certificate", "create_certificate",
             "delete_certificate", "load_balancers", "load_balancer", "create_load_balancer",
             "update_load_balancer", "delete_load_balancer", "firewalls", "firewall", "create_firewall",
             "update_firewall", "delete_firewall"}
    assert {c[0] for c in CALLS} == names
    assert all(callable(getattr(DigitalOceanClient, n)) for n in names)


def test_timeout_and_base(monkeypatch):
    do = DigitalOceanClient(TOKEN)
    assert do._client.timeout.read == 30
    assert str(do._client.base_url) == "https://api.digitalocean.com/v2/"


GET_ONE = [("vpc", ("v-1",)), ("droplet", (4001,)), ("get_action", (4001, 9001)), ("database", ("db-1",)),
           ("database_firewall", ("db-1",)), ("database_ca", ("db-1",)), ("vpc_members", ("v-1",)),
           ("certificate", ("c-1",)), ("load_balancer", ("lb-1",)), ("firewall", ("fw-1",))]
DELETES = [("delete_vpc", ("v-1",)), ("delete_droplet", (4001,)), ("delete_database", ("db-1",)),
           ("delete_spaces_key", ("DOABC",)), ("delete_certificate", ("c-1",)),
           ("delete_load_balancer", ("lb-1",)), ("delete_firewall", ("fw-1",))]
LISTS = [("regions", ()), ("sizes", ()), ("vpcs", ()), ("droplets_tagged", ("slipway",)),
         ("databases_tagged", ("slipway",)), ("spaces_keys", ()), ("certificates", ()), ("load_balancers", ()),
         ("firewalls", ()), ("account", ()), ("database_options", ())]


@pytest.mark.parametrize(("name", "args"), GET_ONE, ids=[g[0] for g in GET_ONE])
async def test_404_on_a_get_is_none(monkeypatch, name, args):
    recorded(monkeypatch, [err(404, "not_found")])
    async with DigitalOceanClient(TOKEN) as do:
        assert await getattr(do, name)(*args) is None


@pytest.mark.parametrize(("name", "args"), DELETES, ids=[d[0] for d in DELETES])
async def test_delete_is_true_then_false_on_404(monkeypatch, name, args):
    recorded(monkeypatch, [httpx.Response(204)])
    async with DigitalOceanClient(TOKEN) as do:
        assert await getattr(do, name)(*args) is True
    recorded(monkeypatch, [err(404, "not_found")])
    async with DigitalOceanClient(TOKEN) as do:
        assert await getattr(do, name)(*args) is False


@pytest.mark.parametrize(("name", "args"), GET_ONE + LISTS, ids=[g[0] for g in GET_ONE + LISTS])
async def test_403_on_every_read_raises_forbidden(monkeypatch, name, args):
    """J13: a token that can't read a kind never makes it look gone or empty."""
    recorded(monkeypatch, [err(403, "forbidden")])
    async with DigitalOceanClient(TOKEN) as do:
        with pytest.raises(Forbidden) as info:
            await getattr(do, name)(*args)
    assert info.value.status == 403
    assert "(DigitalOcean answered 403)" in str(info.value)
    assert SECRET_MESSAGE not in str(info.value)


@pytest.mark.parametrize(("name", "args"), DELETES, ids=[d[0] for d in DELETES])
async def test_403_on_a_delete_raises_forbidden(monkeypatch, name, args):
    recorded(monkeypatch, [err(403, "forbidden")])
    async with DigitalOceanClient(TOKEN) as do:
        with pytest.raises(Forbidden):
            await getattr(do, name)(*args)


async def test_forbidden_names_the_kind(monkeypatch):
    recorded(monkeypatch, [err(403, "forbidden")])
    async with DigitalOceanClient(TOKEN) as do:
        with pytest.raises(Forbidden, match=r"^The token can't read load balancers \(DigitalOcean answered 403\)$"):
            await do.load_balancer("lb-1")
        with pytest.raises(Forbidden, match=r"^The token can't read Spaces keys"):
            await do.spaces_keys()
        with pytest.raises(Forbidden, match=r"^The token can't create droplets"):
            await do.create_droplet({"name": "x"})
        with pytest.raises(Forbidden, match=r"^The token can't change firewalls"):
            await do.update_firewall("fw-1", FW_BODY)
        with pytest.raises(Forbidden, match=r"^The token can't delete certificates"):
            await do.delete_certificate("c-1")
        with pytest.raises(Forbidden, match=r"^The token can't change droplets"):
            await do.droplet_action(1, "power_off")


async def test_forbidden_in_use_is_flagged_without_the_message(monkeypatch):
    recorded(monkeypatch, [err(403, "forbidden", "Certificate is in use by load balancer 1234 " + SECRET_MESSAGE)])
    async with DigitalOceanClient(TOKEN) as do:
        with pytest.raises(Forbidden) as info:
            await do.delete_certificate("c-1")
    assert info.value.in_use is True
    assert SECRET_MESSAGE not in str(info.value) and "1234" not in str(info.value)
    recorded(monkeypatch, [err(403, "forbidden", "You are not authorized")])
    async with DigitalOceanClient(TOKEN) as do:
        with pytest.raises(Forbidden) as info:
            await do.delete_certificate("c-1")
    assert info.value.in_use is False


async def test_401_text(monkeypatch):
    recorded(monkeypatch, [err(401, "Unauthorized", "Unable to authenticate you " + SECRET_MESSAGE)])
    async with DigitalOceanClient(TOKEN) as do:
        for call in (do.account(), do.droplet(1), do.droplets_tagged("slipway"), do.delete_vpc("v-1")):
            with pytest.raises(Unauthorized) as info:
                await call
            assert str(info.value) == "DigitalOcean rejected the API token"
            assert info.value.status == 401


@pytest.mark.parametrize(("status", "start"), [
    (400, "DigitalOcean refused the request"), (409, "DigitalOcean refused the request"),
    (422, "DigitalOcean refused the request"), (500, "DigitalOcean had a problem"),
])
async def test_other_errors_text(monkeypatch, status, start):
    recorded(monkeypatch, [err(status, "unprocessable_entity")])
    async with DigitalOceanClient(TOKEN) as do:
        with pytest.raises(DigitalOceanError) as info:
            await do.create_vpc({"name": "x"})
    text = str(info.value)
    assert text == f"{start} (POST /vpcs, HTTP {status}, unprocessable_entity)"
    assert not isinstance(info.value, (NotFound, Forbidden, Unauthorized))
    assert info.value.status == status and info.value.error_id == "unprocessable_entity"
    assert SECRET_MESSAGE not in text


async def test_404_on_a_write_is_not_found(monkeypatch):
    recorded(monkeypatch, [err(404, "not_found")])
    async with DigitalOceanClient(TOKEN) as do:
        with pytest.raises(NotFound, match=r"PUT /load_balancers/lb-1, HTTP 404"):
            await do.update_load_balancer("lb-1", LB_BODY)
        with pytest.raises(NotFound):
            await do.droplets_tagged("slipway")  # a list never answers [] for a 404


@pytest.mark.parametrize("bad_id", ["Not_Found", "has space", "x" * 41, "<script>", 42, None, "a-b"])
async def test_error_id_named_only_when_it_looks_like_one(monkeypatch, bad_id):
    recorded(monkeypatch, [err(422, bad_id)])
    async with DigitalOceanClient(TOKEN) as do:
        with pytest.raises(DigitalOceanError) as info:
            await do.create_vpc({"name": "x"})
    assert info.value.error_id is None
    assert str(info.value) == "DigitalOcean refused the request (POST /vpcs, HTTP 422)"


async def test_error_without_a_json_body(monkeypatch):
    recorded(monkeypatch, [httpx.Response(418, text="<html>" + SECRET_MESSAGE + "</html>")])
    async with DigitalOceanClient(TOKEN) as do:
        with pytest.raises(DigitalOceanError) as info:
            await do.vpcs()
    assert str(info.value) == "DigitalOcean refused the request (GET /vpcs, HTTP 418)"


async def test_empty_answers_and_nonsense(monkeypatch):
    recorded(monkeypatch, [httpx.Response(202)])
    async with DigitalOceanClient(TOKEN) as do:
        assert await do.resize_database("db-1", "db-s-1vcpu-1gb", 1) is None
        assert await do.database_options() == {}
    for answer in (httpx.Response(200, json=[1, 2]), httpx.Response(200, text="not json"),
                   httpx.Response(200, json={"droplet": "nope"}), httpx.Response(200, json={"droplets": {"a": 1}})):
        recorded(monkeypatch, [answer])
        async with DigitalOceanClient(TOKEN) as do:
            with pytest.raises(DigitalOceanError, match="^DigitalOcean sent a response Slipway didn't understand"):
                await do.droplet(1)
            with pytest.raises(DigitalOceanError, match="^DigitalOcean sent a response Slipway didn't understand"):
                await do.droplets_tagged("slipway")


async def test_network_error(monkeypatch, fake):
    fake.down = True
    async with DigitalOceanClient(TOKEN) as do:
        with pytest.raises(Unreachable) as info:
            await do.account()
    assert str(info.value).startswith("Couldn't reach the DigitalOcean API")
    assert info.value.status is None
    assert TOKEN not in str(info.value)


# ---------------------------------------------------------------------- 2: 429 and retries


async def test_429_waits_retry_after(monkeypatch, waits):
    rec = recorded(monkeypatch, [err(429, headers={"Retry-After": "7"}), Recorder().default()])
    async with DigitalOceanClient(TOKEN) as do:
        await do.account()
    assert waits == [7.0] and len(rec.requests) == 2


async def test_429_waits_ratelimit_reset(monkeypatch, waits):
    monkeypatch.setattr(digitalocean, "clock", lambda: 1_000_000.0)
    recorded(monkeypatch, [err(429, headers={"RateLimit-Reset": "1000012"}), Recorder().default()])
    async with DigitalOceanClient(TOKEN) as do:
        await do.account()
    assert waits == [12.0]


async def test_429_waits_5s_by_default_and_never_more_than_30(monkeypatch, waits):
    recorded(monkeypatch, [err(429), Recorder().default()])
    async with DigitalOceanClient(TOKEN) as do:
        await do.account()
    recorded(monkeypatch, [err(429, headers={"Retry-After": "600"}), Recorder().default()])
    async with DigitalOceanClient(TOKEN) as do:
        await do.account()
    monkeypatch.setattr(digitalocean, "clock", lambda: 1_000_000.0)
    recorded(monkeypatch, [err(429, headers={"RateLimit-Reset": "1009999"}), Recorder().default()])
    async with DigitalOceanClient(TOKEN) as do:
        await do.account()
    recorded(monkeypatch, [err(429, headers={"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}), Recorder().default()])
    async with DigitalOceanClient(TOKEN) as do:
        await do.account()
    assert waits == [5.0, 30.0, 30.0, 5.0]


async def test_a_second_429_fails(monkeypatch, waits):
    rec = recorded(monkeypatch, [err(429, headers={"Retry-After": "1"}), err(429, headers={"Retry-After": "1"}),
                                 Recorder().default()])
    async with DigitalOceanClient(TOKEN) as do:
        with pytest.raises(DigitalOceanError, match="^DigitalOcean is limiting requests") as info:
            await do.account()
    assert info.value.status == 429 and len(rec.requests) == 2 and waits == [1.0]


async def test_429_on_a_write_is_retried_once(monkeypatch, waits):
    """A 429 means DigitalOcean did nothing, so even a create is sent again (once)."""
    rec = recorded(monkeypatch, [err(429, headers={"Retry-After": "2"}), Recorder().default()])
    async with DigitalOceanClient(TOKEN) as do:
        await do.create_droplet({"name": "x"})
    assert [r.method for r in rec.requests] == ["POST", "POST"] and waits == [2.0]


@pytest.mark.parametrize("status", [502, 503, 504])
async def test_a_get_is_retried_once_on_502_to_504(monkeypatch, waits, status):
    rec = recorded(monkeypatch, [err(status), Recorder().default()])
    async with DigitalOceanClient(TOKEN) as do:
        assert await do.droplet(1) == {"id": "x1", "certificate": "Q0E="}
    assert len(rec.requests) == 2 and waits == [2.0]


async def test_a_get_failing_twice_fails(monkeypatch, waits):
    rec = recorded(monkeypatch, [err(503), err(503), Recorder().default()])
    async with DigitalOceanClient(TOKEN) as do:
        with pytest.raises(DigitalOceanError, match=r"^DigitalOcean had a problem \(GET /droplets/1, HTTP 503"):
            await do.droplet(1)
    assert len(rec.requests) == 2


@pytest.mark.parametrize("call", ["create_droplet", "update_load_balancer", "delete_vpc", "droplet_action"])
async def test_a_write_is_never_retried_on_503(monkeypatch, waits, call):
    rec = recorded(monkeypatch, [err(503), Recorder().default()])
    args = {"create_droplet": ({"name": "x"},), "update_load_balancer": ("lb-1", LB_BODY),
            "delete_vpc": ("v-1",), "droplet_action": (1, "power_on")}[call]
    async with DigitalOceanClient(TOKEN) as do:
        with pytest.raises(DigitalOceanError) as info:
            await getattr(do, call)(*args)
    assert info.value.status == 503 and len(rec.requests) == 1 and waits == []


async def test_a_lost_answer_on_a_write_is_not_retried(fake):
    fake.lose_answer[("POST", "/vpcs")] = True
    async with DigitalOceanClient(TOKEN) as do:
        with pytest.raises(Unreachable):
            await do.create_vpc({"name": "slipway-prod", "region": "nyc3"})
    assert len(fake.writes()) == 1
    assert [v["name"] for v in fake.vpcs.values()] == ["slipway-prod"]  # it landed all the same


# ---------------------------------------------------------------------- 3: paging


async def test_paging_follows_next(fake):
    fake.max_per_page = 2
    for i in range(5):
        fake.add_droplet(name=f"d{i}", tags=["slipway"])
    fake.add_droplet(name="other", tags=["someone-else"])
    async with DigitalOceanClient(TOKEN) as do:
        droplets = await do.droplets_tagged("slipway")
    assert [d["name"] for d in droplets] == ["d0", "d1", "d2", "d3", "d4"]
    pages = [r["params"]["page"] for r in fake.requests]
    assert pages == ["1", "2", "3"]
    assert all(r["params"]["tag_name"] == "slipway" and r["params"]["per_page"] == "200" for r in fake.requests)


async def test_an_eleventh_page_fails(fake):
    fake.max_per_page = 1
    for i in range(11):
        fake.add_droplet(name=f"d{i}", tags=["slipway"])
    async with DigitalOceanClient(TOKEN) as do:
        with pytest.raises(DigitalOceanError) as info:
            await do.droplets_tagged("slipway")
    assert str(info.value) == "DigitalOcean listed more than Slipway reads"
    assert len(fake.requests) == 10
    fake.droplets.pop(max(fake.droplets))  # ten droplets: ten pages is fine
    async with DigitalOceanClient(TOKEN) as do:
        assert len(await do.droplets_tagged("slipway")) == 10


async def test_next_link_elsewhere_only_gives_the_page(monkeypatch):
    first = httpx.Response(200, json={"regions": [{"slug": "nyc3"}],
                                      "links": {"pages": {"next": "https://evil.example/v2/regions?page=2"}}})
    second = httpx.Response(200, json={"regions": [{"slug": "ams3"}], "links": {"pages": {}}})
    rec = recorded(monkeypatch, [first, second])
    async with DigitalOceanClient(TOKEN) as do:
        assert [r["slug"] for r in await do.regions()] == ["nyc3", "ams3"]
    assert [r.url.host for r in rec.requests] == ["api.digitalocean.com"] * 2
    assert rec.requests[1].url.params["page"] == "2"


@pytest.mark.parametrize("nxt", ["https://api.digitalocean.com/v2/regions",
                                 "https://api.digitalocean.com/v2/regions?page=1",
                                 "https://api.digitalocean.com/v2/regions?page=x"])
async def test_a_next_link_that_makes_no_sense(monkeypatch, nxt):
    recorded(monkeypatch, [httpx.Response(200, json={"regions": [], "links": {"pages": {"next": nxt}}})])
    async with DigitalOceanClient(TOKEN) as do:
        with pytest.raises(DigitalOceanError, match="didn't understand"):
            await do.regions()


async def test_databases_null_is_an_empty_list(fake):
    async with DigitalOceanClient(TOKEN) as do:
        assert await do.databases_tagged("slipway-env-1") == []
    assert json.loads(json.dumps(fake.requests[-1]["params"]))["tag_name"] == "slipway-env-1"


# ---------------------------------------------------------------------- 4: ids and the token


@pytest.mark.parametrize("bad", ["../account", "1/actions", "a b", "", "x" * 129, "abc?x=1", "abc#", "é", None,
                                 True, 1.5, "a%2Fb", "a.b", "abc\n"])
async def test_a_malformed_id_never_reaches_the_url(monkeypatch, bad):
    rec = recorded(monkeypatch)
    async with DigitalOceanClient(TOKEN) as do:
        for call in (do.droplet(bad), do.delete_vpc(bad), do.get_action(1, bad), do.update_firewall(bad, FW_BODY),
                     do.database_ca(bad), do.delete_spaces_key(bad), do.vpc_members(bad)):
            with pytest.raises(DigitalOceanError, match="^That isn't a DigitalOcean id Slipway can use"):
                await call
    assert rec.requests == []


@pytest.mark.parametrize("bad", ["a b", "x&tag_name=y", "", "t" * 256, "a/b", "slipway\n"])
async def test_a_malformed_tag_is_refused(monkeypatch, bad):
    rec = recorded(monkeypatch)
    async with DigitalOceanClient(TOKEN) as do:
        with pytest.raises(DigitalOceanError, match="tag name"):
            await do.droplets_tagged(bad)
    assert rec.requests == []


async def test_ids_that_fit(monkeypatch):
    rec = recorded(monkeypatch)
    async with DigitalOceanClient(TOKEN) as do:
        await do.droplet(4001)
        await do.vpc("5a4981aa-9653-4bd1-bef5-d6bff52042e4")
        await do.delete_spaces_key("DOABCDEF0123456789XY")
        await do.firewall("x" * 128)
    assert len(rec.requests) == 4


async def test_the_token_is_only_in_the_authorization_header(fake):
    redactor = Redactor()
    async with DigitalOceanClient(TOKEN, redactor=redactor) as do:
        await do.account()
        await do.create_vpc({"name": "slipway-prod", "region": "nyc3", "description": "x"})
        await do.droplets_tagged("slipway")
        with pytest.raises(NotFound):
            await do.update_firewall("nope", FW_BODY)
        assert TOKEN not in repr(do)
    assert redactor.scrub(f"x {TOKEN} y") == "x [hidden] y"
    for req in fake.requests:
        assert TOKEN not in req["url"]
        assert TOKEN not in json.dumps(req["body"])
        holders = [k for k, v in req["headers"].items() if TOKEN in v]
        assert holders == ["authorization"]


async def test_a_wrong_token(fake):
    async with DigitalOceanClient("dop_v1_wrong") as do:
        with pytest.raises(Unauthorized, match="^DigitalOcean rejected the API token$"):
            await do.account()


async def test_no_redirects_are_followed(monkeypatch):
    rec = recorded(monkeypatch, [httpx.Response(302, headers={"Location": "https://evil.example/steal"})])
    async with DigitalOceanClient(TOKEN) as do:
        with pytest.raises(DigitalOceanError, match="didn't understand"):
            await do.account()
    assert [r.url.host for r in rec.requests] == ["api.digitalocean.com"]


# ---------------------------------------------------------------------- 5: droplet_ips


def test_droplet_ips():
    assert droplet_ips(None) == (None, None)
    assert droplet_ips({"networks": {"v4": []}}) == (None, None)
    assert droplet_ips({"networks": {"v4": [{"type": "public", "ip_address": "203.0.113.4"}]}}) == ("203.0.113.4", None)
    assert droplet_ips({"networks": {"v4": [{"type": "private", "ip_address": "10.110.0.3"}]}}) == (None, "10.110.0.3")
    both = {"networks": {"v4": [{"type": "private", "ip_address": "10.110.0.3"},
                                {"type": "public", "ip_address": "203.0.113.4"}],
                         "v6": [{"type": "public", "ip_address": "2001:db8::1"}]}}
    assert droplet_ips(both) == ("203.0.113.4", "10.110.0.3")


# ---------------------------------------------------------------------- 6: the fake


async def test_fake_account_and_team(fake):
    fake.add_token("dop_v1_other", "Another Team")
    async with DigitalOceanClient(TOKEN) as do:
        assert (await do.account())["team"] == TEAM
    async with DigitalOceanClient("dop_v1_other") as do:
        assert (await do.account())["team"]["name"] == "Another Team"
    async with DigitalOceanClient(TOKEN) as do:
        sizes = await do.sizes()
        assert all("price_monthly" in s for s in sizes)
        options = await do.database_options()
        assert options["options"]["pg"]["layouts"][0]["num_nodes"] == 1
        assert any(r["slug"] == "nyc3" for r in await do.regions())


async def test_fake_droplet_boots_after_boot_polls_and_keeps_the_host_key(fake):
    fake.boot_polls = 2
    user_data = ("#cloud-config\nhostname: slipway-prod-blue\n"
                 "ssh_keys: {ed25519_private: \"PRIVATE\", ed25519_public: \"ssh-ed25519 AAAAhost\"}\n")
    async with DigitalOceanClient(TOKEN) as do:
        vpc = await do.create_vpc({"name": "slipway-prod", "region": "nyc3", "description": "slipway:1"})
        made = await do.create_droplet({"name": "slipway-prod-blue", "region": "nyc3", "size": "s-1vcpu-1gb",
                                        "image": "ubuntu-24-04-x64", "vpc_uuid": vpc["id"],
                                        "tags": ["slipway", "slipway-req:0123456789abcdef"],
                                        "monitoring": False, "user_data": user_data})
        assert made["status"] == "new" and "user_data" not in made
        seen = [(await do.droplet(made["id"]))["status"] for _ in range(3)]
        assert seen == ["new", "new", "active"]
        public, private = droplet_ips(await do.droplet(made["id"]))
        other = await do.create_droplet({"name": "slipway-prod-green", "region": "nyc3", "size": "s-1vcpu-1gb",
                                         "image": "ubuntu-24-04-x64", "vpc_uuid": vpc["id"]})
        for _ in range(3):
            other = await do.droplet(other["id"])
        assert public.startswith("203.0.113.") and droplet_ips(other)[0] != public
        assert private.startswith("10.") and droplet_ips(other)[1] != private
        members = await do.vpc_members(vpc["id"])
        assert {m["urn"] for m in members} == {f"do:droplet:{made['id']}", f"do:droplet:{other['id']}"}
    assert fake.host_keys[made["id"]] == "ssh-ed25519 AAAAhost"


async def test_fake_refuses_big_user_data(fake):
    async with DigitalOceanClient(TOKEN) as do:
        with pytest.raises(DigitalOceanError) as info:
            await do.create_droplet({"name": "x", "region": "nyc3", "size": "s-1vcpu-1gb", "image": "u",
                                     "user_data": "#" * (64 * 1024 + 1)})
    assert info.value.status == 422


async def test_fake_lose_answer_lands_the_object(fake):
    fake.lose_answer[("POST", "/droplets")] = True
    tag = "slipway-req:00000000000000aa"
    async with DigitalOceanClient(TOKEN) as do:
        with pytest.raises(Unreachable):
            await do.create_droplet({"name": "slipway-prod-blue", "region": "nyc3", "size": "s-1vcpu-1gb",
                                     "image": "ubuntu-24-04-x64", "tags": ["slipway", tag]})
        found = await do.droplets_tagged(tag)
    assert [d["name"] for d in found] == ["slipway-prod-blue"]
    assert len(fake.droplets) == 1


async def test_fake_lost_object_shows_after_lost_visible_after(fake):
    fake.lose_answer[("POST", "/droplets")] = 1  # once
    fake.lost_visible_after = 90
    tag = "slipway-req:00000000000000bb"
    body = {"name": "slipway-prod-blue", "region": "nyc3", "size": "s-1vcpu-1gb", "image": "u", "tags": [tag]}
    async with DigitalOceanClient(TOKEN) as do:
        with pytest.raises(Unreachable):
            await do.create_droplet(body)
        assert await do.droplets_tagged(tag) == []
        fake.advance(60)
        assert await do.droplets_tagged(tag) == []
        fake.advance(30)
        assert len(await do.droplets_tagged(tag)) == 1
        made = await do.create_droplet({**body, "tags": ["slipway-req:00000000000000cc"]})  # the answer comes back now
        assert made["id"] in fake.droplets


async def test_fake_lost_answers_for_every_create(fake):
    fake.lost_visible_after = 30
    async with DigitalOceanClient(TOKEN) as do:
        vpc = await do.create_vpc({"name": "slipway-prod", "region": "nyc3"})
        fake.lose_answer.update({(m, p): True for m, p in [("POST", "/vpcs"), ("POST", "/databases"),
                                                            ("POST", "/firewalls"), ("POST", "/load_balancers"),
                                                            ("POST", "/spaces/keys"), ("POST", "/certificates")]})
        leaf, key = make_leaf(["app.example.com"])
        creates = [do.create_vpc({"name": "slipway-dev", "region": "nyc3"}),
                   do.create_database({"name": "slipway-prod-db", "engine": "pg", "version": "16", "region": "nyc3",
                                       "size": "db-s-1vcpu-1gb", "num_nodes": 1, "tags": ["slipway-env-1"]}),
                   do.create_firewall({"name": "slipway-prod-fw", "tags": ["slipway-env-1"]}),
                   do.create_load_balancer({"name": "slipway-prod-lb", "region": "nyc3", "vpc_uuid": vpc["id"],
                                            "forwarding_rules": [{"entry_protocol": "http", "entry_port": 80,
                                                                  "target_protocol": "http", "target_port": 80}]}),
                   do.create_spaces_key("slipway-prod-1a2b3c4d-0123456789abcdef",
                                        [{"bucket": "b", "permission": "readwrite"}]),
                   do.create_certificate({"name": "slipway-prod-202611150000", "type": "custom",
                                          "private_key": key, "leaf_certificate": leaf})]
        for create in creates:
            with pytest.raises(Unreachable):
                await create
        lists = (do.vpcs(), do.databases_tagged("slipway-env-1"), do.firewalls(), do.load_balancers(),
                 do.spaces_keys(), do.certificates())
        assert [len(await call) for call in lists] == [1, 0, 0, 0, 0, 0]
        fake.advance(30)
        lists = (do.vpcs(), do.databases_tagged("slipway-env-1"), do.firewalls(), do.load_balancers(),
                 do.spaces_keys(), do.certificates())
        assert [len(await call) for call in lists] == [2, 1, 1, 1, 1, 1]


async def test_fake_forbid_a_kind(fake):
    fake.forbid.add("load_balancers")
    fake.forbid.add("spaces_keys")
    async with DigitalOceanClient(TOKEN) as do:
        with pytest.raises(Forbidden, match="load balancers"):
            await do.load_balancers()
        with pytest.raises(Forbidden):
            await do.load_balancer("lb-1")
        with pytest.raises(Forbidden, match="Spaces keys"):
            await do.spaces_keys()
        assert await do.firewalls() == []


async def test_fake_fail_and_rate_limit(fake, waits):
    fake.fail[("GET", "/droplets/1")] = [503]
    fake.add_droplet(name="x")  # id 3001
    fake.fail[("GET", "/droplets/3001")] = [503]
    async with DigitalOceanClient(TOKEN) as do:
        assert (await do.droplet(3001))["name"] == "x"  # one 503, retried
        fake.rate_limit_once = {"Retry-After": "3"}
        assert (await do.droplet(3001))["name"] == "x"
        fake.fail[("DELETE", "/droplets/3001")] = {"status": 500}
        with pytest.raises(DigitalOceanError):
            await do.delete_droplet(3001)
    assert waits == [2.0, 3.0]
    assert [r["method"] for r in fake.writes()] == ["DELETE"]


async def test_fake_actions_and_resize(fake):
    droplet = fake.add_droplet(name="slipway-prod-blue")
    async with DigitalOceanClient(TOKEN) as do:
        with pytest.raises(DigitalOceanError) as info:
            await do.droplet_action(droplet["id"], "resize", size="s-2vcpu-4gb", disk=True)
        assert info.value.status == 422  # resize only when off
        action = await do.droplet_action(droplet["id"], "power_off")
        assert action["status"] == "in-progress"
        assert (await do.get_action(droplet["id"], action["id"]))["status"] == "in-progress"
        assert (await do.get_action(droplet["id"], action["id"]))["status"] == "completed"
        assert (await do.droplet(droplet["id"]))["status"] == "off"
        action = await do.droplet_action(droplet["id"], "resize", size="s-2vcpu-4gb", disk=True)
        await do.get_action(droplet["id"], action["id"])
        await do.get_action(droplet["id"], action["id"])
        grown = await do.droplet(droplet["id"])
        assert (grown["size_slug"], grown["disk"]) == ("s-2vcpu-4gb", 80)
        fake.action_errors.add("power_on")
        action = await do.droplet_action(droplet["id"], "power_on")
        await do.get_action(droplet["id"], action["id"])
        assert (await do.get_action(droplet["id"], action["id"]))["status"] == "errored"
        fake.action_errors.clear()
        fake.action_stall.add("power_on")
        action = await do.droplet_action(droplet["id"], "power_on")
        for _ in range(5):
            assert (await do.get_action(droplet["id"], action["id"]))["status"] == "in-progress"
        assert await do.get_action(droplet["id"], 1) is None


async def test_fake_database(fake):
    fake.db_polls = 1
    vpc = fake.add_vpc(name="slipway-prod")
    droplet = fake.add_droplet(name="slipway-prod-blue", vpc_uuid=vpc["id"])
    body = {"name": "slipway-prod-db", "engine": "pg", "version": "16", "region": "nyc3", "size": "db-s-1vcpu-1gb",
            "num_nodes": 1, "private_network_uuid": vpc["id"], "tags": ["slipway", "slipway-env-1"],
            "rules": [{"type": "droplet", "value": "999999"}]}
    async with DigitalOceanClient(TOKEN) as do:
        with pytest.raises(DigitalOceanError) as info:
            await do.create_database(body)  # an unknown droplet in the trusted sources
        assert info.value.status == 422
        db = await do.create_database({**body, "rules": [{"type": "droplet", "value": str(droplet["id"])}]})
        assert db["connection"]["password"]
        assert (await do.database(db["id"]))["status"] == "creating"
        assert (await do.database(db["id"]))["status"] == "online"
        rules = await do.database_firewall(db["id"])
        assert [(r["type"], r["value"]) for r in rules] == [("droplet", str(droplet["id"]))]
        fake.firewall_wait = 1
        with pytest.raises(DigitalOceanError) as info:
            await do.set_database_firewall(db["id"], [])
        assert info.value.status == 409
        await do.set_database_firewall(db["id"], [])
        assert await do.database_firewall(db["id"]) == []
        assert (await do.database_ca(db["id"])).startswith("LS0t")  # base64 of "-----BEGIN"
        await do.resize_database(db["id"], "db-s-1vcpu-2gb", 2)
        assert (await do.database(db["id"]))["status"] == "resizing"
        resized = await do.database(db["id"])
        assert (resized["status"], resized["size"], resized["num_nodes"]) == ("online", "db-s-1vcpu-2gb", 2)
        assert [d["id"] for d in await do.databases_tagged("slipway-env-1")] == [db["id"]]
        assert await do.databases_tagged("slipway-env-2") == []
        fake.db_hide_password = True
        assert "password" not in (await do.database(db["id"]))["connection"]
        assert await do.delete_database(db["id"]) is True
        assert await do.database(db["id"]) is None


async def test_fake_spaces_keys(fake):
    async with DigitalOceanClient(TOKEN) as do:
        key = await do.create_spaces_key("slipway-prod-1a2b3c4d-setup-0123456789abcdef",
                                         [{"bucket": "", "permission": "fullaccess"}])
        assert key["secret_key"] and key["access_key"].startswith("DO")
        listed = await do.spaces_keys()
        assert [k["name"] for k in listed] == [key["name"]] and "secret_key" not in listed[0]
        assert listed[0]["grants"] == [{"bucket": "", "permission": "fullaccess"}]
        assert await do.delete_spaces_key(key["access_key"]) is True
        assert await do.delete_spaces_key(key["access_key"]) is False


async def test_fake_certificates_and_load_balancers(fake):
    fake.lb_apply_polls = 1
    vpc = fake.add_vpc(name="slipway-prod")
    droplet = fake.add_droplet(name="slipway-prod-blue", vpc_uuid=vpc["id"])
    later = dt.datetime(2027, 3, 1, tzinfo=dt.UTC)
    leaf, key = make_leaf(["app.example.com", "learn.example.com"], later)
    rules = lambda cert_id: [  # noqa: E731
        {"entry_protocol": "https", "entry_port": 443, "target_protocol": "http", "target_port": 80,
         "certificate_id": cert_id, "tls_passthrough": False},
        {"entry_protocol": "http", "entry_port": 80, "target_protocol": "http", "target_port": 80}]
    async with DigitalOceanClient(TOKEN) as do:
        cert = await do.create_certificate({"name": "slipway-prod-202611150000", "type": "custom", "private_key": key,
                                            "leaf_certificate": leaf, "certificate_chain": leaf})
        assert cert["dns_names"] == ["app.example.com", "learn.example.com"]
        assert cert["not_after"] == "2027-03-01T00:00:00Z"
        body = {"name": "slipway-prod-lb", "region": "nyc3", "size_unit": 1, "vpc_uuid": vpc["id"],
                "forwarding_rules": rules("nope"), "droplet_ids": []}
        with pytest.raises(DigitalOceanError):
            await do.create_load_balancer(body)  # an unknown certificate
        with pytest.raises(DigitalOceanError):
            await do.create_load_balancer({**body, "forwarding_rules": rules(cert["id"]), "tag": "slipway",
                                           "droplet_ids": [droplet["id"]]})  # tag with droplet ids
        lb = await do.create_load_balancer({**body, "forwarding_rules": rules(cert["id"])})
        assert lb["status"] == "new" and lb["droplet_ids"] == []
        with pytest.raises(DigitalOceanError) as info:
            await do.update_load_balancer(lb["id"], {**body, "forwarding_rules": rules(cert["id"])})
        assert info.value.status == 422  # mid-change
        assert (await do.load_balancer(lb["id"]))["status"] == "new"
        live = await do.load_balancer(lb["id"])
        assert live["status"] == "active" and live["ip"].startswith("192.0.2.") and "size" in live
        put = {**body, "forwarding_rules": rules(cert["id"]), "droplet_ids": [droplet["id"]]}
        updated = await do.update_load_balancer(lb["id"], put)
        assert updated["droplet_ids"] == [droplet["id"]]
        with pytest.raises(Forbidden) as info:
            await do.delete_certificate(cert["id"])
        assert info.value.in_use
        assert [c["id"] for c in await do.certificates()] == [cert["id"]]
        assert await do.delete_droplet(droplet["id"]) is True
        assert (await do.load_balancer(lb["id"]))["droplet_ids"] == []  # DigitalOcean drops a deleted droplet
        assert await do.delete_load_balancer(lb["id"]) is True
        assert await do.delete_certificate(cert["id"]) is True
        assert await do.certificate(cert["id"]) is None


async def test_fake_cert_in_use_polls(fake):
    fake.cert_in_use_polls = 2
    cert = fake.add_certificate("slipway-prod-202611150000", ["app.example.com"])
    async with DigitalOceanClient(TOKEN) as do:
        for _ in range(2):
            with pytest.raises(Forbidden):
                await do.delete_certificate(cert["id"])
        assert await do.delete_certificate(cert["id"]) is True


async def test_fake_firewalls(fake):
    lb = fake.add_load_balancer(name="slipway-prod-lb")
    body = {"name": "slipway-prod-fw", "tags": ["slipway-env-1"], "droplet_ids": [],
            "inbound_rules": [{"protocol": "tcp", "ports": "22", "sources": {"addresses": ["198.51.100.7/32"]}}],
            "outbound_rules": [{"protocol": "tcp", "ports": "all",
                                "destinations": {"addresses": ["0.0.0.0/0", "::/0"]}},
                               {"protocol": "icmp", "destinations": {"addresses": ["0.0.0.0/0", "::/0"]}}]}
    async with DigitalOceanClient(TOKEN) as do:
        fw = await do.create_firewall(body)
        assert fw["outbound_rules"][0]["ports"] == "0"  # DigitalOcean answers "0" for all
        full = {**body, "inbound_rules": body["inbound_rules"] + [
            {"protocol": "tcp", "ports": "80", "sources": {"load_balancer_uids": [lb["id"]]}}]}
        updated = await do.update_firewall(fw["id"], full)
        assert len(updated["inbound_rules"]) == 2
        updated = await do.update_firewall(fw["id"], {"name": "slipway-prod-fw"})  # the whole body: rules gone
        assert updated["inbound_rules"] == [] and updated["tags"] == []
        assert [f["name"] for f in await do.firewalls()] == ["slipway-prod-fw"]
        assert await do.delete_firewall(fw["id"]) is True
        assert await do.firewall(fw["id"]) is None


async def test_fake_vpc_delete_waits_for_members(fake):
    fake.member_linger = 30
    vpc = fake.add_vpc(name="slipway-prod")
    droplet = fake.add_droplet(name="slipway-prod-blue", vpc_uuid=vpc["id"])
    async with DigitalOceanClient(TOKEN) as do:
        with pytest.raises(DigitalOceanError):
            await do.create_vpc({"name": "SLIPWAY-prod", "region": "nyc3"})  # names are unique
        with pytest.raises(Forbidden) as info:
            await do.delete_vpc(vpc["id"])
        assert info.value.in_use
        await do.delete_droplet(droplet["id"])
        assert len(await do.vpc_members(vpc["id"])) == 1  # it lingers
        with pytest.raises(Forbidden):
            await do.delete_vpc(vpc["id"])
        fake.advance(31)
        assert await do.vpc_members(vpc["id"]) == []
        assert await do.delete_vpc(vpc["id"]) is True
        assert await do.vpc(vpc["id"]) is None
        assert await do.vpc_members(vpc["id"]) is None


# ---------------------------------------------------------------------- waits


async def test_poll_returns_when_ready(fake):
    fake.boot_polls = 3
    droplet = fake.add_droplet(name="x", status="new")
    async with DigitalOceanClient(TOKEN) as do:
        start = fake.now
        ready = await poll(lambda: do.droplet(droplet["id"]), lambda d: d["status"] == "active", 600, "Droplet x")
    assert ready["status"] == "active" and fake.now - start == 30


async def test_poll_times_out(fake):
    fake.boot_polls = 1000
    droplet = fake.add_droplet(name="x", status="new")
    async with DigitalOceanClient(TOKEN) as do:
        with pytest.raises(DigitalOceanError, match="^Droplet x wasn't ready after 10 minutes$"):
            await poll(lambda: do.droplet(droplet["id"]), lambda d: d["status"] == "active", 600, "Droplet x")


async def test_poll_fails_when_the_object_disappears(fake):
    droplet = fake.add_droplet(name="x", status="new")
    fake.boot_polls = 1000
    async with DigitalOceanClient(TOKEN) as do:
        async def fetch():
            got = await do.droplet(droplet["id"])
            fake.droplets.pop(droplet["id"], None)
            return got

        with pytest.raises(DigitalOceanError, match="^Droplet x disappeared from DigitalOcean while Slipway waited$"):
            await poll(fetch, lambda d: False, 600, "Droplet x")


async def test_poll_raises_a_403_as_is(fake):
    fake.forbid.add("droplets")
    async with DigitalOceanClient(TOKEN) as do:
        with pytest.raises(Forbidden):
            await poll(lambda: do.droplet(1), lambda d: True, 600, "Droplet x")
