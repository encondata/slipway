"""Phase 4 pure rules (``slipway/services/do_rules.py``): spec tests 13-19, no fakes needed."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import uuid
from datetime import UTC, datetime, timedelta, timezone

import pytest
import yaml

from slipway.services import cloudinit
from slipway.services import do_rules as d
from slipway.services.do_rules import DoRuleError
from slipway.services.ssh import generate_keypair

ENV_ID = uuid.UUID("1a2b3c4d-0000-4000-8000-000000000001")
OTHER_ID = uuid.UUID("9f8e7d6c-0000-4000-8000-000000000002")
NONCE = "0123456789abcdef"


# ---------------------------------------------------------------------- 13. user-data


def _userdata(**kw):
    host_private, host_public = generate_keypair("host")
    _, login = generate_keypair("slipway")
    args = dict(authorized_key=login, host_private_key=host_private, host_public_key=host_public)
    args.update(kw)
    return d.droplet_userdata("prod", "blue", **args), login, host_private, host_public


def test_userdata_keys_user_packages_and_runcmd():
    text, login, host_private, host_public = _userdata()
    assert text.startswith("#cloud-config\n")
    doc = yaml.safe_load(text)
    assert doc["hostname"] == "slipway-prod-blue" and doc["preserve_hostname"] is False
    assert doc["ssh_pwauth"] is False and doc["disable_root"] is True
    # The generated host key only: the image's keys are deleted and none are generated.
    assert doc["ssh_deletekeys"] is True and doc["ssh_genkeytypes"] == []
    assert doc["ssh_keys"] == {"ed25519_private": host_private if host_private.endswith("\n") else host_private + "\n",
                               "ed25519_public": host_public}
    [user] = doc["users"]
    assert user == {"name": "slipway", "shell": "/bin/bash", "lock_passwd": True, "ssh_authorized_keys": [login]}
    # The same Linux user as on VMs (plan Decision 10), and no sudo on a droplet (D24).
    assert d.DROPLET_USER == cloudinit.GUEST_USER == "slipway"
    assert "sudo" not in user
    # No sudo anywhere, and no group at user creation (docker doesn't exist yet).
    assert "sudo" not in user and "groups" not in user and "sudo" not in text
    assert doc["packages"] == ["docker.io", "docker-compose-v2", "curl"]
    assert doc["package_update"] is True
    assert doc["growpart"] == {"mode": "auto", "devices": ["/"]} and doc["resize_rootfs"] is True
    assert doc["runcmd"] == [
        ["usermod", "-aG", "docker", "slipway"],
        ["install", "-d", "-o", "slipway", "-g", "slipway", "-m", "0755", "/opt/slipway"],
        ["systemctl", "daemon-reload"],
        ["systemctl", "enable", "--now", "docker"],
        ["sh", "-c", "{ iptables -C DOCKER-USER -d 169.254.169.254/32 -j DROP 2>/dev/null || "
                     "iptables -I DOCKER-USER -d 169.254.169.254/32 -j DROP; } && touch /var/lib/slipway-ready"],
    ]
    # runcmd (where the docker group is joined) runs after packages; nothing pipes a script into a shell.
    assert "curl |" not in text and "| sh" not in text and "| bash" not in text
    assert len(text.encode()) < 64 * 1024


def test_userdata_refuses_bad_input():
    with pytest.raises(DoRuleError):
        _userdata(authorized_key="ssh-ed25519 AAAA\nssh-rsa BBBB")
    with pytest.raises(DoRuleError):
        _userdata(host_public_key="ssh-rsa AAAA")
    with pytest.raises(DoRuleError):
        _userdata(host_private_key="not a key")
    with pytest.raises(DoRuleError, match="64"):
        _userdata(authorized_key="ssh-ed25519 " + "A" * 70000)
    with pytest.raises(DoRuleError):
        d.droplet_userdata("prod", "orange", authorized_key="ssh-ed25519 A", host_private_key="PRIVATE KEY",
                           host_public_key="ssh-ed25519 B")


def test_hostname_pattern():
    longest = "a" + "b" * 24 + "c"  # 26 characters, the longest environment name
    for slot in d.SLOTS:
        name = d.droplet_name(longest, slot)
        assert d.DROPLET_NAME_RE.match(name)
    for bad in ("Prod", "-prod", "prod-", "p", "a" * 27, "pr_od"):
        with pytest.raises(DoRuleError):
            d.droplet_name(bad, "blue")


def test_droplet_body_has_monitoring_off_and_the_tags():
    body = d.droplet_body("prod", ENV_ID, "green", region="nyc3", size="s-2vcpu-4gb", vpc_uuid="vpc-1",
                          nonce=NONCE, user_data="#cloud-config\n")
    assert body["monitoring"] is False and body["ipv6"] is False
    assert body["with_droplet_agent"] is False  # no DigitalOcean agent on a droplet (plan Decision 11)
    assert body["image"] == "ubuntu-24-04-x64" and body["name"] == "slipway-prod-green"
    assert body["tags"] == ["slipway", f"slipway-env-{ENV_ID}", "slipway-env:prod", "slipway-slot:green",
                            f"slipway-req:{NONCE}"]
    # The body hash leaves out the user-data (it holds the private host key).
    assert d.body_hash(body) == d.body_hash({**body, "user_data": "other"})
    assert d.body_hash(body) != d.body_hash({**body, "size": "s-4vcpu-8gb"})


def test_env_name_rule_matches_the_model():
    from slipway.models.environment import ENVIRONMENT_NAME_RE

    assert d.ENV_NAME_RE.pattern == ENVIRONMENT_NAME_RE


# ---------------------------------------------------------------------- 14. pgauth

# RFC 7677's SCRAM-SHA-256 example (user "user", password "pencil", this salt, 4096 iterations), which
# is the algorithm PostgreSQL stores in pg_authid. Its client proof and server signature check the
# stored and server keys below.
RFC_SALT = "W22ZaJ0SNY7soEsUEjb6gQ=="
RFC_VERIFIER = ("SCRAM-SHA-256$4096:W22ZaJ0SNY7soEsUEjb6gQ==$WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY="
                ":wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU=")


def test_scram_sha256_known_verifier():
    verifier = d.scram_sha256("pencil", salt=base64.b64decode(RFC_SALT))
    assert verifier == RFC_VERIFIER
    stored, server = (base64.b64decode(x) for x in verifier.rsplit("$", 1)[1].split(":"))
    nonce = "rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0"
    auth = f"n=user,r=rOprNGfwEbeRWgbNEkqO,r={nonce},s={RFC_SALT},i=4096,c=biws,r={nonce}".encode()
    signature = hmac.new(server, auth, hashlib.sha256).digest()
    assert base64.b64encode(signature).decode() == "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="
    proof = base64.b64decode("dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=")
    client_key = bytes(a ^ b for a, b in zip(proof, hmac.new(stored, auth, hashlib.sha256).digest(), strict=True))
    assert hashlib.sha256(client_key).digest() == stored


def test_scram_sha256_fresh_salt_and_format():
    a, b = d.scram_sha256("secret"), d.scram_sha256("secret")
    assert a != b and d.SCRAM_RE.match(a) and d.SCRAM_RE.match(b)
    assert "secret" not in a
    with pytest.raises(DoRuleError):
        d.scram_sha256("")
    # A non-ASCII password goes through SASLprep (NFKC): the ligature and "fi" hash the same.
    salt = b"0123456789abcdef"
    assert d.scram_sha256("ﬁle", salt=salt) == d.scram_sha256("file", salt=salt)
    # A prohibited character falls back to the raw bytes, as PostgreSQL does.
    assert d.scram_sha256("a\u0007é", salt=salt) != d.scram_sha256("aé", salt=salt)


def test_setup_sql_is_idempotent_and_uses_the_verifier():
    sql = d.setup_sql("serversherpa", "serversherpa", verifier=RFC_VERIFIER)
    assert "pencil" not in sql and RFC_VERIFIER in sql
    lines = sql.splitlines()
    assert lines[0].startswith("SELECT 'CREATE ROLE \"serversherpa\" LOGIN' WHERE NOT EXISTS")
    assert lines[0].endswith("\\gexec")
    assert lines[1] == f"ALTER ROLE \"serversherpa\" WITH LOGIN PASSWORD '{RFC_VERIFIER}';"
    assert lines[2] == 'GRANT "serversherpa" TO doadmin;'
    assert "CREATE DATABASE \"serversherpa\" OWNER \"serversherpa\"" in lines[3] and lines[3].endswith("\\gexec")
    assert lines[4] == 'ALTER DATABASE "serversherpa" OWNER TO "serversherpa";'


@pytest.mark.parametrize("role,database", [
    ("Server", "db"), ("1abc", "db"), ("a;drop", "db"), ("a" * 64, "db"), ("ok", "x'y"), ("ok", ""),
    ("doadmin", "db"), ("pg_monitor", "db"), ("ok", "defaultdb"), ("ok", "postgres"), ("ok", "template1"),
])
def test_setup_and_reset_refuse_bad_identifiers(role, database):
    with pytest.raises(DoRuleError):
        d.setup_sql(role, database, verifier=RFC_VERIFIER)
    with pytest.raises(DoRuleError):
        d.reset_sql(role, database)


@pytest.mark.parametrize("verifier", [
    "pencil", "md5abcdef", RFC_VERIFIER + "'", RFC_VERIFIER.replace("SCRAM", "scram"),
    "SCRAM-SHA-256$4096:abc$def:ghi", RFC_VERIFIER + ";DROP ROLE doadmin",
])
def test_setup_refuses_bad_verifiers(verifier):
    with pytest.raises(DoRuleError) as err:
        d.setup_sql("app", "app", verifier=verifier)
    assert verifier not in str(err.value)


def test_reset_sql_repeatable():
    sql = d.reset_sql("serversherpa", "serversherpa")
    assert sql.splitlines() == [
        'DROP DATABASE IF EXISTS "serversherpa" WITH (FORCE);',
        "SELECT 'CREATE DATABASE \"serversherpa\" OWNER \"serversherpa\"' WHERE NOT EXISTS "
        "(SELECT FROM pg_database WHERE datname = 'serversherpa') \\gexec",
    ]


def test_psql_command_and_stdin():
    cmd = d.psql_command(host="private-slipway-prod-db-do-user-1-0.db.ondigitalocean.com", port=25060,
                         version="16")
    assert "postgres:16-alpine" in cmd and "sslmode=verify-full sslrootcert=/s/ca.pem" in cmd
    assert "-v ON_ERROR_STOP=1 -q -f -" in cmd and "PGPASSFILE=/s/pgpass" in cmd
    assert "IFS= read -r pw; IFS= read -r ca" in cmd and "umask 077" in cmd
    stdin = d.psql_stdin(admin_password="p:a\\ss", ca_b64="QUJD\nREVG\n", sql="SELECT 1;\n")
    pw, ca, sql = stdin.split("\n", 2)
    assert pw == "p\\:a\\\\ss" and ca == "QUJDREVG" and sql == "SELECT 1;\n"
    for bad in (dict(host="h; rm -rf /", port=1, version="16"), dict(host="h", port=0, version="16"),
                dict(host="h", port=5432, version="16; id")):
        with pytest.raises(DoRuleError):
            d.psql_command(**bad)
    with pytest.raises(DoRuleError):
        d.psql_stdin(admin_password="a\nb", ca_b64="QUJD", sql="")
    with pytest.raises(DoRuleError):
        d.psql_stdin(admin_password="ab", ca_b64="not base64!", sql="")


# ---------------------------------------------------------------------- 15. load balancer


def _live_lb(**over):
    body = d.lb_body("prod", region="nyc3", vpc_uuid="vpc-1", port=80, health="/healthz", certificate_id="cert-1")
    live = {**body, "id": "lb-1", "ip": "198.51.100.10", "ipv6": "", "status": "active",
            "created_at": "2026-11-01T00:00:00Z", "region": {"slug": "nyc3", "name": "New York 3"},
            "size": "lb-small", "tag": "", "droplet_ids": [4001]}
    live.update(over)
    return live


def test_lb_body():
    body = d.lb_body("prod", region="nyc3", vpc_uuid="vpc-1", port=80, health="/healthz", certificate_id="cert-1")
    assert body["name"] == "slipway-prod-lb" and body["size_unit"] == 1 and body["vpc_uuid"] == "vpc-1"
    assert body["droplet_ids"] == [] and body["redirect_http_to_https"] is False
    assert body["forwarding_rules"] == [
        {"entry_protocol": "https", "entry_port": 443, "target_protocol": "http", "target_port": 80,
         "certificate_id": "cert-1", "tls_passthrough": False},
        {"entry_protocol": "http", "entry_port": 80, "target_protocol": "http", "target_port": 80},
    ]
    assert body["health_check"] == {"protocol": "http", "port": 80, "path": "/healthz", "check_interval_seconds": 10,
                                    "response_timeout_seconds": 5, "healthy_threshold": 3, "unhealthy_threshold": 3}
    assert d.https_certificate(body) == "cert-1"
    assert d.settle_seconds(body) == 40
    with pytest.raises(DoRuleError):
        d.lb_body("prod", region="nyc3", vpc_uuid="v", port=70000, health="/h", certificate_id="c")
    with pytest.raises(DoRuleError):
        d.lb_body("prod", region="nyc3", vpc_uuid="v", port=80, health="healthz", certificate_id="c")


def test_lb_update_body():
    live = _live_lb()
    body = d.lb_update_body(live, certificate_id="cert-2", droplet_ids=[4001, 4002])
    for field in ("id", "ip", "ipv6", "status", "created_at"):
        assert field not in body
    assert body["region"] == "nyc3"
    assert "size" not in body and body["size_unit"] == 1
    assert "tag" not in body and body["droplet_ids"] == [4001, 4002]
    assert d.https_certificate(body) == "cert-2"
    # The live answer is left alone.
    assert d.https_certificate(live) == "cert-1" and live["droplet_ids"] == [4001] and "id" in live
    # Without changes the targets stay what they were.
    assert d.lb_update_body(live)["droplet_ids"] == [4001]
    # A size-only load balancer keeps its size; a tag-only one keeps its tag.
    old = {k: v for k, v in _live_lb(tag="web").items() if k not in ("size_unit", "droplet_ids")}
    kept = d.lb_update_body(old)
    assert kept["size"] == "lb-small" and kept["tag"] == "web"
    with pytest.raises(DoRuleError):
        d.lb_update_body(_live_lb(forwarding_rules=[]), certificate_id="cert-2")


def test_https_certificate_and_edge_checks():
    assert d.https_certificate({"forwarding_rules": [{"entry_protocol": "http", "entry_port": 80}]}) is None
    live = _live_lb()
    assert d.lb_matches(live, "prod", "vpc-1") and not d.lb_matches(live, "prod", "vpc-2")
    assert not d.lb_matches(live, "prod-eu", "vpc-1")
    assert d.lb_edge_problem(live, port=80, health="/healthz") is None
    assert d.lb_edge_problem(live, port=8080, health="/healthz") == \
        "slipway-prod-lb no longer forwards to port 8080: Slipway changed nothing"
    moved = _live_lb(health_check={**live["health_check"], "path": "/"})
    assert "no longer checks /healthz" in d.lb_edge_problem(moved, port=80, health="/healthz")
    assert d.lb_targets(live) == [4001]


# ---------------------------------------------------------------------- 16. firewall


def test_firewall_body_ssh_only_then_full():
    ssh_only = d.firewall_body("prod", ENV_ID, ssh_sources=["198.51.100.7", "2001:db8::/48"])
    assert ssh_only["name"] == "slipway-prod-fw" and ssh_only["tags"] == [f"slipway-env-{ENV_ID}"]
    assert ssh_only["droplet_ids"] == []
    assert ssh_only["inbound_rules"] == [
        {"protocol": "tcp", "ports": "22", "sources": {"addresses": ["198.51.100.7/32", "2001:db8::/48"]}}]
    anywhere = {"addresses": ["0.0.0.0/0", "::/0"]}
    assert ssh_only["outbound_rules"] == [
        {"protocol": "tcp", "ports": "all", "destinations": anywhere},
        {"protocol": "udp", "ports": "all", "destinations": anywhere},
        {"protocol": "icmp", "destinations": anywhere},
    ]
    full = d.firewall_body("prod", ENV_ID, ssh_sources=["198.51.100.7"], lb_id="lb-1", port=80)
    assert full["inbound_rules"][1] == {"protocol": "tcp", "ports": "80", "sources": {"load_balancer_uids": ["lb-1"]}}
    assert d.firewall_has_lb_rule(full, lb_id="lb-1", port=80)
    assert not d.firewall_has_lb_rule(ssh_only, lb_id="lb-1", port=80)
    assert not d.firewall_has_lb_rule(full, lb_id="lb-2", port=80)
    with pytest.raises(DoRuleError):
        d.firewall_body("prod", ENV_ID, ssh_sources=[])
    with pytest.raises(DoRuleError):
        d.firewall_body("prod", ENV_ID, ssh_sources=["not-an-ip"])
    with pytest.raises(DoRuleError):
        d.firewall_body("prod", ENV_ID, ssh_sources=[f"198.51.100.{i}" for i in range(11)])
    with pytest.raises(DoRuleError):
        d.firewall_body("prod", ENV_ID, ssh_sources=["198.51.100.7"], lb_id="lb-1")


def test_firewall_matches_digitalocean_answer():
    wanted = d.firewall_body("prod", ENV_ID, ssh_sources=["198.51.100.7", "203.0.113.0/24"], lb_id="lb-1", port=80)
    # What DigitalOcean answers: "0" for all ports and for ICMP, rules and addresses reordered, extra fields.
    live = {
        "id": "fw-1", "status": "succeeded", "created_at": "x", "pending_changes": [],
        "name": "slipway-prod-fw", "tags": [f"slipway-env-{ENV_ID}"], "droplet_ids": [],
        "inbound_rules": [
            {"protocol": "tcp", "ports": "80", "sources": {"load_balancer_uids": ["lb-1"]}},
            {"protocol": "tcp", "ports": "22", "sources": {"addresses": ["203.0.113.0/24", "198.51.100.7"]}},
        ],
        "outbound_rules": [
            {"protocol": "icmp", "ports": "0", "destinations": {"addresses": ["::/0", "0.0.0.0/0"]}},
            {"protocol": "udp", "ports": "0", "destinations": {"addresses": ["0.0.0.0/0", "::/0"]}},
            {"protocol": "tcp", "ports": "0", "destinations": {"addresses": ["0.0.0.0/0", "::/0"]}},
        ],
    }
    assert d._firewall_matches(live, wanted)
    assert not d.firewall_ssh_changed(live, wanted)
    # SSH opened to the world: drift, and an SSH change Slipway must prove.
    opened = {**live, "inbound_rules": [live["inbound_rules"][0],
                                        {"protocol": "tcp", "ports": "22", "sources": {"addresses": ["0.0.0.0/0"]}}]}
    assert not d._firewall_matches(opened, wanted) and d.firewall_ssh_changed(opened, wanted)
    assert d.firewall_ssh_sources(opened) == {"0.0.0.0/0"}
    # The load balancer rule gone, another port, another tag, a droplet added by hand: all drift.
    assert not d._firewall_matches({**live, "inbound_rules": live["inbound_rules"][1:]}, wanted)
    other_port = [{**live["inbound_rules"][0], "ports": "8080"}, live["inbound_rules"][1]]
    assert not d._firewall_matches({**live, "inbound_rules": other_port}, wanted)
    assert not d._firewall_matches({**live, "tags": ["slipway-env-other"]}, wanted)
    assert not d._firewall_matches({**live, "droplet_ids": [99]}, wanted)
    assert not d._firewall_matches({**live, "outbound_rules": live["outbound_rules"][1:]}, wanted)
    # An all-ports SSH rule still counts as SSH.
    assert d.firewall_ssh_sources({"inbound_rules": [{"protocol": "tcp", "ports": "0",
                                                      "sources": {"addresses": ["10.0.0.1"]}}]}) == {"10.0.0.1/32"}
    assert d.firewall_adoptable(live, "prod", ENV_ID) and not d.firewall_adoptable(live, "prod", OTHER_ID)


def test_ssh_sources_open_to_world():
    assert d.open_to_world(["0.0.0.0/0"]) and d.open_to_world(["::/0"]) and d.open_to_world(["0.0.0.0"]) is False
    assert d.normalise_ssh_sources([" 198.51.100.7 ", "198.51.100.7/32", "203.0.113.9/24"]) == \
        ["198.51.100.7/32", "203.0.113.0/24"]


# ---------------------------------------------------------------------- 17. sizes


def _catalog():
    sizes = [
        {"slug": "s-1vcpu-1gb", "vcpus": 1, "memory": 1024, "disk": 25, "price_monthly": 6.0, "available": True,
         "regions": ["nyc3", "ams3"]},
        {"slug": "s-2vcpu-4gb", "vcpus": 2, "memory": 4096, "disk": 80, "price_monthly": 24.0, "available": True,
         "regions": ["nyc3", "ams3"]},
        {"slug": "s-4vcpu-8gb", "vcpus": 4, "memory": 8192, "disk": 160, "price_monthly": 48.0, "available": True,
         "regions": ["nyc3"]},
        {"slug": "s-2vcpu-2gb", "vcpus": 2, "memory": 2048, "disk": 60, "price_monthly": 18.0, "available": True,
         "regions": ["nyc3"]},
        {"slug": "s-4vcpu-8gb-amd", "vcpus": 4, "memory": 8192, "disk": 160, "price_monthly": 56.0,
         "available": True, "regions": ["nyc3"]},
        {"slug": "c-4", "vcpus": 4, "memory": 8192, "disk": 50, "price_monthly": 84.0, "available": True,
         "regions": ["nyc3"]},
        {"slug": "s-8vcpu-16gb", "vcpus": 8, "memory": 16384, "disk": 320, "price_monthly": 96.0,
         "available": True, "regions": ["ams3"]},
        {"slug": "s-8vcpu-32gb", "vcpus": 8, "memory": 32768, "disk": 320, "price_monthly": 160.0,
         "available": False, "regions": ["nyc3"]},
    ]
    regions = [{"slug": "nyc3", "name": "New York 3", "available": True},
               {"slug": "nyc1", "name": "New York 1", "available": True},
               {"slug": "sfo1", "name": "San Francisco 1", "available": False}]
    options = {"options": {"pg": {
        "regions": ["nyc3"], "versions": ["14", "15", "16", "17"],
        "layouts": [{"num_nodes": 1, "sizes": ["db-s-1vcpu-1gb", "db-s-1vcpu-2gb", "db-s-2vcpu-4gb"]},
                    {"num_nodes": 2, "sizes": ["db-s-1vcpu-2gb", "db-s-2vcpu-4gb"]}],
    }}}
    return d.build_catalog("nyc3", regions, sizes, options)


def test_size_parts():
    assert d.size_parts("s-2vcpu-4gb") == d.SizeParts("s-2vcpu-4gb", "s", 2, 4096, None)
    assert d.size_parts("s-1vcpu-512mb-10gb") == d.SizeParts("s-1vcpu-512mb-10gb", "s", 1, 512, 10)
    assert d.size_parts("s-4vcpu-8gb-amd").family == "s-amd"
    assert d.size_parts("s-2vcpu-4gb-120gb-intel") == d.SizeParts("s-2vcpu-4gb-120gb-intel", "s-intel", 2, 4096, 120)
    assert d.size_parts("c-4") == d.SizeParts("c-4", "c", 4, None, None)
    assert d.size_parts("db-s-1vcpu-2gb") == d.SizeParts("db-s-1vcpu-2gb", "db-s", 1, 2048, None)
    assert d.size_parts("so1_5-2vcpu-16gb").family == "so1_5"
    # The catalog's amounts win over the slug's.
    assert d.size_parts("c-4", {"vcpus": 4, "memory": 8192, "disk": 50}) == d.SizeParts("c-4", "c", 4, 8192, 50)
    with pytest.raises(DoRuleError):
        d.size_parts("")


def test_grows():
    p = d.size_parts
    assert d.grows(p("s-2vcpu-4gb"), p("s-4vcpu-8gb"))
    assert d.grows(p("s-2vcpu-2gb"), p("s-2vcpu-4gb"))  # larger in one, equal in the rest
    assert not d.grows(p("s-2vcpu-4gb"), p("s-2vcpu-4gb"))  # equal is no grow
    assert not d.grows(p("s-4vcpu-8gb"), p("s-2vcpu-4gb"))
    assert not d.grows(p("s-2vcpu-4gb"), p("s-4vcpu-2gb"))  # smaller in one way
    assert not d.grows(p("s-2vcpu-4gb"), p("s-4vcpu-8gb-amd"))  # another family
    assert not d.grows(p("s-1vcpu-1gb", {"vcpus": 1, "memory": 1024, "disk": 25}), p("s-2vcpu-2gb"))  # disk unknown


def test_droplet_grow_against_the_catalog():
    cat = _catalog()
    assert [s["slug"] for s in cat["sizes"]] == ["s-1vcpu-1gb", "s-2vcpu-4gb", "s-4vcpu-8gb", "s-2vcpu-2gb",
                                                 "s-4vcpu-8gb-amd", "c-4"]
    assert d.droplet_grow_problem("s-2vcpu-4gb", "s-4vcpu-8gb", cat) is None
    assert d.droplet_grow_problem("s-2vcpu-4gb", "s-2vcpu-4gb", cat) is None
    assert d.droplet_grow_problem("s-4vcpu-8gb", "s-2vcpu-4gb", cat) == \
        "s-2vcpu-4gb isn't larger than s-4vcpu-8gb in every way"
    assert d.droplet_grow_problem("s-1vcpu-1gb", "s-2vcpu-2gb", cat) is None  # larger in every way
    assert d.droplet_grow_problem("s-2vcpu-2gb", "s-1vcpu-1gb", cat) is not None
    # Another family.
    assert "another kind of droplet" in d.droplet_grow_problem("s-2vcpu-4gb", "s-4vcpu-8gb-amd", cat)
    assert "another kind of droplet" in d.droplet_grow_problem("s-2vcpu-4gb", "c-4", cat)
    # Not offered in the region (only in ams3), or not available at all.
    assert d.droplet_grow_problem("s-2vcpu-4gb", "s-8vcpu-16gb", cat) == \
        "s-8vcpu-16gb isn't a droplet size DigitalOcean offers in nyc3"
    assert d.droplet_grow_problem("s-2vcpu-4gb", "s-8vcpu-32gb", cat) is not None
    # A retired current size falls back to its slug (no disk known, so only vCPUs and memory count).
    assert d.droplet_grow_problem("s-1vcpu-2gb", "s-2vcpu-4gb", cat) is None
    assert d.droplet_grow_problem("s-8vcpu-16gb-old", "s-4vcpu-8gb", cat) is not None
    assert d.droplet_size_problem("s-2vcpu-4gb", cat) is None
    assert d.droplet_size_problem("s-8vcpu-16gb", cat) == "s-8vcpu-16gb isn't a droplet size DigitalOcean offers in nyc3"


def test_database_grow_and_standby():
    cat = _catalog()
    assert cat["database_sizes"] == {"1": ["db-s-1vcpu-1gb", "db-s-1vcpu-2gb", "db-s-2vcpu-4gb"],
                                     "2": ["db-s-1vcpu-2gb", "db-s-2vcpu-4gb"]}
    assert d.database_grow_problem("db-s-1vcpu-2gb", 1, "db-s-2vcpu-4gb", 1, cat) is None
    assert d.database_grow_problem("db-s-1vcpu-2gb", 1, "db-s-1vcpu-2gb", 2, cat) is None  # add a standby
    assert d.database_grow_problem("db-s-1vcpu-2gb", 1, "db-s-1vcpu-2gb", 1, cat) is None  # nothing changes
    assert d.database_grow_problem("db-s-1vcpu-2gb", 2, "db-s-1vcpu-2gb", 1, cat) == \
        "A standby node can be added but not removed"
    assert d.database_grow_problem("db-s-2vcpu-4gb", 1, "db-s-1vcpu-2gb", 1, cat) == \
        "db-s-1vcpu-2gb isn't larger than db-s-2vcpu-4gb in every way"
    assert d.database_grow_problem("db-s-1vcpu-1gb", 1, "db-s-1vcpu-1gb", 2, cat) == \
        "db-s-1vcpu-1gb has no 2-node layout"
    assert d.database_size_problem("db-s-1vcpu-1gb", 3, cat) is not None
    assert d.db_version_problem("16", cat) is None
    assert d.db_version_problem("13", cat) == "PostgreSQL 13 isn't offered by DigitalOcean here (14, 15, 16, 17)"


def test_region_rules():
    cat = _catalog()
    assert d.region_problem(cat) is None
    assert "has no Spaces" in d.region_problem({**cat, "region": "nyc1"})
    assert d.region_problem({**cat, "region": "sfo1"}) == "sfo1 isn't open for new objects in DigitalOcean"
    assert cat["spaces"] is True
    assert {r["slug"]: r["spaces"] for r in cat["regions"]} == {"nyc3": True, "nyc1": False, "sfo1": False}


# ---------------------------------------------------------------------- 18. cost


def _plan(**over):
    args = dict(droplets=2, droplet_size="s-2vcpu-4gb", db_size="db-s-1vcpu-2gb", db_nodes=1, db_version="16")
    args.update(over)
    return d.make_plan(**args)


def test_cost_lines_and_total():
    c = d.cost(_plan(), _catalog())
    by = {line.object: line for line in c.lines}
    assert [line.object for line in c.lines] == ["droplet", "database", "load_balancer", "spaces", "vpc",
                                                 "firewall", "certificate"]
    assert by["droplet"].label == "2 × droplet s-2vcpu-4gb (2 vCPU, 4 GB, 80 GB)"
    assert (by["droplet"].unit_cents, by["droplet"].cents, by["droplet"].source) == (2400, 4800, "api")
    assert by["database"].label == "Database cluster db-s-1vcpu-2gb × 1 node, PostgreSQL 16"
    assert (by["database"].cents, by["database"].source) == (3000, "table")
    assert by["load_balancer"].label == "Load balancer, 1 node" and by["load_balancer"].cents == 1200
    assert by["spaces"].cents == 500
    assert all(by[k].cents == 0 for k in ("vpc", "firewall", "certificate"))
    assert c.total_cents == 4800 + 3000 + 1200 + 500 and c.total == "95.00"
    assert c.as_of == d.PRICES["as_of"]
    assert c.note == f"Estimated, prices as of {d.PRICES['as_of']}; bandwidth beyond the allowance, " \
                     "DigitalOcean backups and taxes are extra."
    j = c.to_json()
    assert j["total"] == "95.00" and j["total_cents"] == 9500 and j["lines"][0]["amount"] == "48.00"


def test_cost_prices_in_cents_from_the_api():
    cat = _catalog()
    cat["sizes"][1] = {**cat["sizes"][1], "price_monthly": 24.005}
    assert d.cost(_plan(droplets=1), cat).lines[0].cents == 2401
    half = {**cat, "sizes": [{"slug": "s-1vcpu-512mb-10gb", "vcpus": 1, "memory": 512, "disk": 10,
                              "price_monthly": 4}]}
    assert d.cost(_plan(droplets=1, droplet_size="s-1vcpu-512mb-10gb"), half).lines[0].label == \
        "1 × droplet s-1vcpu-512mb-10gb (1 vCPU, 0.5 GB, 10 GB)"
    with pytest.raises(DoRuleError, match="doesn't price droplet size s-9vcpu"):
        d.cost(_plan(droplet_size="s-9vcpu-9gb"), cat)


def test_cost_account_over_install_over_code():
    install = d.check_prices({"as_of": "2026-10-01", "database": {"db-s-1vcpu-2gb": {"1": 3100}},
                              "spaces": 600})
    account = d.check_prices({"as_of": "2026-11-10", "database": {"db-s-1vcpu-2gb": {"1": 3200}}})
    c = d.cost(_plan(), _catalog(), d.price_layers(account, install))
    by = {line.object: line for line in c.lines}
    assert (by["database"].cents, by["database"].source) == (3200, "account")
    assert (by["spaces"].cents, by["spaces"].source) == (600, "install")
    assert (by["load_balancer"].cents, by["load_balancer"].source) == (1200, "table")
    # The oldest table a price came from dates the estimate.
    assert c.as_of == "2026-10-01"
    only_account = d.cost(_plan(), _catalog(), d.price_layers(account, None))
    assert only_account.as_of == min("2026-11-10", d.PRICES["as_of"])


def test_cost_missing_price():
    no_database = [("table", {"as_of": "2026-01-01", "load_balancer": {"1": 1}, "spaces": 1})]
    with pytest.raises(DoRuleError) as err:
        d.cost(_plan(db_size="db-s-2vcpu-4gb", db_nodes=2, droplets=1), _catalog(), no_database)
    assert str(err.value) == "Slipway has no price for database db-s-2vcpu-4gb with 2 nodes; set one on the account"
    with pytest.raises(DoRuleError, match="Slipway has no price for database db-s-9vcpu-9gb with 1 node; set one"):
        d.cost(_plan(db_size="db-s-9vcpu-9gb"), _catalog())


def test_check_prices_refuses_bad_shapes():
    for bad in ({"database": {}}, {"as_of": "soon"}, {"as_of": "2026-11-01", "spaces": 1.5},
                {"as_of": "2026-11-01", "spaces": -1}, {"as_of": "2026-11-01", "droplets": {}},
                {"as_of": "2026-11-01", "database": {"db-s-1vcpu-1gb": 10}}, "cheap",
                {"as_of": "2026-11-01", "load_balancer": {"1": True}}):
        with pytest.raises(DoRuleError):
            d.check_prices(bad)
    assert d.check_prices({"as_of": "2026-11-01", "database": {"x": {1: 5}}}) == \
        {"as_of": "2026-11-01", "database": {"x": {"1": 5}}}
    d.check_prices(d.PRICES)  # the code's own table has the shape it asks of overrides


def test_confirm_figure():
    c = d.cost(_plan(), _catalog())
    assert d.confirm_problem("95.00", c) is None
    assert d.confirm_problem(" $95.00 ", c) is None and d.confirm_problem("$ 95.00", c) is None
    for wrong in ("95", "95.0", "94.00", "", None, "95.001", "095.00"):
        assert d.confirm_problem(wrong, c) == "Type 95.00 to confirm about $95.00 a month"
    assert d.dollars(8400) == "84.00" and d.dollars(5) == "0.05"
    assert d.delta_text(8400, 10800) == "+$24.00 a month" and d.delta_text(10800, 8400) == "-$24.00 a month"
    with pytest.raises(DoRuleError):
        d.make_plan(droplets=3, droplet_size="s", db_size="d", db_nodes=1, db_version="16")


# ---------------------------------------------------------------------- 19. names and tags


def test_names():
    assert d.vpc_name("prod") == "slipway-prod"
    assert d.droplet_name("prod", "blue") == "slipway-prod-blue"
    assert d.database_name("prod") == "slipway-prod-db"
    assert d.bucket_name("prod", ENV_ID) == "slipway-prod-1a2b3c4d"
    assert d.lb_name("prod") == "slipway-prod-lb" and d.firewall_name("prod") == "slipway-prod-fw"
    assert d.spaces_key_name("prod", ENV_ID, NONCE) == f"slipway-prod-1a2b3c4d-{NONCE}"
    assert d.spaces_key_name("prod", ENV_ID, NONCE, setup=True) == f"slipway-prod-1a2b3c4d-setup-{NONCE}"
    when = datetime(2026, 11, 15, 22, 5, tzinfo=timezone(timedelta(hours=-1)))
    assert d.certificate_name("prod", when) == "slipway-prod-202611152305"
    with pytest.raises(DoRuleError):
        d.certificate_name("prod", datetime(2026, 11, 15))
    with pytest.raises(DoRuleError):
        d.spaces_key_name("prod", ENV_ID, "XYZ")
    assert re.fullmatch(r"[0-9a-f]{16}", d.new_nonce()) and d.new_nonce() != d.new_nonce()


def test_bucket_name_length_for_the_longest_environment():
    longest = "a" + "b" * 24 + "c"
    name = d.bucket_name(longest, ENV_ID)
    assert len(longest) == 26 and len(name) < 63
    assert re.fullmatch(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]", name)


def test_vpc_marker_and_request():
    desc = d.vpc_description("prod", ENV_ID, NONCE)
    assert desc == f"slipway:{ENV_ID} Made by Slipway for environment prod. req:{NONCE}"
    assert d.vpc_is_marked({"description": desc}, ENV_ID)
    assert not d.vpc_is_marked({"description": desc}, OTHER_ID)
    assert not d.vpc_is_marked({"description": f"x slipway:{ENV_ID}"}, ENV_ID)
    assert not d.vpc_is_marked({"description": None}, ENV_ID)
    assert d.vpc_request_nonce({"description": desc}) == NONCE
    assert d.vpc_request_nonce({"description": f"slipway:{ENV_ID} Made by Slipway"}) is None
    body = d.vpc_body("prod", ENV_ID, region="nyc3", nonce=NONCE)
    assert body == {"name": "slipway-prod", "region": "nyc3", "description": desc}


def test_tags_and_request_tag():
    assert d.tags("prod", ENV_ID, nonce=NONCE) == ["slipway", f"slipway-env-{ENV_ID}", "slipway-env:prod",
                                                   f"slipway-req:{NONCE}"]
    assert d.request_nonce(d.tags("prod", ENV_ID, nonce=NONCE, slot="blue")) == NONCE
    assert d.request_nonce(["slipway", "slipway-req:short"]) is None and d.request_nonce(None) is None
    for tag in d.tags("prod", ENV_ID, nonce=NONCE, slot="blue"):
        assert re.fullmatch(r"[A-Za-z0-9:_-]{1,255}", tag)  # DigitalOcean's tag characters


def test_exact_match_patterns():
    prod, prod_eu, prod_setup = "prod", "prod-eu", "prod-setup"
    # Certificates: prod's pattern never takes prod-eu's or prod-setup's names.
    stamp = datetime(2026, 11, 15, 12, 0, tzinfo=UTC)
    assert d.certificate_name_matches(d.certificate_name(prod, stamp), prod)
    assert not d.certificate_name_matches(d.certificate_name(prod_eu, stamp), prod)
    assert not d.certificate_name_matches(d.certificate_name(prod_setup, stamp), prod)
    assert not d.certificate_name_matches("slipway-prod-2026111512", prod)
    assert not d.certificate_name_matches("slipway-prod-2026111512000", prod)
    # Exact means exact: a trailing newline (which a bare ``$`` would let through) never matches.
    assert not d.certificate_name_matches(d.certificate_name(prod, stamp) + "\n", prod)
    assert not d.spaces_key_is_ours(d.spaces_key_name(prod, ENV_ID, NONCE) + "\n", prod, ENV_ID)
    with pytest.raises(DoRuleError):
        d.bucket_name("prod\n", ENV_ID)
    # Spaces keys: the id8 and the exact tail keep prod from matching prod-eu's and prod-setup's keys.
    ids = {prod: ENV_ID, prod_eu: OTHER_ID, prod_setup: uuid.uuid4()}
    ours = d.spaces_key_name(prod, ids[prod], NONCE)
    setup = d.spaces_key_name(prod, ids[prod], NONCE, setup=True)
    assert d.spaces_key_is_ours(ours, prod, ids[prod]) and d.spaces_key_is_ours(setup, prod, ids[prod])
    assert d.spaces_key_nonce(setup, prod, ids[prod]) == NONCE and d.spaces_key_is_setup(setup, prod, ids[prod])
    assert not d.spaces_key_is_setup(ours, prod, ids[prod])
    for other in (prod_eu, prod_setup):
        for key in (d.spaces_key_name(other, ids[other], NONCE), d.spaces_key_name(other, ids[other], NONCE, setup=True)):
            assert not d.spaces_key_is_ours(key, prod, ids[prod])
    # The same name with another environment's id isn't ours either.
    assert not d.spaces_key_is_ours(d.spaces_key_name(prod, OTHER_ID, NONCE), prod, ENV_ID)
    # An environment literally named like prod's id8 still can't collide: its own id8 follows.
    tricky = "prod-1a2b3c4d"
    assert not d.spaces_key_is_ours(d.spaces_key_name(tricky, OTHER_ID, NONCE), prod, ENV_ID)
    assert not d.spaces_key_is_ours(f"slipway-prod-1a2b3c4d-{NONCE}-x", prod, ENV_ID)


def test_tagged_objects_and_stops():
    name = d.droplet_name("prod", "blue")
    ours = {"id": 4001, "name": name, "tags": ["slipway", f"slipway-env-{ENV_ID}"]}
    assert d.tagged_matches(ours, name, ENV_ID)
    assert not d.tagged_matches({**ours, "tags": ["slipway"]}, name, ENV_ID)
    assert not d.tagged_matches({**ours, "name": "slipway-prod-eu-blue"}, name, ENV_ID)
    assert d.pick_tagged([ours, {"id": 5, "name": name, "tags": []}], name, ENV_ID, "droplet") is ours
    assert d.pick_tagged([{"id": 5, "name": name, "tags": []}], name, ENV_ID, "droplet") is None
    with pytest.raises(DoRuleError, match="4001, 4002.*Slipway changed nothing: fix it by hand, then retry"):
        d.pick_tagged([ours, {**ours, "id": 4002}], name, ENV_ID, "droplet")
    with pytest.raises(DoRuleError, match="but not the slipway tag"):
        d.pick_tagged([{"id": 7, "name": name, "tags": [f"slipway-env-{ENV_ID}"]}], name, ENV_ID, "droplet")


def test_spaces_key_verdicts():
    bucket = d.bucket_name("prod", ENV_ID)
    mine = d.spaces_key_name("prod", ENV_ID, NONCE)
    left = d.spaces_key_name("prod", ENV_ID, "fedcba9876543210", setup=True)
    verdict = lambda key: d.spaces_key_verdict(key, "prod", ENV_ID, bucket=bucket, recorded=[mine])  # noqa: E731
    assert verdict({"name": mine, "grants": [{"bucket": bucket, "permission": "readwrite"}]}) == "keep"
    assert verdict({"name": left, "grants": [{"bucket": "", "permission": "fullaccess"}]}) == "delete"
    lost = d.spaces_key_name("prod", ENV_ID, "00000000000000aa")
    assert verdict({"name": lost, "grants": [{"bucket": bucket, "permission": "readwrite"}]}) == "delete"
    assert verdict({"name": lost, "grants": [{"bucket": "someone-else", "permission": "readwrite"}]}) == "stop"
    assert verdict({"name": "another-key", "grants": []}) == "foreign"


def test_database_body_and_rules():
    body = d.database_body("prod", ENV_ID, region="nyc3", size="db-s-1vcpu-2gb", nodes=1, version="16",
                           vpc_uuid="vpc-1", nonce=NONCE, droplet_ids=[4002, 4001, 4001])
    assert body["name"] == "slipway-prod-db" and body["engine"] == "pg" and body["num_nodes"] == 1
    assert body["private_network_uuid"] == "vpc-1" and body["version"] == "16"
    assert body["rules"] == [{"type": "droplet", "value": "4001"}, {"type": "droplet", "value": "4002"}]
    assert body["tags"][-1] == f"slipway-req:{NONCE}" and "slipway-slot:blue" not in body["tags"]
    live = [{"uuid": "r1", "type": "droplet", "value": "4002"}, {"uuid": "r2", "type": "droplet", "value": "4001"}]
    assert d.database_rules_match(live, [4001, 4002])
    assert not d.database_rules_match(live, [4001])
    assert not d.database_rules_match(live + [{"type": "ip_addr", "value": "0.0.0.0/0"}], [4001, 4002])
