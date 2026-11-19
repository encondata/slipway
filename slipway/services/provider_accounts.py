"""Provider accounts: one service for DigitalOcean, Proxmox and ESXi (phase 4 §8, phase 5 §9.1).

The router (``api/v1/provider_accounts.py``) maps a request to one function here; each function checks,
writes and commits. What differs per provider sits in ``PROVIDERS``, a small dispatch table:

* **Config.** DigitalOcean's ``{region, ssh_sources, monthly_limit_cents, prices, team}`` is checked here
  (``do_rules.normalise_ssh_sources`` and ``do_rules.check_prices``); Proxmox's and ESXi's by their
  clients' ``clean_config``. A bad field is ``vmtypes.AccountInvalid`` (422 with ``field``).
* **The secret** (the DigitalOcean token, the whole Proxmox token, the ESXi password) is write-only:
  answers carry ``has_secret`` and ``secret_hint`` only, and no audit row, log line or error holds it.
  ``redactions(account)`` is what a job's redactor hides.
* **Test** answers ``{status, checks, facts}`` for every provider. Proxmox's ``run_test`` returns a
  ``TestResult``, ESXi's a list of checks with ``account.facts`` set (Decision 34); DigitalOcean's is
  here (``do_test``), with its pass, warn and fail stored as ok, warning and error.
* **Trust** pins a Proxmox or ESXi certificate by its fingerprint (``tls_pin``). DigitalOcean pins none.

An account is used by every environment row that names it and isn't deleted (``new``, ``live`` and
``deleting`` alike: those can still hold billing objects), and by every machine row. Remove is refused
while anything uses it; an account only deleted environments point at is kept as a tombstone.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import logging
import re
import time
import uuid
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from slipway.models import Environment, Machine, ProviderAccount, ProviderKind, User
from slipway.models.provider import ACCOUNT_NAME_RE, AccountStatus
from slipway.services import audit, digitalocean, do_rules, esxi, proxmox, tls_pin
from slipway.services.vmtypes import AccountInvalid, Check, status_of

log = logging.getLogger(__name__)

LABELS = {"digitalocean": "DigitalOcean", "proxmox": "Proxmox", "esxi": "ESXi"}
PROVIDER_KINDS = tuple(kind.value for kind in ProviderKind)

NAME_RE = re.compile(ACCOUNT_NAME_RE)
REGION_RE = re.compile(r"^[a-z]{3}[0-9]$")
DO_TOKEN_RE = re.compile(r"^[!-~]{1,200}$")  # 1-200 printable characters, no spaces (it goes in a header)
LIMIT_MAX = 100_000_000_00  # a monthly limit above a hundred million dollars is a typo
HINT_LEN = 4
CATALOG_TTL = 600.0  # seconds a catalog read stays fresh for the pages (§8)
SCOPES_NOTE = "Slipway can't check that the token may create and delete these without making one."

# Which fields each provider's account has (besides name and secret). Anything else is refused by field.
DO_FIELDS = frozenset({"production", "region", "ssh_sources", "monthly_limit_cents", "prices", "clear_secret"})
PROXMOX_FIELDS = frozenset({"url", "node", "pool", "storage", "template_vmid", "networks", "trust_fingerprint"})
ESXI_FIELDS = frozenset({"url", "user", "datastore", "resource_pool", "source_vm", "networks", "trust_fingerprint"})
# Fields where an explicit null means "clear it" (the rest treat null as "not given").
NULLABLE = frozenset({"monthly_limit_cents", "prices"})

# Tests swap this for the fake's clock, so the catalog cache's ten minutes take no time.
monotonic: Callable[[], float] = time.monotonic


class AccountRefused(Exception):
    """A refusal the API answers with ``status`` and ``body()``: the text, and a field, code or certificate."""

    def __init__(self, status: int, text: str, *, field: str | None = None, code: str | None = None,
                 certificate: dict[str, Any] | None = None) -> None:
        super().__init__(text)
        self.status = status
        self.text = text
        self.field = field
        self.code = code
        self.certificate = certificate

    def body(self) -> dict[str, Any]:
        out: dict[str, Any] = {"detail": self.text}
        if self.field:
            out["field"] = self.field
        if self.code:
            out["code"] = self.code
        if self.certificate is not None:
            out["certificate"] = self.certificate
        return out


@dataclass(frozen=True)
class TestAnswer:
    """What every provider's Test answers (and what the row keeps)."""

    status: str
    checks: list[dict[str, Any]]
    facts: dict[str, Any]

    __test__ = False  # not a pytest class

    def to_json(self) -> dict[str, Any]:
        return {"status": self.status, "checks": self.checks, "facts": self.facts}


def _now() -> datetime:
    return datetime.now(UTC)


def label(provider: str) -> str:
    return LABELS.get(provider, provider)


def _names(items: Iterable[str]) -> str:
    items = list(items)
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


# --------------------------------------------------------------------------- reads


async def get(db: AsyncSession, account_id: uuid.UUID, *, lock: bool = False) -> ProviderAccount | None:
    stmt = select(ProviderAccount).where(ProviderAccount.id == account_id).execution_options(populate_existing=True)
    if lock:
        stmt = stmt.with_for_update()
    return await db.scalar(stmt)


async def list_accounts(db: AsyncSession, provider: str | None = None) -> list[ProviderAccount]:
    stmt = select(ProviderAccount).order_by(ProviderAccount.provider, ProviderAccount.name)
    if provider:
        stmt = stmt.where(ProviderAccount.provider == provider)
    return list(await db.scalars(stmt))


async def environments_using(db: AsyncSession, account_id: uuid.UUID) -> list[Environment]:
    """Every environment that uses the account: it names the account and isn't deleted (new, live, deleting)."""
    stmt = (select(Environment).where(Environment.provider_account_id == account_id, Environment.deleted_at.is_(None))
            .order_by(Environment.name))
    return list(await db.scalars(stmt))


async def any_environment_row(db: AsyncSession, account_id: uuid.UUID) -> bool:
    """Whether any environment row points at the account, deleted ones included (RESTRICT keeps it then)."""
    found = await db.scalar(select(Environment.id).where(Environment.provider_account_id == account_id).limit(1))
    return found is not None


async def machines_using(db: AsyncSession, account_id: uuid.UUID) -> list[tuple[Machine, str]]:
    """Every machine row on the account, with its environment's name."""
    stmt = (select(Machine, Environment.name).join(Environment, Environment.id == Machine.environment_id)
            .where(Machine.account_id == account_id).order_by(Environment.name, Machine.slot))
    return [(machine, name) for machine, name in (await db.execute(stmt)).all()]


async def used_by(db: AsyncSession, account: ProviderAccount) -> list[dict[str, Any]]:
    """``ProviderAccountOut.used_by``: the environments (DigitalOcean) or the VMs (Proxmox, ESXi) using it."""
    out: list[dict[str, Any]] = [{"environment": env.name, "environment_id": env.id, "slot": None, "name": None}
                                 for env in await environments_using(db, account.id)]
    out += [{"environment": env_name, "environment_id": machine.environment_id, "slot": machine.slot,
             "name": machine.name} for machine, env_name in await machines_using(db, account.id)]
    return out


def _cost_cents(env: Environment) -> int:
    value = ((env.cloud or {}).get("cost") or {}).get("total_cents")
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


async def estimate_cents(db: AsyncSession, account_id: uuid.UUID, *,
                         except_environment: uuid.UUID | None = None) -> int:
    """The sum of ``cloud.cost.total_cents`` over the environments using the account (§12.2's limit check)."""
    return sum(_cost_cents(env) for env in await environments_using(db, account_id) if env.id != except_environment)


# ------------------------------------------------------------------- small checks


def clean_name(value: Any) -> str:
    name = value.strip() if isinstance(value, str) else ""
    if not NAME_RE.fullmatch(name):
        raise AccountInvalid("name", "Give the account a name of up to 64 letters, digits, spaces, '.', '_' or '-', "
                                     "starting with a letter or digit")
    return name


async def _check_name_free(db: AsyncSession, name: str, *, except_id: uuid.UUID | None = None) -> None:
    rows = await db.scalars(select(ProviderAccount))
    for other in rows:
        if other.id != except_id and other.name.lower() == name.lower():
            if other.is_removed:
                raise AccountRefused(409, f"An account named {other.name} already exists: it was removed, but keeps "
                                          "its name so old logs can still name it. Pick another name", field="name")
            raise AccountRefused(409, f"An account named {other.name} already exists", field="name")


def clean_do_token(value: Any) -> str:
    token = value.strip() if isinstance(value, str) else ""
    if not token:
        raise AccountInvalid("secret", "Paste the API token (DigitalOcean shows it once; it starts dop_v1_)")
    if not DO_TOKEN_RE.fullmatch(token):
        raise AccountInvalid("secret", "That isn't an API token: it should be up to 200 characters with no spaces, "
                                       "such as dop_v1_…")
    return token


def clean_region(value: Any) -> str:
    region = value.strip() if isinstance(value, str) else ""
    if not REGION_RE.fullmatch(region):
        raise AccountInvalid("region", "Pick a region such as nyc3 or fra1")
    return region


def clean_ssh_sources(value: Any) -> list[str]:
    if not isinstance(value, list):
        raise AccountInvalid("ssh_sources", "SSH sources must be a list of addresses")
    try:
        return do_rules.normalise_ssh_sources(value)
    except do_rules.DoRuleError as exc:
        raise AccountInvalid("ssh_sources", str(exc)) from None


def clean_limit(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= LIMIT_MAX:
        raise AccountInvalid("monthly_limit_cents", "The monthly limit must be whole cents, more than 0 "
                                                    "(leave it empty for no limit)")
    return value


def clean_prices(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    try:
        return do_rules.check_prices(value)
    except do_rules.DoRuleError as exc:
        raise AccountInvalid("prices", str(exc)) from None


def team_of(answer: dict[str, Any]) -> dict[str, str]:
    """The team ``GET /account`` answers for, ``{id, name}``.

    A personal account's id is ``personal:<uuid or email>``.
    """
    team = answer.get("team") if isinstance(answer.get("team"), dict) else {}
    if team.get("uuid"):
        team_id = str(team["uuid"])
        return {"id": team_id[:80], "name": str(team.get("name") or team_id)[:80]}
    who = answer.get("uuid") or answer.get("email") or "unknown"
    return {"id": f"personal:{who}"[:80], "name": "Personal account"}


def redactions(account: Any) -> list[str]:
    """What a job's redactor hides for this account: the secret (and a Proxmox token's secret part)."""
    secret = getattr(account, "secret", None)
    if not secret:
        return []
    if getattr(account, "provider", None) == ProviderKind.PROXMOX:
        return proxmox.redactions(secret)
    return [secret]


def _secret_hint(provider: str, secret: str, config: dict[str, Any]) -> str:
    if provider == ProviderKind.PROXMOX:
        return str(config.get("token_id") or "")[-HINT_LEN:]
    if provider == ProviderKind.ESXI:
        return "set"
    return secret[-HINT_LEN:]


def _secret_word(provider: str) -> str:
    return "password" if provider == ProviderKind.ESXI else "token"


def _fields_for(provider: str, fields: dict[str, Any]) -> dict[str, Any]:
    """The fields that apply to ``provider``; one meant for another provider is refused by name."""
    allowed = {ProviderKind.DIGITALOCEAN: DO_FIELDS, ProviderKind.PROXMOX: PROXMOX_FIELDS,
               ProviderKind.ESXI: ESXI_FIELDS}[ProviderKind(provider)] | {"name", "secret", "provider"}
    for key in sorted(fields):
        if key not in allowed:
            raise AccountInvalid(key, f"A {label(provider)} account has no {key} setting")
    return {k: v for k, v in fields.items() if v is not None or k in NULLABLE}


# ------------------------------------------------------------------ certificates


def certificate_view(pem: str) -> dict[str, Any]:
    """What a trust dialog shows of a live certificate: never its PEM, which nobody compares by eye."""
    cert = tls_pin.load_one(pem)
    described = tls_pin.describe(pem)
    return {"fingerprint_sha256": described["fingerprint_sha256"], "subject": described["subject"],
            "issuer": described["issuer"], "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": described["not_after"], "sans": described["sans"]}


def _default_port(provider: str) -> int:
    return proxmox.DEFAULT_PORT if provider == ProviderKind.PROXMOX else 443


async def live_certificate(provider: str, url: str) -> str:
    """The leaf certificate the account's URL presents now, unverified (``tls_pin.read_certificate``)."""
    try:
        host, port = tls_pin.url_host_port(url, _default_port(provider))
        return await tls_pin.read_certificate(host, port)
    except tls_pin.TlsPinError as exc:
        raise AccountRefused(502, str(exc)) from None


def _trusted(pem: str, fingerprint: str, *, field: str, actor: User | None, what: str) -> dict[str, Any]:
    """The ``tls`` value for ``pem`` when ``fingerprint`` is its own; 409 ``tls_mismatch`` otherwise."""
    try:
        wanted = tls_pin.normalize_fingerprint(fingerprint)
    except tls_pin.TlsPinError as exc:
        raise AccountInvalid(field, str(exc)) from None
    if not tls_pin.matches(pem, wanted):
        raise AccountRefused(409, f"That fingerprint isn't the certificate {what} presents now: compare them again",
                             field=field, code="tls_mismatch", certificate=certificate_view(pem))
    return {**tls_pin.describe(pem), "trusted_at": _now().isoformat(),
            "trusted_by": actor.email if actor is not None else None}


def _untrusted(pem: str, provider: str, what: str) -> AccountRefused:
    return AccountRefused(409, f"Slipway doesn't trust {what}'s certificate yet: compare its fingerprint with the one "
                               f"{label(provider)} shows, then trust it", code="tls_untrusted",
                          certificate=certificate_view(pem))


def _where(url: str, provider: str) -> str:
    try:
        host, port = tls_pin.url_host_port(url, _default_port(provider))
    except tls_pin.TlsPinError:
        return url
    return f"{host}:{port}"


# ---------------------------------------------------------------- per-provider config


def _do_config(stored: dict[str, Any], fields: dict[str, Any], *, creating: bool) -> dict[str, Any]:
    out = {"region": stored.get("region"), "ssh_sources": list(stored.get("ssh_sources") or []),
           "monthly_limit_cents": stored.get("monthly_limit_cents"), "prices": stored.get("prices"),
           "team": stored.get("team")}
    if creating or "region" in fields:
        out["region"] = clean_region(fields.get("region"))
    if creating or "ssh_sources" in fields:
        out["ssh_sources"] = clean_ssh_sources(fields.get("ssh_sources"))
    if "monthly_limit_cents" in fields:
        out["monthly_limit_cents"] = clean_limit(fields["monthly_limit_cents"])
    if "prices" in fields:
        out["prices"] = clean_prices(fields["prices"])
    return out


_PROXMOX_KEYS = ("url", "node", "pool", "storage", "template_vmid", "networks")


def _proxmox_config(stored: dict[str, Any], fields: dict[str, Any], secret: str | None) -> dict[str, Any]:
    merged = {k: stored[k] for k in _PROXMOX_KEYS if k in stored}
    merged.update({k: v for k, v in fields.items() if k in _PROXMOX_KEYS})
    out = proxmox.clean_config(merged, secret)
    if "token_id" not in out and stored.get("token_id"):
        out["token_id"] = stored["token_id"]  # the stored token is kept
    return out


def _esxi_config(stored: dict[str, Any], fields: dict[str, Any], secret: str | None) -> dict[str, Any]:
    merged = {k: stored[k] for k in esxi.CONFIG_KEYS if k in stored}
    merged.update({k: v for k, v in fields.items() if k in esxi.CONFIG_KEYS})
    return esxi.clean_config(merged, secret)


def _hypervisor_secret(provider: str, value: str) -> str:
    """A secret ``clean_config`` has checked, as stored: a Proxmox token without stray spaces, a password as typed."""
    return value.strip() if provider == ProviderKind.PROXMOX else value


def _connection(provider: str, config: dict[str, Any]) -> tuple[str, ...]:
    """What the secret was saved for: the URL, and ESXi's user. The secret goes nowhere else."""
    url = str(config.get("url") or "")
    if provider == ProviderKind.ESXI:
        return (url, str(config.get("user") or ""))
    if provider == ProviderKind.PROXMOX and url:
        try:
            url = proxmox.clean_url(url)  # a URL stored before the port was written in names the same endpoint
        except AccountInvalid:
            pass
    return (url,)


# ------------------------------------------------------------------------- Test


async def _do_read(client: digitalocean.DigitalOceanClient, path: str) -> dict[str, Any]:
    return await client._call("GET", path, params={"per_page": 1})


DO_READS = (("vpcs", "/vpcs", "VPCs"), ("databases", "/databases", "databases"),
            ("spaces_keys", "/spaces/keys", "Spaces keys"), ("certificates", "/certificates", "certificates"),
            ("load_balancers", "/load_balancers", "load balancers"), ("firewalls", "/firewalls", "firewalls"))


async def do_test(token: str, region: str | None) -> tuple[list[Check], dict[str, Any], dict[str, str] | None]:
    """DigitalOcean's Test (§8): the account, the region, the droplet count, and one read of each kind.

    Reads only. Answers the checks, the facts and the team the token answers for (None when the token
    couldn't be read at all).
    """
    checks: list[Check] = []
    facts: dict[str, Any] = {}
    async with digitalocean.DigitalOceanClient(token) as client:
        try:
            answer = await client.account()
        except digitalocean.DigitalOceanError as exc:
            return [Check.failed("account", str(exc))], facts, None
        team = team_of(answer)
        status = str(answer.get("status") or "")
        limit = answer.get("droplet_limit")
        facts.update(team=team, account_status=status[:20])
        if isinstance(limit, int) and not isinstance(limit, bool):
            facts["droplet_limit"] = limit
        if status == "active":
            checks.append(Check.passed("account", f"Team {team['name']}, the account is active"))
        else:
            checks.append(Check.failed("account", f"DigitalOcean says the account is {status[:20] or 'not active'}: "
                                                  "it can't make anything until that is fixed"))

        if region:
            try:
                regions = await client.regions()
                found = next((r for r in regions if r.get("slug") == region), None)
                if found is None or not found.get("available"):
                    checks.append(Check.failed("region", f"{region} isn't open for new objects in DigitalOcean"))
                elif region not in do_rules.SPACES_REGIONS:
                    checks.append(Check.warning("region", f"{region} has no Spaces, which an environment's bucket "
                                                          "needs: environments here need another region"))
                else:
                    checks.append(Check.passed("region", f"{region} is open, with Spaces"))
            except digitalocean.DigitalOceanError as exc:
                checks.append(Check.failed("region", str(exc)))

        try:
            data = await _do_read(client, "/droplets")
            total = (data.get("meta") or {}).get("total")
            count = total if isinstance(total, int) and not isinstance(total, bool) else len(data.get("droplets") or [])
            facts["droplet_count"] = count
            if "droplet_limit" in facts and count >= facts["droplet_limit"]:
                checks.append(Check.warning("droplets", f"The account has {count} droplets, at its limit of "
                                                        f"{facts['droplet_limit']}: DigitalOcean would refuse a "
                                                        "new one"))
            elif "droplet_limit" in facts and facts["droplet_limit"] - count < 2:
                checks.append(Check.warning("droplets", f"The account has {count} droplets of its "
                                                        f"{facts['droplet_limit']}: room for one more, and Blue/Green "
                                                        "needs two"))
            else:
                of = f" of {facts['droplet_limit']}" if "droplet_limit" in facts else ""
                checks.append(Check.passed("droplets", f"{count} droplet{'' if count == 1 else 's'}{of}"))
        except digitalocean.DigitalOceanError as exc:
            checks.append(Check.failed("droplets", str(exc)))

        for name, path, what in DO_READS:
            try:
                await _do_read(client, path)
                checks.append(Check.passed(name, f"The token can read {what}"))
            except digitalocean.DigitalOceanError as exc:
                checks.append(Check.failed(name, str(exc)))
    checks.append(Check.note("scopes", SCOPES_NOTE))
    return checks, facts, team


async def _run_test(account: ProviderAccount) -> tuple[list[Check], dict[str, Any], dict[str, str] | None]:
    if account.provider == ProviderKind.DIGITALOCEAN:
        if not account.secret:
            return [Check.failed("token", f"{account.name} has no API token: save one, then test again")], {}, None
        return await do_test(account.secret, (account.config or {}).get("region"))
    if account.provider == ProviderKind.PROXMOX:
        result = await proxmox.run_test(account)
        return list(result.checks), dict(result.facts), None
    found = await esxi.run_test(account)
    return list(found), dict(account.facts or {}), None


def _tested_with(account: ProviderAccount) -> bytes:
    """A digest of what a Test's answer is about: the secret, the connection (URL, ESXi's user) and the pinned
    certificate. Only the digest is kept, so the secret isn't held a second time."""
    digest = hashlib.sha256()
    pinned = (account.tls or {}).get("fingerprint_sha256")
    for part in (str(account.provider), account.secret or "", *_connection(account.provider, account.config or {}),
                 str(pinned or "")):
        data = part.encode()
        digest.update(len(data).to_bytes(8, "big") + data)
    return digest.digest()


def _test_audit(account: ProviderAccount, answer: TestAnswer) -> dict[str, Any]:
    return {"name": account.name, "provider": account.provider, "status": answer.status,
            "checks": [{"name": c["name"], "level": c["level"]} for c in answer.checks]}


async def test(db: AsyncSession, account: ProviderAccount, *, actor: User | None, request: Request | None = None,
               summary: str | None = None) -> TestAnswer:
    """``POST /provider-accounts/{id}/test``: runs the provider's Test and keeps its status, checks and facts.

    No lock is held while the provider answers. A test of a DigitalOcean account no environment uses
    remembers the team the token answers for; while environments use it, a token of another team fails.
    """
    _refuse_removed(account)
    account_id = account.id
    tested = _tested_with(account)
    await db.commit()  # nothing is held open while the provider answers
    checks, facts, team = await _run_test(account)
    account = await get(db, account_id, lock=True)
    if account is None:
        raise AccountRefused(404, "Provider account not found")
    if not hmac.compare_digest(_tested_with(account), tested):
        # Someone saved another secret, address or certificate while the provider answered: this answer is about
        # what the account was, so it must not become the new one's status, facts or team.
        name = account.name
        await db.rollback()
        raise AccountRefused(409, f"{name} changed while the Test ran: test again", code="test_stale")
    if account.provider == ProviderKind.DIGITALOCEAN and team is not None:
        envs = await environments_using(db, account.id)
        frozen = _frozen_team(account, envs)
        if envs and frozen is not None and frozen["id"] != team["id"]:
            checks.insert(1, Check.failed("team", _team_text(envs, frozen, team)))
        elif not envs or frozen is None:
            account.config = {**(account.config or {}), "team": team}
    answer = TestAnswer(status_of(checks), [c.to_dict() for c in checks], facts)
    account.status = answer.status
    account.checks = answer.checks
    account.facts = dict(facts)
    account.last_checked_at = _now()
    audit.record(db, "provider_account.test", actor=actor, target=account, target_type="provider_account",
                 summary=summary or f"Tested {label(account.provider)} account {account.name}: {answer.status}",
                 details=_test_audit(account, answer), request=request)
    await db.commit()
    return answer


async def test_unsaved(secret: Any, region: Any = None) -> TestAnswer:
    """``POST /provider-accounts/test``: a DigitalOcean token not saved yet. Writes nothing."""
    token = clean_do_token(secret)
    if region not in (None, ""):
        region = clean_region(region)
    checks, facts, _team = await do_test(token, region or None)
    return TestAnswer(status_of(checks), [c.to_dict() for c in checks], facts)


async def test_in_background(account_id: uuid.UUID, actor_id: uuid.UUID | None) -> None:
    """The Test a new Proxmox or ESXi account gets once, after the create's answer (phase 5 §9.1)."""
    from slipway.db.session import get_sessionmaker

    try:
        async with get_sessionmaker()() as db:
            account = await get(db, account_id)
            if account is None or account.is_removed:
                return
            actor = await db.get(User, actor_id) if actor_id else None
            await test(db, account, actor=actor, summary=f"Tested {label(account.provider)} account {account.name} "
                                                         "after it was added")
    except AccountRefused as exc:  # changed or removed meanwhile: the row keeps what the change gave it
        log.info("The first test of provider account %s was not kept: %s", account_id, exc.text)
    except Exception:  # noqa: BLE001  (a background test must never take the app down; the row keeps its status)
        log.exception("The first test of provider account %s failed", account_id)


# ------------------------------------------------------------------ DigitalOcean team


def _frozen_team(account: ProviderAccount, envs: list[Environment]) -> dict[str, str] | None:
    """The team the account's environments were built in: theirs when frozen, else the account's."""
    stored = (account.config or {}).get("team") or None
    for env in envs:
        if env.provider_team:
            name = stored["name"] if stored and stored.get("id") == env.provider_team else env.provider_team
            return {"id": env.provider_team, "name": name}
    return stored


def _team_text(envs: list[Environment], frozen: dict[str, str], other: dict[str, str]) -> str:
    n = len(envs)
    return (f"{n} environment{'s were' if n != 1 else ' was'} built in team {frozen['name']}; a token for "
            f"{other['name']} can't manage {'them' if n != 1 else 'it'}")


async def read_team(token: str) -> dict[str, str]:
    """The team a token answers for (``GET /account``); a token DigitalOcean refuses is a 422 on ``secret``."""
    try:
        async with digitalocean.DigitalOceanClient(token) as client:
            return team_of(await client.account())
    except digitalocean.Unauthorized as exc:
        raise AccountInvalid("secret", str(exc)) from None
    except digitalocean.DigitalOceanError as exc:
        raise AccountRefused(502, f"Slipway couldn't read the token's team, so nothing was saved: {exc}") from None


async def _token_taken(db: AsyncSession, token: str, *, except_id: uuid.UUID | None) -> ProviderAccount | None:
    rows = await db.scalars(select(ProviderAccount).where(ProviderAccount.provider == ProviderKind.DIGITALOCEAN,
                                                          ProviderAccount.secret.is_not(None)))
    for other in rows:
        if other.id != except_id and other.secret and hmac.compare_digest(other.secret.encode(), token.encode()):
            return other
    return None


def _contains(sources: list[str], address: str) -> bool:
    try:
        ip = ipaddress.ip_address(str(address).strip())
    except ValueError:
        return True  # nothing Slipway could have connected from; not a lock-out
    for source in sources:
        try:
            if ip in ipaddress.ip_network(source, strict=False):
                return True
        except ValueError:
            continue
    return False


def _lockout(envs: list[Environment], sources: list[str]) -> str | None:
    for env in envs:
        for address in (env.cloud or {}).get("slipway_addresses") or []:
            if not _contains(sources, address):
                return (f"Slipway connects to {env.name}'s droplets from {address}, which these SSH sources leave out: "
                        "Slipway would lose SSH to them, and with it backups, snapshots and Delete")
    return None


def _production_problem(account_name: str, production: bool, envs: list[Environment]) -> str | None:
    if production:
        plain = [env.name for env in envs if not env.production]
        if plain:
            return (f"{_names(plain)} use{'s' if len(plain) == 1 else ''} {account_name} and "
                    f"{'isn' if len(plain) == 1 else 'aren'}'t production: a production account serves only "
                    "production environments")
    else:
        prod = [env.name for env in envs if env.production]
        if prod:
            return f"{_names(prod)} {'is a' if len(prod) == 1 else 'are'} production environment" \
                   f"{'' if len(prod) == 1 else 's'} using {account_name}: it stays a production account"
    return None


# ------------------------------------------------------------------------ create


def _audit_details(account: ProviderAccount, **extra: Any) -> dict[str, Any]:
    details: dict[str, Any] = {"name": account.name, "provider": account.provider, "production": account.production}
    config = account.config or {}
    if account.provider == ProviderKind.DIGITALOCEAN:
        details["region"] = config.get("region")
    else:
        details["url"] = config.get("url")
    details.update(extra)
    return details


async def _commit(db: AsyncSession, name: str, *, flush_only: bool = False) -> None:
    """Commits (or flushes); a name another save took meanwhile (``uq_provider_accounts_name``) is the 409 the
    check before it gives."""
    try:
        await (db.flush() if flush_only else db.commit())
    except IntegrityError as exc:
        await db.rollback()
        text = str(exc.orig)
        if "uq_provider_accounts_name" not in text and "provider_accounts.name" not in text:
            raise
        raise AccountRefused(409, f"An account named {name} already exists", field="name") from None


async def create(db: AsyncSession, fields: dict[str, Any], *, actor: User | None,
                 request: Request | None = None) -> ProviderAccount:
    """``POST /provider-accounts``. Refusals in P5 §9.1's order; nothing is written when one applies.

    A Proxmox or ESXi account is saved only with its certificate trusted: without ``trust_fingerprint``
    the live certificate comes back in a 409 ``tls_untrusted`` for the person to compare.
    """
    provider = fields.get("provider")
    if provider not in PROVIDER_KINDS:
        raise AccountInvalid("provider", "Pick DigitalOcean, Proxmox or ESXi")
    fields = _fields_for(provider, fields)
    name = clean_name(fields.get("name"))
    await _check_name_free(db, name)
    account = ProviderAccount(provider=provider, name=name, created_by_id=actor.id if actor else None,
                              updated_by_id=actor.id if actor else None)
    trust_details: dict[str, Any] | None = None

    if provider == ProviderKind.DIGITALOCEAN:
        config = _do_config({}, fields, creating=True)
        config["team"] = None  # learned by Test or the first prepare
        token = clean_do_token(fields["secret"]) if fields.get("secret") not in (None, "") else None
        if token is not None:
            other = await _token_taken(db, token, except_id=None)
            if other is not None:
                raise AccountRefused(409, f"This token already belongs to account {other.name}", field="secret")
        account.production = bool(fields.get("production", False))
        account.config = config
        if token is not None:
            account.secret = token
            account.secret_hint = _secret_hint(provider, token, config)
    else:
        given = fields.get("secret") if fields.get("secret") not in (None, "") else None
        config = (_proxmox_config if provider == ProviderKind.PROXMOX else _esxi_config)({}, fields, given)
        if given is None:
            raise AccountInvalid("secret", f"Give the {label(provider)} {_secret_word(provider)}")
        secret = _hypervisor_secret(provider, given)
        what = _where(config["url"], provider)
        pem = await live_certificate(provider, config["url"])
        if not fields.get("trust_fingerprint"):
            raise _untrusted(pem, provider, what)
        account.tls = _trusted(pem, fields["trust_fingerprint"], field="trust_fingerprint", actor=actor, what=what)
        account.config = config
        account.secret = secret
        account.secret_hint = _secret_hint(provider, secret, config)
        trust_details = {"name": name, "provider": provider, "fingerprint": account.tls["fingerprint_sha256"],
                         "subject": account.tls["subject"], "not_after": account.tls["not_after"]}

    db.add(account)
    await _commit(db, name, flush_only=True)  # the audit rows need the id
    audit.record(db, "provider_account.create", actor=actor, target=account, target_type="provider_account",
                 summary=f"Added {label(provider)} account {name}", details=_audit_details(account), request=request)
    if trust_details is not None:
        audit.record(db, "provider_account.trust", actor=actor, target=account, target_type="provider_account",
                     summary=f"Trusted {name}'s certificate {trust_details['fingerprint'][:23]}…",
                     details=trust_details, request=request)
    await _commit(db, name)
    return account


# ------------------------------------------------------------------------ update


def _refuse_removed(account: ProviderAccount) -> None:
    if account.is_removed:
        raise AccountRefused(409, f"{account.name} was removed: add a new account instead")


async def update(db: AsyncSession, account: ProviderAccount, fields: dict[str, Any], *, actor: User | None,
                 request: Request | None = None) -> ProviderAccount:
    """``PATCH /provider-accounts/{id}``: partial; an omitted field keeps its value."""
    _refuse_removed(account)
    fields = _fields_for(account.provider, {k: v for k, v in fields.items() if k != "provider"})
    if account.provider == ProviderKind.DIGITALOCEAN:
        return await _update_do(db, account, fields, actor=actor, request=request)
    return await _update_hypervisor(db, account, fields, actor=actor, request=request)


async def _update_do(db: AsyncSession, account: ProviderAccount, fields: dict[str, Any], *, actor: User | None,
                     request: Request | None) -> ProviderAccount:
    account_id = account.id
    name = clean_name(fields["name"]) if "name" in fields else account.name
    if name != account.name:
        await _check_name_free(db, name, except_id=account_id)
    config = _do_config(account.config or {}, fields, creating=False)
    clear = bool(fields.get("clear_secret"))
    token = None
    if fields.get("secret") not in (None, ""):
        if clear:
            raise AccountInvalid("secret", "Either paste a new token or clear it, not both")
        token = clean_do_token(fields["secret"])
        if account.secret and hmac.compare_digest(account.secret.encode(), token.encode()):
            token = None  # the same token again changes nothing
    if token is not None:
        other = await _token_taken(db, token, except_id=account_id)
        if other is not None:
            raise AccountRefused(409, f"This token already belongs to account {other.name}", field="secret")

    # The new token's team is read before the row is locked: no HTTP call is made under the lock (§8).
    envs = await environments_using(db, account_id)
    team = await read_team(token) if token is not None and envs else None

    locked = await get(db, account_id, lock=True)
    if locked is None:
        raise AccountRefused(404, "Provider account not found")
    account = locked
    envs = await environments_using(db, account_id)
    if token is not None and envs:
        if team is None:
            raise AccountRefused(409, "Save again: an environment started using this account")
        frozen = _frozen_team(account, envs)
        if frozen is not None and frozen["id"] != team["id"]:
            raise AccountRefused(409, _team_text(envs, frozen, team), field="secret")
    if clear and account.secret and envs:
        raise AccountRefused(409, f"{_names([e.name for e in envs])} use{'s' if len(envs) == 1 else ''} "
                                  f"{account.name}: its token can't be cleared", field="clear_secret")
    production = bool(fields["production"]) if "production" in fields else account.production
    problem = _production_problem(account.name, production, envs)
    if problem and production != account.production:
        raise AccountRefused(409, problem, field="production")
    if "ssh_sources" in fields and envs:
        problem = _lockout(envs, config["ssh_sources"])
        if problem:
            raise AccountRefused(409, problem, field="ssh_sources")

    changed: list[str] = []
    if name != account.name:
        changed.append("name")
    for key in ("region", "ssh_sources", "monthly_limit_cents", "prices"):
        if config.get(key) != (account.config or {}).get(key):
            changed.append(key)
    if production != account.production:
        changed.append("production")
    if token is not None:
        config["team"] = team if envs else None  # with no environment it is learned again by Test
        account.secret = token
        account.secret_hint = _secret_hint(account.provider, token, config)
        _forget_test(account)
        changed.append("token replaced")
    elif clear and account.secret:
        config["team"] = None
        account.secret = None
        account.secret_hint = ""
        _forget_test(account)
        changed.append("token cleared")
    account.name = name
    account.production = production
    account.config = config
    account.updated_by_id = actor.id if actor else None
    audit.record(db, "provider_account.update", actor=actor, target=account, target_type="provider_account",
                 summary=_changed_summary("DigitalOcean", account.name, changed),
                 details=_audit_details(account, changed=changed), request=request)
    await _commit(db, name)
    return account


def _changed_summary(provider_label: str, name: str, changed: list[str]) -> str:
    return f"Changed {provider_label} account {name}" + (f" ({', '.join(changed)})" if changed else "")


def _forget_test(account: ProviderAccount) -> None:
    """A new secret or address makes the last Test's answer stale (a key-change error included)."""
    account.status = AccountStatus.UNKNOWN
    account.checks = []
    account.facts = {}
    account.last_checked_at = None


async def _update_hypervisor(db: AsyncSession, account: ProviderAccount, fields: dict[str, Any], *,
                             actor: User | None, request: Request | None) -> ProviderAccount:
    provider = account.provider
    word = _secret_word(provider)
    name = clean_name(fields["name"]) if "name" in fields else account.name
    if name != account.name:
        await _check_name_free(db, name, except_id=account.id)
    given = fields.get("secret") if fields.get("secret") not in (None, "") else None
    stored = dict(account.config or {})
    clean = _proxmox_config if provider == ProviderKind.PROXMOX else _esxi_config
    config = clean(stored, fields, given)
    secret = _hypervisor_secret(provider, given) if given is not None else None

    moved = _connection(provider, config) != _connection(provider, stored)
    machines = await machines_using(db, account.id)
    if moved and machines:
        url_moved = config.get("url") != stored.get("url")
        user_moved = config.get("user") != stored.get("user")
        what = "URL and user" if url_moved and user_moved else ("URL" if url_moved else "user")
        raise AccountRefused(409, f"{account.name} has VMs ({_names([m.name for m, _ in machines])}): its {what} can't "
                                  "change. Make another account for the new address",
                             field="url" if what != "user" else "user")
    kept = {net["name"] for net in config.get("networks") or []}
    for machine, _env in machines:
        network = (machine.network or {}).get("name")
        if network and network not in kept:
            users = [m.name for m, _ in machines if (m.network or {}).get("name") == network]
            raise AccountRefused(409, f"{network} is used by {_names(users)}", field="networks")
    if secret is None and moved:
        raise AccountInvalid("secret", f"Enter the {word} again: Slipway sends it only to the address it was saved for")
    if secret is None and not account.secret:
        raise AccountInvalid("secret", f"Give the {label(provider)} {word}")

    tls = account.tls
    trust_details: dict[str, Any] | None = None
    if moved:
        tls = None  # a new address must be trusted again
    if fields.get("trust_fingerprint"):
        what = _where(config["url"], provider)
        pem = await live_certificate(provider, config["url"])
        tls = _trusted(pem, fields["trust_fingerprint"], field="trust_fingerprint", actor=actor, what=what)
        trust_details = {"name": name, "provider": provider, "fingerprint": tls["fingerprint_sha256"],
                         "subject": tls["subject"], "not_after": tls["not_after"]}

    changed = [key for key in sorted(set(config) | set(stored))
               if key != "token_id" and config.get(key) != stored.get(key)]
    if name != account.name:
        changed.insert(0, "name")
    if secret is not None and secret != account.secret:
        changed.append(f"{word} replaced")
    if moved and tls is None:
        changed.append("certificate forgotten")
    if secret is not None and secret != account.secret or moved:
        _forget_test(account)
    account.name = name
    account.config = config
    if secret is not None:
        account.secret = secret
        account.secret_hint = _secret_hint(provider, secret, config)
    account.tls = tls
    account.updated_by_id = actor.id if actor else None
    audit.record(db, "provider_account.update", actor=actor, target=account, target_type="provider_account",
                 summary=_changed_summary(label(provider), account.name, changed),
                 details=_audit_details(account, changed=changed), request=request)
    if trust_details is not None:
        audit.record(db, "provider_account.trust", actor=actor, target=account, target_type="provider_account",
                     summary=f"Trusted {name}'s certificate {trust_details['fingerprint'][:23]}…",
                     details=trust_details, request=request)
    await _commit(db, name)
    return account


# ------------------------------------------------------------------------- trust


async def trust(db: AsyncSession, account: ProviderAccount, fingerprint: Any, *, actor: User | None,
                request: Request | None = None) -> ProviderAccount:
    """``POST /provider-accounts/{id}/trust``: pins the certificate the account's URL presents now, when it is
    the one the person compared (a renewed certificate, or a URL change that forgot the pin)."""
    _refuse_removed(account)
    if account.provider == ProviderKind.DIGITALOCEAN:
        raise AccountRefused(409, f"{account.name} is a DigitalOcean account: Slipway pins no certificate for it")
    url = str((account.config or {}).get("url") or "")
    what = _where(url, account.provider)
    account_id = account.id
    await db.commit()
    pem = await live_certificate(account.provider, url)
    tls = _trusted(pem, str(fingerprint or ""), field="fingerprint", actor=actor, what=what)
    account = await get(db, account_id, lock=True)
    if account is None:
        raise AccountRefused(404, "Provider account not found")
    if str((account.config or {}).get("url") or "") != url:
        raise AccountRefused(409, "Trust again: the account's URL changed meanwhile")
    account.tls = tls
    account.updated_by_id = actor.id if actor else None
    audit.record(db, "provider_account.trust", actor=actor, target=account, target_type="provider_account",
                 summary=f"Trusted {account.name}'s certificate {tls['fingerprint_sha256'][:23]}…",
                 details={"name": account.name, "provider": account.provider, "fingerprint": tls["fingerprint_sha256"],
                          "subject": tls["subject"], "not_after": tls["not_after"]}, request=request)
    await db.commit()
    return account


# ------------------------------------------------------------------------ remove


async def remove(db: AsyncSession, account: ProviderAccount, confirm: Any, *, actor: User | None,
                 request: Request | None = None) -> bool:
    """``DELETE /provider-accounts/{id} {confirm}``. True when the row was deleted, False when it was kept as a
    tombstone (only deleted environments point at it: RESTRICT keeps it, and their logs still name it)."""
    if confirm != account.name:
        raise AccountRefused(422, f"Type the account's name, {account.name}, exactly to confirm", field="confirm")
    _refuse_removed(account)
    account = await get(db, account.id, lock=True) or account
    envs = await environments_using(db, account.id)
    if envs:
        raise AccountRefused(409, f"Environment{'s' if len(envs) != 1 else ''} {_names([e.name for e in envs])} "
                                  f"use{'s' if len(envs) == 1 else ''} {account.name}; delete "
                                  f"{'them' if len(envs) != 1 else 'it'} first")
    machines = await machines_using(db, account.id)
    if machines:
        raise AccountRefused(409, f"{account.name} has VMs: {_names([m.name for m, _ in machines])}. "
                                  "Delete their environments first")
    kept = await any_environment_row(db, account.id)
    details = {"name": account.name, "provider": account.provider, "tombstone": kept}
    audit.record(db, "provider_account.delete", actor=actor, target=account, target_type="provider_account",
                 summary=f"Removed {label(account.provider)} account {account.name}", details=details, request=request)
    if kept:
        account.secret = None
        account.secret_hint = ""
        account.config = {}
        account.tls = None
        _forget_test(account)
        account.removed_at = _now()
        account.updated_by_id = actor.id if actor else None
    else:
        await db.delete(account)
    await db.commit()
    _catalog_cache_drop(account.id)
    return not kept


# ----------------------------------------------------------------------- catalog


_catalog_cache: dict[tuple[uuid.UUID, str, str], tuple[float, dict[str, Any]]] = {}


def _catalog_cache_drop(account_id: uuid.UUID) -> None:
    for key in [k for k in _catalog_cache if k[0] == account_id]:
        _catalog_cache.pop(key, None)


def clear_catalog_cache() -> None:
    _catalog_cache.clear()


async def catalog(account: ProviderAccount, region: str | None = None, *, fresh: bool = False) -> dict[str, Any]:
    """The account's catalog for ``region`` (``do_rules.build_catalog``): regions, sizes offered there with their
    prices, database sizes per node count, versions and Spaces. Cached ten minutes per account and region for
    the pages; ``fresh=True`` skips the cache (Create, Add slot and a growing PATCH, §12.2)."""
    _refuse_removed(account)
    if account.provider != ProviderKind.DIGITALOCEAN:
        raise AccountRefused(409, f"{account.name} is a {label(account.provider)} account: "
                                  "only DigitalOcean has a catalog")
    region = clean_region(region) if region else clean_region((account.config or {}).get("region"))
    if not account.secret:
        raise AccountRefused(409, f"{account.name} has no API token: save one first")
    key = (account.id, region, hashlib.sha256(account.secret.encode()).hexdigest()[:16])
    now = monotonic()
    hit = _catalog_cache.get(key)
    if hit is not None and not fresh and now - hit[0] < CATALOG_TTL:
        return hit[1]
    async with digitalocean.DigitalOceanClient(account.secret) as client:
        regions = await client.regions()
        sizes = await client.sizes()
        options = await client.database_options()
    built = do_rules.build_catalog(region, regions, sizes, options)
    _catalog_cache[key] = (now, built)
    return built


# --------------------------------------------------------------------- addresses (phase 5 §6.6, §11)


ADDRESS_COUNT = 10  # free addresses an addresses read lists unless asked for another count
ADDRESS_COUNT_MAX = 256
_HOLDER_PREFIXES = ("is reserved for ", "is used by ", "is ")


def _holder(phrase: str) -> str:
    """``machines.addresses_in_use``'s phrase as a noun: ``is used by host pve1`` -> ``host pve1``."""
    for prefix in _HOLDER_PREFIXES:
        if phrase.startswith(prefix):
            return phrase[len(prefix):]
    return phrase


async def addresses(db: AsyncSession, account: ProviderAccount, network: str | None = None,
                    count: int = ADDRESS_COUNT) -> dict[str, Any]:
    """``GET /provider-accounts/{id}/addresses`` (phase 5 §11): the lowest ``count`` free addresses of a network's
    pool, and what holds each address of its subnet that is taken (``machines.addresses_in_use``: claims, hosts,
    the accounts' API hosts, Switchyard, the gateway and the DNS servers). From Slipway's records only: no
    address is probed. Proxmox and ESXi accounts only; ``network`` may be left out when the account has one."""
    from slipway.services import machines, vmnet  # machines imports the providers, which import this module

    _refuse_removed(account)
    if account.provider == ProviderKind.DIGITALOCEAN:
        raise AccountRefused(409, f"{account.name} is a DigitalOcean account: its droplets get their addresses "
                                  "from DigitalOcean")
    if not 1 <= count <= ADDRESS_COUNT_MAX:
        raise AccountInvalid("count", f"Ask for 1 to {ADDRESS_COUNT_MAX} addresses")
    networks = list((account.config or {}).get("networks") or [])
    if network is None:
        if len(networks) != 1:
            names = _names(str(n.get("name")) for n in networks) or "none"
            raise AccountInvalid("network", f"Pick one of {account.name}'s networks: {names}")
        profile = networks[0]
    else:
        profile = vmnet.find_network(networks, network)
        if profile is None:
            raise AccountInvalid("network", f"{account.name} has no network named {network}")
    held = await machines.addresses_in_use(db, network=profile)
    subnet = vmnet.network_of(profile)
    free: list[str] = []
    skip = {profile.get("gateway"), *vmnet.dns_for(profile)}
    for address in vmnet.pool_range(profile):
        if len(free) >= count:
            break
        if address in skip or address in held:
            continue
        try:
            free.append(vmnet.check_address(address, profile))
        except ValueError:
            continue
    in_use = []
    for address, phrase in held.items():
        try:
            ip = ipaddress.IPv4Address(address)
        except ValueError:
            continue
        if ip in subnet:
            in_use.append((int(ip), {"address": address, "by": _holder(phrase), "text": f"{address} {phrase}"}))
    return {"network": profile.get("name"), "subnet": profile.get("subnet"), "pool": profile.get("pool"),
            "free": free, "in_use": [row for _, row in sorted(in_use, key=lambda pair: pair[0])]}


def catalog_out(built: dict[str, Any]) -> dict[str, Any]:
    """The API's shape of a catalog (P4 §16): ``{region, regions, sizes, db_sizes, db_versions, spaces}``."""
    return {"region": built["region"], "regions": built["regions"], "sizes": built["sizes"],
            "db_sizes": built["database_sizes"], "db_versions": built["database_versions"],
            "spaces": sorted(do_rules.SPACES_REGIONS), "region_has_spaces": built["spaces"]}


# -------------------------------------------------------------------- the dispatch


@dataclass(frozen=True)
class Provider:
    """What differs per provider, for callers that hold an account of any kind."""

    kind: str
    label: str
    secret_word: str
    pins_certificate: bool
    has_catalog: bool
    run_test: Callable[[ProviderAccount], Awaitable[tuple[list[Check], dict[str, Any], dict[str, str] | None]]]


PROVIDERS: dict[str, Provider] = {
    kind.value: Provider(kind.value, LABELS[kind.value], _secret_word(kind.value), kind.is_hypervisor,
                         kind is ProviderKind.DIGITALOCEAN, _run_test)
    for kind in ProviderKind
}
