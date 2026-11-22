"""The load balancer's certificate on DigitalOcean: which names, which certificate is ours, when to renew, issuing.

Phase 4 §11.2 and D12. Slipway is the only issuer and renewer: Let's Encrypt by DNS-01, the
challenge records in the Cloudflare zone, the result uploaded to DigitalOcean as a ``custom``
certificate named ``slipway-<env>-<UTC yyyymmddhhmm>``.

This module holds the parts that need neither a database nor a DigitalOcean client:

* the names (``wanted_names``: the union of every app slot's live names, plus the deploying slot's);
* ownership (``is_ours``, ``ours_for_teardown``), matched by the exact name pattern, never a prefix;
* choosing (``best``) and timing (``is_due``, ``needs_new``, ``kept_usable``), 30 days before expiry;
* the staging rule (``check_staging``, ``directory_url``);
* ``issue``, an ACME order over two small protocols, ``TxtRecords`` (the challenge records) and
  ``AccountKeys`` (one account key per directory), so the Cloudflare and ``app_settings`` adapters
  can live with the provisioner;
* ``sweep_challenges``, which removes challenge records a crashed run left behind.

The certificate's private key is only ever in memory and in the returned ``Issued``; the caller keeps
it encrypted on a pending ``resources`` row and adds it to the job's Redactor (``Issued.secrets``).
Nothing here logs it, the account key, or any request body.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from slipway.services import acme

RENEW_DAYS = 30  # renew at 30 days or fewer (D12)
MAX_NAMES = 100  # Let's Encrypt's limit for one certificate
DNS_SETTLE = 15  # seconds the challenge records are held before the ACME server is told (SD/certs.py:25)
CHALLENGE_PREFIX = "_acme-challenge."
CHALLENGE_COMMENT = "Managed by Slipway: ACME challenge"
LETSENCRYPT_DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory"
LETSENCRYPT_STAGING_DIRECTORY = "https://acme-staging-v02.api.letsencrypt.org/directory"
STAMP_FORMAT = "%Y%m%d%H%M"
HOSTNAME_RE = re.compile(r"^(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\Z")

Say = Callable[[str], Awaitable[None]]  # writes a line to the job's log
# Tests swap this so the DNS settle wait doesn't wait.
sleep: Callable[[float], Awaitable[None]] = asyncio.sleep


async def _quiet(_: str) -> None:
    return None


class CertError(RuntimeError):
    """A certificate rule refused, or issuing failed. ``str()`` is a plain-English message."""


# ------------------------------------------------------------------------ names


def certificate_name(env_name: str, now: datetime | None = None) -> str:
    """``slipway-<env>-<UTC yyyymmddhhmm>`` (§6.1)."""
    now = (now or datetime.now(UTC)).astimezone(UTC)
    return f"slipway-{env_name}-{now.strftime(STAMP_FORMAT)}"


def name_pattern(env_name: str) -> re.Pattern[str]:
    """The exact pattern of an environment's certificate names: ``prod``'s never matches ``prod-eu``'s."""
    return re.compile(rf"^slipway-{re.escape(env_name)}-[0-9]{{12}}\Z")


def _route_names(routes: Iterable[Any]) -> list[str]:
    """Hostnames from routes that follow the active slot: dicts or objects with ``hostname``/``follows``,
    or plain hostnames. On DigitalOcean every route follows the active slot; a server-following one is
    left out all the same, so the rule doesn't depend on that."""
    out: list[str] = []
    for route in routes:
        if isinstance(route, str):
            out.append(route)
            continue
        get = route.get if isinstance(route, Mapping) else (lambda k, d=None, r=route: getattr(r, k, d))
        if (get("follows", "active") or "active") != "active":
            continue
        hostname = get("hostname")
        if hostname:
            out.append(str(hostname))
    return out


def clean_names(names: Iterable[str]) -> list[str]:
    """Sorted, lower case, unique, each a plain hostname; at least one, at most ``MAX_NAMES``."""
    cleaned = sorted({str(n).strip().lower().rstrip(".") for n in names if str(n).strip()})
    if not cleaned:
        raise CertError("No names to put on a certificate: no slot serves any")
    bad = [n for n in cleaned if not HOSTNAME_RE.match(n)]
    if bad:
        raise CertError(f"These aren't hostnames a certificate can cover: {', '.join(bad[:5])}")
    if len(cleaned) > MAX_NAMES:
        raise CertError(f"A certificate covers at most {MAX_NAMES} names; the environment serves {len(cleaned)}")
    return cleaned


def wanted_names(live_routes: Iterable[Iterable[Any]], deploying: Iterable[Any] | None = None, *,
                 zone: str | None = None) -> list[str]:
    """The names the certificate must cover (§11.2 step 1).

    ``live_routes`` holds each app slot's live release's routes (``app_state.routes``), one list
    per slot; ``deploying`` the deploying slot's new release's routes during a deploy. The result is
    the sorted union, so a name leaves only when no slot's live release serves it. With ``zone``,
    every name must be inside the Cloudflare zone (DNS-01 can't prove any other).
    """
    names: list[str] = []
    for routes in live_routes:
        names.extend(_route_names(routes or ()))
    if deploying is not None:
        names.extend(_route_names(deploying))
    cleaned = clean_names(names)
    if zone:
        zone = zone.lower().rstrip(".")
        outside = [n for n in cleaned if n != zone and not n.endswith("." + zone)]
        if outside:
            raise CertError(f"{', '.join(outside[:5])} {'is' if len(outside) == 1 else 'are'} outside the "
                            f"Cloudflare zone {zone}, so Slipway can't prove {'it' if len(outside) == 1 else 'them'} "
                            "to Let's Encrypt")
    return cleaned


# ------------------------------------------------------------------------ ownership and choice


def dns_names(cert: Mapping[str, Any]) -> list[str]:
    return sorted({str(n).lower().rstrip(".") for n in cert.get("dns_names") or []})


def is_ours(cert: Mapping[str, Any], env_name: str, wanted: Iterable[str]) -> bool:
    """A listed DigitalOcean certificate is this environment's (§6.2): the exact name pattern and exactly
    the wanted names (Sirdar matched by prefix, ``SD/certs.py:44-51``)."""
    return bool(name_pattern(env_name).match(str(cert.get("name") or ""))) and dns_names(cert) == sorted(
        {n.lower().rstrip(".") for n in wanted})


def ours_for_teardown(cert: Mapping[str, Any], env_name: str, hostnames: Iterable[str]) -> bool:
    """Teardown's wider rule (§6.2): the name pattern, and every name one of the environment's hostnames."""
    if not name_pattern(env_name).match(str(cert.get("name") or "")):
        return False
    names = dns_names(cert)
    allowed = {h.lower().rstrip(".") for h in hostnames}
    return bool(names) and all(n in allowed for n in names)


def parse_time(value: Any) -> datetime | None:
    """An aware UTC datetime from DigitalOcean's ``not_after`` (ISO 8601, ``Z`` or an offset), or None."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if not value or not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return (parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)).astimezone(UTC)


def not_after(cert: Mapping[str, Any]) -> datetime | None:
    return parse_time(cert.get("not_after"))


def best(certs: Iterable[Mapping[str, Any]], served_id: str | None = None) -> Mapping[str, Any] | None:
    """The certificate expiring last; on a tie, the one the load balancer serves (``SD/do_provision.py:993-996``).
    One without a readable ``not_after`` counts as expiring first."""
    floor = datetime.min.replace(tzinfo=UTC)
    chosen: Mapping[str, Any] | None = None
    for cert in certs:
        if chosen is None:
            chosen = cert
            continue
        mine, theirs = not_after(cert) or floor, not_after(chosen) or floor
        if mine > theirs or (mine == theirs and served_id is not None and str(cert.get("id")) == str(served_id)):
            chosen = cert
    return chosen


def is_due(expires: datetime | None, now: datetime | None = None, days: int = RENEW_DAYS) -> bool:
    """30 days or fewer left (or no known expiry)."""
    if expires is None:
        return True
    now = now or datetime.now(UTC)
    return expires - now <= timedelta(days=days)


def needs_new(current: Mapping[str, Any] | None, wanted: Iterable[str], now: datetime | None = None) -> bool:
    """§11.2 step 4: none, due, or not exactly the wanted names."""
    if current is None:
        return True
    return is_due(not_after(current), now) or dns_names(current) != sorted({n.lower() for n in wanted})


def kept_usable(details: Mapping[str, Any], wanted: Iterable[str], now: datetime | None = None) -> bool:
    """A kept certificate (a pending row's details) can be uploaded again instead of a new order (§11.2 4a):
    exactly the wanted names and more than 30 days left."""
    return dns_names(details) == sorted({n.lower() for n in wanted}) and not is_due(not_after(details), now)


# ------------------------------------------------------------------------ staging


def check_staging(production: bool, staging: bool) -> None:
    """Production never uses staging certificates (D20, §13)."""
    if production and staging:
        raise CertError("A production environment can't use Let's Encrypt staging certificates")


def directory_url(*, staging: bool, production: bool = False, settings: Any = None) -> str:
    """The ACME directory for an environment: staging when ``cloud.acme_staging``, else the real one.
    ``settings`` (``core.config.Settings``) may carry ``acme_directory`` and ``acme_staging_directory``."""
    check_staging(production, staging)
    if staging:
        return getattr(settings, "acme_staging_directory", None) or LETSENCRYPT_STAGING_DIRECTORY
    return getattr(settings, "acme_directory", None) or LETSENCRYPT_DIRECTORY


# ------------------------------------------------------------------------ the protocols


@dataclass(frozen=True)
class TxtRecord:
    id: str
    name: str
    content: str
    comment: str | None = None


class TxtRecords(Protocol):
    """The challenge records' home: Cloudflare in the provisioner, a dict in tests."""

    async def create(self, name: str, content: str, comment: str) -> str:
        """Create a TXT record; returns its id."""

    async def list(self, comment: str) -> Sequence[TxtRecord]:
        """Every TXT record in the zone carrying exactly this comment."""

    async def delete(self, record_id: str) -> None:
        """Delete a record; a record already gone is not an error."""


@dataclass(frozen=True)
class AccountKey:
    directory: str
    pem: str = field(repr=False)
    kid: str | None = None

    def __repr__(self) -> str:  # never shows the key
        return f"AccountKey({self.directory!r}, kid={self.kid!r})"


class AccountKeys(Protocol):
    """One ACME account key per directory (the ``acme`` row of ``app_settings`` in the provisioner)."""

    async def get(self, directory: str) -> AccountKey | None:
        """The stored key for ``directory``, or None."""

    async def put_if_absent(self, directory: str, pem: str) -> AccountKey:
        """Store ``pem`` only when ``directory`` has no key yet; returns what is stored afterwards (the
        earlier key when another caller got there first). Under ``SELECT … FOR UPDATE`` of the row."""

    async def remember_kid(self, directory: str, kid: str) -> None:
        """Keep the account URL for ``directory``."""


async def account_key(keys: AccountKeys, directory: str) -> AccountKey:
    """The directory's account key, made on first use. The new key is generated before any store call
    (outside any transaction) and dropped when another caller stored one first (§3.8)."""
    found = await keys.get(directory)
    if found is not None:
        return found
    return await keys.put_if_absent(directory, acme.generate_account_key())


# ------------------------------------------------------------------------ issuing


@dataclass(frozen=True)
class Issued:
    """A certificate fresh from the ACME server. ``private_key`` is a secret: keep it encrypted, add it to
    the Redactor (``secrets()``), never log it."""

    private_key: str = field(repr=False)
    leaf: str = field(repr=False)
    chain: str = field(repr=False)
    not_after: datetime
    dns_names: list[str]

    def __repr__(self) -> str:
        return f"Issued(dns_names={self.dns_names!r}, not_after={self.not_after.isoformat()!r})"

    def secrets(self) -> list[str]:
        return [self.private_key]

    def credentials(self) -> dict[str, str]:
        """What a pending ``certificate`` row keeps until the upload is recorded (§3.7)."""
        return {"private_key": self.private_key, "leaf": self.leaf, "chain": self.chain}

    def details(self) -> dict[str, Any]:
        return {"not_after": self.not_after.isoformat().replace("+00:00", "Z"), "dns_names": list(self.dns_names)}


def challenge_name(hostname: str) -> str:
    """``_acme-challenge.<name>``; a wildcard's record sits at its parent (RFC 8555 §8.4)."""
    return CHALLENGE_PREFIX + hostname.lower().rstrip(".").removeprefix("*.")


async def sweep_challenges(txt: TxtRecords, names: Iterable[str], say: Say = _quiet) -> int:
    """Delete challenge records Slipway left for ``names`` (a crashed run's leftovers). Only records with
    exactly Slipway's comment at ``_acme-challenge.<name>`` go; a record without the comment is someone
    else's and stays. Returns how many were deleted; a failed delete is logged and the sweep goes on."""
    targets = {challenge_name(n) for n in names}
    deleted = 0
    for rec in await txt.list(CHALLENGE_COMMENT):
        if rec.name.lower().rstrip(".") not in targets:
            continue
        if rec.comment is not None and rec.comment != CHALLENGE_COMMENT:
            continue  # an adapter that lists more than it was asked for
        try:
            await txt.delete(rec.id)
        except Exception as exc:  # noqa: BLE001 - logged by type; the order makes its own records
            await say(f"Couldn't delete a left-over challenge record at {rec.name} ({type(exc).__name__})")
            continue
        deleted += 1
    if deleted:
        await say(f"Deleted {deleted} left-over challenge record{'s' if deleted != 1 else ''}")
    return deleted


async def issue(
    names: Iterable[str], *, directory: str, keys: AccountKeys, txt: TxtRecords, say: Say = _quiet,
    settle: float = DNS_SETTLE, contact: Iterable[str] = (), transport: acme.Transport = None,
) -> Issued:
    """Order a certificate for ``names`` by DNS-01 and return it (§11.2 step 4b).

    Left-over challenge records for these names are swept first. Each name's record is created with
    Slipway's comment, held ``settle`` seconds, and deleted in a ``finally`` whether the order passed
    or not; a failed delete is logged, never raised. The account key is made once per directory and
    its ``kid`` remembered, so later orders skip ``newAccount``.
    """
    wanted = clean_names(names)
    account = await account_key(keys, directory)
    host = _host(directory)
    async with acme.AcmeClient(directory, account.pem, kid=account.kid, transport=transport) as client:
        if not account.kid:
            kid = await client.register(contact)
            await keys.remember_kid(directory, kid)
        await sweep_challenges(txt, wanted, say)
        await say(f"Ordering a certificate for {len(wanted)} name{'s' if len(wanted) != 1 else ''} from {host}")
        order_url, order = await client.new_order(wanted)

        created: list[tuple[str, str]] = []  # (record id, record name)
        try:
            to_answer: list[tuple[str, str]] = []  # (authorization URL, challenge URL)
            for authz_url in order["authorizations"]:
                authz = await client.get(authz_url, "authorization")
                status = authz.get("status")
                if status == "valid":
                    continue  # the server still remembers an earlier proof for this name
                if status != "pending":
                    raise CertError(f"{host} answered an authorization that is {status}, not pending")
                domain = str((authz.get("identifier") or {}).get("value") or "")
                challenge = next((c for c in authz.get("challenges") or []
                                  if isinstance(c, dict) and c.get("type") == "dns-01"), None)
                if not domain or challenge is None or not challenge.get("token") or not challenge.get("url"):
                    raise CertError(f"{host} offered no DNS-01 challenge for {domain or 'a name'}")
                record = challenge_name(("*." if authz.get("wildcard") else "") + domain)
                record_id = await txt.create(record, client.dns01_value(str(challenge["token"])), CHALLENGE_COMMENT)
                created.append((record_id, record))
                to_answer.append((authz_url, str(challenge["url"])))
            if to_answer:
                await say(f"Created {len(to_answer)} challenge record{'s' if len(to_answer) != 1 else ''}; "
                          f"waiting {settle:g} s for DNS")
                await sleep(settle)
                for _, challenge_url in to_answer:
                    await client.answer(challenge_url)
                for authz_url, _ in to_answer:
                    await client.wait(authz_url, "authorization")
        finally:
            for record_id, record in created:
                try:
                    await txt.delete(record_id)
                except Exception as exc:  # noqa: BLE001 - logged by type, never raised (§11.2)
                    await say(f"Couldn't delete the challenge record at {record} ({type(exc).__name__}); "
                              "the next order or the teardown removes it")

        key_pem = acme.new_certificate_key()
        await client.finalize(order["finalize"], acme.make_csr(wanted, key_pem))
        done = await client.wait(order_url, "order")
        if not isinstance(done.get("certificate"), str):
            raise CertError(f"{host} finished the order without a certificate")
        bundle = await client.download(done["certificate"])

    leaf, chain = acme.split_chain(bundle)
    got = acme.certificate_names(leaf)
    if got != wanted:
        raise CertError(f"{host} issued a certificate for other names than Slipway asked for")
    expires = acme.certificate_not_after(leaf)
    await say(f"Issued a certificate for {', '.join(wanted[:3])}{' and more' if len(wanted) > 3 else ''}, "
              f"valid until {expires.strftime('%Y-%m-%d')}")
    return Issued(private_key=key_pem, leaf=leaf, chain=chain, not_after=expires, dns_names=got)


def _host(url: str) -> str:
    match = re.match(r"^[a-z]+://([^/:]+)", url)
    return match.group(1) if match else url
