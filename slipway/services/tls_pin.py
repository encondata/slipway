"""Pinned TLS for hypervisor APIs (Proxmox and ESXi), ported from Sirdar's ``tls_pin.py``.

Hypervisors on a LAN almost always serve a self-signed certificate, so the system's trust store
can't vouch for them, and turning verification off would let anyone on the network answer as the
hypervisor and collect its token or password. Instead a person trusts one certificate, by its
SHA-256 fingerprint, when they add the account (``read_certificate`` fetches it for the dialog),
and every later connection trusts that certificate and nothing else:

* ``pinned_context(pem)`` is an ``ssl.SSLContext`` whose only trust anchor is the pinned
  certificate. ``VERIFY_X509_PARTIAL_CHAIN`` lets that certificate anchor the chain even when it is
  a leaf signed by a CA Slipway never saw (Proxmox's node certificate is signed by its own
  ``pve-root-ca``). Nothing from the system's store is loaded, and TLS 1.2 is the minimum.
* Host names are checked by default (Proxmox, and Terraform through ``SSL_CERT_FILE``). ESXi's
  default certificate names ``localhost.localdomain``, so its client passes ``check_hostname=False``:
  the pin still decides, and pyvmomi's thumbprint check comes on top.

A certificate renewed on purpose has to be trusted again; until then every call fails with the
client's "isn't the one Slipway trusts" text (``pin_refused`` tells that failure apart).
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import re
import ssl
from datetime import UTC
from typing import Any
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import serialization

# A single PEM certificate is a few kilobytes; anything far bigger isn't one.
PEM_LIMIT = 64 * 1024
FETCH_TIMEOUT = 10.0  # seconds, §14 "the certificate fetch"

_PEM_BLOCK = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----")
_HEX64 = re.compile(r"^[0-9A-F]{64}$")


class TlsPinError(ValueError):
    """A certificate or fingerprint Slipway can't use, or a certificate it couldn't fetch."""


# ------------------------------------------------------------------------ certificates


def load_one(pem: str | bytes) -> x509.Certificate:
    """The one certificate in ``pem``; refuses empty input, garbage, other PEM blocks and two certificates.

    Exactly one matters: a bundle would trust every certificate in it, and an empty file given to
    Terraform as ``SSL_CERT_FILE`` would fall back to the system's trust store.
    """
    text = pem.decode("ascii", "replace") if isinstance(pem, bytes) else (pem or "")
    if not text.strip():
        raise TlsPinError("No certificate was given")
    if len(text) > PEM_LIMIT:
        raise TlsPinError("That is far too long to be one certificate")
    blocks = _PEM_BLOCK.findall(text)
    if not blocks:
        raise TlsPinError("That isn't a PEM certificate (it should start with -----BEGIN CERTIFICATE-----)")
    if any(kind != "CERTIFICATE" for kind in blocks):
        raise TlsPinError("Give the certificate alone: the text holds other PEM blocks (such as a key)")
    if len(blocks) != 1:
        raise TlsPinError(f"Give exactly one certificate, not {len(blocks)}: Slipway trusts only the one it pins")
    try:
        certs = x509.load_pem_x509_certificates(text.encode("ascii", "replace"))
    except ValueError as exc:
        raise TlsPinError("That certificate can't be read: it is damaged or isn't X.509") from exc
    if len(certs) != 1:
        raise TlsPinError("Give exactly one certificate")
    return certs[0]


def clean_pem(pem: str | bytes) -> str:
    """The one certificate in ``pem``, written out again as plain PEM (no comments or extra text)."""
    return load_one(pem).public_bytes(serialization.Encoding.PEM).decode("ascii")


def _der(cert: x509.Certificate | str | bytes) -> bytes:
    if not isinstance(cert, x509.Certificate):
        cert = load_one(cert)
    return cert.public_bytes(serialization.Encoding.DER)


def fingerprint(cert: x509.Certificate | str | bytes) -> str:
    """SHA-256 of the certificate's DER bytes as upper-case hex pairs: ``AB:CD:…`` (95 characters).

    The form Proxmox's and ESXi's own pages show, so a person can compare them by eye.
    """
    digest = hashlib.sha256(_der(cert)).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, 64, 2))


def normalize_fingerprint(value: str) -> str:
    """A typed or pasted SHA-256 fingerprint in ``fingerprint``'s form.

    Accepts upper or lower case, with or without colons, spaces or a ``sha256:`` / ``SHA256 Fingerprint=``
    prefix (what ``openssl x509 -fingerprint -sha256`` prints).
    """
    text = (value or "").strip()
    text = re.sub(r"^(?:sha-?256\s*(?:fingerprint)?\s*[:=]?\s*)", "", text, flags=re.IGNORECASE)
    bare = re.sub(r"[\s:]", "", text).upper()
    if not _HEX64.fullmatch(bare):
        raise TlsPinError("That isn't a SHA-256 fingerprint: it should be 64 hexadecimal digits, in pairs such as AB:CD:…")
    return ":".join(bare[i:i + 2] for i in range(0, 64, 2))


def matches(cert: x509.Certificate | str | bytes, expected: str) -> bool:
    """Whether the certificate's fingerprint is ``expected`` (in any form ``normalize_fingerprint`` takes)."""
    try:
        wanted = normalize_fingerprint(expected)
    except TlsPinError:
        return False
    return hmac.compare_digest(fingerprint(cert), wanted)


def _names(name: x509.Name) -> str:
    return name.rfc4514_string()


def describe(pem: str | bytes) -> dict[str, Any]:
    """What ``provider_accounts.tls`` keeps of a certificate, and what the trust dialog shows.

    ``trusted_at`` and ``trusted_by`` are the accounts service's to add.
    """
    cert = load_one(pem)
    sans: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        ext = None
    if ext is not None:
        sans = [str(v) for v in ext.get_values_for_type(x509.DNSName)]
        sans += [str(v) for v in ext.get_values_for_type(x509.IPAddress)]
    return {
        "pem": cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        "fingerprint_sha256": fingerprint(cert),
        "subject": _names(cert.subject),
        "issuer": _names(cert.issuer),
        "not_after": cert.not_valid_after_utc.astimezone(UTC).isoformat(),
        "sans": sans,
    }


# ------------------------------------------------------------------------- contexts


def pinned_context(pem: str | bytes, *, check_hostname: bool = True) -> ssl.SSLContext:
    """A client context that trusts exactly the pinned certificate (see the module's notes)."""
    one = clean_pem(pem)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # loads no system CAs, unlike create_default_context
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = check_hostname
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    # Hypervisor certificates often lack extensions the strict profile demands (an authority key id).
    ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
    ctx.load_verify_locations(cadata=one)
    return ctx


def pin_refused(exc: BaseException | None) -> bool:
    """Whether ``exc`` (or anything it was raised from) is the TLS check refusing the certificate.

    httpx and pyvmomi wrap ``ssl.SSLCertVerificationError`` in their own errors; the clients use this
    to answer "the certificate isn't the one Slipway trusts" instead of a connection failure.
    """
    seen: set[int] = set()
    while exc is not None and id(exc) not in seen:
        if isinstance(exc, ssl.SSLCertVerificationError):
            return True
        seen.add(id(exc))
        exc = exc.__cause__ or exc.__context__
    return False


# ---------------------------------------------------------------------------- fetch


def url_host_port(url: str, default_port: int = 443) -> tuple[str, int]:
    """The host and port of an ``https://host[:port]`` URL (IPv6 without brackets)."""
    parts = urlsplit((url or "").strip())
    if parts.scheme != "https" or not parts.hostname:
        raise TlsPinError("The URL must start with https://, such as https://pve.example.lan:8006")
    try:
        port = parts.port or default_port
    except ValueError as exc:
        raise TlsPinError("The URL's port isn't a number between 1 and 65535") from exc
    return parts.hostname, port


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


async def read_certificate(host: str, port: int, *, timeout: float = FETCH_TIMEOUT) -> str:
    """The leaf certificate ``host:port`` presents, as PEM, without trusting it.

    This is the one TLS connection Slipway makes without a pin: it only reads the certificate for a
    person to compare and trust, and sends nothing. Tests may reach only 127.0.0.1 (the guard).
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    where = f"{host}:{port}"
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=None if _is_ip(host) else host),
            timeout,
        )
    except TimeoutError as exc:
        raise TlsPinError(f"{where} didn't answer in {timeout:g} seconds, so Slipway couldn't read its certificate") from exc
    except ssl.SSLError as exc:
        raise TlsPinError(f"{where} answered, but not with TLS 1.2 or later, so Slipway couldn't read its certificate") from exc
    except OSError as exc:
        raise TlsPinError(f"Slipway couldn't connect to {where} to read its certificate") from exc
    try:
        ssl_object = writer.get_extra_info("ssl_object")
        der = ssl_object.getpeercert(binary_form=True) if ssl_object is not None else None
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 2)
        except (OSError, TimeoutError, ssl.SSLError):
            pass
    if not der:
        raise TlsPinError(f"{where} presented no certificate")
    return x509.load_der_x509_certificate(der).public_bytes(serialization.Encoding.PEM).decode("ascii")
