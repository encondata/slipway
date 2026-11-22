"""Phase 5 test 3: the pinned TLS helpers (``slipway.services.tls_pin``)."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import re
import ssl
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from slipway.services import tls_pin

from tests.hypervisor_guard import no_real_hypervisors  # noqa: F401  (the fixture)

pytestmark = pytest.mark.usefixtures("no_real_hypervisors")


# --------------------------------------------------------------------------- helpers


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_cert(cn: str, *, issuer: tuple[x509.Certificate, ec.EllipticCurvePrivateKey] | None = None,
              ca: bool = False, dns: list[str] = (), ips: list[str] = ()) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    issuer_cert, issuer_key = issuer if issuer else (None, key)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(issuer_cert.subject if issuer_cert else _name(cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    sans = [x509.DNSName(d) for d in dns] + [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    return builder.sign(issuer_key, hashes.SHA256()), key


def pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


@pytest.fixture(scope="module")
def chain():
    """A CA, a leaf it signed for 127.0.0.1, an ESXi-style leaf naming localhost.localdomain, a stranger."""
    ca = make_cert("pve-root-ca", ca=True)
    leaf = make_cert("pve.lan", issuer=ca, ips=["127.0.0.1"])
    esxi = make_cert("localhost.localdomain", issuer=ca, dns=["localhost.localdomain"])
    stranger = make_cert("stranger", ips=["127.0.0.1"])
    return {"ca": ca, "leaf": leaf, "esxi": esxi, "stranger": stranger}


async def _serve(tmp_path, cert, key, ca) -> asyncio.Server:
    """A TLS server on 127.0.0.1 presenting ``cert`` and its CA (a full chain, as Proxmox serves)."""
    cert_file = tmp_path / f"{id(cert)}.pem"
    key_file = tmp_path / f"{id(cert)}.key"
    cert_file.write_text(pem(cert) + pem(ca))
    key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_file, key_file)

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await reader.read(1)
        except (ConnectionError, ssl.SSLError):
            pass
        finally:
            writer.close()

    return await asyncio.start_server(handle, "127.0.0.1", 0, ssl=ctx)


async def _connect(server: asyncio.Server, ctx: ssl.SSLContext, server_hostname: str = "127.0.0.1") -> None:
    port = server.sockets[0].getsockname()[1]
    reader, writer = await asyncio.open_connection("127.0.0.1", port, ssl=ctx, server_hostname=server_hostname)
    writer.close()


# ----------------------------------------------------------------------------- load


def test_load_one_takes_exactly_one_certificate(chain):
    leaf = chain["leaf"][0]
    assert tls_pin.load_one(pem(leaf)) == leaf
    assert tls_pin.load_one(pem(leaf).encode()) == leaf
    # Text around the block is tolerated; the cleaned PEM drops it.
    assert tls_pin.clean_pem("subject=CN pve.lan\n" + pem(leaf)) == pem(leaf)


@pytest.mark.parametrize("bad, text", [
    ("", "No certificate"),
    ("   \n", "No certificate"),
    ("hello there", "isn't a PEM certificate"),
    ("-----BEGIN CERTIFICATE-----\nnot base64 at all!\n-----END CERTIFICATE-----\n", "can't be read"),
])
def test_load_one_refuses_empty_and_garbage(bad, text):
    with pytest.raises(tls_pin.TlsPinError, match=text):
        tls_pin.load_one(bad)


def test_load_one_refuses_two_certificates_and_keys(chain):
    leaf, key = chain["leaf"]
    ca = chain["ca"][0]
    with pytest.raises(tls_pin.TlsPinError, match="exactly one certificate, not 2"):
        tls_pin.load_one(pem(leaf) + pem(ca))
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()).decode()
    with pytest.raises(tls_pin.TlsPinError, match="other PEM blocks"):
        tls_pin.load_one(pem(leaf) + key_pem)
    with pytest.raises(tls_pin.TlsPinError, match="far too long"):
        tls_pin.load_one(pem(leaf) + "x" * tls_pin.PEM_LIMIT)


def test_pinned_context_refuses_a_bundle(chain):
    with pytest.raises(tls_pin.TlsPinError):
        tls_pin.pinned_context(pem(chain["leaf"][0]) + pem(chain["ca"][0]))
    with pytest.raises(tls_pin.TlsPinError):
        tls_pin.pinned_context("")


# ----------------------------------------------------------------------- fingerprints


def test_fingerprint_format(chain):
    leaf = chain["leaf"][0]
    fp = tls_pin.fingerprint(leaf)
    assert re.fullmatch(r"(?:[0-9A-F]{2}:){31}[0-9A-F]{2}", fp)
    der = leaf.public_bytes(serialization.Encoding.DER)
    assert fp.replace(":", "").lower() == hashlib.sha256(der).hexdigest()
    assert tls_pin.fingerprint(pem(leaf)) == fp
    bare = fp.replace(":", "").lower()
    for typed in (fp, fp.lower(), bare, f"sha256:{bare}", f"SHA256 Fingerprint={fp}", " ".join(fp.split(":"))):
        assert tls_pin.normalize_fingerprint(typed) == fp
        assert tls_pin.matches(leaf, typed)
    assert not tls_pin.matches(leaf, tls_pin.fingerprint(chain["ca"][0]))
    assert not tls_pin.matches(leaf, "nonsense")
    for bad in ("", "AB:CD", bare[:-1] + "G", bare + "00"):
        with pytest.raises(tls_pin.TlsPinError, match="SHA-256 fingerprint"):
            tls_pin.normalize_fingerprint(bad)


def test_describe(chain):
    leaf = chain["leaf"][0]
    info = tls_pin.describe(pem(leaf))
    assert info["pem"] == pem(leaf)
    assert info["fingerprint_sha256"] == tls_pin.fingerprint(leaf)
    assert info["subject"] == "CN=pve.lan"
    assert info["issuer"] == "CN=pve-root-ca"
    assert info["sans"] == ["127.0.0.1"]
    assert datetime.fromisoformat(info["not_after"]) == leaf.not_valid_after_utc
    assert tls_pin.describe(pem(chain["esxi"][0]))["sans"] == ["localhost.localdomain"]


# --------------------------------------------------------------------------- contexts


def test_pinned_context_settings(chain):
    ctx = tls_pin.pinned_context(pem(chain["leaf"][0]))
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True
    assert ctx.verify_flags & ssl.VERIFY_X509_PARTIAL_CHAIN
    # Exactly one trust anchor (a leaf, so not counted as a CA), and nothing from the system's store.
    assert ctx.cert_store_stats() == {"x509": 1, "crl": 0, "x509_ca": 0}
    esxi = tls_pin.pinned_context(pem(chain["esxi"][0]), check_hostname=False)
    assert esxi.check_hostname is False
    assert esxi.verify_mode == ssl.CERT_REQUIRED


async def test_pinned_leaf_alone_is_enough(chain, tmp_path):
    """A partial chain: the pinned leaf anchors it although its CA isn't trusted."""
    leaf, key = chain["leaf"]
    server = await _serve(tmp_path, leaf, key, chain["ca"][0])
    async with server:
        await _connect(server, tls_pin.pinned_context(pem(leaf)))


async def test_another_certificate_is_refused(chain, tmp_path):
    leaf, key = chain["leaf"]
    server = await _serve(tmp_path, leaf, key, chain["ca"][0])
    async with server:
        with pytest.raises(ssl.SSLCertVerificationError) as caught:
            await _connect(server, tls_pin.pinned_context(pem(chain["stranger"][0])))
    wrapped = RuntimeError("connect failed")
    wrapped.__cause__ = caught.value
    assert tls_pin.pin_refused(wrapped)
    assert not tls_pin.pin_refused(RuntimeError("connection refused"))
    assert not tls_pin.pin_refused(None)


async def test_host_name_check_on_and_off(chain, tmp_path):
    """ESXi's certificate names localhost.localdomain: refused with the check, accepted by the pin without it."""
    cert, key = chain["esxi"]
    server = await _serve(tmp_path, cert, key, chain["ca"][0])
    async with server:
        with pytest.raises(ssl.SSLCertVerificationError):
            await _connect(server, tls_pin.pinned_context(pem(cert)))
        await _connect(server, tls_pin.pinned_context(pem(cert), check_hostname=False))
        # Host-name checking off doesn't mean any certificate: the pin still decides.
        with pytest.raises(ssl.SSLCertVerificationError):
            await _connect(server, tls_pin.pinned_context(pem(chain["stranger"][0]), check_hostname=False))


# ------------------------------------------------------------------------------ fetch


async def test_read_certificate_returns_the_leaf(chain, tmp_path):
    leaf, key = chain["leaf"]
    server = await _serve(tmp_path, leaf, key, chain["ca"][0])
    async with server:
        port = server.sockets[0].getsockname()[1]
        got = await tls_pin.read_certificate("127.0.0.1", port)
    assert got == pem(leaf)
    assert tls_pin.describe(got)["fingerprint_sha256"] == tls_pin.fingerprint(leaf)


async def test_read_certificate_failures_are_plain(unused_tcp_port):
    with pytest.raises(tls_pin.TlsPinError, match="couldn't connect to 127.0.0.1"):
        await tls_pin.read_certificate("127.0.0.1", unused_tcp_port, timeout=2)

    async def plain(reader, writer):  # answers, but not with TLS
        writer.write(b"SSH-2.0-OpenSSH_9.6\r\n" * 50)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(plain, "127.0.0.1", 0)
    async with server:
        port = server.sockets[0].getsockname()[1]
        with pytest.raises(tls_pin.TlsPinError, match="not with TLS"):
            await tls_pin.read_certificate("127.0.0.1", port, timeout=2)

    async def silent(reader, writer):  # accepts, then never answers the handshake
        await reader.read()
        writer.close()

    server = await asyncio.start_server(silent, "127.0.0.1", 0)
    async with server:
        port = server.sockets[0].getsockname()[1]
        with pytest.raises(tls_pin.TlsPinError, match="didn't answer in 0.3 seconds"):
            await tls_pin.read_certificate("127.0.0.1", port, timeout=0.3)


@pytest.mark.parametrize("url, expected", [
    ("https://pve.lan:8006", ("pve.lan", 8006)),
    ("https://esxi.lan", ("esxi.lan", 443)),
    ("https://10.0.0.2:8006/", ("10.0.0.2", 8006)),
    ("https://[fd00::2]:8006", ("fd00::2", 8006)),
])
def test_url_host_port(url, expected):
    assert tls_pin.url_host_port(url) == expected


@pytest.mark.parametrize("url", ["http://pve.lan:8006", "pve.lan", "", "https://pve.lan:99999"])
def test_url_host_port_refuses(url):
    with pytest.raises(tls_pin.TlsPinError):
        tls_pin.url_host_port(url)
