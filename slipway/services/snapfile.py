"""The snapshot file format: the plaintext tar (version 1) and the encrypted ``.sbx`` container.

A snapshot's plaintext is an uncompressed POSIX tar (gzip is accepted on input) holding, in this order,
``slipway-snapshot.json``, ``identity.json`` (when the snapshot carries identity keys), ``database`` and
``files`` (when it has files). Slipway stores and exports it inside the ``.sbx`` container::

    magic "SLWSNAP1" | header_len (4, big-endian) | header JSON | keyblock_len (4) | keyblock JSON | chunks

The body is AES-256-GCM in chunks of 2^chunk_log2 plaintext bytes. Chunk i uses the nonce
``nonce_prefix(7) | be32(i) | last(1)`` and the SHA-256 of ``magic | header_len | header`` as associated data,
so reordering, truncation, appended data and header changes all fail to decrypt. The key block either says
``kdf: none`` (stored on a Slipway; the data key lives in the database) or wraps the data key with a key
derived from a passphrase by scrypt. The key block is outside the associated data, so a download can put a
new key block in front of the unchanged body.

This module imports only the standard library and ``cryptography``, so ``slipway snapshot pack`` works on a
laptop without the rest of Slipway's dependencies being configured. Every error is a ``SnapshotError`` whose
text is safe to show to the person who supplied the file.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import secrets
import struct
import tarfile
import time
import unicodedata
import uuid
import zlib
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, BinaryIO, Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

KiB = 1024
MiB = 1024 * KiB
GiB = 1024 * MiB

# --- the inner format ----------------------------------------------------------------------------------------

FORMAT = "slipway-snapshot"
VERSION = 1
MANIFEST = "slipway-snapshot.json"
IDENTITY = "identity.json"
DATABASE = "database"
FILES = "files"
MEMBERS = (MANIFEST, IDENTITY, DATABASE, FILES)
MANIFEST_MAX = 64 * KiB
IDENTITY_MAX = 16 * KiB
REVISION_MAX = 16 * KiB
PAX_MAX = 64 * KiB
IDENTITY_KEYS_MAX = 16
NOTES_MAX = 2000
DEFAULT_MAX_BYTES = 20 * GiB  # Settings.snapshot_max_bytes; callers pass the configured value
INFLATION_SLACK = 1 * MiB  # tar headers and padding on top of the declared member sizes

APP_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}\Z")
FORMAT_RE = re.compile(r"^[a-z0-9][a-z0-9._+-]{0,39}\Z")
# owner/name, at most 200 characters in all: what snapshots.repository (String(200)) holds.
REPOSITORY_RE = re.compile(r"^(?=.{3,200}\Z)[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}\Z")
SOURCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,99}\Z")
CREATED_AT_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}\Z")
SHA256_RE = re.compile(r"^[0-9a-f]{64}\Z")
ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}\Z")  # manifest.ENV_KEY_RE, with a length cap
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")

_MANIFEST_KEYS = {
    "format", "version", "app", "app_name", "repository", "commit", "source", "created_at", "notes",
    "database", "files", "identity", "producer",
}
_MANIFEST_REQUIRED = {"format", "version", "app", "app_name", "source", "created_at", "database"}

# --- the container -------------------------------------------------------------------------------------------

MAGIC = b"SLWSNAP1"
CIPHER = "aes-256-gcm-stream"
CHUNK_LOG2 = 20
CHUNK_LOG2_MIN, CHUNK_LOG2_MAX = 16, 24
PREAMBLE_PART_MAX = 4096  # header and key block, each
TAG = 16
MAX_CHUNKS = 2**32  # the counter is 32 bits: chunk indexes 0 .. 2^32-1
KDF_LOG2_N = 17  # what Slipway and pack write
KDF_LOG2_N_ACCEPTED = (17, 18)
PASSPHRASE_MIN, PASSPHRASE_MAX = 12, 1024
STORED_KEYBLOCK: dict[str, Any] = {"kdf": "none"}

NOT_A_SNAPSHOT = "This isn't a Slipway snapshot file"
WRONG_PASSPHRASE = "That passphrase doesn't open this file"
BAD_KDF = "This file asks for key-derivation settings Slipway doesn't accept"
INCOMPLETE = "The file is incomplete"
AFTER_END = "The file has data after its end"
NOT_TAR = "The file isn't a Slipway snapshot (not a tar or tar.gz)"
DAMAGED_TAR = "The file isn't a Slipway snapshot (its tar data is damaged)"
TOO_BIG_UNPACKED = "The file unpacks to more than the sizes it declares"


class SnapshotError(ValueError):
    """A snapshot file was refused. ``str(exc)`` is plain English, safe to show, and never holds a secret."""


class _Truncated(SnapshotError):
    """The plaintext ended inside the tar (told apart from a damaged header after the last member)."""


def _damaged(index: int) -> SnapshotError:
    return SnapshotError(f"The file is damaged (part {index + 1} doesn't decrypt)")


class Readable(Protocol):
    def read(self, n: int = -1, /) -> bytes: ...


class Writable(Protocol):
    def write(self, data: bytes, /) -> Any: ...


def _read_exact(f: Readable, n: int) -> bytes:
    """Read ``n`` bytes, fewer only at the end of the stream (some streams return short reads mid-way)."""
    first = f.read(n)
    if len(first) == n or not first:
        return first
    parts = [first]
    got = len(first)
    while got < n:
        more = f.read(n - got)
        if not more:
            break
        parts.append(more)
        got += len(more)
    return b"".join(parts)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(value: Any, length: int, error: str) -> bytes:
    if not isinstance(value, str):
        raise SnapshotError(error)
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise SnapshotError(error) from None
    if len(raw) != length:
        raise SnapshotError(error)
    return raw


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate key {key!r}")
        out[key] = value
    return out


def _load_json(raw: bytes) -> Any:
    """Strict JSON: UTF-8, no duplicate keys (two readers could otherwise disagree about a value), and no
    text that isn't valid Unicode: an escaped lone surrogate (``"\\ud800"``) decodes to a string nothing can
    store or write as UTF-8. Raises ``ValueError``."""
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates)
        # Encoding it again finds a lone surrogate anywhere in it, in keys and values alike.
        json.dumps(value, ensure_ascii=False).encode("utf-8")
    except RecursionError:  # nested too deeply
        raise ValueError("JSON nested too deeply") from None
    return value


def _dump_json(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


# --- passphrases and key blocks ------------------------------------------------------------------------------


def new_data_key() -> bytes:
    """A fresh 32-byte data key (DEK) for one snapshot."""
    return AESGCM.generate_key(bit_length=256)


def check_passphrase(passphrase: str) -> None:
    """Refuse a passphrase a new file shouldn't be locked with. It is never stored, logged or audited."""
    if not isinstance(passphrase, str) or not PASSPHRASE_MIN <= len(passphrase) <= PASSPHRASE_MAX:
        raise SnapshotError(f"Choose a passphrase of {PASSPHRASE_MIN} to {PASSPHRASE_MAX} characters")
    if _CONTROL.search(passphrase):
        raise SnapshotError("The passphrase can't contain control characters (such as tabs or line breaks)")


def check_keyblock(keyblock: Any) -> dict[str, Any]:
    """Validate a key block's shape and scrypt settings. Runs before any key derivation (security 10)."""
    if not isinstance(keyblock, dict) or not isinstance(keyblock.get("kdf"), str):
        raise SnapshotError(NOT_A_SNAPSHOT)
    kdf = keyblock["kdf"]
    if kdf == "none":
        if set(keyblock) != {"kdf"}:
            raise SnapshotError(NOT_A_SNAPSHOT)
        return keyblock
    if kdf != "scrypt":
        raise SnapshotError(BAD_KDF)
    if set(keyblock) != {"kdf", "log2_n", "r", "p", "salt", "nonce", "wrapped"}:
        raise SnapshotError(NOT_A_SNAPSHOT)
    log2_n, r, p = keyblock["log2_n"], keyblock["r"], keyblock["p"]
    if not (_is_int(log2_n) and _is_int(r) and _is_int(p)):
        raise SnapshotError(BAD_KDF)
    if log2_n not in KDF_LOG2_N_ACCEPTED or r != 8 or p != 1:
        raise SnapshotError(BAD_KDF)
    _unb64(keyblock["salt"], 16, NOT_A_SNAPSHOT)
    _unb64(keyblock["nonce"], 12, NOT_A_SNAPSHOT)
    _unb64(keyblock["wrapped"], 32 + TAG, NOT_A_SNAPSHOT)
    return keyblock


def _kek(passphrase: str, salt: bytes, log2_n: int, r: int, p: int) -> bytes:
    secret = unicodedata.normalize("NFC", passphrase).encode("utf-8")
    return Scrypt(salt=salt, length=32, n=2**log2_n, r=r, p=p).derive(secret)


def wrap_key(data_key: bytes, passphrase: str, header_hash: bytes, *, log2_n: int = KDF_LOG2_N) -> dict[str, Any]:
    """A passphrase key block for ``data_key``, bound to one file's header. Slow on purpose (scrypt):
    the server runs it in ``asyncio.to_thread`` inside the KDF semaphore."""
    check_passphrase(passphrase)
    if log2_n not in KDF_LOG2_N_ACCEPTED:
        raise SnapshotError(BAD_KDF)
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    wrapped = AESGCM(_kek(passphrase, salt, log2_n, 8, 1)).encrypt(nonce, data_key, header_hash)
    return {"kdf": "scrypt", "log2_n": log2_n, "r": 8, "p": 1, "salt": _b64(salt), "nonce": _b64(nonce),
            "wrapped": _b64(wrapped)}


def unwrap_key(keyblock: dict[str, Any], passphrase: str, header_hash: bytes) -> bytes:
    """The data key from a passphrase key block, or ``SnapshotError(WRONG_PASSPHRASE)``."""
    check_keyblock(keyblock)
    if keyblock["kdf"] != "scrypt":
        raise SnapshotError("This file isn't locked with a passphrase")
    if not isinstance(passphrase, str) or not passphrase or len(passphrase) > PASSPHRASE_MAX:
        raise SnapshotError(WRONG_PASSPHRASE)
    salt = _unb64(keyblock["salt"], 16, NOT_A_SNAPSHOT)
    nonce = _unb64(keyblock["nonce"], 12, NOT_A_SNAPSHOT)
    wrapped = _unb64(keyblock["wrapped"], 32 + TAG, NOT_A_SNAPSHOT)
    kek = _kek(passphrase, salt, keyblock["log2_n"], keyblock["r"], keyblock["p"])
    try:
        return AESGCM(kek).decrypt(nonce, wrapped, header_hash)
    except InvalidTag:
        raise SnapshotError(WRONG_PASSPHRASE) from None


# --- the container preamble ----------------------------------------------------------------------------------


@dataclass(frozen=True)
class Preamble:
    """The parsed front of an ``.sbx`` file: header and key block."""

    header: dict[str, Any]
    header_bytes: bytes  # the header JSON exactly as it is in the file (the hash covers these bytes)
    keyblock: dict[str, Any]
    keyblock_bytes: bytes

    @property
    def header_hash(self) -> bytes:
        """H = SHA-256(magic | header_len | header): the associated data of every chunk and of the key wrap."""
        return hashlib.sha256(MAGIC + struct.pack(">I", len(self.header_bytes)) + self.header_bytes).digest()

    @property
    def chunk_log2(self) -> int:
        return int(self.header["chunk_log2"])

    @property
    def nonce_prefix(self) -> bytes:
        return base64.b64decode(self.header["nonce_prefix"])

    @property
    def file_id(self) -> str:
        return str(self.header["id"])

    @property
    def length(self) -> int:
        """Bytes before the first chunk."""
        return 16 + len(self.header_bytes) + len(self.keyblock_bytes)

    @property
    def locked(self) -> bool:
        """True when the key block wraps the data key with a passphrase."""
        return self.keyblock.get("kdf") == "scrypt"

    def prefix(self, keyblock: dict[str, Any] | None = None) -> bytes:
        """The bytes in front of the body, with ``keyblock`` in place of this file's own key block."""
        kb = self.keyblock_bytes if keyblock is None else _dump_json(check_keyblock(keyblock))
        if len(kb) > PREAMBLE_PART_MAX:
            raise SnapshotError(NOT_A_SNAPSHOT)
        return MAGIC + struct.pack(">I", len(self.header_bytes)) + self.header_bytes + struct.pack(">I", len(kb)) + kb

    def stored_prefix(self) -> bytes:
        """The front of the stored form: the same header with a ``kdf: none`` key block (D15)."""
        return self.prefix(STORED_KEYBLOCK)

    def body_size(self, plaintext_bytes: int) -> int:
        chunk = 1 << self.chunk_log2
        return plaintext_bytes + TAG * (plaintext_bytes // chunk + 1)


def container_size(plaintext_bytes: int, *, header_len: int, keyblock_len: int, chunk_log2: int = CHUNK_LOG2) -> int:
    """Size = 16 + header_len + keyblock_len + P + 16 * (floor(P / C) + 1)."""
    return 16 + header_len + keyblock_len + plaintext_bytes + TAG * (plaintext_bytes // (1 << chunk_log2) + 1)


def new_header(*, chunk_log2: int = CHUNK_LOG2) -> bytes:
    """A fresh container header (random nonce prefix and file id), as the JSON bytes to write."""
    if not CHUNK_LOG2_MIN <= chunk_log2 <= CHUNK_LOG2_MAX:
        raise ValueError("chunk_log2 must be 16-24")
    return _dump_json({"v": 1, "cipher": CIPHER, "chunk_log2": chunk_log2,
                       "nonce_prefix": _b64(secrets.token_bytes(7)), "id": str(uuid.uuid4())})


def _check_header(raw: bytes) -> dict[str, Any]:
    try:
        header = _load_json(raw)
    except ValueError:
        raise SnapshotError(NOT_A_SNAPSHOT) from None
    if not isinstance(header, dict):
        raise SnapshotError(NOT_A_SNAPSHOT)
    version = header.get("v")
    if _is_int(version) and version > 1:
        raise SnapshotError(
            f"This file was made by a newer Slipway (container version {version}); update Slipway to open it"
        )
    if set(header) != {"v", "cipher", "chunk_log2", "nonce_prefix", "id"} or version != 1:
        raise SnapshotError(NOT_A_SNAPSHOT)
    if header["cipher"] != CIPHER:
        raise SnapshotError(NOT_A_SNAPSHOT)
    log2 = header["chunk_log2"]
    if not _is_int(log2) or not CHUNK_LOG2_MIN <= log2 <= CHUNK_LOG2_MAX:
        raise SnapshotError(NOT_A_SNAPSHOT)
    _unb64(header["nonce_prefix"], 7, NOT_A_SNAPSHOT)
    if not isinstance(header["id"], str):
        raise SnapshotError(NOT_A_SNAPSHOT)
    try:
        uuid.UUID(header["id"])
    except ValueError:
        raise SnapshotError(NOT_A_SNAPSHOT) from None
    return header


def parse_preamble(data: bytes) -> Preamble | None:
    """Parse the front of a container from the first bytes of a file or upload.

    Returns None when ``data`` is too short to hold the whole preamble yet (feed more and call again).
    Raises ``SnapshotError`` as soon as the bytes can't be a Slipway snapshot or ask for refused settings.
    """
    if len(data) < len(MAGIC):
        if not MAGIC.startswith(data):
            raise SnapshotError(NOT_A_SNAPSHOT)
        return None
    if data[: len(MAGIC)] != MAGIC:
        raise SnapshotError(NOT_A_SNAPSHOT)
    pos = len(MAGIC)
    if len(data) < pos + 4:
        return None
    (header_len,) = struct.unpack(">I", data[pos : pos + 4])
    if not 0 < header_len <= PREAMBLE_PART_MAX:
        raise SnapshotError(NOT_A_SNAPSHOT)
    pos += 4
    if len(data) < pos + header_len:
        return None
    header_bytes = data[pos : pos + header_len]
    header = _check_header(header_bytes)
    pos += header_len
    if len(data) < pos + 4:
        return None
    (keyblock_len,) = struct.unpack(">I", data[pos : pos + 4])
    if not 0 < keyblock_len <= PREAMBLE_PART_MAX:
        raise SnapshotError(NOT_A_SNAPSHOT)
    pos += 4
    if len(data) < pos + keyblock_len:
        return None
    keyblock_bytes = data[pos : pos + keyblock_len]
    try:
        keyblock = _load_json(keyblock_bytes)
    except ValueError:
        raise SnapshotError(NOT_A_SNAPSHOT) from None
    check_keyblock(keyblock)
    return Preamble(header, header_bytes, keyblock, keyblock_bytes)


def read_preamble(f: Readable) -> Preamble:
    """Read and parse the preamble from the start of ``f``, leaving ``f`` at the first chunk."""
    data = _read_exact(f, len(MAGIC) + 4)
    parse_preamble(data)  # refuses a wrong magic or header length straight away
    if len(data) < len(MAGIC) + 4:
        raise SnapshotError(NOT_A_SNAPSHOT if len(data) < len(MAGIC) else INCOMPLETE)
    for need in (struct.unpack(">I", data[-4:])[0] + 4, None):
        if need is None:  # the key block: its length is the last four bytes read
            need = struct.unpack(">I", data[-4:])[0]
        part = _read_exact(f, need)
        data += part
        preamble = parse_preamble(data)  # raises as soon as what is there is wrong
        if len(part) < need:
            raise SnapshotError(INCOMPLETE)
    if preamble is None:  # pragma: no cover - every part was read in full
        raise SnapshotError(INCOMPLETE)
    return preamble


# --- the container body --------------------------------------------------------------------------------------


def _nonce(prefix: bytes, index: int, last: bool) -> bytes:
    return prefix + struct.pack(">I", index) + (b"\x01" if last else b"\x00")


class ContainerWriter:
    """Encrypts a plaintext stream into an ``.sbx`` container written to ``out``.

    The preamble is written straight away; ``write`` buffers at most one chunk; ``close`` writes the final
    chunk (0 to C-1 bytes, ``last=1``). ``file_bytes`` and ``file_sha256`` describe everything written to
    ``out``. Pass ``passphrase`` for a portable file (scrypt key block), or nothing for the stored form.
    """

    def __init__(
        self,
        out: Writable,
        data_key: bytes,
        *,
        passphrase: str | None = None,
        keyblock: dict[str, Any] | None = None,
        header_bytes: bytes | None = None,
        chunk_log2: int = CHUNK_LOG2,
    ) -> None:
        self._out = out
        header_bytes = header_bytes if header_bytes is not None else new_header(chunk_log2=chunk_log2)
        header = _check_header(header_bytes)
        h = hashlib.sha256(MAGIC + struct.pack(">I", len(header_bytes)) + header_bytes).digest()
        if passphrase is not None:
            keyblock = wrap_key(data_key, passphrase, h)
        keyblock = check_keyblock(keyblock if keyblock is not None else STORED_KEYBLOCK)
        self.preamble = Preamble(header, header_bytes, keyblock, _dump_json(keyblock))
        self._aes = AESGCM(data_key)
        self._aad = h
        self._prefix = self.preamble.nonce_prefix
        self._chunk = 1 << self.preamble.chunk_log2
        self._buf = bytearray()
        self._index = 0
        self._hash = hashlib.sha256()
        self.file_bytes = 0
        self.plaintext_bytes = 0
        self.closed = False
        self._emit(self.preamble.prefix())

    @property
    def header_hash(self) -> bytes:
        return self._aad

    @property
    def file_sha256(self) -> str:
        return self._hash.hexdigest()

    def _emit(self, data: bytes) -> None:
        self._out.write(data)
        self._hash.update(data)
        self.file_bytes += len(data)

    def _seal(self, plaintext: bytes | memoryview, last: bool) -> None:
        if self._index >= MAX_CHUNKS:
            raise SnapshotError("The snapshot is too large for its container (more than 2^32 parts)")
        self._emit(self._aes.encrypt(_nonce(self._prefix, self._index, last), bytes(plaintext), self._aad))
        self._index += 1

    def write(self, data: bytes) -> int:
        if self.closed:
            raise ValueError("write to a closed ContainerWriter")
        self.plaintext_bytes += len(data)
        view = memoryview(data)
        if self._buf:  # top up the partly filled chunk first
            take = self._chunk - len(self._buf)
            self._buf += view[:take]
            view = view[take:]
            if len(self._buf) < self._chunk:
                return len(data)
            # A full chunk is never the final one: the final chunk holds 0..C-1 bytes.
            self._seal(self._buf, last=False)
            self._buf = bytearray()
        while len(view) >= self._chunk:
            self._seal(view[: self._chunk], last=False)
            view = view[self._chunk :]
        self._buf += view
        return len(data)

    def close(self) -> None:
        """Write the final chunk. Does not close ``out``."""
        if self.closed:
            return
        self._seal(self._buf, last=True)
        self._buf = bytearray()
        self.closed = True


def iter_plaintext(f: Readable, data_key: bytes, preamble: Preamble | None = None) -> Iterator[bytes]:
    """Decrypt a container chunk by chunk. ``f`` is at the first chunk when ``preamble`` is given, otherwise
    at the start of the file. Each chunk is checked before its plaintext is yielded; the generator raises
    ``SnapshotError`` for a damaged, reordered, truncated or extended body."""
    if preamble is None:
        preamble = read_preamble(f)
    aes = AESGCM(data_key)
    aad, prefix = preamble.header_hash, preamble.nonce_prefix
    full = (1 << preamble.chunk_log2) + TAG
    index = 0
    while True:
        sealed = _read_exact(f, full)
        if len(sealed) == full:
            # A chunk of full size is never the final one.
            try:
                yield aes.decrypt(_nonce(prefix, index, False), sealed, aad)
            except InvalidTag:
                raise _damaged(index) from None
            index += 1
            if index >= MAX_CHUNKS:
                raise _damaged(index)
            continue
        if len(sealed) < TAG:  # nothing, or less than a tag: the final chunk is missing
            raise SnapshotError(INCOMPLETE)
        try:
            plaintext = aes.decrypt(_nonce(prefix, index, True), sealed, aad)
        except InvalidTag:
            raise _damaged(index) from None
        if f.read(1):
            raise SnapshotError(AFTER_END)
        yield plaintext
        return


def open_container(path: str | os.PathLike[str], data_key: bytes) -> Iterator[bytes]:
    """Decrypt a stored ``.sbx`` file (see ``iter_plaintext``)."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as f:
        yield from iter_plaintext(f, data_key)


def rewrap(src: Readable, out: Writable, keyblock: dict[str, Any], *, bufsize: int = MiB) -> int:
    """Copy a container to ``out`` with ``keyblock`` in place of its own; the body bytes stay identical.
    Returns the number of bytes written."""
    preamble = read_preamble(src)
    head = preamble.prefix(keyblock)
    out.write(head)
    written = len(head)
    while chunk := src.read(bufsize):
        out.write(chunk)
        written += len(chunk)
    return written


# --- the inner tar: validation -------------------------------------------------------------------------------


def _check_text(value: Any, where: str, *, limit: int, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise _bad(where, "must be text")
    if (not value and not allow_empty) or len(value) > limit:
        raise _bad(where, f"must be {'0' if allow_empty else '1'}-{limit} characters")
    if "\x00" in value:  # PostgreSQL text can't hold it: the row couldn't be saved
        raise _bad(where, "can't contain a NUL character")
    return value


def _bad(where: str, why: str) -> SnapshotError:
    return SnapshotError(f"The snapshot's {MANIFEST} isn't valid: {where} {why}")


def _check_member_entry(value: Any, where: str, keys: set[str], *, min_bytes: int) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise _bad(where, f"must have exactly the keys {', '.join(sorted(keys))}")
    size = value["bytes"]
    if not _is_int(size) or size < min_bytes:
        raise _bad(f"{where}.bytes", f"must be a whole number of at least {min_bytes}")
    if not isinstance(value["sha256"], str) or not SHA256_RE.match(value["sha256"]):
        raise _bad(f"{where}.sha256", "must be 64 lowercase hex characters")
    return value


def validate_manifest(manifest: Any, *, max_bytes: int = DEFAULT_MAX_BYTES) -> dict[str, Any]:
    """Check a ``slipway-snapshot.json`` object against the version 1 rules (spec §10.1). Returns it."""
    if not isinstance(manifest, dict) or manifest.get("format") != FORMAT:
        raise SnapshotError(f"The file isn't a Slipway snapshot ({MANIFEST} has no format: {FORMAT})")
    version = manifest.get("version")
    if _is_int(version) and version > VERSION:
        raise SnapshotError(
            f"This snapshot was made by a newer Slipway (format version {version}); update Slipway to import it"
        )
    if version != VERSION or not _is_int(version):
        raise _bad("version", "must be 1")
    unknown = sorted(str(k)[:40] for k in set(manifest) - _MANIFEST_KEYS)
    if unknown:
        raise SnapshotError(f"The snapshot's {MANIFEST} has keys Slipway doesn't know: {', '.join(unknown[:5])}")
    missing = sorted(_MANIFEST_REQUIRED - set(manifest))
    if missing:
        raise SnapshotError(f"The snapshot's {MANIFEST} is missing {', '.join(missing)}")

    if not isinstance(manifest["app"], str) or not APP_RE.match(manifest["app"]):
        raise _bad("app", "must be lowercase letters, digits, '.', '_' or '-' (at most 64)")
    app_name = _check_text(manifest["app_name"], "app_name", limit=100)
    if _CONTROL.search(app_name):
        raise _bad("app_name", "can't contain control characters")
    repository = manifest.get("repository")
    if repository is not None and (not isinstance(repository, str) or not REPOSITORY_RE.match(repository)):
        raise _bad("repository", "must be owner/name (at most 200 characters)")
    commit = manifest.get("commit")
    if commit is not None and (not isinstance(commit, str) or not COMMIT_RE.match(commit)):
        raise _bad("commit", "must be a 40-character lowercase hex commit SHA")
    if not isinstance(manifest["source"], str) or not SOURCE_RE.match(manifest["source"]):
        raise _bad("source", "must start with a letter or digit and use letters, digits, '.', '_', '-' or spaces (at most 100)")
    created = manifest["created_at"]
    if not isinstance(created, str) or not CREATED_AT_RE.match(created):
        raise _bad("created_at", "must be YYYY-MM-DDTHH:MM:SSZ")
    try:
        datetime.strptime(created, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise _bad("created_at", "isn't a real date and time") from None
    _check_text(manifest.get("notes", ""), "notes", limit=NOTES_MAX, allow_empty=True)
    if manifest.get("producer") is not None:
        _check_text(manifest["producer"], "producer", limit=100)

    database = _check_member_entry(
        manifest["database"], "database", {"format", "revision", "bytes", "sha256"}, min_bytes=1
    )
    if not isinstance(database["format"], str) or not FORMAT_RE.match(database["format"]):
        raise _bad("database.format", "must be lowercase letters, digits, '.', '_', '+' or '-' (at most 40)")
    revision = database["revision"]
    if revision is not None:
        if not isinstance(revision, str) or len(revision.encode("utf-8")) > REVISION_MAX or "\x00" in revision:
            raise _bad("database.revision", "must be text of at most 16 KiB with no NUL characters")
    total = database["bytes"]

    files = manifest.get("files")
    if files is not None:
        _check_member_entry(files, "files", {"format", "bytes", "sha256"}, min_bytes=0)
        if not isinstance(files["format"], str) or not FORMAT_RE.match(files["format"]):
            raise _bad("files.format", "must be lowercase letters, digits, '.', '_', '+' or '-' (at most 40)")
        total += files["bytes"]

    identity = manifest.get("identity")
    if identity is not None:
        _check_member_entry(identity, "identity", {"keys", "bytes", "sha256"}, min_bytes=2)
        keys = identity["keys"]
        if not isinstance(keys, list) or not 1 <= len(keys) <= IDENTITY_KEYS_MAX:
            raise _bad("identity.keys", f"must list 1-{IDENTITY_KEYS_MAX} keys")
        if any(not isinstance(k, str) or not ENV_KEY_RE.match(k) for k in keys):
            raise _bad("identity.keys", "must be environment variable names")
        if len(set(keys)) != len(keys):
            raise _bad("identity.keys", "lists a key twice")
        if identity["bytes"] > IDENTITY_MAX:
            raise _bad("identity.bytes", "is over 16 KiB")
        total += identity["bytes"]

    if total > max_bytes:
        raise SnapshotError(
            f"The snapshot holds {_size(total)}, more than this Slipway accepts "
            f"({_size(max_bytes)}, SLIPWAY_SNAPSHOT_MAX_BYTES)"
        )
    return manifest


def validate_identity(identity: Any, keys: list[str]) -> dict[str, str]:
    """Check ``identity.json``: exactly the declared keys, each value 1-4096 characters with no control
    characters. The values are secrets: no message quotes them."""
    if not isinstance(identity, dict):
        raise SnapshotError(f"The snapshot's {IDENTITY} isn't a JSON object")
    if sorted(identity) != sorted(keys):
        raise SnapshotError(f"The snapshot's {IDENTITY} doesn't hold the keys {MANIFEST} lists")
    for key, value in identity.items():
        if not isinstance(value, str) or not 1 <= len(value) <= 4096 or _CONTROL.search(value):
            raise SnapshotError(
                f"The snapshot's {IDENTITY}: {key} must be 1-4096 characters with no control characters"
            )
    return identity


def _size(n: int) -> str:
    for unit, scale in (("GiB", GiB), ("MiB", MiB), ("KiB", KiB)):
        if n >= scale:
            return f"{n / scale:.1f} {unit}"
    return f"{n} bytes"


class _ChunkReader:
    """A ``read(n)`` view of an iterable of byte chunks, with a peek at the start. It keeps one chunk and an
    offset into it, so many small reads from a large chunk don't copy the chunk each time."""

    def __init__(self, chunks: Iterable[bytes]) -> None:
        self._it = iter(chunks)
        self._buf = b""
        self._pos = 0

    def _next_chunk(self) -> bool:
        for chunk in self._it:
            if chunk:
                self._buf, self._pos = bytes(chunk), 0
                return True
        return False

    def peek(self, n: int) -> bytes:
        while len(self._buf) - self._pos < n:
            rest = self._buf[self._pos :]
            if not self._next_chunk():
                self._buf, self._pos = rest, 0
                break
            self._buf = rest + self._buf
        return self._buf[self._pos : self._pos + n]

    def read(self, n: int = -1) -> bytes:
        if self._pos >= len(self._buf) and not self._next_chunk():
            return b""
        end = len(self._buf) if n < 0 else self._pos + n
        out = self._buf[self._pos : end]
        self._pos += len(out)
        return out


class _Gunzip:
    """gzip decompression with Slipway's own zlib object and bounded reads (a bomb can't fill memory)."""

    def __init__(self, raw: _ChunkReader) -> None:
        self._raw = raw
        self._z = zlib.decompressobj(wbits=31)

    def read(self, n: int) -> bytes:
        while True:
            if self._z.eof:
                rest = self._z.unused_data or self._raw.read(64 * KiB)
                if not rest:
                    return b""
                if len(rest) < 2:  # a magic number split across two pieces of input
                    rest += self._raw.read(1)
                if rest[:2] != b"\x1f\x8b":  # anything but another gzip member after the end
                    raise SnapshotError(AFTER_END)
                self._z = zlib.decompressobj(wbits=31)
                data = rest
            else:
                data = self._z.unconsumed_tail or self._raw.read(64 * KiB)
                if not data:
                    raise SnapshotError("The file isn't a complete Slipway snapshot (the gzip stream ends early)")
            try:
                out = self._z.decompress(data, n)
            except zlib.error:
                raise SnapshotError("The file isn't a Slipway snapshot (its gzip data is damaged)") from None
            if out:
                return out


class _Capped:
    """Limits how many plaintext (decompressed) bytes the tar reader may consume."""

    def __init__(self, inner: _ChunkReader | _Gunzip, limit: int) -> None:
        self._inner = inner
        self.limit = limit
        self.count = 0

    def read(self, n: int) -> bytes:
        data = _read_exact(self._inner, n)
        self.count += len(data)
        if self.count > self.limit:
            raise SnapshotError(TOO_BIG_UNPACKED)
        return data


_TYPE_NAMES = {
    b"1": "a hard link", b"2": "a symbolic link", b"3": "a character device", b"4": "a block device",
    b"5": "a folder", b"6": "a named pipe", b"7": "a contiguous file",
}
_ZERO_BLOCK = bytes(512)
_PAX_KEYS = {"path", "size", "mtime"}


@dataclass
class _Member:
    name: str
    size: int


def _octal(field_bytes: bytes, what: str) -> int:
    if field_bytes and field_bytes[0] & 0x80:  # GNU base-256 for values that don't fit in octal
        if field_bytes[0] != 0x80:
            raise SnapshotError(f"The file isn't a Slipway snapshot (a member has a bad {what})")
        return int.from_bytes(field_bytes[1:], "big")
    text = field_bytes.replace(b"\x00", b" ").strip()
    if not text:
        return 0
    try:
        return int(text, 8)
    except ValueError:
        raise SnapshotError(f"The file isn't a Slipway snapshot (a member has a bad {what})") from None


def _parse_pax(data: bytes) -> dict[str, str]:
    """PAX records ``"<len> <key>=<value>\\n"``; only path, size, mtime and SLIPWAY.* are accepted."""
    records: dict[str, str] = {}
    pos = 0
    while pos < len(data):
        if data[pos:] == bytes(len(data) - pos):  # NUL padding after the last record
            break
        space = data.find(b" ", pos)
        if space < 0 or not data[pos:space].isdigit():
            raise SnapshotError("The file isn't a Slipway snapshot (a PAX header is damaged)")
        length = int(data[pos:space])
        record = data[pos : pos + length]
        if length <= space - pos + 1 or len(record) != length or not record.endswith(b"\n") or b"=" not in record:
            raise SnapshotError("The file isn't a Slipway snapshot (a PAX header is damaged)")
        key_bytes, _, value_bytes = record[space - pos + 1 : -1].partition(b"=")
        try:
            key, value = key_bytes.decode("utf-8"), value_bytes.decode("utf-8")
        except UnicodeDecodeError:
            raise SnapshotError("The file isn't a Slipway snapshot (a PAX header is damaged)") from None
        if key.startswith("GNU.sparse."):
            raise SnapshotError("The snapshot has a sparse file; members must be plain files")
        if key not in _PAX_KEYS and not key.startswith("SLIPWAY."):
            raise SnapshotError(f"The snapshot uses the PAX header key {key[:60]!r}, which Slipway doesn't accept")
        if key in records:
            raise SnapshotError("The file isn't a Slipway snapshot (a PAX header repeats a key)")
        records[key] = value
        pos += length
    return records


class _TarReader:
    """A strict reader for the snapshot tar. It accepts only what the format allows (regular files, ustar
    or PAX headers with a few keys) and refuses everything else before buffering it. Unlike ``tarfile``'s
    stream mode it never treats an unreadable header as the end of the archive, so data after the last
    member can't slip through."""

    def __init__(self, stream: _Capped) -> None:
        self._f = stream
        self.ended = False

    def _block(self, context: str) -> bytes:
        block = _read_exact(self._f, 512)
        if len(block) < 512:
            raise _Truncated(f"The file isn't a complete Slipway snapshot (it ends {context})")
        return block

    def next(self, context: str) -> _Member | None:
        """The next member's header, or None at the end-of-archive block."""
        pax: dict[str, str] | None = None
        while True:
            block = self._block(context)
            if block == _ZERO_BLOCK:
                if pax is not None:
                    raise SnapshotError("The file isn't a Slipway snapshot (a PAX header has no member)")
                self.ended = True
                return None
            magic = block[257:263]
            posix = magic == b"ustar\x00"
            if not posix and block[257:265] != b"ustar  \x00":
                raise SnapshotError(NOT_TAR)
            stored = _octal(block[148:156], "checksum")
            header = block[:148] + b" " * 8 + block[156:]
            signed = sum(struct.unpack("512b", header))
            if stored not in (sum(header), signed):
                raise SnapshotError("The file isn't a Slipway snapshot (a member header is damaged)")
            kind = block[156:157]
            size = _octal(block[124:136], "size")
            if kind == b"x":
                if pax is not None:
                    raise SnapshotError("The file isn't a Slipway snapshot (two PAX headers in a row)")
                if size > PAX_MAX:
                    raise SnapshotError("The snapshot has a PAX header over 64 KiB")
                data = _read_exact(self._f, size)
                if len(data) < size:
                    raise _Truncated(f"The file isn't a complete Slipway snapshot (it ends {context})")
                self._skip_padding(size, context)
                pax = _parse_pax(data)
                continue
            if kind == b"g":
                raise SnapshotError("The snapshot has a global PAX header, which Slipway doesn't accept")
            if kind in (b"L", b"K"):
                raise SnapshotError("The snapshot uses GNU long names, which Slipway doesn't accept")
            if kind == b"S":
                raise SnapshotError("The snapshot has a sparse file; members must be plain files")
            name_raw = block[:100].split(b"\x00", 1)[0]
            prefix = block[345:500].split(b"\x00", 1)[0] if posix else b""
            if prefix:
                name_raw = prefix + b"/" + name_raw
            try:
                name = name_raw.decode("utf-8")
            except UnicodeDecodeError:
                raise SnapshotError("The snapshot has a member whose name isn't UTF-8") from None
            if pax is not None:
                name = pax.get("path", name)
                if "size" in pax:
                    # ASCII digits only: str.isdigit() also accepts digits such as "²" that int() refuses.
                    if not re.fullmatch(r"[0-9]{1,20}", pax["size"]):
                        raise SnapshotError("The file isn't a Slipway snapshot (a PAX size is damaged)")
                    size = int(pax["size"])
            if kind not in (b"0", b"\x00"):
                what = _TYPE_NAMES.get(kind, "an unsupported kind of member")
                raise SnapshotError(f"The snapshot's {name[:100]!r} is {what}; members must be plain files")
            return _Member(name, size)

    def _skip_padding(self, size: int, context: str) -> None:
        pad = -size % 512
        if pad and len(_read_exact(self._f, pad)) < pad:
            raise _Truncated(f"The file isn't a complete Slipway snapshot (it ends {context})")

    def read_data(self, member: _Member, piece: int = MiB) -> Iterator[bytes]:
        left = member.size
        while left:
            data = self._f.read(min(piece, left))
            if not data:
                raise _Truncated(f"The file isn't a complete Slipway snapshot (it ends inside {member.name!r})")
            left -= len(data)
            yield data
        self._skip_padding(member.size, f"inside {member.name!r}")

    def check_end(self) -> None:
        """After the end-of-archive block only zero padding may follow."""
        while data := self._f.read(64 * KiB):
            if data.count(0) != len(data):
                raise SnapshotError(AFTER_END)


@dataclass
class SnapshotContents:
    """What validation found: the checked manifest and identity values (secrets: keep them in memory)."""

    manifest: dict[str, Any]
    identity: dict[str, str] | None
    compressed: bool
    plaintext_bytes: int = 0
    members: list[str] = field(default_factory=list)


def _sniff(raw: _ChunkReader) -> bool:
    """True for gzip, False for a plain tar; refuses everything else (bz2, xz, zstd included)."""
    head = raw.peek(262)
    if head[:2] == b"\x1f\x8b":
        return True
    if len(head) >= 262 and head[257:262] == b"ustar":
        return False
    raise SnapshotError(NOT_TAR)


# What a parser can raise on input it didn't foresee, besides SnapshotError (ValueError covers UnicodeError).
_PARSE_ERRORS = (ValueError, struct.error, OverflowError, RecursionError, zlib.error)


class _Outside:
    """Runs the caller's code (the plaintext source, ``sink``, ``on_manifest``) for ``validate`` and notes when
    an exception came from there, so ``validate`` passes it on unchanged instead of calling the file bad."""

    def __init__(self) -> None:
        self.raised = False

    def iterate(self, chunks: Iterable[bytes]) -> Iterator[bytes]:
        it = iter(chunks)
        while True:
            self.raised = True
            try:
                chunk = next(it)
            except StopIteration:
                self.raised = False
                return
            self.raised = False
            yield chunk

    def wrap(self, fn: Callable[..., None] | None) -> Callable[..., None] | None:
        if fn is None:
            return None

        def call(*args: Any) -> None:
            self.raised = True
            fn(*args)
            self.raised = False

        return call


def validate(
    plaintext: Iterable[bytes],
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    sink: Callable[[str, bytes | None], None] | None = None,
    on_manifest: Callable[[dict[str, Any]], None] | None = None,
) -> SnapshotContents:
    """Check a snapshot's plaintext (tar or tar.gz) in one streaming pass (spec §10.3).

    ``sink(name, chunk)`` receives the bytes of ``database`` and ``files`` as they are read, then
    ``sink(name, None)`` once that member's size and SHA-256 have matched. ``on_manifest`` is called with the
    checked manifest before any other member is read. Raises ``SnapshotError``; on an error a sink may
    already have received bytes, which the caller must discard. Errors raised by ``plaintext``, ``sink`` or
    ``on_manifest`` themselves reach the caller unchanged.
    """
    outside = _Outside()
    try:
        return _validate(outside.iterate(plaintext), max_bytes=max_bytes, sink=outside.wrap(sink),
                         on_manifest=outside.wrap(on_manifest))
    except SnapshotError:
        raise
    except _PARSE_ERRORS:
        if outside.raised:
            raise
        # A case the checks above didn't foresee: still a refusal of the file, never a crash.
        raise SnapshotError(DAMAGED_TAR) from None


def _validate(
    plaintext: Iterable[bytes],
    *,
    max_bytes: int,
    sink: Callable[[str, bytes | None], None] | None,
    on_manifest: Callable[[dict[str, Any]], None] | None,
) -> SnapshotContents:
    raw = _ChunkReader(plaintext)
    compressed = _sniff(raw)
    capped = _Capped(_Gunzip(raw) if compressed else raw, 4 * max_bytes)
    tar = _TarReader(capped)

    first = tar.next(f"before {MANIFEST}")
    if first is None or first.name != MANIFEST:
        got = "nothing" if first is None else repr(first.name[:100])
        raise SnapshotError(f"The file isn't a Slipway snapshot (its first member is {got}, not {MANIFEST})")
    if first.size > MANIFEST_MAX:
        raise SnapshotError(f"The snapshot's {MANIFEST} is over 64 KiB")
    raw_manifest = b"".join(tar.read_data(first))
    try:
        manifest = _load_json(raw_manifest)
    except ValueError:
        raise SnapshotError(f"The snapshot's {MANIFEST} isn't valid JSON") from None
    validate_manifest(manifest, max_bytes=max_bytes)
    if on_manifest is not None:
        on_manifest(manifest)

    expected = [(IDENTITY, manifest.get("identity")), (DATABASE, manifest["database"]), (FILES, manifest.get("files"))]
    declared = [name for name, entry in expected if entry is not None]
    sizes = sum(entry["bytes"] for _, entry in expected if entry is not None)
    # Inflation guard: from here on only the declared sizes plus a little tar overhead may follow.
    capped.limit = min(capped.limit, capped.count + sizes + INFLATION_SLACK)

    seen = [MANIFEST]
    identity: dict[str, str] | None = None
    for position, name in enumerate(declared):
        member = tar.next(f"before {name!r}")
        if member is None:
            raise SnapshotError(f"The snapshot is missing {name!r}, which {MANIFEST} declares")
        if member.name != name:
            raise _misplaced(member.name, name, seen, declared[position:])
        entry = manifest[name.removesuffix(".json")]
        if member.size != entry["bytes"]:
            raise SnapshotError(
                f"The snapshot's {name!r} is {member.size} bytes, but {MANIFEST} says {entry['bytes']}"
            )
        digest = hashlib.sha256()
        held: list[bytes] = []
        for piece in tar.read_data(member):
            digest.update(piece)
            if name == IDENTITY:
                held.append(piece)
            elif sink is not None:
                sink(name, piece)
        if digest.hexdigest() != entry["sha256"]:
            raise SnapshotError(f"The snapshot's {name!r} doesn't match its SHA-256 in {MANIFEST}")
        if name == IDENTITY:
            try:
                values = _load_json(b"".join(held))
            except ValueError:
                raise SnapshotError(f"The snapshot's {IDENTITY} isn't valid JSON") from None
            identity = validate_identity(values, entry["keys"])
        elif sink is not None:
            sink(name, None)
        seen.append(name)

    try:
        trailing = tar.next("after the last member")
    except _Truncated:
        raise
    except SnapshotError:  # not a member header: bytes that don't belong to the snapshot
        raise SnapshotError(AFTER_END) from None
    if trailing is not None:
        raise _misplaced(trailing.name, None, seen, [])
    tar.check_end()
    return SnapshotContents(manifest, identity, compressed, capped.count, seen)


def _misplaced(got: str, wanted: str | None, seen: list[str], still: list[str]) -> SnapshotError:
    shown = repr(got[:100])
    if got in seen:
        return SnapshotError(f"The snapshot has {shown} twice")
    if got in still:
        return SnapshotError(f"The snapshot's members are in the wrong order ({shown} before {wanted!r})")
    if got in MEMBERS:
        return SnapshotError(f"The snapshot has {shown}, which {MANIFEST} doesn't declare")
    if wanted is None:
        return SnapshotError(f"The snapshot has an unexpected member {shown} after its last one")
    return SnapshotError(f"The snapshot has an unexpected member {shown}")


def validate_container(
    f: Readable,
    data_key: bytes,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    sink: Callable[[str, bytes | None], None] | None = None,
    on_manifest: Callable[[dict[str, Any]], None] | None = None,
) -> SnapshotContents:
    """Decrypt and validate a container from ``f`` (positioned at the start of the file)."""
    plaintext = iter_plaintext(f, data_key)
    contents = validate(plaintext, max_bytes=max_bytes, sink=sink, on_manifest=on_manifest)
    for _ in plaintext:  # the tar ended: the rest must still decrypt and end properly
        pass
    return contents


# --- the inner tar: writing ----------------------------------------------------------------------------------


def utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def file_digest(path: str | os.PathLike[str], *, bufsize: int = MiB) -> tuple[int, str]:
    """Size and SHA-256 of a file."""
    digest, size = hashlib.sha256(), 0
    with open(path, "rb") as f:
        while chunk := f.read(bufsize):
            digest.update(chunk)
            size += len(chunk)
    return size, digest.hexdigest()


def identity_member(identity: dict[str, str]) -> bytes:
    """The bytes of ``identity.json`` for these values (sorted keys, so the same values hash the same)."""
    return json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _tar_header(name: str, size: int) -> bytes:
    """A member header from ``tarfile`` (used only for writing): PAX, so sizes over 8 GiB are standard."""
    info = tarfile.TarInfo(name)
    info.size, info.mode, info.mtime, info.type = size, 0o600, int(time.time()), tarfile.REGTYPE
    info.uname = info.gname = ""
    return info.tobuf(tarfile.PAX_FORMAT, "utf-8", "strict")


def _write_member(out: Writable, name: str, source: Readable, size: int, sha256: str, *, bufsize: int) -> None:
    out.write(_tar_header(name, size))
    digest, left = hashlib.sha256(), size
    while left:
        chunk = source.read(min(bufsize, left))
        if not chunk:
            raise SnapshotError(f"The {name} changed while it was copied (it ended early)")
        digest.update(chunk)
        out.write(chunk)
        left -= len(chunk)
    if source.read(1):
        raise SnapshotError(f"The {name} changed while it was copied (it grew)")
    if digest.hexdigest() != sha256:
        raise SnapshotError(f"The {name} changed while it was copied")
    if pad := -size % 512:
        out.write(bytes(pad))


def write_tar(
    out: Writable,
    manifest: dict[str, Any],
    *,
    identity: dict[str, str] | None,
    database: Readable,
    files: Readable | None = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
    bufsize: int = MiB,
) -> None:
    """Write a version 1 snapshot tar to ``out`` (a file, or a ``ContainerWriter``).

    ``manifest`` must already declare each member's size and SHA-256 (they come first in the tar). Each
    source is hashed again as it is copied, and a difference raises ``<member> changed while it was copied``;
    the caller then deletes what it was writing.
    """
    validate_manifest(manifest, max_bytes=max_bytes)
    if (identity is None) != (manifest.get("identity") is None):
        raise ValueError("identity values and manifest['identity'] must come together")
    if (files is None) != (manifest.get("files") is None):
        raise ValueError("a files source and manifest['files'] must come together")
    raw_manifest = _dump_json(manifest)
    if len(raw_manifest) > MANIFEST_MAX:
        raise SnapshotError(f"The snapshot's {MANIFEST} would be over 64 KiB (shorten the notes)")
    out.write(_tar_header(MANIFEST, len(raw_manifest)) + raw_manifest + bytes(-len(raw_manifest) % 512))
    if identity is not None:
        entry = manifest["identity"]
        validate_identity(identity, entry["keys"])
        raw_identity = identity_member(identity)
        if len(raw_identity) != entry["bytes"] or hashlib.sha256(raw_identity).hexdigest() != entry["sha256"]:
            raise ValueError("manifest['identity'] doesn't describe these identity values")
        out.write(_tar_header(IDENTITY, len(raw_identity)) + raw_identity + bytes(-len(raw_identity) % 512))
    db = manifest["database"]
    _write_member(out, DATABASE, database, db["bytes"], db["sha256"], bufsize=bufsize)
    if files is not None:
        entry = manifest["files"]
        _write_member(out, FILES, files, entry["bytes"], entry["sha256"], bufsize=bufsize)
    out.write(bytes(1024))  # the end-of-archive marker: two zero blocks


def build_manifest(
    *,
    app: str,
    app_name: str,
    source: str,
    database: dict[str, Any],
    repository: str | None = None,
    commit: str | None = None,
    notes: str = "",
    files: dict[str, Any] | None = None,
    identity: dict[str, str] | None = None,
    producer: str | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    """A version 1 manifest. ``database`` is ``{format, revision, bytes, sha256}``, ``files`` is
    ``{format, bytes, sha256}``; the identity entry is computed from the values."""
    manifest: dict[str, Any] = {
        "format": FORMAT, "version": VERSION, "app": app, "app_name": app_name, "repository": repository,
        "commit": commit, "source": source, "created_at": created_at or utc_now(), "notes": notes,
        "database": database, "files": files, "identity": None,
    }
    if identity is not None:
        raw = identity_member(identity)
        manifest["identity"] = {"keys": sorted(identity), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    if producer is not None:
        manifest["producer"] = producer
    return manifest


# --- slipway snapshot pack -----------------------------------------------------------------------------------


@dataclass
class PackResult:
    path: str
    bytes: int
    sha256: str
    encrypted: bool
    has_identity: bool


def _open_new(path: str) -> BinaryIO:
    """Create ``path`` (0600), refusing an existing file or a symlink in its place."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    return os.fdopen(os.open(path, flags, 0o600), "wb")


class _HashingWriter:
    def __init__(self, out: BinaryIO) -> None:
        self._out = out
        self.digest = hashlib.sha256()
        self.count = 0

    def write(self, data: bytes) -> int:
        self._out.write(data)
        self.digest.update(data)
        self.count += len(data)
        return len(data)


def pack(
    out_path: str,
    manifest: dict[str, Any],
    *,
    database_path: str,
    files_path: str | None = None,
    identity: dict[str, str] | None = None,
    passphrase: str | None = None,
) -> PackResult:
    """Write a snapshot file: the plain tar, or (with ``passphrase``) an ``.sbx`` with an scrypt key block.

    Refuses an existing ``out_path`` and writes through ``<out>.partial`` (0600), which is removed on failure.
    """
    if os.path.lexists(out_path):
        raise SnapshotError(f"{out_path} already exists; choose another --out or remove it first")
    partial = f"{out_path}.partial"
    if passphrase is not None:
        check_passphrase(passphrase)
    try:
        f = _open_new(partial)
    except FileExistsError:
        raise SnapshotError(f"{partial} already exists; remove it if no other pack is writing it") from None
    try:
        with f:
            hashed = _HashingWriter(f)
            sink: Writable = hashed
            writer = None
            if passphrase is not None:
                writer = ContainerWriter(hashed, new_data_key(), passphrase=passphrase)
                sink = writer
            with open(database_path, "rb") as db:
                files = open(files_path, "rb") if files_path is not None else None  # noqa: SIM115
                try:
                    write_tar(sink, manifest, identity=identity, database=db, files=files)
                finally:
                    if files is not None:
                        files.close()
            if writer is not None:
                writer.close()
            f.flush()
            os.fsync(f.fileno())
        try:
            os.link(partial, out_path)  # fails if something appeared at out_path meanwhile
        except FileExistsError:
            raise SnapshotError(f"{out_path} already exists; choose another --out or remove it first") from None
        except OSError:  # a filesystem without hard links
            if os.path.lexists(out_path):
                raise SnapshotError(f"{out_path} already exists; choose another --out or remove it first") from None
            os.rename(partial, out_path)
    finally:
        if os.path.lexists(partial):
            os.unlink(partial)
    return PackResult(out_path, hashed.count, hashed.digest.hexdigest(), passphrase is not None, identity is not None)
