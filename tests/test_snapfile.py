"""The snapshot file format (spec §10.1-10.3), ``slipway snapshot pack`` (§10.9) and the rotate-encryption-key
fix-ups for snapshots and first admins (§6.7)."""

from __future__ import annotations

import argparse
import bz2
import gzip
import hashlib
import io
import json
import lzma
import os
import stat
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import select, text

from slipway import cli
from slipway.core.config import get_settings
from slipway.core.crypto import reset_crypto_cache
from slipway.db.session import get_sessionmaker
from slipway.services import snapfile
from slipway.services.snapfile import SnapshotError

ROOT = Path(__file__).resolve().parent.parent
C16 = 1 << 16  # the smallest chunk size, so multi-chunk files stay small
PASSPHRASE = "correct horse battery staple"
SHA_A = "a" * 64


# --- helpers -------------------------------------------------------------------------------------------------


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _manifest(database: bytes, *, files: bytes | None = None, identity: dict[str, str] | None = None, **extra):
    manifest = snapfile.build_manifest(
        app="serversherpa", app_name="ServerSherpa", source="uat", repository="encondata/BaseCampV3",
        commit="0" * 40, notes="seed data",
        database={"format": "pg-custom", "revision": "0090", "bytes": len(database), "sha256": _sha(database)},
        files=None if files is None else {"format": "serversherpa-objects-v1", "bytes": len(files), "sha256": _sha(files)},
        identity=identity, producer="slipway test",
    )
    manifest.update(extra)
    return manifest


def _snapshot(database: bytes = b"DB:" + bytes(range(256)) * 40, *, files: bytes | None = None,
              identity: dict[str, str] | None = None) -> bytes:
    """A version 1 tar written by Slipway's own writer."""
    out = io.BytesIO()
    snapfile.write_tar(out, _manifest(database, files=files, identity=identity), identity=identity,
                       database=io.BytesIO(database), files=None if files is None else io.BytesIO(files))
    return out.getvalue()


def _tar(*members: tuple[tarfile.TarInfo, bytes | None], fmt: int = tarfile.PAX_FORMAT) -> bytes:
    """A tar built with tarfile, for members Slipway's writer would never produce."""
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=fmt) as tf:
        for info, data in members:
            tf.addfile(info, None if data is None else io.BytesIO(data))
    return out.getvalue()


def _member(name: str, data: bytes = b"", **attrs) -> tuple[tarfile.TarInfo, bytes]:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    for key, value in attrs.items():
        setattr(info, key, value)
    return info, data


def _manifest_member(database: bytes, **kw) -> tuple[tarfile.TarInfo, bytes]:
    return _member(snapfile.MANIFEST, json.dumps(_manifest(database, **kw)).encode())


def _retype(tar: bytes, offset: int, kind: bytes) -> bytes:
    """Change the type flag of the header at ``offset`` and fix its checksum."""
    block = bytearray(tar[offset : offset + 512])
    block[156:157] = kind
    block[148:156] = b" " * 8
    block[148:156] = b"%06o\x00 " % sum(block)
    return tar[:offset] + bytes(block) + tar[offset + 512 :]


def _refused(data: bytes | list[bytes], **kw) -> str:
    chunks = [data] if isinstance(data, bytes) else data
    with pytest.raises(SnapshotError) as exc:
        snapfile.validate(iter(chunks), **kw)
    return str(exc.value)


def _encrypt(plaintext: bytes, *, key: bytes, chunk_log2: int = 16, passphrase: str | None = None) -> bytes:
    out = io.BytesIO()
    writer = snapfile.ContainerWriter(out, key, chunk_log2=chunk_log2, passphrase=passphrase)
    # Uneven writes exercise the chunk buffering.
    for start in range(0, len(plaintext), 7777):
        writer.write(plaintext[start : start + 7777])
    writer.close()
    data = out.getvalue()
    assert writer.file_bytes == len(data) and writer.file_sha256 == _sha(data)
    return data


def _decrypt(data: bytes, key: bytes) -> bytes:
    return b"".join(snapfile.iter_plaintext(io.BytesIO(data), key))


def _decrypt_error(data: bytes, key: bytes) -> str:
    with pytest.raises(SnapshotError) as exc:
        _decrypt(data, key)
    return str(exc.value)


# --- the inner format: round trips ---------------------------------------------------------------------------


def test_plain_round_trip_with_identity_and_files():
    database, files = os.urandom(300_000), os.urandom(5000)
    identity = {"SS_PASSWORD_PEPPER": "ab" * 32, "SS_TOTP_ENCRYPTION_KEY": "x" * 44}
    got: dict[str, list[bytes | None]] = {}
    seen_manifest = []
    contents = snapfile.validate(
        iter([_snapshot(database, files=files, identity=identity)]),
        sink=lambda name, chunk: got.setdefault(name, []).append(chunk),
        on_manifest=seen_manifest.append,
    )
    assert contents.members == [snapfile.MANIFEST, snapfile.IDENTITY, snapfile.DATABASE, snapfile.FILES]
    assert contents.identity == identity and not contents.compressed
    assert contents.manifest["identity"]["keys"] == sorted(identity)
    assert seen_manifest == [contents.manifest]
    # Each member streams out and is closed with None only after its sha matched; identity never reaches the sink.
    assert set(got) == {"database", "files"}
    assert got["database"][-1] is None and b"".join(got["database"][:-1]) == database
    assert got["files"][-1] is None and b"".join(got["files"][:-1]) == files


def test_database_only_and_gzip_round_trip():
    database = b"DB:" + os.urandom(70_000)
    plain = _snapshot(database)
    contents = snapfile.validate(iter([plain]))
    assert contents.members == [snapfile.MANIFEST, snapfile.DATABASE]
    assert contents.identity is None and contents.manifest["files"] is None

    # tar czf output is accepted, fed in small pieces as an upload would arrive.
    packed = gzip.compress(plain)
    pieces = [packed[i : i + 1000] for i in range(0, len(packed), 1000)]
    got = []
    contents = snapfile.validate(iter(pieces), sink=lambda name, chunk: got.append(chunk))
    assert contents.compressed and b"".join(c for c in got if c) == database


def test_a_tar_made_by_tarfile_itself_is_accepted():
    """A hand-made tar (ustar, GNU or PAX headers, tarfile's record padding) passes when it follows the rules."""
    database = b"DB:hello"
    for fmt in (tarfile.USTAR_FORMAT, tarfile.GNU_FORMAT, tarfile.PAX_FORMAT):
        tar = _tar(_manifest_member(database), _member("database", database), fmt=fmt)
        assert snapfile.validate(iter([tar])).members == [snapfile.MANIFEST, snapfile.DATABASE]


def test_large_sizes_use_pax_headers_the_reader_accepts():
    header = snapfile._tar_header("database", 9 * snapfile.GiB)
    assert header[156:157] == b"x" and b" size=9663676416\n" in header  # PAX, since ustar stops at 8 GiB
    reader = snapfile._TarReader(snapfile._Capped(snapfile._ChunkReader([header]), 1 << 40))
    member = reader.next("here")
    assert member is not None and (member.name, member.size) == ("database", 9 * snapfile.GiB)


# --- the inner format: refusals ------------------------------------------------------------------------------


def test_wrong_order_extra_member_and_duplicates_are_refused():
    db = b"DB:x"
    identity = {"APP_KEY": "k" * 32}
    ident = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    with_identity = _manifest_member(db, identity=identity)
    assert "wrong order ('database' before 'identity.json')" in _refused(
        _tar(with_identity, _member("database", db), _member("identity.json", ident))
    )
    assert "has 'files', which slipway-snapshot.json doesn't declare" in _refused(
        _tar(_manifest_member(db), _member("database", db), _member("files", b"x"))
    )
    assert "has 'database' twice" in _refused(_tar(_manifest_member(db), _member("database", db), _member("database", db)))
    assert "unexpected member 'notes.txt' after its last one" in _refused(
        _tar(_manifest_member(db), _member("database", db), _member("notes.txt", b"hi"))
    )
    assert "missing 'database'" in _refused(_tar(_manifest_member(db)))
    assert "first member is 'database'" in _refused(_tar(_member("database", db), _manifest_member(db)))
    assert "unexpected member '../x'" in _refused(_tar(_manifest_member(db), _member("../x", db)))
    assert "unexpected member './database'" in _refused(_tar(_manifest_member(db), _member("./database", db)))


@pytest.mark.parametrize(
    ("kind", "words"),
    [
        (tarfile.SYMTYPE, "is a symbolic link"),
        (tarfile.LNKTYPE, "is a hard link"),
        (tarfile.CHRTYPE, "is a character device"),
        (tarfile.BLKTYPE, "is a block device"),
        (tarfile.DIRTYPE, "is a folder"),
        (tarfile.FIFOTYPE, "is a named pipe"),
    ],
    ids=["symlink", "hardlink", "char-device", "block-device", "folder", "fifo"],
)
def test_members_must_be_regular_files(kind, words):
    info = tarfile.TarInfo("database")
    info.type = kind
    info.linkname = "/etc/passwd" if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE) else ""
    message = _refused(_tar(_manifest_member(b"DB:x"), (info, None)))
    assert words in message and "members must be plain files" in message


def test_sparse_files_long_names_and_pax_keys_are_refused():
    db = b"DB:x"
    plain = _tar(_manifest_member(db), _member("database", db), fmt=tarfile.GNU_FORMAT)
    # GNU sparse type 'S' (the second member's header is at 512 + the manifest's padded size).
    manifest_len = len(json.dumps(_manifest(db)).encode())
    second = 512 + manifest_len + (-manifest_len % 512)
    assert "sparse file" in _refused(_retype(plain, second, b"S"))
    # PAX sparse keys.
    sparse_pax = _member("database", db, pax_headers={"GNU.sparse.major": "1", "GNU.sparse.minor": "0"})
    assert "sparse file" in _refused(_tar(_manifest_member(db), sparse_pax))
    # A GNU long name ('L' header) for a name over 100 characters.
    long_name = _member("d" * 120, db)
    assert "GNU long names" in _refused(_tar(_manifest_member(db), long_name, fmt=tarfile.GNU_FORMAT))
    # An unknown PAX key, and a global PAX header.
    assert "PAX header key 'comment'" in _refused(
        _tar(_manifest_member(db), _member("database", db, pax_headers={"comment": "hi"}))
    )
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.PAX_FORMAT, pax_headers={"SLIPWAY.x": "1"}) as tf:
        info, data = _manifest_member(db)
        tf.addfile(info, io.BytesIO(data))
    assert "global PAX header" in _refused(out.getvalue())
    # SLIPWAY.* keys are allowed.
    ok = _tar(_manifest_member(db), _member("database", db, pax_headers={"SLIPWAY.note": "fine"}))
    assert snapfile.validate(iter([ok])).members[-1] == "database"


def test_a_pax_header_over_64_kib_is_refused_before_it_is_read():
    db = b"DB:x"
    big = _member("database", db, pax_headers={"SLIPWAY.pad": "x" * (70 * 1024)})
    tar = _tar(_manifest_member(db), big)
    # Cut the file inside the PAX data: the refusal comes from the header size alone.
    manifest_len = len(json.dumps(_manifest(db)).encode())
    pax_at = 512 + manifest_len + (-manifest_len % 512)
    assert "PAX header over 64 KiB" in _refused(tar[: pax_at + 512 + 100])


def test_manifest_rules():
    db = b"DB:x"
    oversize = _member(snapfile.MANIFEST, b" " * (65 * 1024))
    assert "over 64 KiB" in _refused(_tar(oversize, _member("database", db)))
    unknown = _member(snapfile.MANIFEST, json.dumps(_manifest(db, colour="blue")).encode())
    assert "keys Slipway doesn't know: colour" in _refused(_tar(unknown, _member("database", db)))
    v2 = _member(snapfile.MANIFEST, json.dumps(_manifest(db, version=2, extra_v2_key=1)).encode())
    assert _refused(_tar(v2, _member("database", db))) == (
        "This snapshot was made by a newer Slipway (format version 2); update Slipway to import it"
    )
    dup = _member(snapfile.MANIFEST, json.dumps(_manifest(db))[:-1].encode() + b', "app": "other"}')
    assert "isn't valid JSON" in _refused(_tar(dup, _member("database", db)))
    with pytest.raises(SnapshotError, match="format: slipway-snapshot"):
        snapfile.validate_manifest({**_manifest(db), "format": "sirdar"})
    for key, value, words in [
        ("app", "Server Sherpa", "app must be"),
        ("repository", "no-slash", "repository must be owner/name"),
        ("source", "-uat", "source must"),
        ("created_at", "2026-11-15 10:15:00", "created_at must be"),
        ("created_at", "2026-13-15T10:15:00Z", "isn't a real date"),
        ("commit", "abc", "commit must be"),
        ("notes", "n" * 2001, "notes must be"),
    ]:
        with pytest.raises(SnapshotError, match=words):
            snapfile.validate_manifest({**_manifest(db), key: value})
    for nullable in ("repository", "commit"):
        snapfile.validate_manifest({**_manifest(db), nullable: None})
    with pytest.raises(SnapshotError, match="revision must be"):
        snapfile.validate_manifest(_manifest(db) | {"database": {**_manifest(db)["database"], "revision": "a\x00b"}})
    with pytest.raises(SnapshotError, match="more than this Slipway accepts"):
        snapfile.validate_manifest(_manifest(b"x" * 2000), max_bytes=1000)
    many = {f"KEY_{i}": "v" * 20 for i in range(17)}
    with pytest.raises(SnapshotError, match="must list 1-16 keys"):
        snapfile.validate_manifest(_manifest(db, identity=many))


def test_values_the_database_or_an_env_file_cant_hold_are_refused():
    """Review findings 32 and 33: every refusal is a SnapshotError, never a raw ValueError or a row the
    database can't store."""
    db = b"DB:x"
    # A PAX size made of a digit int() refuses ("²" passes str.isdigit()).
    pax_size = _member(snapfile.MANIFEST, b"{}", pax_headers={"size": "\u00b2"})
    assert _refused(_tar(pax_size)) == "The file isn't a Slipway snapshot (a PAX size is damaged)"
    fullwidth = _member(snapfile.MANIFEST, b"{}", pax_headers={"size": "\uff12"})
    assert "PAX size is damaged" in _refused(_tar(fullwidth))
    # A lone surrogate written as a JSON escape: valid UTF-8 bytes, but text no database can store.
    for where in ("app_name", "notes"):
        manifest = _member(snapfile.MANIFEST, json.dumps(_manifest(db, **{where: "Server\ud800Sherpa"})).encode())
        assert "isn't valid JSON" in _refused(_tar(manifest, _member("database", db)))
    revision = _manifest(db)
    revision["database"] = {**revision["database"], "revision": "0090\udfff"}
    assert "isn't valid JSON" in _refused(_tar(_member(snapfile.MANIFEST, json.dumps(revision).encode()),
                                               _member("database", db)))
    identity_json = json.dumps({"APP_KEY": "secret\ud800"}).encode()
    manifest = _manifest(db, identity={"APP_KEY": "x"})
    manifest["identity"] = {"keys": ["APP_KEY"], "bytes": len(identity_json), "sha256": _sha(identity_json)}
    assert _refused(_tar(_member(snapfile.MANIFEST, json.dumps(manifest).encode()),
                         _member(snapfile.IDENTITY, identity_json), _member("database", db))) == (
        "The snapshot's identity.json isn't valid JSON")
    # snapshots.repository is String(200): owner/name of 201 characters is refused, 200 is fine.
    with pytest.raises(SnapshotError, match="repository must be owner/name"):
        snapfile.validate_manifest({**_manifest(db), "repository": "a" * 100 + "/" + "b" * 100})
    snapfile.validate_manifest({**_manifest(db), "repository": "a" * 100 + "/" + "b" * 99})
    # "$" also matches before a final newline; nothing may end in one.
    for key, value in [("app", "serversherpa\n"), ("repository", "encondata/BaseCampV3\n"),
                       ("source", "uat\n"), ("commit", "0" * 40 + "\n"), ("created_at", "2026-11-15T10:15:00Z\n")]:
        with pytest.raises(SnapshotError, match=f"{key} "):
            snapfile.validate_manifest({**_manifest(db), key: value})
    with pytest.raises(SnapshotError, match="identity.keys must be environment variable names"):
        snapfile.validate_manifest(_manifest(db) | {"identity": {"keys": ["APP_KEY\n"], "bytes": 20, "sha256": SHA_A}})
    # PostgreSQL text can't hold NUL: the upload would be a 500 and the import's check would fail.
    for key in ("notes", "app_name", "producer"):
        with pytest.raises(SnapshotError, match=f"{key} can't contain a NUL character"):
            snapfile.validate_manifest({**_manifest(db), key: "a\x00b"})
    manifest = _member(snapfile.MANIFEST, json.dumps(_manifest(db, notes="a\x00b")).encode())
    assert "notes can't contain a NUL character" in _refused(_tar(manifest, _member("database", db)))


def test_an_unforeseen_parse_error_is_a_refusal_but_the_callers_errors_pass_through(monkeypatch):
    db = b"DB:" + os.urandom(100)
    plain = _snapshot(db)

    def boom(data: bytes) -> dict[str, str]:
        raise ValueError("a case the reader didn't foresee")

    monkeypatch.setattr(snapfile, "_parse_pax", boom)
    pax = _tar(_manifest_member(db), _member("database", db, pax_headers={"SLIPWAY.note": "x"}))
    assert _refused(pax) == snapfile.DAMAGED_TAR
    monkeypatch.undo()

    # A ValueError from the plaintext source or the sink is the caller's, and reaches it unchanged.
    def source():
        yield plain[:1000]
        raise ValueError("the source broke")

    with pytest.raises(ValueError, match="the source broke") as caught:
        snapfile.validate(source())
    assert not isinstance(caught.value, SnapshotError)

    def sink(name: str, chunk: bytes | None) -> None:
        raise ValueError("the sink broke")

    with pytest.raises(ValueError, match="the sink broke") as caught:
        snapfile.validate(iter([plain]), sink=sink)
    assert not isinstance(caught.value, SnapshotError)
    assert snapfile.validate(iter([plain])).members == [snapfile.MANIFEST, "database"]


def test_sha_mismatch_and_size_mismatch_are_refused():
    db = b"DB:" + os.urandom(1000)
    other = b"DB:" + os.urandom(1000)
    assert "'database' doesn't match its SHA-256" in _refused(_tar(_manifest_member(db), _member("database", other)))
    assert "'database' is 4 bytes, but slipway-snapshot.json says 1003" in _refused(
        _tar(_manifest_member(db), _member("database", b"DB:x"))
    )


def test_identity_keys_must_match_the_manifest():
    db = b"DB:x"
    declared = {"APP_KEY": "k" * 32, "OTHER_KEY": "o" * 32}
    actual = json.dumps({"APP_KEY": "k" * 32, "THIRD_KEY": "o" * 32}, sort_keys=True, separators=(",", ":")).encode()
    manifest = _manifest(db, identity=declared)
    manifest["identity"]["bytes"], manifest["identity"]["sha256"] = len(actual), _sha(actual)
    tar = _tar(_member(snapfile.MANIFEST, json.dumps(manifest).encode()), _member("identity.json", actual),
               _member("database", db))
    message = _refused(tar)
    assert "doesn't hold the keys slipway-snapshot.json lists" in message and "k" * 32 not in message
    bad_value = {"APP_KEY": "line\nbreak-secret"}
    raw = json.dumps(bad_value).encode()
    manifest = _manifest(db, identity={"APP_KEY": "placeholder"})
    manifest["identity"]["bytes"], manifest["identity"]["sha256"] = len(raw), _sha(raw)
    message = _refused(_tar(_member(snapfile.MANIFEST, json.dumps(manifest).encode()), _member("identity.json", raw),
                            _member("database", db)))
    assert "APP_KEY must be 1-4096 characters" in message and "break-secret" not in message


def test_compressors_other_than_gzip_are_refused_before_decompressing():
    plain = _snapshot()

    def only_the_start(data: bytes):
        yield data[:512]
        raise AssertionError("read past the sniff")

    for packed in (lzma.compress(plain), bz2.compress(plain), b"\x28\xb5\x2f\xfd" + bytes(600), b"plain text " * 60):
        with pytest.raises(SnapshotError) as exc:
            snapfile.validate(only_the_start(packed))
        assert str(exc.value) == "The file isn't a Slipway snapshot (not a tar or tar.gz)"


def test_a_gzip_bomb_stops_at_the_declared_size():
    # A valid snapshot followed by 200 MiB of zeros, which gzip squeezes to a few hundred KiB.
    plain = _snapshot() + bytes(200 * 1024 * 1024)
    packed = gzip.compress(plain, compresslevel=9)
    pieces = [packed[i : i + 4096] for i in range(0, len(packed), 4096)]
    used = 0

    def counted():
        nonlocal used
        for piece in pieces:
            used += 1
            yield piece

    with pytest.raises(SnapshotError) as exc:
        snapfile.validate(counted())
    assert str(exc.value) == snapfile.TOO_BIG_UNPACKED
    assert used < len(pieces) // 10  # it stopped long before the end


def test_data_after_the_end_and_a_missing_end_are_refused():
    plain = _snapshot()
    assert _refused(plain + b"junk" + bytes(508)) == snapfile.AFTER_END
    assert _refused(plain + bytes(512) + b"x") == snapfile.AFTER_END
    assert _refused(gzip.compress(plain) + b"garbage") == snapfile.AFTER_END
    assert "it ends inside 'database'" in _refused(plain[:4000])
    assert "it ends before 'database'" in _refused(plain[:1500])
    assert "it ends after the last member" in _refused(plain[:-1024])  # no end-of-archive blocks


def test_write_tar_refuses_a_source_that_changed():
    database = b"DB:" + os.urandom(5000)
    manifest = _manifest(database)
    for changed, words in [
        (b"DB:" + os.urandom(5000), "The database changed while it was copied"),
        (database[:-1], "ended early"),
        (database + b"!", "grew"),
    ]:
        with pytest.raises(SnapshotError, match=words):
            snapfile.write_tar(io.BytesIO(), manifest, identity=None, database=io.BytesIO(changed))


# --- the container -------------------------------------------------------------------------------------------


@pytest.mark.parametrize("size", [0, 1, C16 - 1, C16, C16 + 1, 3 * C16], ids=["0", "1", "C-1", "C", "C+1", "3C"])
def test_container_round_trip_and_size(size):
    key = snapfile.new_data_key()
    plaintext = os.urandom(size)
    data = _encrypt(plaintext, key=key)
    preamble = snapfile.parse_preamble(data)
    assert preamble is not None and preamble.keyblock == {"kdf": "none"}  # the stored form (D15)
    assert len(data) == snapfile.container_size(
        size, header_len=len(preamble.header_bytes), keyblock_len=len(preamble.keyblock_bytes), chunk_log2=16
    )
    assert len(data) - preamble.length == preamble.body_size(size)
    assert _decrypt(data, key) == plaintext


def _three_and_a_bit() -> tuple[bytes, bytes, int]:
    key = snapfile.new_data_key()
    data = _encrypt(os.urandom(3 * C16 + 5), key=key)
    return data, key, snapfile.parse_preamble(data).length


def test_truncation_damage_reordering_and_appended_bytes_are_refused():
    data, key, body = _three_and_a_bit()
    full = C16 + snapfile.TAG
    # Cut at a chunk boundary: the final chunk is missing.
    assert _decrypt_error(data[: body + 3 * full], key) == snapfile.INCOMPLETE
    assert _decrypt_error(data[: body + 3 * full + 10], key) == snapfile.INCOMPLETE  # less than a tag left
    # A flipped byte in the middle of the second chunk.
    flipped = bytearray(data)
    flipped[body + full + full // 2] ^= 0x01
    assert _decrypt_error(bytes(flipped), key) == "The file is damaged (part 2 doesn't decrypt)"
    # Two chunks swapped.
    c = [data[body + i * full : body + (i + 1) * full] for i in range(3)]
    swapped = data[:body] + c[0] + c[2] + c[1] + data[body + 3 * full :]
    assert _decrypt_error(swapped, key) == "The file is damaged (part 2 doesn't decrypt)"
    # Bytes appended after the final chunk: the final chunk no longer decrypts at the end of the file.
    assert _decrypt_error(data + b"more", key) in ("The file is damaged (part 4 doesn't decrypt)", snapfile.AFTER_END)
    # A whole extra chunk's worth appended.
    assert "doesn't decrypt" in _decrypt_error(data + os.urandom(full), key)
    # The wrong data key, and a changed header (the hash covers it).
    assert _decrypt_error(data, snapfile.new_data_key()) == "The file is damaged (part 1 doesn't decrypt)"
    header = snapfile.parse_preamble(data).header
    other = json.dumps({**header, "id": "00000000-0000-4000-8000-000000000000"}, separators=(",", ":")).encode()
    tampered = data.replace(snapfile.parse_preamble(data).header_bytes, other)
    assert _decrypt_error(tampered, key) == "The file is damaged (part 1 doesn't decrypt)"


def test_preamble_refusals():
    assert snapfile.parse_preamble(b"SLW") is None  # not enough yet
    for bad in (b"PK\x03\x04", b"SLWSNAP2" + bytes(8), b"SLWSNAP1" + b"\x00\x00\x10\x01"):
        with pytest.raises(SnapshotError, match="This isn't a Slipway snapshot file"):
            snapfile.parse_preamble(bad)
    data, key, body = _three_and_a_bit()
    # Fed a byte at a time it says "more" until the whole preamble is there.
    for n in range(body):
        assert snapfile.parse_preamble(data[:n]) is None
    assert snapfile.parse_preamble(data[:body]) is not None
    with pytest.raises(SnapshotError, match="The file is incomplete"):
        snapfile.read_preamble(io.BytesIO(data[: body - 3]))
    with pytest.raises(SnapshotError, match="This isn't a Slipway snapshot file"):
        snapfile.read_preamble(io.BytesIO(b""))
    newer = json.dumps({"v": 2, "cipher": "x"}).encode()
    with pytest.raises(SnapshotError, match="newer Slipway"):
        snapfile.parse_preamble(snapfile.MAGIC + len(newer).to_bytes(4, "big") + newer)


class _ScryptProbe:
    calls = 0

    def __init__(self, *args, **kwargs):
        type(self).calls += 1
        raise AssertionError("scrypt ran")


@pytest.mark.parametrize(
    "change", [{"log2_n": 16}, {"log2_n": 19}, {"p": 2}, {"r": 4}, {"log2_n": True}, {"kdf": "argon2id"}],
    ids=["n16", "n19", "p2", "r4", "bool", "other-kdf"],
)
def test_key_derivation_settings_are_refused_before_scrypt_runs(change, monkeypatch):
    key = snapfile.new_data_key()
    data = _encrypt(b"x" * 100, key=key, passphrase=PASSPHRASE)
    preamble = snapfile.parse_preamble(data)
    keyblock = {**preamble.keyblock, **change}
    monkeypatch.setattr(snapfile, "Scrypt", _ScryptProbe)
    raw = json.dumps(keyblock).encode()
    file = snapfile.MAGIC + len(preamble.header_bytes).to_bytes(4, "big") + preamble.header_bytes
    file += len(raw).to_bytes(4, "big") + raw
    with pytest.raises(SnapshotError) as exc:
        snapfile.parse_preamble(file)
    assert str(exc.value) == snapfile.BAD_KDF
    with pytest.raises(SnapshotError, match="key-derivation settings"):
        snapfile.unwrap_key(keyblock, PASSPHRASE, preamble.header_hash)
    assert _ScryptProbe.calls == 0


def test_passphrase_wrap_unwrap_wrong_passphrase_and_grafted_keyblock():
    key_a, key_b = snapfile.new_data_key(), snapfile.new_data_key()
    a = _encrypt(b"A" * 5000, key=key_a, passphrase=PASSPHRASE)
    b = _encrypt(b"B" * 5000, key=key_b, passphrase=PASSPHRASE)
    pa, pb = snapfile.parse_preamble(a), snapfile.parse_preamble(b)
    assert pa.locked and pa.keyblock["log2_n"] == 17 and (pa.keyblock["r"], pa.keyblock["p"]) == (8, 1)
    assert snapfile.unwrap_key(pa.keyblock, PASSPHRASE, pa.header_hash) == key_a
    # The passphrase is NFC-normalised before key derivation.
    nfc, nfd = "café-passphrase", "café-passphrase"
    wrapped = snapfile.wrap_key(key_a, nfc, pa.header_hash)
    assert snapfile.unwrap_key(wrapped, nfd, pa.header_hash) == key_a
    with pytest.raises(SnapshotError) as exc:
        snapfile.unwrap_key(pa.keyblock, "wrong horse battery staple", pa.header_hash)
    assert str(exc.value) == "That passphrase doesn't open this file"
    # A's key block grafted onto B: the wrap is bound to A's header, so B's header doesn't open it.
    grafted = pb.prefix(pa.keyblock) + b[pb.length :]
    pg = snapfile.parse_preamble(grafted)
    with pytest.raises(SnapshotError, match="That passphrase doesn't open this file"):
        snapfile.unwrap_key(pg.keyblock, PASSPHRASE, pg.header_hash)
    for bad in ("short", "x" * 1025, "twelve chars\tand a tab"):
        with pytest.raises(SnapshotError):
            snapfile.check_passphrase(bad)


def test_rewrap_keeps_the_body_and_the_stored_form_has_kdf_none():
    key = snapfile.new_data_key()
    plaintext = os.urandom(2 * C16 + 77)
    stored = _encrypt(plaintext, key=key)
    ps = snapfile.parse_preamble(stored)
    assert ps.keyblock == {"kdf": "none"} and not ps.locked
    # Export: a new scrypt key block in front of the unchanged body.
    keyblock = snapfile.wrap_key(key, PASSPHRASE, ps.header_hash)
    out = io.BytesIO()
    written = snapfile.rewrap(io.BytesIO(stored), out, keyblock)
    exported = out.getvalue()
    pe = snapfile.parse_preamble(exported)
    assert written == len(exported) == snapfile.container_size(
        len(plaintext), header_len=len(pe.header_bytes), keyblock_len=len(pe.keyblock_bytes), chunk_log2=16
    )
    assert exported[pe.length :] == stored[ps.length :]  # the body bytes are identical
    assert pe.header_bytes == ps.header_bytes and pe.locked
    # Import on another Slipway: stored with kdf:none in front, the passphrase key block held separately.
    imported = pe.stored_prefix() + exported[pe.length :]
    assert imported == stored
    unlocked = snapfile.unwrap_key(pe.keyblock, PASSPHRASE, snapfile.parse_preamble(imported).header_hash)
    assert _decrypt(imported, unlocked) == plaintext


def test_validate_container_end_to_end(tmp_path):
    identity = {"APP_KEY": "s3cret-identity-value-1234"}
    database = b"DB:" + os.urandom(200_000)
    key = snapfile.new_data_key()
    sbx = tmp_path / "snap.sbx"
    sbx.write_bytes(_encrypt(_snapshot(database, identity=identity), key=key, chunk_log2=16))
    assert b"s3cret-identity-value" not in sbx.read_bytes()
    with sbx.open("rb") as f:
        contents = snapfile.validate_container(f, key)
    assert contents.identity == identity and contents.manifest["database"]["sha256"] == _sha(database)
    assert snapfile.validate(snapfile.open_container(sbx, key)).identity == identity
    # A tar that validates but whose container was cut after the tar's end still fails.
    data = sbx.read_bytes()
    cut = data[: len(data) - 20]
    with pytest.raises(SnapshotError, match="damaged|incomplete"):
        snapfile.validate_container(io.BytesIO(cut), key)


# --- slipway snapshot pack -----------------------------------------------------------------------------------


def _pack(tmp_path: Path, *extra: str, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "slipway.cli", "snapshot", "pack", "--app", "serversherpa", "--app-name",
         "ServerSherpa", "--format", "pg-custom", "--database", str(tmp_path / "db.dump"), *extra],
        input=stdin, capture_output=True, text=True, cwd=ROOT, timeout=60,
        env={**os.environ, "PYTHONPATH": str(ROOT)},
    )


@pytest.fixture
def pack_inputs(tmp_path: Path) -> Path:
    (tmp_path / "db.dump").write_bytes(b"DB:" + os.urandom(150_000))
    (tmp_path / "objects.tar").write_bytes(os.urandom(4000))
    (tmp_path / "rev").write_text("0090\n")
    (tmp_path / "keys.env").write_text(
        "# identity keys\nexport SS_PASSWORD_PEPPER='" + "ab" * 32 + "'\nSS_TOTP_ENCRYPTION_KEY=pack-secret-value-xyz\n"
    )
    return tmp_path


def test_pack_encrypted(pack_inputs: Path):
    out = pack_inputs / "seed.slipway-snapshot"
    result = _pack(
        pack_inputs, "--revision-file", str(pack_inputs / "rev"), "--commit", "1" * 40, "--repository",
        "encondata/BaseCampV3", "--files", str(pack_inputs / "objects.tar"), "--files-format",
        "serversherpa-objects-v1", "--identity-env", str(pack_inputs / "keys.env"), "--identity",
        "SS_PASSWORD_PEPPER,SS_TOTP_ENCRYPTION_KEY", "--source", "mac dev", "--notes", "starter",
        "--passphrase-stdin", "--out", str(out), stdin=PASSPHRASE + "\n",
    )
    assert result.returncode == 0, result.stderr
    data = out.read_bytes()
    assert f"SHA-256 {_sha(data)}" in result.stdout and f"{len(data)} bytes" in result.stdout
    assert "Upload it on Slipway's Snapshots page (it asks for the passphrase)." in result.stdout
    assert stat.S_IMODE(out.stat().st_mode) == 0o600 and not Path(f"{out}.partial").exists()
    assert b"pack-secret-value" not in data and PASSPHRASE not in result.stdout + result.stderr
    preamble = snapfile.parse_preamble(data)
    assert preamble.keyblock["kdf"] == "scrypt" and preamble.keyblock["log2_n"] == 17
    key = snapfile.unwrap_key(preamble.keyblock, PASSPHRASE, preamble.header_hash)
    contents = snapfile.validate_container(io.BytesIO(data), key)
    m = contents.manifest
    assert (m["app"], m["source"], m["notes"], m["repository"], m["commit"]) == (
        "serversherpa", "mac dev", "starter", "encondata/BaseCampV3", "1" * 40
    )
    assert m["database"]["revision"] == "0090" and m["files"]["format"] == "serversherpa-objects-v1"
    assert contents.identity == {"SS_PASSWORD_PEPPER": "ab" * 32, "SS_TOTP_ENCRYPTION_KEY": "pack-secret-value-xyz"}
    assert m["producer"].startswith("slipway ")


def test_pack_plain_refuses_an_existing_out_and_bad_input(pack_inputs: Path):
    out = pack_inputs / "seed.tar"
    result = _pack(pack_inputs, "--identity-env", str(pack_inputs / "keys.env"), "--identity",
                   "SS_TOTP_ENCRYPTION_KEY", "--out", str(out))
    assert result.returncode == 0, result.stderr
    assert "then delete it: its keys are not encrypted" in result.stdout
    assert "pack-secret-value" not in result.stdout + result.stderr
    contents = snapfile.validate(iter([out.read_bytes()]))
    assert contents.members == [snapfile.MANIFEST, snapfile.IDENTITY, snapfile.DATABASE]
    with tarfile.open(out) as tf:  # an ordinary tar
        assert tf.getnames() == ["slipway-snapshot.json", "identity.json", "database"]
    assert stat.S_IMODE(out.stat().st_mode) == 0o600

    before = out.read_bytes()
    again = _pack(pack_inputs, "--out", str(out))
    assert again.returncode != 0 and "already exists" in again.stderr and out.read_bytes() == before

    for extra, words in [
        (["--identity-env", str(pack_inputs / "keys.env"), "--identity", "NOPE"], "doesn't set NOPE"),
        (["--identity", "SS_TOTP_ENCRYPTION_KEY"], "--identity-env and --identity come together"),
        (["--files", str(pack_inputs / "objects.tar")], "--files and --files-format come together"),
        (["--commit", "abc"], "commit must be"),
        (["--passphrase-stdin"], "Choose a passphrase of 12 to 1024 characters"),
    ]:
        target = pack_inputs / "other.tar"
        result = _pack(pack_inputs, *extra, "--out", str(target), stdin="short\n")
        assert result.returncode != 0 and words in result.stderr, (extra, result.stderr)
        assert not target.exists() and not Path(f"{target}.partial").exists()
    (pack_inputs / "db.dump").write_bytes(b"")
    empty = _pack(pack_inputs, "--out", str(pack_inputs / "x.tar"))
    assert empty.returncode != 0 and "is empty" in empty.stderr


def test_pack_refuses_a_leftover_partial(pack_inputs: Path):
    out = pack_inputs / "seed.tar"
    Path(f"{out}.partial").write_bytes(b"someone else's")
    result = _pack(pack_inputs, "--out", str(out))
    assert result.returncode != 0 and "seed.tar.partial already exists" in result.stderr
    assert Path(f"{out}.partial").read_bytes() == b"someone else's" and not out.exists()


# --- rotate-encryption-key fix-ups (§6.7) --------------------------------------------------------------------


@pytest.fixture
def encryption_key():
    saved = os.environ.get("SLIPWAY_ENCRYPTION_KEY")

    def apply(value: str) -> None:
        os.environ["SLIPWAY_ENCRYPTION_KEY"] = value
        get_settings.cache_clear()
        reset_crypto_cache()

    yield apply
    if saved is None:
        os.environ.pop("SLIPWAY_ENCRYPTION_KEY", None)
    else:
        os.environ["SLIPWAY_ENCRYPTION_KEY"] = saved
    get_settings.cache_clear()
    reset_crypto_cache()


async def test_rotate_clear_unreadable_fails_snapshots_and_flags_first_admins(encryption_key, tmp_path):
    from slipway.models import Host, Instance, Repository
    from slipway.models.data import FirstAdmin, Snapshot

    old, new = Fernet.generate_key().decode(), Fernet.generate_key().decode()
    encryption_key(old)
    async with get_sessionmaker()() as db:
        host = Host(name="h1", hostname="10.0.0.1", username="deploy", password="pw")
        repo = Repository(github_id=1, full_name="encondata/BaseCampV3", owner="encondata", name="BaseCampV3",
                          html_url="https://github.com/encondata/BaseCampV3")
        inst = Instance(name="uat", slug="uat", repository=repo, host=host, branch="main",
                        live_identity={"SECRET_KEY": "identity-value-1"})
        db.add_all([host, repo, inst])
        await db.flush()
        ready = dict(status="ready", origin="upload", app="serversherpa", file_sha256=SHA_A, db_sha256=SHA_A)
        db.add_all([
            Snapshot(name="lost", data_key="a2V5", **ready),
            Snapshot(name="kept", data_key="a2V5", **ready),
            Snapshot(name="locked-import", status="locked", origin="import"),
            FirstAdmin(instance_id=inst.id, fields={"email": "a@example.com"}, mode="password", password="pw-12345678",
                       status="pending"),
        ])
        await db.commit()
    # "kept" is re-encrypted under the new key by hand, so only "lost" (and the first admin) become unreadable.
    async with get_sessionmaker()() as db:
        await db.execute(text("UPDATE snapshots SET data_key = :v WHERE name = 'kept'"),
                         {"v": Fernet(new.encode()).encrypt(b"a2V5").decode()})
        await db.commit()

    encryption_key(new)
    args = argparse.Namespace(clear_unreadable=False)
    async with get_sessionmaker()() as db:
        _, unreadable, fixed = await cli._rotate_all(db, args)
        await db.commit()
    assert any(u.startswith("snapshots.data_key") for u in unreadable) and fixed == []
    async with get_sessionmaker()() as db:  # without --clear-unreadable nothing is touched
        assert (await db.scalar(select(Snapshot).where(Snapshot.name == "lost"))).status == "ready"

    args = argparse.Namespace(clear_unreadable=True)
    async with get_sessionmaker()() as db:
        _, unreadable, fixed = await cli._rotate_all(db, args)
        await db.commit()
    assert any(u.startswith("first_admins.password") for u in unreadable)
    assert any("Marked 1 snapshot(s) failed" in line for line in fixed) and "  lost" in fixed
    assert any("lost their password" in line for line in fixed)
    assert not any("pw-12345678" in line for line in fixed + unreadable)
    async with get_sessionmaker()() as db:
        rows = {s.name: s for s in (await db.scalars(select(Snapshot))).all()}
        assert (rows["lost"].status, rows["lost"].data_key) == ("failed", None)
        assert rows["lost"].error == "Its key was lost with an old SLIPWAY_ENCRYPTION_KEY; delete it"
        assert (rows["kept"].status, rows["kept"].data_key) == ("ready", "a2V5")
        assert rows["locked-import"].status == "locked"
        admin = await db.scalar(select(FirstAdmin))
        assert (admin.status, admin.password, admin.last_error) == ("pending", None, "Set the password again")
        # live_identity is re-entered like env and app_secrets (§6.5): an encrypted null, not a NULL column.
        raw = await db.scalar(text("SELECT live_identity FROM instances WHERE slug = 'uat'"))
        assert raw is not None and (await db.scalar(select(Instance.live_identity))) is None
    assert not any("identity-value-1" in line for line in fixed + unreadable)
