"""Spaces through S3 SigV4 (phase 4 spec §10.3, tests 7-9): the signer against AWS's published
examples, virtual-hosted addressing, XML with a DOCTYPE refused, the idempotent bucket create, emptying
page by page with multipart uploads aborted, and CORS written only when it differs."""

from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime, timedelta, timezone

import httpx
import pytest

from slipway.services import s3sig, spaces
from slipway.services.spaces import BucketTaken, SpacesClient, SpacesDenied, SpacesError, SpacesKey
from tests.fake_spaces import NS, FakeSpaces

# ------------------------------------------------------------------ SigV4 against AWS's examples
#
# Amazon S3 API Reference, "Signature Calculations for the Authorization Header: Transferring Payload
# in a Single Chunk (AWS Signature Version 4)", the four examples: every one uses this key pair, the
# bucket examplebucket in us-east-1 and the time 20130524T000000Z. If one fails, compare the canonical
# request and string to sign with that page before changing the signer.

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AWS_NOW = datetime(2013, 5, 24, tzinfo=UTC)
AWS_HOST = "examplebucket.s3.amazonaws.com"


def _aws_sign(**kwargs) -> dict[str, str]:
    return s3sig.sign(host=AWS_HOST, access_key=AWS_KEY, secret_key=AWS_SECRET, region="us-east-1",
                      now=AWS_NOW, **kwargs)


def _signature(headers: dict[str, str]) -> str:
    return headers["Authorization"].rsplit("Signature=", 1)[1]


def test_sigv4_get_object_example():
    headers = _aws_sign(method="GET", path="/test.txt", query={}, headers={"Range": "bytes=0-9"},
                        payload_sha256=s3sig.EMPTY_SHA256)
    assert headers["Authorization"] == (
        "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, "
        "SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, "
        "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41")
    assert headers["x-amz-date"] == "20130524T000000Z"
    assert headers["x-amz-content-sha256"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    # The intermediate strings the page prints.
    request, signed = s3sig.canonical_request(method="GET", host=AWS_HOST, path="/test.txt", query={},
                                              headers={"Range": "bytes=0-9"}, payload_sha256=s3sig.EMPTY_SHA256,
                                              amz_date="20130524T000000Z")
    assert request == (
        "GET\n/test.txt\n\n"
        "host:examplebucket.s3.amazonaws.com\nrange:bytes=0-9\n"
        "x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
        "x-amz-date:20130524T000000Z\n\n"
        "host;range;x-amz-content-sha256;x-amz-date\n"
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert signed == "host;range;x-amz-content-sha256;x-amz-date"
    assert hashlib.sha256(request.encode()).hexdigest() == \
        "7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972"


def test_sigv4_put_object_example():
    body = b"Welcome to Amazon S3."
    payload = hashlib.sha256(body).hexdigest()
    assert payload == "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072"
    headers = _aws_sign(method="PUT", path="/test$file.text", query={}, payload_sha256=payload,
                        headers={"Date": "Fri, 24 May 2013 00:00:00 GMT", "x-amz-storage-class": "REDUCED_REDUNDANCY"})
    assert "SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class, " in headers["Authorization"]
    assert _signature(headers) == "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
    request, _ = s3sig.canonical_request(method="PUT", host=AWS_HOST, path="/test$file.text", query={},
                                         headers={"Date": "Fri, 24 May 2013 00:00:00 GMT",
                                                  "x-amz-storage-class": "REDUCED_REDUNDANCY"},
                                         payload_sha256=payload, amz_date="20130524T000000Z")
    assert request.split("\n")[1] == "/test%24file.text"  # "$" encoded once, as S3 wants
    assert hashlib.sha256(request.encode()).hexdigest() == \
        "9e0e90d9c76de8fa5b200d8c849cd5b8dc7a3be3951ddb7f6a76b4158342019d"


def test_sigv4_get_bucket_lifecycle_example():
    headers = _aws_sign(method="GET", path="/", query={"lifecycle": ""}, headers={},
                        payload_sha256=s3sig.EMPTY_SHA256)
    assert "SignedHeaders=host;x-amz-content-sha256;x-amz-date, " in headers["Authorization"]
    assert _signature(headers) == "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543"


def test_sigv4_list_objects_example():
    headers = _aws_sign(method="GET", path="/", query={"prefix": "J", "max-keys": "2"}, headers={},
                        payload_sha256=s3sig.EMPTY_SHA256)
    assert _signature(headers) == "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"
    assert s3sig.canonical_query({"prefix": "J", "max-keys": "2"}) == "max-keys=2&prefix=J"


def test_sigv4_signing_key_examples():
    """AWS General Reference, "Examples of how to derive a signing key for Signature Version 4"."""
    secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
    assert s3sig.signing_key(secret, "20120215", "us-east-1", "iam").hex() == \
        "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"
    assert s3sig.signing_key(secret, "20150830", "us-east-1", "iam").hex() == \
        "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"


def test_sign_normalises_to_utc_folds_spaces_and_rejects_naive_times():
    args = dict(method="GET", path="/", query={}, payload_sha256=s3sig.EMPTY_SHA256)
    eastern = AWS_NOW.astimezone(timezone(timedelta(hours=-4)))
    assert s3sig.sign(host=AWS_HOST, access_key=AWS_KEY, secret_key=AWS_SECRET, region="us-east-1",
                      now=eastern, headers={}, **args) == _aws_sign(headers={}, **args)
    assert _signature(_aws_sign(headers={"X-Amz-Meta-A": "  one   two "}, **args)) == \
        _signature(_aws_sign(headers={"x-amz-meta-a": "one two"}, **args))
    with pytest.raises(ValueError):
        s3sig.sign(host=AWS_HOST, access_key=AWS_KEY, secret_key=AWS_SECRET, region="us-east-1",
                   now=datetime(2013, 5, 24), headers={}, **args)
    assert AWS_SECRET not in str(_aws_sign(headers={}, **args))


def test_paths_and_queries_are_encoded_once():
    assert s3sig.canonical_path("/photos/a b&c+d~e.jpg") == "/photos/a%20b%26c%2Bd~e.jpg"
    assert s3sig.canonical_path("/ünï") == "/%C3%BCn%C3%AF"
    assert s3sig.canonical_query({"delete": ""}) == "delete="
    assert s3sig.canonical_query({"uploadId": "2~a/b=c"}) == "uploadId=2~a%2Fb%3Dc"


# ----------------------------------------------------------------------------------- the client

BUCKET = "slipway-prod-1a2b3c4d"
REGION = "nyc3"


@pytest.fixture
def fake(monkeypatch) -> FakeSpaces:
    fake = FakeSpaces()
    monkeypatch.setattr(spaces, "transport_factory", fake.transport)
    waits: list[float] = []

    async def no_sleep(seconds: float) -> None:
        waits.append(seconds)

    monkeypatch.setattr(spaces, "sleep", no_sleep)
    fake.waits = waits  # type: ignore[attr-defined]
    return fake


def _key(fake: FakeSpaces, name: str, grants: list[dict[str, str]]) -> SpacesKey:
    made = fake.add_key(name, grants)
    return SpacesKey(made["access_key"], made["secret_key"])


def _setup(fake: FakeSpaces) -> SpacesKey:
    return _key(fake, "slipway-prod-1a2b3c4d-setup-0123456789abcdef", [{"bucket": "", "permission": "fullaccess"}])


def _own(fake: FakeSpaces) -> SpacesKey:
    return _key(fake, "slipway-prod-1a2b3c4d-0123456789abcdef", [{"bucket": BUCKET, "permission": "readwrite"}])


async def test_virtual_hosted_addressing_and_the_endpoint(fake):
    async with SpacesClient(REGION, _setup(fake)) as s3:
        assert await s3.create_bucket(BUCKET) is True
        assert await s3.bucket_exists(BUCKET) is True
    for request in fake.requests:
        assert request.url.host == f"{BUCKET}.nyc3.digitaloceanspaces.com"
        assert request.url.scheme == "https"
        assert request.url.path == "/"
        assert request.headers["authorization"].startswith("AWS4-HMAC-SHA256 Credential=DO00")
        assert "/nyc3/s3/aws4_request, " in request.headers["authorization"]
    assert spaces.endpoint("nyc3") == "https://nyc3.digitaloceanspaces.com"
    assert spaces.bucket_host(BUCKET, "sfo3") == f"{BUCKET}.sfo3.digitaloceanspaces.com"


async def test_bad_names_and_regions_send_nothing(fake):
    key = _setup(fake)
    for bucket in ("Bad_Name", "ab", "-abc", "abc-", "a" * 64, "x.evil.com/abc", "abc\n", "a.b.c", "", None):
        with pytest.raises(SpacesError, match="valid Spaces bucket name"):
            async with SpacesClient(REGION, key) as s3:
                await s3.bucket_exists(bucket)  # type: ignore[arg-type]
    for region in ("nyc3.evil.com", "", "nyc3\n", "NYC3", "nyc3/x"):
        with pytest.raises(SpacesError, match="valid Spaces region"):
            SpacesClient(region, key)
        with pytest.raises(SpacesError, match="valid Spaces region"):
            spaces.endpoint(region)
    assert fake.requests == []


async def test_xml_with_a_doctype_is_refused(fake):
    key = _setup(fake)
    fake.put(BUCKET, "a.txt", b"a")
    bomb = (b'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;">]>'
            b'<ListBucketResult><Contents><Key>&lol2;</Key></Contents></ListBucketResult>')
    inner = fake.transport()

    class Doctype(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            if request.method == "GET":
                fake.requests.append(request)
                return httpx.Response(200, content=bomb)
            return await inner.handle_async_request(request)

    async with SpacesClient(REGION, key, transport=Doctype()) as s3:
        with pytest.raises(SpacesError) as err:
            await s3.empty_bucket(BUCKET)
        assert str(err.value) == "Spaces sent a listing Slipway didn't understand"
        with pytest.raises(SpacesError, match="a CORS configuration Slipway didn't understand"):
            await s3.bucket_cors(BUCKET)
    assert [r.method for r in fake.requests] == ["GET", "GET"]  # no delete was sent
    assert fake.buckets[BUCKET] == {"a.txt": b"a"}

    # An entity declaration without the word DOCTYPE in upper case is refused too.
    lower = b'<!doctype x [<!ENTITY a "b">]><ListBucketResult/>'
    resp = httpx.Response(200, content=lower)
    with pytest.raises(SpacesError):
        spaces._parse(resp, "a listing")


# -- test 8: create_bucket


async def test_create_bucket_made_now(fake):
    async with SpacesClient(REGION, _setup(fake)) as s3:
        assert await s3.create_bucket(BUCKET) is True
    assert BUCKET in fake.buckets
    assert [r.method for r in fake.requests] == ["PUT"]


async def test_create_bucket_already_owned_by_you(fake):
    async with SpacesClient(REGION, _setup(fake)) as s3:
        assert await s3.create_bucket(BUCKET) is True
        assert await s3.create_bucket(BUCKET) is False
    assert [r.method for r in fake.requests] == ["PUT", "PUT"]  # BucketAlreadyOwnedByYou needs no HEAD


async def test_create_bucket_409_then_head_200_is_ours(fake):
    fake.recreate_conflict = True
    async with SpacesClient(REGION, _setup(fake)) as s3:
        assert await s3.create_bucket(BUCKET) is True
        assert await s3.create_bucket(BUCKET) is False
    assert [r.method for r in fake.requests] == ["PUT", "PUT", "HEAD"]


async def test_create_bucket_409_then_head_403_is_another_accounts(fake):
    fake.foreign.add(BUCKET)
    key = _setup(fake)
    async with SpacesClient(REGION, key) as s3:
        with pytest.raises(BucketTaken) as err:
            await s3.create_bucket(BUCKET)
    assert str(err.value).startswith(f"Another Spaces account already has the bucket {BUCKET}")
    assert [r.method for r in fake.requests] == ["PUT", "HEAD"]
    assert BUCKET not in fake.buckets
    assert key.secret_key not in str(err.value) + repr(err.value) + repr(key)


async def test_create_bucket_409_then_head_404_stops_without_guessing(fake, monkeypatch):
    key = _setup(fake)
    inner = fake.transport()

    class Vanishing(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            fake.requests.append(request)
            if request.method == "PUT":
                return httpx.Response(409, content=b"<Error><Code>OperationAborted</Code></Error>")
            return await inner.handle_async_request(request)

    async with SpacesClient(REGION, key, transport=Vanishing()) as s3:
        with pytest.raises(SpacesError) as err:
            await s3.create_bucket(BUCKET)
    assert not isinstance(err.value, BucketTaken)
    assert "retry in a few minutes" in str(err.value)


async def test_create_bucket_with_a_key_for_another_bucket_is_denied(fake):
    key = _key(fake, "other", [{"bucket": "slipway-other-00000000", "permission": "readwrite"}])
    async with SpacesClient(REGION, key) as s3:
        with pytest.raises(SpacesDenied) as err:
            await s3.create_bucket(BUCKET)
    assert "(AccessDenied)" in str(err.value) and err.value.status == 403
    assert BUCKET not in fake.buckets


async def test_only_a_404_means_gone(fake):
    own = _own(fake)
    async with SpacesClient(REGION, own) as s3:
        assert await s3.bucket_exists(BUCKET) is False  # 404 NoSuchBucket
        fake.buckets[BUCKET] = {}
        assert await s3.bucket_exists(BUCKET) is True
        with pytest.raises(SpacesDenied):
            await s3.bucket_exists("slipway-other-00000000")  # the key's grant doesn't cover it: 403
        fake.fail_next = [(500, "InternalError"), (500, "InternalError")]
        with pytest.raises(SpacesError) as err:
            await s3.bucket_exists(BUCKET)
        assert not isinstance(err.value, SpacesDenied) and err.value.status == 500


async def test_a_get_is_retried_once_and_a_write_never(fake):
    key = _setup(fake)
    async with SpacesClient(REGION, key) as s3:
        await s3.create_bucket(BUCKET)
        fake.requests.clear()
        fake.fail_next = [(503, "SlowDown")]
        assert await s3.bucket_exists(BUCKET) is True
        assert [r.method for r in fake.requests] == ["HEAD", "HEAD"]
        assert fake.waits == [spaces.GET_RETRY_WAIT]
        fake.requests.clear()
        fake.fail_next = [(503, "SlowDown")]
        with pytest.raises(SpacesError) as err:
            await s3.delete_bucket(BUCKET)
        assert str(err.value) == f"Spaces refused to delete the bucket {BUCKET} (SlowDown)"
        assert [r.method for r in fake.requests] == ["DELETE"]
    assert BUCKET in fake.buckets


async def test_unreachable(fake):
    fake.down = True
    async with SpacesClient(REGION, _setup(fake)) as s3:
        with pytest.raises(SpacesError) as err:
            await s3.bucket_exists(BUCKET)
    assert str(err.value) == "Couldn't reach DigitalOcean Spaces"
    assert err.value.__cause__ is None


# -- test 9: emptying and CORS


async def test_empty_bucket_pages_and_deletes(fake):
    key = _setup(fake)
    fake.page_size = 2
    async with SpacesClient(REGION, key) as s3:
        await s3.create_bucket(BUCKET)
        for i in range(5):
            fake.put(BUCKET, f"photos/{i}&<x> ü.jpg", b"x")
        fake.requests.clear()
        assert await s3.empty_bucket(BUCKET) == 5
        assert fake.buckets[BUCKET] == {}
        # Three pages of 2, 2 and 1 keys, a delete after each, an empty listing, then the uploads listing.
        assert [(r.method, sorted(r.url.params)) for r in fake.requests] == [
            ("GET", ["list-type"]), ("POST", ["delete"]),
            ("GET", ["list-type"]), ("POST", ["delete"]),
            ("GET", ["list-type"]), ("POST", ["delete"]),
            ("GET", ["list-type"]), ("GET", ["uploads"]),
        ]
        post = fake.requests[1]
        assert post.headers["content-md5"] == base64.b64encode(hashlib.md5(post.content).digest()).decode()
        assert b"&amp;&lt;x&gt;" in post.content
        assert await s3.delete_bucket(BUCKET) is True
        assert await s3.delete_bucket(BUCKET) is False
        assert await s3.empty_bucket(BUCKET) == 0  # a missing bucket: nothing to delete


async def test_empty_bucket_aborts_multipart_uploads(fake):
    key = _setup(fake)
    fake.page_size = 1
    fake.put(BUCKET, "done.bin", b"x")
    fake.start_upload(BUCKET, "big/one&<x>.bin")
    fake.start_upload(BUCKET, "big/two ü.bin")
    fake.start_upload(BUCKET, "big/three.bin")
    async with SpacesClient(REGION, key) as s3:
        assert await s3.empty_bucket(BUCKET) == 1
        assert fake.uploads[BUCKET] == {}
        aborts = [r for r in fake.requests if r.method == "DELETE"]
        assert len(aborts) == 3 and all("uploadId" in r.url.params for r in aborts)
        assert await s3.delete_bucket(BUCKET) is True


async def test_an_upload_with_a_dot_segment_is_refused_not_misaddressed(fake):
    key = _setup(fake)
    fake.put(BUCKET, "a", b"x")
    fake.start_upload(BUCKET, "x/../etc")
    async with SpacesClient(REGION, key) as s3:
        with pytest.raises(SpacesError, match="abort it by hand"):
            await s3.empty_bucket(BUCKET)
    assert not [r for r in fake.requests if r.method == "DELETE"]


async def test_a_partial_multi_delete_is_an_error(fake):
    key = _setup(fake)
    for name in ("a.txt", "b.txt", "c.txt"):
        fake.put(BUCKET, name, b"x")
    fake.undeletable = {"b.txt"}
    async with SpacesClient(REGION, key) as s3:
        with pytest.raises(SpacesError) as err:
            await s3.empty_bucket(BUCKET)
    assert str(err.value) == f"Spaces couldn't delete 1 object in the bucket {BUCKET} (AccessDenied)"
    assert set(fake.buckets[BUCKET]) == {"b.txt"}


async def test_a_delete_that_makes_no_progress_stops(fake):
    key = _setup(fake)
    fake.put(BUCKET, "a.txt", b"x")
    inner = fake.transport()

    class Silent(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            if request.method == "POST":
                fake.requests.append(request)
                return httpx.Response(200, content=f'<DeleteResult xmlns="{NS}"/>'.encode())
            return await inner.handle_async_request(request)

    async with SpacesClient(REGION, key, transport=Silent()) as s3:
        with pytest.raises(SpacesError, match="deleted nothing"):
            await s3.empty_bucket(BUCKET)
    assert [r.method for r in fake.requests] == ["GET", "POST"]


async def test_the_page_cap_stops_a_bottomless_bucket(fake, monkeypatch):
    monkeypatch.setattr(spaces, "MAX_PAGES", 2)
    fake.page_size = 1
    for i in range(5):
        fake.put(BUCKET, f"{i}.txt", b"x")
    async with SpacesClient(REGION, _setup(fake)) as s3:
        with pytest.raises(SpacesError, match="more objects than Slipway deletes in one step"):
            await s3.empty_bucket(BUCKET)
    assert len(fake.buckets[BUCKET]) == 3


async def test_deleting_a_bucket_with_objects_is_refused(fake):
    fake.put(BUCKET, "a.txt", b"a")
    async with SpacesClient(REGION, _setup(fake)) as s3:
        with pytest.raises(SpacesError, match="still holds objects"):
            await s3.delete_bucket(BUCKET)
    assert BUCKET in fake.buckets


ORIGINS_HOSTS = ("portal.serversherpa.com", "wiki.serversherpa.com")


def test_wanted_cors():
    assert spaces.wanted_cors([]) == []
    [rule] = spaces.wanted_cors(["Wiki.ServerSherpa.com.", "portal.serversherpa.com", "portal.serversherpa.com"])
    assert rule == spaces.CorsRule(
        origins=("https://portal.serversherpa.com", "https://wiki.serversherpa.com"),
        methods=("GET", "HEAD", "PUT"), headers=("*",), expose=("ETag",), max_age=3000)


async def test_cors_read_compare_and_write_only_when_different(fake):
    key = _own(fake)
    fake.buckets[BUCKET] = {}
    wanted = spaces.wanted_cors(ORIGINS_HOSTS)
    async with SpacesClient(REGION, key) as s3:
        assert await s3.bucket_cors(BUCKET) == []
        assert await s3.ensure_cors(BUCKET, wanted) is True
        assert await s3.bucket_cors(BUCKET) == wanted
        assert fake.cors[BUCKET] == [{"origins": ["https://portal.serversherpa.com", "https://wiki.serversherpa.com"],
                                      "methods": ["GET", "HEAD", "PUT"], "headers": ["*"], "expose": ["ETag"],
                                      "max_age": 3000}]
        put = next(r for r in fake.requests if r.method == "PUT")
        assert put.headers["content-md5"] == base64.b64encode(hashlib.md5(put.content).digest()).decode()

        # The same rules, in another order on Spaces' side: read, no write.
        fake.cors[BUCKET][0]["origins"].reverse()
        fake.requests.clear()
        assert await s3.ensure_cors(BUCKET, wanted) is False
        assert [r.method for r in fake.requests] == ["GET"]

        # Different (someone edited them by hand): written back once.
        fake.cors[BUCKET][0]["max_age"] = 60
        fake.requests.clear()
        assert await s3.ensure_cors(BUCKET, wanted) is True
        assert [r.method for r in fake.requests] == ["GET", "PUT"]
        assert fake.cors[BUCKET][0]["max_age"] == 3000

        # No CORS services any more: the rules are cleared, not replaced by an empty (refused) document.
        fake.requests.clear()
        assert await s3.ensure_cors(BUCKET, []) is True
        assert [r.method for r in fake.requests] == ["GET", "DELETE"]
        assert BUCKET not in fake.cors
        assert await s3.ensure_cors(BUCKET, []) is False


async def test_cors_refused_to_the_bucket_key_is_spaces_denied(fake):
    fake.buckets[BUCKET] = {}
    fake.cors_needs_fullaccess = True
    wanted = spaces.wanted_cors(ORIGINS_HOSTS)
    async with SpacesClient(REGION, _own(fake)) as s3:
        with pytest.raises(SpacesDenied):
            await s3.ensure_cors(BUCKET, wanted)
    assert BUCKET not in fake.cors
    async with SpacesClient(REGION, _setup(fake)) as s3:  # the caller's fallback: the temporary key
        assert await s3.ensure_cors(BUCKET, wanted) is True
    assert fake.cors[BUCKET][0]["max_age"] == 3000


async def test_cors_on_a_missing_bucket_is_an_error(fake):
    async with SpacesClient(REGION, _setup(fake)) as s3:
        with pytest.raises(SpacesError, match=r"\(NoSuchBucket\)"):
            await s3.bucket_cors(BUCKET)


# ----------------------------------------------------------------------------- the fake and secrets


async def _raw(fake: FakeSpaces, key: SpacesKey, *, method="GET", query=None, send_query=None, body=b"",
               send_body=None, region="nyc3", headers=None, host=None) -> httpx.Response:
    """Sign one request, then send it, possibly changed on the way."""
    host = host or f"{BUCKET}.nyc3.digitaloceanspaces.com"
    signed = s3sig.sign(method=method, host=host, path="/", query=query or {}, headers=headers or {},
                        payload_sha256=hashlib.sha256(body).hexdigest(), access_key=key.access_key,
                        secret_key=key.secret_key, region=region, now=datetime.now(UTC))
    q = send_query if send_query is not None else (query or {})
    url = f"https://{host}/" + ("?" + s3sig.canonical_query(q) if q else "")
    async with httpx.AsyncClient(transport=fake.transport()) as client:
        return await client.request(method, url, headers=signed, content=body if send_body is None else send_body)


def _delete_doc(*names: str) -> tuple[bytes, dict[str, str]]:
    doc = ("<Delete>" + "".join(f"<Object><Key>{n}</Key></Object>" for n in names) + "</Delete>").encode()
    md5 = base64.b64encode(hashlib.md5(doc).digest()).decode()
    return doc, {"Content-MD5": md5, "Content-Type": "application/xml"}


async def test_the_fake_checks_signatures(fake):
    setup = _setup(fake)
    fake.put(BUCKET, "a.txt", b"a")
    fake.put(BUCKET, "b.txt", b"b")
    assert (await _raw(fake, setup, query={"list-type": "2"})).status_code == 200

    def code(resp: httpx.Response) -> tuple[int, str | None]:
        return resp.status_code, spaces._code(resp)

    denied = (403, "SignatureDoesNotMatch")
    assert code(await _raw(fake, setup, query={"list-type": "2"}, send_query={"list-type": "2", "prefix": "a"})) == denied
    assert code(await _raw(fake, setup, region="sfo3")) == denied
    assert code(await _raw(fake, SpacesKey(setup.access_key, "wrong"))) == denied
    assert code(await _raw(fake, SpacesKey("DO00NOBODY", "wrong"))) == (403, "InvalidAccessKeyId")
    assert code(await _raw(fake, setup, host="nyc3.digitaloceanspaces.com")) == (400, "InvalidRequest")  # path-style
    doc, headers = _delete_doc("a.txt")
    other, _ = _delete_doc("b.txt")
    assert code(await _raw(fake, setup, method="POST", query={"delete": ""}, body=doc, send_body=other,
                           headers=headers)) == denied
    assert set(fake.buckets[BUCKET]) == {"a.txt", "b.txt"}
    resp = await _raw(fake, setup, method="POST", query={"delete": ""}, body=doc, headers=headers)
    assert resp.status_code == 200 and set(fake.buckets[BUCKET]) == {"b.txt"}


async def test_the_fake_reads_keys_from_another_store():
    store = {"DO00SHARED": {"secret_key": "s3cr3t-shared", "grants": [{"bucket": BUCKET, "permission": "readwrite"}]}}
    fake = FakeSpaces(store)
    fake.buckets[BUCKET] = {}
    async with SpacesClient(REGION, SpacesKey("DO00SHARED", "s3cr3t-shared"), transport=fake.transport()) as s3:
        assert await s3.bucket_exists(BUCKET) is True
    lookup = FakeSpaces(store.get)
    lookup.buckets[BUCKET] = {}
    async with SpacesClient(REGION, SpacesKey("DO00SHARED", "s3cr3t-shared"), transport=lookup.transport()) as s3:
        assert await s3.bucket_exists(BUCKET) is True


async def test_keys_made_by_the_digitalocean_fake_and_read_only_grants():
    from tests.fake_digitalocean import FakeDigitalOcean

    do = FakeDigitalOcean()
    fake = FakeSpaces(do.spaces_keys)
    setup = do.add_spaces_key("setup", [{"bucket": "", "permission": "fullaccess"}])
    reader = do.add_spaces_key("reader", [{"bucket": BUCKET, "permission": "read"}])
    async with SpacesClient(REGION, SpacesKey(setup["access_key"], setup["secret_key"]),
                            transport=fake.transport()) as s3:
        assert await s3.create_bucket(BUCKET) is True
    fake.put(BUCKET, "a.txt", b"a")
    async with SpacesClient(REGION, SpacesKey(reader["access_key"], reader["secret_key"]),
                            transport=fake.transport()) as s3:
        assert await s3.bucket_exists(BUCKET) is True
        with pytest.raises(SpacesDenied):
            await s3.empty_bucket(BUCKET)  # lists, then the delete is refused
    assert fake.buckets[BUCKET] == {"a.txt": b"a"}
    del do.spaces_keys[setup["access_key"]]  # deleted through the API: Spaces no longer accepts it
    async with SpacesClient(REGION, SpacesKey(setup["access_key"], setup["secret_key"]),
                            transport=fake.transport()) as s3:
        with pytest.raises(SpacesDenied, match="InvalidAccessKeyId"):
            await s3.bucket_exists(BUCKET)


async def test_the_secret_never_leaves_in_a_request_or_an_error(fake):
    setup = _setup(fake)
    secret = setup.secret_key
    reasons: list[str] = []
    async with SpacesClient(REGION, setup) as s3:
        await s3.create_bucket(BUCKET)
        fake.put(BUCKET, "a.txt", b"a")
        fake.start_upload(BUCKET, "b.bin")
        await s3.empty_bucket(BUCKET)
        await s3.ensure_cors(BUCKET, spaces.wanted_cors(ORIGINS_HOSTS))
        await s3.ensure_cors(BUCKET, [])
        await s3.delete_bucket(BUCKET)
        fake.put(BUCKET, "c.txt", b"c")
        fake.undeletable = {"c.txt"}
        fake.foreign.add("slipway-taken-00000000")
        for call in (s3.empty_bucket(BUCKET), s3.delete_bucket(BUCKET), s3.create_bucket("slipway-taken-00000000")):
            with pytest.raises(SpacesError) as err:
                await call
            reasons += [str(err.value), repr(err.value), str(err.value.__cause__), str(err.value.__context__)]
        reasons.append(repr(s3))
    async with SpacesClient(REGION, SpacesKey("DO00NOBODY", secret)) as s3:
        with pytest.raises(SpacesError) as err:
            await s3.bucket_exists(BUCKET)
        reasons += [str(err.value), repr(err.value)]
    assert len(fake.requests) > 10
    for request in fake.requests:
        seen = str(request.url) + str(dict(request.headers)) + request.content.decode()
        assert secret not in seen
    assert all(secret not in r for r in reasons)
    assert secret not in repr(setup)
