"""Community apps: instances of public container images, and public GitHub repositories added by URL."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
import uuid

import httpx
import pytest
from sqlalchemy import select

from slipway.db.session import get_sessionmaker
from slipway.models import AuditEvent, Deployment, Host, Instance, Repository
from slipway.services import deployer, github, registry, repos
from tests.conftest import make_user
from tests.test_deployer import FakeGitHub, FakeRemote, _connect

INDEX_DIGEST = "sha256:" + "ab" * 32


# ------------------------------------------------------------------------------------------- references


@pytest.mark.parametrize("text, label, api_host, name", [
    ("nginx", "nginx:latest", "registry-1.docker.io", "library/nginx"),
    ("nginx:1.27", "nginx:1.27", "registry-1.docker.io", "library/nginx"),
    ("docker.io/library/nginx:1.27", "nginx:1.27", "registry-1.docker.io", "library/nginx"),
    ("linuxserver/jellyfin", "linuxserver/jellyfin:latest", "registry-1.docker.io", "linuxserver/jellyfin"),
    ("lscr.io/linuxserver/jellyfin:10.9.11", "lscr.io/linuxserver/jellyfin:10.9.11", "lscr.io", "linuxserver/jellyfin"),
    ("ghcr.io/home-assistant/home-assistant:stable", "ghcr.io/home-assistant/home-assistant:stable", "ghcr.io",
     "home-assistant/home-assistant"),
    (f"ghcr.io/owner/app@{INDEX_DIGEST}", f"ghcr.io/owner/app@{INDEX_DIGEST}", "ghcr.io", "owner/app"),
    ("https://hub.docker.com/r/linuxserver/jellyfin", "linuxserver/jellyfin:latest", "registry-1.docker.io",
     "linuxserver/jellyfin"),
    ("https://hub.docker.com/_/nginx?tab=tags", "nginx:latest", "registry-1.docker.io", "library/nginx"),
    ("localhost:5000/app:dev", "localhost:5000/app:dev", "localhost:5000", "app"),
])
def test_parse_image_references(text, label, api_host, name):
    ref = registry.parse(text)
    assert ref.label == label and ref.api_host == api_host and ref.name == name
    assert registry.parse(ref.label) == ref  # what is stored parses back to the same image


@pytest.mark.parametrize("text", ["", "Nginx", "nginx:", "nginx:bad tag", "a/b@sha256:short", "https://example.com/x",
                                  "nginx;rm", "-x", "a" * 300])
def test_parse_rejects_bad_references(text):
    with pytest.raises(ValueError):
        registry.parse(text)


def test_only_known_registries_are_asked():
    registry.check_allowed(registry.parse("quay.io/org/app"))
    with pytest.raises(ValueError, match="doesn't read images from internal.example"):
        registry.check_allowed(registry.parse("internal.example/app"))


def test_image_dockerfile_pins_the_digest():
    ref = registry.parse("nginx:1.27")
    assert registry.image_dockerfile(ref, INDEX_DIGEST).splitlines()[-1] == f"FROM docker.io/library/nginx@{INDEX_DIGEST}"
    assert ref.branch == "1.27" and registry.parse(f"nginx@{INDEX_DIGEST}").branch == "digest"


# ------------------------------------------------------------------------------------- a fake registry


class FakeRegistry:
    """Docker Hub's flow: 401 with a Bearer challenge, an anonymous token, then manifests and the config blob."""

    def __init__(self) -> None:
        self.config = {"config": {"ExposedPorts": {"8096/tcp": {}, "7359/udp": {}}, "Volumes": {"/config": {}},
                                  "Env": ["PATH=/usr/bin", "PUID=1000", "TZ=Etc/UTC"],
                                  "Labels": {"org.opencontainers.image.title": "Jellyfin"}}}
        self.config_body = json.dumps(self.config).encode()
        self.config_digest = "sha256:" + hashlib.sha256(self.config_body).hexdigest()
        self.manifest = json.dumps({"mediaType": registry.MANIFEST_TYPES[0],
                                    "config": {"digest": self.config_digest}}).encode()
        self.manifest_digest = "sha256:" + hashlib.sha256(self.manifest).hexdigest()
        self.index = json.dumps({"mediaType": registry.INDEX_TYPES[0], "manifests": [
            {"digest": "sha256:" + "cd" * 32, "platform": {"os": "linux", "architecture": "arm64"}},
            {"digest": self.manifest_digest, "platform": {"os": "linux", "architecture": "amd64"}},
        ]}).encode()
        self.index_digest = "sha256:" + hashlib.sha256(self.index).hexdigest()
        self.requests: list[str] = []

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(f"{request.method} {request.url}")
        if request.url.host == "auth.docker.io":
            assert request.url.params["scope"] == "repository:linuxserver/jellyfin:pull"
            return httpx.Response(200, json={"token": "anon-token"})
        if request.headers.get("authorization") != "Bearer anon-token":
            return httpx.Response(401, headers={"WWW-Authenticate": 'Bearer realm="https://auth.docker.io/token",'
                                                'service="registry.docker.io",scope="repository:linuxserver/jellyfin:pull"'})
        path = request.url.path
        if path == "/v2/linuxserver/jellyfin/manifests/latest":
            headers = {"Docker-Content-Digest": self.index_digest, "Content-Type": registry.INDEX_TYPES[0]}
            return httpx.Response(200, headers=headers, content=b"" if request.method == "HEAD" else self.index)
        if path == f"/v2/linuxserver/jellyfin/manifests/{self.manifest_digest}":
            return httpx.Response(200, content=self.manifest)
        if path == f"/v2/linuxserver/jellyfin/blobs/{self.config_digest}":
            return httpx.Response(200, content=self.config_body)
        return httpx.Response(404, json={"errors": [{"code": "MANIFEST_UNKNOWN"}]})


@pytest.fixture
def fake_registry(monkeypatch) -> FakeRegistry:
    fake = FakeRegistry()
    monkeypatch.setattr(registry, "transport_factory", lambda: httpx.MockTransport(fake.handle))
    return fake


async def test_resolve_follows_the_token_challenge(fake_registry):
    digest = await registry.resolve(registry.parse("linuxserver/jellyfin"))
    assert digest == fake_registry.index_digest
    assert fake_registry.requests[1].startswith("GET https://auth.docker.io/token?")


async def test_inspect_reads_ports_volumes_and_variables(fake_registry):
    info = await registry.inspect(registry.parse("linuxserver/jellyfin"))
    assert info.digest == fake_registry.index_digest and info.platform == "linux/amd64"
    assert info.ports == [{"container": 7359, "protocol": "udp"}, {"container": 8096, "protocol": "tcp"}]
    assert info.volumes == ["/config"] and info.env == {"PUID": "1000", "TZ": "Etc/UTC"} and info.title == "Jellyfin"


async def test_missing_image_is_reported(fake_registry):
    with pytest.raises(registry.RegistryError, match="not found"):
        await registry.resolve(registry.parse("linuxserver/jellyfin:nope"))


# ------------------------------------------------------------------------------------ the deploy itself


async def _seed_image_instance(image: str = "linuxserver/jellyfin:latest") -> uuid.UUID:
    user = await make_user("admin@example.com")
    async with get_sessionmaker()() as db:
        host = Host(name="prod-01", hostname="10.0.0.1", username="deploy", host_key="ssh-ed25519 AAAA", metrics={})
        ref = registry.parse(image)
        inst = Instance(name="jellyfin", slug="jellyfin", branch=ref.branch, host=host, repository=None,
                        build_source="image", image=ref.label, env={"TZ": "Europe/Oslo"},
                        ports=[{"host": 8096, "container": 8096, "protocol": "tcp"}],
                        volumes=[{"source": "jellyfin-config", "target": "/config"}])
        db.add(inst)
        await db.flush()
        dep = Deployment(instance_id=inst.id, branch=ref.branch, triggered_by_id=user.id, log="",
                         steps=deployer.new_steps(inst))
        db.add(dep)
        await db.commit()
        return dep.id


def _dockerfile_in(archive: bytes) -> str:
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        member = tar.extractfile("slipway-image/Dockerfile")
        assert member is not None
        return member.read().decode()


async def test_image_instance_deploys_the_resolved_digest(fake_registry):
    dep_id = await _seed_image_instance()
    remote = FakeRemote()
    await deployer.run_deployment(dep_id, connect=_connect(remote), github=FakeGitHub)
    digest = fake_registry.index_digest
    async with get_sessionmaker()() as db:
        dep = await db.get(Deployment, dep_id)
        assert dep.status == "succeeded", dep.log
        assert dep.commit_sha == digest.removeprefix("sha256:")[:40]
        assert dep.options["image_digest"] == digest and dep.commit_author == "docker.io"
        assert [s["name"] for s in dep.steps][:2] == ["Resolve the image", "Prepare the release"]
        assert dep.instance.status == "running" and dep.instance.current_commit_sha == dep.commit_sha
    upload = next(v for k, v in remote.files.items() if k.endswith(".tar.gz"))
    assert _dockerfile_in(upload).splitlines()[-1] == f"FROM docker.io/linuxserver/jellyfin@{digest}"
    build = next(c for c in remote.commands if "docker build" in c)
    assert "--pull" in build and "-f Dockerfile" in build
    run = next(c for c in remote.commands if c.startswith("docker run -d"))
    assert "-p 8096:8096/tcp" in run and "-v jellyfin-config:/config" in run
    assert remote.files["/opt/slipway/jellyfin/shared/.env"] == "TZ=Europe/Oslo\n"


async def test_image_deploy_fails_cleanly_when_the_tag_is_gone(fake_registry):
    dep_id = await _seed_image_instance("linuxserver/jellyfin:nope")
    remote = FakeRemote()
    await deployer.run_deployment(dep_id, connect=_connect(remote), github=FakeGitHub)
    async with get_sessionmaker()() as db:
        dep = await db.get(Deployment, dep_id)
        assert dep.status == "failed" and "not found" in dep.error
    assert not any("docker run" in c for c in remote.commands)


# ----------------------------------------------------------------------------------------------- the API


async def _host_id() -> uuid.UUID:
    async with get_sessionmaker()() as db:
        host = Host(name="prod-01", hostname="10.0.0.1", username="deploy", host_key="ssh-ed25519 AAAA", metrics={})
        db.add(host)
        await db.commit()
        return host.id


async def test_create_an_image_instance(admin_client, fake_registry):
    host_id = await _host_id()
    body = {"name": "jellyfin", "host_id": str(host_id), "build_source": "image", "deploy": False,
            "image": "https://hub.docker.com/r/linuxserver/jellyfin",
            "ports": [{"host": 8096, "container": 8096}], "volumes": [{"source": "jellyfin-config", "target": "/config"}]}
    resp = await admin_client.post("/api/v1/instances", json=body)
    assert resp.status_code == 201, resp.text
    out = resp.json()
    assert out["image"] == "linuxserver/jellyfin:latest" and out["repository"] == "linuxserver/jellyfin:latest"
    assert out["repository_id"] is None and out["branch"] == "latest" and out["build_source"] == "image"
    # The tag can change later; the instance can't become a repository's.
    resp = await admin_client.patch(f"/api/v1/instances/{out['id']}", json={"image": "linuxserver/jellyfin:10.9"})
    assert resp.status_code == 200 and resp.json()["branch"] == "10.9", resp.text
    resp = await admin_client.patch(f"/api/v1/instances/{out['id']}", json={"build_source": "dockerfile"})
    assert resp.status_code == 400
    page = await admin_client.get(f"/instances/{out['id']}")
    assert page.status_code == 200 and "linuxserver/jellyfin:10.9" in page.text
    assert (await admin_client.get(f"/instances/{out['id']}/edit")).status_code == 200
    assert "jellyfin" in (await admin_client.get("/instances")).text
    resp = await admin_client.get("/api/v1/images/inspect", params={"ref": "linuxserver/jellyfin"})
    assert resp.status_code == 200 and resp.json()["volumes"] == ["/config"]


async def test_image_instance_needs_an_image_and_a_known_registry(admin_client):
    host_id = await _host_id()
    base = {"name": "x", "host_id": str(host_id), "build_source": "image", "deploy": False}
    assert (await admin_client.post("/api/v1/instances", json=base)).status_code == 422
    resp = await admin_client.post("/api/v1/instances", json={**base, "image": "10.0.0.5:5000/app"})
    assert resp.status_code == 422 and "doesn't read images" in resp.text
    resp = await admin_client.post("/api/v1/instances", json={**base, "build_source": "dockerfile", "image": "nginx"})
    assert resp.status_code == 422  # a repository's instance names its repository


async def test_new_instance_form_offers_images(admin_client):
    await _host_id()
    page = await admin_client.get("/instances/new")
    assert page.status_code == 200 and 'name="image"' in page.text and "Container image" in page.text


# ---------------------------------------------------------------------------- public repositories by URL


@pytest.mark.parametrize("text, full", [
    ("https://github.com/jellyfin/jellyfin", "jellyfin/jellyfin"),
    ("https://github.com/jellyfin/jellyfin.git", "jellyfin/jellyfin"),
    ("github.com/owner/repo/tree/main/docker", "owner/repo"),
    ("git@github.com:owner/repo.git", "owner/repo"),
    ("owner/repo", "owner/repo"),
])
def test_parse_repo_url(text, full):
    assert repos.parse_repo_url(text) == full


@pytest.mark.parametrize("text", ["https://gitlab.com/a/b", "owner", "https://github.com/owner", "bad owner/x"])
def test_parse_repo_url_rejects(text):
    with pytest.raises(ValueError):
        repos.parse_repo_url(text)


def _github_handler(request: httpx.Request) -> httpx.Response:
    assert "authorization" not in request.headers  # no account linked: read anonymously
    path = request.url.path
    if path == "/repos/community/app":
        return httpx.Response(200, json={"id": 777, "full_name": "community/app", "owner": {"login": "community"},
                                         "name": "app", "html_url": "https://github.com/community/app",
                                         "default_branch": "main", "visibility": "public", "description": "An app"})
    if path == "/repositories/777/contents/":
        return httpx.Response(200, json=[{"name": "Dockerfile", "type": "file"}, {"name": "README.md", "type": "file"}])
    return httpx.Response(404, json={"message": "Not Found"})


async def test_import_a_public_repository(admin_client, monkeypatch):
    monkeypatch.setattr(github, "transport_factory", lambda: httpx.MockTransport(_github_handler))
    resp = await admin_client.post("/api/v1/repositories/import", json={"url": "https://github.com/community/app"})
    assert resp.status_code == 200, resp.text
    out = resp.json()
    assert out["full_name"] == "community/app" and out["github_id"] == 777 and out["deployable"] is True
    again = await admin_client.post("/api/v1/repositories/import", json={"url": "community/app"})
    assert again.status_code == 200 and again.json()["id"] == out["id"]  # the same row, refreshed
    missing = await admin_client.post("/api/v1/repositories/import", json={"url": "community/nothing"})
    assert missing.status_code == 400 and "no repository community/nothing" in missing.text
    async with get_sessionmaker()() as db:
        assert len((await db.scalars(select(Repository))).all()) == 1
        actions = [e.action for e in (await db.scalars(select(AuditEvent))).all()]
        assert actions.count("repos.import") == 2
    assert "Add by URL" in (await admin_client.get("/repositories")).text
