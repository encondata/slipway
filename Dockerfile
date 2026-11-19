# syntax=docker/dockerfile:1

# Terraform and the bpg/proxmox provider, for Proxmox VMs. Each zip is checked against its SHA-256
# below; the provider goes into a filesystem mirror, so `terraform init` in the image never goes
# online (docker/terraformrc). The versions equal slipway/services/terraform.py (TERRAFORM_VERSION,
# PROVIDER_VERSION) and the module's versions.tf; tests/test_image.py checks they agree.
FROM python:3.13-slim AS terraform
ARG TARGETARCH
ARG TERRAFORM_VERSION=1.16.5
ARG PROXMOX_PROVIDER_VERSION=0.115.0
# SHA-256 of each zip, one line per architecture, from HashiCorp's terraform_1.16.5_SHA256SUMS and the
# provider release's terraform-provider-proxmox_0.115.0_SHA256SUMS. The provider lines equal zh: hashes
# in slipway/terraform/proxmox-vm/.terraform.lock.hcl (tests/test_image.py checks it). When a version
# changes, record its sums here and regenerate the lock file with `terraform providers lock
# -platform=linux_amd64 -platform=linux_arm64` in that folder.
ARG TERRAFORM_SHA256_LINUX_AMD64=2bc2fcfff033265c9e02ca0351f01794eb122f62a9b2a49a3294b9e49eaab5e4
ARG TERRAFORM_SHA256_LINUX_ARM64=61a50b00485ee4810cf20581ef080fc54d34d666e175c58d9a10501c65c1ccde
ARG PROXMOX_PROVIDER_SHA256_LINUX_AMD64=36c1c6bdcb9c74456ecab30beac94d7984b50deedd236cda8708e5aac924469e
ARG PROXMOX_PROVIDER_SHA256_LINUX_ARM64=7e73903b42fc17078233a6c32fa0b79640c8a2890ed80f69d3fdefba4d0ad085

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*
RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) tf_sum="${TERRAFORM_SHA256_LINUX_AMD64}"; pv_sum="${PROXMOX_PROVIDER_SHA256_LINUX_AMD64}" ;; \
      arm64) tf_sum="${TERRAFORM_SHA256_LINUX_ARM64}"; pv_sum="${PROXMOX_PROVIDER_SHA256_LINUX_ARM64}" ;; \
      *) echo "No Terraform build for architecture '${TARGETARCH}'" >&2; exit 1 ;; \
    esac; \
    tf_zip="terraform_${TERRAFORM_VERSION}_linux_${TARGETARCH}.zip"; \
    curl -fsSLo "/tmp/${tf_zip}" "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/${tf_zip}"; \
    echo "${tf_sum}  /tmp/${tf_zip}" | sha256sum -c -; \
    unzip -o -d /usr/local/bin "/tmp/${tf_zip}" terraform; \
    rm "/tmp/${tf_zip}"; \
    mirror="/opt/terraform/providers/registry.terraform.io/bpg/proxmox"; \
    pv_zip="terraform-provider-proxmox_${PROXMOX_PROVIDER_VERSION}_linux_${TARGETARCH}.zip"; \
    mkdir -p "${mirror}"; \
    curl -fsSLo "${mirror}/${pv_zip}" \
      "https://github.com/bpg/terraform-provider-proxmox/releases/download/v${PROXMOX_PROVIDER_VERSION}/${pv_zip}"; \
    echo "${pv_sum}  ${mirror}/${pv_zip}" | sha256sum -c -; \
    /usr/local/bin/terraform version

FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SLIPWAY_ENV=production

WORKDIR /app
RUN useradd --create-home --uid 10001 slipway

# Terraform, its provider mirror and the mirror-only CLI config (SLIPWAY_TERRAFORM_CLI_CONFIG's default).
COPY --from=terraform /usr/local/bin/terraform /usr/local/bin/terraform
COPY --from=terraform /opt/terraform/providers /opt/terraform/providers
COPY docker/terraformrc /etc/slipway/terraformrc

# ESXi support (pyvmomi), pinned with hashes, before Slipway itself.
# pyvmomi 8.0.3.0.1 is published only as an sdist, so pip builds it here, and the build backend pip
# fetches for that build isn't hash-checked. That gap is accepted (docs/phase5-machines.md §19.14); no
# pinned wheel is pre-built.
COPY requirements-esxi.txt ./
RUN pip install --require-hashes --no-deps -r requirements-esxi.txt

# Dependencies first for better layer caching.
COPY pyproject.toml README.md ./
COPY slipway ./slipway
RUN pip install .

COPY alembic.ini ./
COPY alembic ./alembic
COPY docker/entrypoint.sh /usr/local/bin/slipway-entrypoint
RUN chmod +x /usr/local/bin/slipway-entrypoint

# Stored snapshots (encrypted). docker-compose.yml mounts data/files here; Slipway runs as uid 10001.
# Terraform's working folders are made under it at run time (<storage_dir>/terraform, mode 700).
ENV SLIPWAY_STORAGE_DIR=/var/lib/slipway
RUN mkdir -p /var/lib/slipway && chown 10001:10001 /var/lib/slipway && chmod 700 /var/lib/slipway

# Which commit this image was built from, so the Updates page can say what runs. install.sh and the
# upgrade script pass these; an image built without them reports the commit as unknown. They come after
# the pip install layers so a new commit doesn't rebuild the dependencies.
ARG SLIPWAY_COMMIT=
ARG SLIPWAY_BRANCH=
ARG SLIPWAY_BUILT_AT=
ENV SLIPWAY_COMMIT=$SLIPWAY_COMMIT \
    SLIPWAY_BRANCH=$SLIPWAY_BRANCH \
    SLIPWAY_BUILT_AT=$SLIPWAY_BUILT_AT

USER slipway
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health', timeout=4)" || exit 1

ENTRYPOINT ["slipway-entrypoint"]
CMD ["slipway", "serve", "--host", "0.0.0.0", "--port", "8000"]
