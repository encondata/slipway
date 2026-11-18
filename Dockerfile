# syntax=docker/dockerfile:1

# Terraform and the bpg/proxmox provider, for Proxmox VMs. Each zip is checked against its SHA-256
# below; the provider goes into a filesystem mirror, so `terraform init` in the image never goes
# online (docker/terraformrc). The versions equal slipway/services/terraform.py (TERRAFORM_VERSION,
# PROVIDER_VERSION) and the module's versions.tf; tests/test_image.py checks they agree.
FROM python:3.13-slim AS terraform
ARG TARGETARCH
ARG TERRAFORM_VERSION=1.16.5
ARG PROXMOX_PROVIDER_VERSION=0.115.0
# SHA-256 of each zip, one line per architecture.
# PLACEHOLDER: these are not recorded yet. A networked session records them from HashiCorp's
# SHA256SUMS and the provider release's SHA256SUMS, together with slipway/terraform/proxmox-vm/
# .terraform.lock.hcl, whose zh: hashes must equal the provider lines. Until then `sha256sum -c`
# fails and the image doesn't build, rather than installing an unchecked binary.
ARG TERRAFORM_SHA256_LINUX_AMD64=PLACEHOLDER-not-recorded-yet
ARG TERRAFORM_SHA256_LINUX_ARM64=PLACEHOLDER-not-recorded-yet
ARG PROXMOX_PROVIDER_SHA256_LINUX_AMD64=PLACEHOLDER-not-recorded-yet
ARG PROXMOX_PROVIDER_SHA256_LINUX_ARM64=PLACEHOLDER-not-recorded-yet

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
# fetches for that build isn't hash-checked. Pre-building a wheel and pinning its hash needs a
# networked session; until then this is a known gap.
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
