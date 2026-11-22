"""Application settings, read from environment variables (prefix ``SLIPWAY_``) or ``.env``."""

from __future__ import annotations

import base64
import hashlib
import logging
import os
from functools import lru_cache
from typing import Annotated, Literal

from cryptography.fernet import Fernet
from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict
from sqlalchemy.engine import make_url

log = logging.getLogger(__name__)

DEV_SECRET = "dev-insecure-secret-change-me"

CommaList = Annotated[list[str], NoDecode]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SLIPWAY_",
        # SLIPWAY_ENV_FILE="" disables .env loading (the test suite does this).
        env_file=os.environ.get("SLIPWAY_ENV_FILE", ".env") or None,
        env_file_encoding="utf-8",
        extra="ignore",
        # Keep secrets out of configuration error messages.
        hide_input_in_errors=True,
    )

    env: Literal["development", "production", "test"] = "development"
    base_url: str = "http://localhost:8000"
    log_level: str = "INFO"
    # Proxies trusted to set X-Forwarded-For/-Proto (comma-separated IPs or CIDRs, passed to uvicorn).
    forwarded_allow_ips: str = "127.0.0.1"

    # Signs nothing user-visible today but is the root secret for derived keys.
    secret_key: str = DEV_SECRET
    # Fernet key(s) used to encrypt SSH keys, passwords, env vars and OAuth tokens at rest.
    # Comma-separate several keys to rotate: the first encrypts, all are tried for decryption.
    encryption_key: str = ""

    database_url: str = "postgresql+asyncpg://slipway:slipway@localhost:5432/slipway"
    # Optional; used unless a configured database_url has its own password. It may contain any character.
    database_password: str | None = None
    database_echo: bool = False

    session_ttl_hours: int = 24 * 14
    allow_signup: bool = False
    default_role: str = "viewer"

    # Optional first-run admin. Created on startup only when the users table is empty.
    admin_email: str | None = None
    admin_password: str | None = None

    github_client_id: str | None = None
    github_client_secret: str | None = None
    github_scopes: str = "read:user user:email repo"
    # GitHub logins / orgs allowed to create a Slipway account on first sign-in.
    github_allowed_users: CommaList = Field(default_factory=list)
    github_allowed_orgs: CommaList = Field(default_factory=list)
    # Optional machine token (PAT or GitHub App installation token) used for deploys
    # when the user triggering the deploy has not linked GitHub.
    github_service_token: str | None = None
    github_api_url: str = "https://api.github.com"
    github_web_url: str = "https://github.com"

    host_poll_interval: int = 300  # seconds; 0 disables background host health checks
    default_deploy_root: str = "/opt/slipway"
    ssh_connect_timeout: int = 15

    # Data safety. Snapshot bundles live in this folder on the Slipway server (the image sets
    # /var/lib/slipway, mounted from data/files); every file in it is encrypted.
    storage_dir: str = "data/files"
    # Largest snapshot accepted (the members added up; also the upload limit), and all stored snapshots together.
    snapshot_max_bytes: int = Field(default=20 * 1024**3, ge=1)
    snapshot_total_bytes: int = Field(default=100 * 1024**3, ge=1)
    # All backups Slipway keeps on this server for environments whose data has no host of its own
    # (DigitalOcean managed data, phase 4), added up.
    backup_total_bytes: int = Field(default=100 * 1024**3, ge=1)
    # Snapshot transfers (takes, uploads, checks, downloads) and passphrase key derivations run at once.
    snapshot_transfers: int = Field(default=2, ge=1, le=8)
    snapshot_kdf_slots: int = Field(default=2, ge=1, le=4)
    # An uploaded encrypted snapshot nobody unlocks is deleted after this many days.
    snapshot_locked_days: int = Field(default=7, ge=1)
    # Free space a host must keep beyond the expected size of a backup, in MB.
    backup_free_margin_mb: int = Field(default=1024, ge=0)
    # Backups taken by hand ("Back up now") that one instance may keep.
    manual_backups_max: int = Field(default=10, ge=1)

    # Certificates for DigitalOcean load balancers (phase 4): Let's Encrypt's directories, and how
    # often the renewal loop looks for certificates due, in seconds (0 turns the loop off).
    acme_directory: str = "https://acme-v02.api.letsencrypt.org/directory"
    acme_staging_directory: str = "https://acme-staging-v02.api.letsencrypt.org/directory"
    cert_renew_interval: int = Field(default=21600, ge=0)

    # Terraform for Proxmox VMs (phase 5). The binary is an absolute path or a name on PATH; the CLI
    # config is the image's mirror-only one (docker/terraformrc), so `init` never goes online.
    terraform_binary: str = "terraform"
    terraform_cli_config: str = "/etc/slipway/terraformrc"
    # Terraform's working folders, one per VM, mode 700. Empty means <storage_dir>/terraform.
    terraform_dir: str = ""
    # Terraform processes at once across Slipway.
    terraform_parallel: int = Field(default=2, ge=1, le=8)
    # The TCP probe of a new VM's address before it is made; tests patch the probe itself.
    vm_address_probe: bool = True

    @field_validator("github_allowed_users", "github_allowed_orgs", mode="before")
    @classmethod
    def _split_commas(cls, value: object) -> object:
        if isinstance(value, str):
            return [v.strip().lower() for v in value.split(",") if v.strip()]
        return value

    @field_validator("base_url")
    @classmethod
    def _strip_slash(cls, value: str) -> str:
        return value.rstrip("/")

    @field_validator("log_level", mode="before")
    @classmethod
    def _log_level(cls, value: object) -> object:
        if isinstance(value, str):
            value = value.strip().upper()
            if value not in logging.getLevelNamesMapping():
                raise ValueError("SLIPWAY_LOG_LEVEL must be one of DEBUG, INFO, WARNING, ERROR, CRITICAL")
        return value

    @model_validator(mode="after")
    def _check_production(self) -> Settings:
        if self.env == "production":
            if self.secret_key == DEV_SECRET or len(self.secret_key) < 32:
                raise ValueError("SLIPWAY_SECRET_KEY must be set to a random value of 32+ characters")
            if not self.encryption_key:
                raise ValueError(
                    "SLIPWAY_ENCRYPTION_KEY must be set in production (run `slipway generate-secrets`)"
                )
        return self

    @model_validator(mode="after")
    def _check_encryption_keys(self) -> Settings:
        if not self.encryption_key:
            return self
        keys = self.fernet_keys()
        if not keys:
            raise ValueError("SLIPWAY_ENCRYPTION_KEY contains no keys (run `slipway generate-secrets`)")
        for i, key in enumerate(keys, 1):
            try:
                Fernet(key)
            except ValueError:
                raise ValueError(
                    f"SLIPWAY_ENCRYPTION_KEY entry {i} is not a valid Fernet key (run `slipway generate-secrets`)"
                ) from None
        return self

    @model_validator(mode="after")
    def _apply_database_password(self) -> Settings:
        if self.database_password is None:
            return self
        url = make_url(self.database_url)
        # A password written into a configured SLIPWAY_DATABASE_URL wins, so an overridden URL keeps working.
        url_has_password = url.password is not None and "database_url" in self.model_fields_set
        if url.get_backend_name() != "sqlite" and not url_has_password:
            self.database_url = url.set(password=self.database_password).render_as_string(hide_password=False)
        return self

    @property
    def is_production(self) -> bool:
        return self.env == "production"

    @property
    def secure_cookies(self) -> bool:
        return self.base_url.startswith("https://")

    @property
    def github_enabled(self) -> bool:
        return bool(self.github_client_id and self.github_client_secret)

    @property
    def github_callback_url(self) -> str:
        return f"{self.base_url}/auth/github/callback"

    @property
    def oauth_scopes(self) -> str:
        scopes = self.github_scopes.split()
        if self.github_allowed_orgs and "read:org" not in scopes:
            scopes.append("read:org")
        return " ".join(scopes)

    def fernet_keys(self) -> list[bytes]:
        if self.encryption_key:
            return [k.strip().encode() for k in self.encryption_key.split(",") if k.strip()]
        # Development fallback: derive a stable key from the secret key.
        digest = hashlib.sha256(f"slipway-encryption:{self.secret_key}".encode()).digest()
        return [base64.urlsafe_b64encode(digest)]


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    if not settings.encryption_key and not settings.is_production:
        log.warning("SLIPWAY_ENCRYPTION_KEY not set; deriving one from SLIPWAY_SECRET_KEY (dev only)")
    return settings
