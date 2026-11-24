"""Application settings, read from environment variables (prefix ``SLIPWAY_``) or ``.env``."""

from __future__ import annotations

import base64
import hashlib
import logging
import os
from functools import lru_cache
from typing import Annotated, Literal
from urllib.parse import urlsplit

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

    # Password and GitHub sign-ins. A HackSpaceLabs sign-in lasts as long as its Keycloak session instead.
    session_ttl_hours: int = 96
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

    # Sign in with HackSpaceLabs (the HackSpaceLabs Keycloak, OpenID Connect). These use the unprefixed HSL_* names
    # every HackSpaceLabs app reads. Off unless the issuer, client id and secret are all set.
    hsl_oidc_issuer: str = Field("", validation_alias="HSL_OIDC_ISSUER")
    hsl_oidc_client_id: str = Field("slipway", validation_alias="HSL_OIDC_CLIENT_ID")
    hsl_oidc_client_secret: str = Field("", validation_alias="HSL_OIDC_CLIENT_SECRET")
    # Optional origin for calls from Slipway to Keycloak (discovery, tokens, keys) when the public address
    # isn't reachable from here. Browser redirects and the issuer check always use the public issuer.
    hsl_oidc_internal_url: str = Field("", validation_alias="HSL_OIDC_INTERNAL_URL")
    # Send signed-out visitors straight to HackSpaceLabs instead of showing the sign-in page.
    hsl_oidc_auto_redirect: bool = Field(False, validation_alias="HSL_OIDC_AUTO_REDIRECT")
    # How often a HackSpaceLabs session is rechecked with Keycloak, in seconds.
    hsl_oidc_recheck_seconds: int = Field(60, ge=1, validation_alias="HSL_OIDC_RECHECK_SECONDS")
    hsl_portal_url: str = Field("", validation_alias="HSL_PORTAL_URL")
    # The portal gateway's own address (not through the proxy), for the owner check of API tokens.
    hsl_portal_internal_url: str = Field("", validation_alias="HSL_PORTAL_INTERNAL_URL")
    # The app switcher: id|name|url entries separated by commas.
    hsl_suite_apps: str = Field("", validation_alias="HSL_SUITE_APPS")

    host_poll_interval: int = 300  # seconds; 0 disables background host health checks
    # seconds between host history rollups and cleanups; 0 disables them
    metrics_retention_interval: int = 3600
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

    @field_validator("base_url", "hsl_oidc_issuer", "hsl_oidc_internal_url", "hsl_portal_url", "hsl_portal_internal_url")
    @classmethod
    def _strip_slash(cls, value: str) -> str:
        return value.strip().rstrip("/")

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

    def hsl_problem(self) -> str | None:
        """Why HackSpaceLabs sign-in is half set up, or None (fully set up, or not at all)."""
        issuer, secret = self.hsl_oidc_issuer, self.hsl_oidc_client_secret
        if not issuer and not secret:
            return None
        missing = [name for name, value in (
            ("HSL_OIDC_ISSUER", issuer), ("HSL_OIDC_CLIENT_ID", self.hsl_oidc_client_id),
            ("HSL_OIDC_CLIENT_SECRET", secret), ("SLIPWAY_BASE_URL", self.base_url),
        ) if not value]
        if missing:
            return f"{', '.join(missing)} {'is' if len(missing) == 1 else 'are'} not set"
        if not _http_url(issuer, path=True):
            return "HSL_OIDC_ISSUER must be an http(s) URL without a query or fragment"
        if self.hsl_oidc_internal_url and not _http_url(self.hsl_oidc_internal_url, path=False):
            return "HSL_OIDC_INTERNAL_URL must be an origin (scheme://host[:port]) without a path"
        if not _http_url(self.base_url, path=True):
            return "SLIPWAY_BASE_URL must be an http(s) URL"
        return None

    @property
    def hsl_enabled(self) -> bool:
        return bool(self.hsl_oidc_issuer and self.hsl_oidc_client_secret) and self.hsl_problem() is None

    @property
    def hsl_callback_url(self) -> str:
        return f"{self.base_url}/auth/hsl/callback"

    @property
    def hsl_apps(self) -> list[dict[str, str]]:
        """HSL_SUITE_APPS as [{id, name, url}]; malformed entries are skipped."""
        apps = []
        for entry in self.hsl_suite_apps.split(","):
            parts = [p.strip() for p in entry.split("|")]
            if len(parts) == 3 and all(parts) and _http_url(parts[2], path=True):
                apps.append({"id": parts[0], "name": parts[1], "url": parts[2]})
        return apps

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


def _http_url(value: str, *, path: bool) -> bool:
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.query or parts.fragment:
        return False
    return "@" not in parts.netloc and (path or parts.path in ("", "/"))


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    if not settings.encryption_key and not settings.is_production:
        log.warning("SLIPWAY_ENCRYPTION_KEY not set; deriving one from SLIPWAY_SECRET_KEY (dev only)")
    return settings
