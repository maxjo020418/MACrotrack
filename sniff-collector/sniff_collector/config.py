from __future__ import annotations

import os
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


ENV_FILE = Path(os.getenv("COLLECTOR_ENV_FILE", Path(__file__).resolve().parents[1] / ".env"))


class Settings(BaseSettings):
    app_name: str = "sniff-collector"
    host: str = "0.0.0.0"
    port: int = 8888
    log_level: str = "info"
    auth_required: bool = True
    api_tokens: str = ""
    max_body_bytes: int = 262_144
    hex_preview_bytes: int = 128
    log_headers: bool = True
    log_raw_body: bool = False

    database_url: str = ""
    database_host: str = ""
    database_port: int = 5432
    database_name: str = ""
    database_user: str = ""
    database_password: str = ""
    auto_create_schema: bool = True
    store_raw_body: bool = False
    store_raw_frames: bool = True
    store_raw_macs: bool = False
    store_plaintext_ssids: bool = False
    mac_hash_key: str = ""
    ssid_hash_key: str = ""

    model_config = SettingsConfigDict(
        env_prefix="COLLECTOR_",
        env_file=ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @property
    def valid_api_tokens(self) -> list[str]:
        tokens = self.api_tokens or os.getenv("SERVICE_PASSWORD_COLLECTOR_API_TOKEN", "")
        return [token.strip() for token in tokens.split(",") if token.strip()]

    @property
    def database_enabled(self) -> bool:
        return bool(self.database_url.strip() or self.database_host.strip())

    @property
    def resolved_database_user(self) -> str:
        return self.database_user or os.getenv("SERVICE_USER_POSTGRES", "")

    @property
    def resolved_database_password(self) -> str:
        return self.database_password or os.getenv("SERVICE_PASSWORD_POSTGRES", "")

    @property
    def resolved_mac_hash_key(self) -> str:
        return self.mac_hash_key or os.getenv("SERVICE_PASSWORD_COLLECTOR_MAC_HASH_KEY", "")

    @property
    def resolved_ssid_hash_key(self) -> str:
        return self.ssid_hash_key or os.getenv("SERVICE_PASSWORD_COLLECTOR_SSID_HASH_KEY", "")


settings = Settings()
