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
        return [token.strip() for token in self.api_tokens.split(",") if token.strip()]

    @property
    def database_enabled(self) -> bool:
        return bool(self.database_url.strip() or self.database_host.strip())


settings = Settings()
