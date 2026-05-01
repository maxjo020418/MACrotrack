from __future__ import annotations

from typing import Any

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine, URL

from .config import settings
from .models import metadata


_engine: Engine | None = None


def _database_url() -> str | URL:
    if settings.database_url.strip():
        return settings.database_url
    return URL.create(
        "postgresql+psycopg",
        username=settings.database_user,
        password=settings.database_password,
        host=settings.database_host,
        port=settings.database_port,
        database=settings.database_name,
    )


def get_engine() -> Engine | None:
    global _engine
    if not settings.database_enabled:
        return None
    if _engine is None:
        _engine = create_engine(_database_url(), pool_pre_ping=True, future=True)
    return _engine


def init_database() -> None:
    engine = get_engine()
    if engine is None or not settings.auto_create_schema:
        return

    metadata.create_all(engine)
    with engine.begin() as conn:
        conn.execute(text("drop index if exists ingest_batches_sender_seq_idx"))
        conn.execute(
            text(
                """
                create index if not exists ingest_batches_sender_seq_idx
                on ingest_batches(sender_id, batch_seq)
                """
            )
        )
        conn.execute(
            text(
                """
                create index if not exists ingest_batches_sender_body_sha_idx
                on ingest_batches(sender_id, body_sha256)
                """
            )
        )
        conn.execute(
            text(
                """
                create or replace view station_management_frames as
                select *
                from wifi_frames
                where is_station_originated is true
                  and station_mac_id is not null
                  and parse_ok is true
                """
            )
        )
        conn.execute(
            text(
                """
                create or replace view station_probe_frames as
                select *
                from station_management_frames
                where mgmt_subtype = 4
                """
            )
        )


def database_health() -> dict[str, Any]:
    engine = get_engine()
    if engine is None:
        return {"enabled": False, "ok": None}
    try:
        with engine.connect() as conn:
            conn.execute(text("select 1"))
        return {"enabled": True, "ok": True}
    except Exception as exc:  # pragma: no cover - exact DB errors vary by driver
        return {"enabled": True, "ok": False, "error": str(exc)}
