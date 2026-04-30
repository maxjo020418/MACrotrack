from __future__ import annotations

from typing import Any

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from .config import settings
from .models import metadata


_engine: Engine | None = None


def get_engine() -> Engine | None:
    global _engine
    if not settings.database_enabled:
        return None
    if _engine is None:
        _engine = create_engine(settings.database_url, pool_pre_ping=True, future=True)
    return _engine


def init_database() -> None:
    engine = get_engine()
    if engine is None or not settings.auto_create_schema:
        return

    metadata.create_all(engine)
    with engine.begin() as conn:
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

