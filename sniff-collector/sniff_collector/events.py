from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from .config import settings


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def now_iso() -> str:
    return now_utc().isoformat()


def print_event(event: str, payload: dict[str, Any]) -> None:
    line = {"ts": now_iso(), "event": event, **payload}
    print(json.dumps(line, sort_keys=True, default=str), flush=True)


def hex_preview(data: bytes) -> str:
    return data[: settings.hex_preview_bytes].hex(" ")


def bytes_summary(data: bytes) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "hex_preview": hex_preview(data),
    }
    if settings.log_raw_body:
        summary["hex"] = data.hex(" ")
    return summary


def clean_c_string(value: bytes) -> str:
    return value.split(b"\x00", 1)[0].decode("utf-8", errors="replace")

