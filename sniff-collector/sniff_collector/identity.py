from __future__ import annotations

import hashlib
import hmac
from datetime import datetime
from typing import Any

from sqlalchemy.dialects.postgresql import insert as pg_insert

from .config import settings
from .models import collector_senders, mac_addresses
from .wifi import is_local_admin_mac, is_multicast_mac, mac_text


def keyed_hash(name: str, key: str, value: bytes) -> bytes:
    if not key:
        raise ValueError(f"COLLECTOR_{name}_HASH_KEY is required when storing DB records")
    return hmac.new(key.encode("utf-8"), value, hashlib.sha256).digest()


def upsert_sender(conn: Any, device_id: str, now: datetime) -> int:
    stmt = (
        pg_insert(collector_senders)
        .values(device_id=device_id, first_seen_at=now, last_seen_at=now)
        .on_conflict_do_update(
            index_elements=[collector_senders.c.device_id],
            set_={"last_seen_at": now},
        )
        .returning(collector_senders.c.id)
    )
    return int(conn.execute(stmt).scalar_one())


def upsert_mac(conn: Any, raw_mac: bytes | None, now: datetime) -> int | None:
    if raw_mac is None:
        return None

    mac_hash = keyed_hash("MAC", settings.resolved_mac_hash_key, raw_mac)
    multicast = is_multicast_mac(raw_mac)
    local_admin = is_local_admin_mac(raw_mac)
    oui = raw_mac[:3] if not multicast and not local_admin else None
    values = {
        "mac_hash": mac_hash,
        "mac_text": mac_text(raw_mac) if settings.store_raw_macs else None,
        "oui": oui,
        "is_local_admin": local_admin,
        "is_multicast": multicast,
        "first_seen_at": now,
        "last_seen_at": now,
    }
    stmt = (
        pg_insert(mac_addresses)
        .values(**values)
        .on_conflict_do_update(
            index_elements=[mac_addresses.c.mac_hash],
            set_={
                "last_seen_at": now,
                "mac_text": values["mac_text"],
                "oui": values["oui"],
                "is_local_admin": values["is_local_admin"],
                "is_multicast": values["is_multicast"],
            },
        )
        .returning(mac_addresses.c.id)
    )
    return int(conn.execute(stmt).scalar_one())


def ssid_values(ssid: bytes | None) -> tuple[bytes | None, str | None]:
    if ssid is None:
        return None, None
    ssid_hash = keyed_hash("SSID", settings.resolved_ssid_hash_key, ssid)
    ssid_text = ssid.decode("utf-8", errors="replace") if settings.store_plaintext_ssids else None
    return ssid_hash, ssid_text
