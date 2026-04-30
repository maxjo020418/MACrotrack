from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import select, update

from .models import access_points
from .wifi import (
    AP_ORIGINATED_SUBTYPES,
    CONTROL_EXCHANGE_SUBTYPES,
    STATION_REQUEST_SUBTYPES,
    is_local_admin_mac,
    is_multicast_mac,
    is_zero_mac,
)


AP_SCORE_THRESHOLD = 5


def is_known_ap(conn: Any, mac_id: int | None) -> bool:
    if mac_id is None:
        return False
    score = conn.execute(
        select(access_points.c.evidence_score).where(access_points.c.mac_id == mac_id)
    ).scalar_one_or_none()
    return bool(score is not None and score >= AP_SCORE_THRESHOLD)


def unique_bytes(values: list[bytes], value: bytes | None) -> list[bytes]:
    normalized = [bytes(item) for item in values]
    if value is not None and value not in normalized:
        normalized.append(value)
    return normalized


def update_ap_evidence(
    conn: Any,
    mac_id: int | None,
    subtype: int | None,
    channel: int,
    ssid_hash: bytes | None,
    now: datetime,
) -> None:
    if mac_id is None or subtype not in AP_ORIGINATED_SUBTYPES:
        return

    score_delta = {8: 10, 1: 8, 3: 8, 5: 5}.get(subtype, 1)
    count_updates = {
        "beacon_count": 1 if subtype == 8 else 0,
        "probe_response_count": 1 if subtype == 5 else 0,
        "assoc_response_count": 1 if subtype in {1, 3} else 0,
    }
    row = (
        conn.execute(select(access_points).where(access_points.c.mac_id == mac_id))
        .mappings()
        .one_or_none()
    )
    if row is None:
        conn.execute(
            access_points.insert().values(
                mac_id=mac_id,
                first_seen_at=now,
                last_seen_at=now,
                channels=[channel],
                ssid_hashes=[ssid_hash] if ssid_hash is not None else [],
                beacon_count=count_updates["beacon_count"],
                probe_response_count=count_updates["probe_response_count"],
                assoc_response_count=count_updates["assoc_response_count"],
                evidence_score=score_delta,
            )
        )
        return

    channels = sorted({*(row["channels"] or []), channel})
    ssid_hashes = unique_bytes(row["ssid_hashes"] or [], ssid_hash)
    conn.execute(
        update(access_points)
        .where(access_points.c.mac_id == mac_id)
        .values(
            last_seen_at=now,
            channels=channels,
            ssid_hashes=ssid_hashes,
            beacon_count=int(row["beacon_count"]) + count_updates["beacon_count"],
            probe_response_count=int(row["probe_response_count"])
            + count_updates["probe_response_count"],
            assoc_response_count=int(row["assoc_response_count"])
            + count_updates["assoc_response_count"],
            evidence_score=int(row["evidence_score"]) + score_delta,
        )
    )


def first_known_ap_id(known_ap_ids: set[int], *ids: int | None) -> int | None:
    for mac_id in ids:
        if mac_id is not None and mac_id in known_ap_ids:
            return mac_id
    return None


def classify_direction(
    wifi: dict[str, Any],
    ids: dict[str, int | None],
    known_ap_ids: set[int],
) -> dict[str, Any]:
    addr2 = wifi.get("addr2")
    subtype = wifi.get("mgmt_subtype")
    unknown = {
        "direction": "unknown",
        "is_station_originated": None,
        "station_mac_id": None,
        "ap_mac_id": None,
        "direction_confidence": 0,
    }

    if not wifi.get("parse_ok"):
        return {**unknown, "direction_reason": "frame parser rejected frame"}
    if addr2 is None or is_zero_mac(addr2) or is_multicast_mac(addr2):
        return {**unknown, "direction_reason": "invalid or non-unicast transmitter address"}

    if ids["addr2_id"] in known_ap_ids:
        return {
            **unknown,
            "direction": "ap",
            "is_station_originated": False,
            "ap_mac_id": ids["addr2_id"],
            "direction_confidence": 95,
            "direction_reason": "transmitter has AP evidence",
        }

    if subtype in AP_ORIGINATED_SUBTYPES:
        return {
            **unknown,
            "direction": "ap",
            "is_station_originated": False,
            "ap_mac_id": ids["addr2_id"] or ids["addr3_id"],
            "direction_confidence": 95,
            "direction_reason": "AP-originated management subtype",
        }

    if subtype in STATION_REQUEST_SUBTYPES:
        return {
            **unknown,
            "direction": "station",
            "is_station_originated": True,
            "station_mac_id": ids["addr2_id"],
            "ap_mac_id": first_known_ap_id(known_ap_ids, ids["addr3_id"], ids["addr1_id"]),
            "direction_confidence": 95,
            "direction_reason": "station request management subtype",
        }

    if subtype in CONTROL_EXCHANGE_SUBTYPES:
        ap_id = first_known_ap_id(known_ap_ids, ids["addr1_id"], ids["addr3_id"])
        if ap_id is not None:
            return {
                **unknown,
                "direction": "station",
                "is_station_originated": True,
                "station_mac_id": ids["addr2_id"],
                "ap_mac_id": ap_id,
                "direction_confidence": 70 if subtype != 11 else 80,
                "direction_reason": "transmitter is non-AP and peer has AP evidence",
            }

    if is_local_admin_mac(addr2):
        return {
            **unknown,
            "direction_reason": "locally administered transmitter without enough AP context",
        }

    return {**unknown, "direction_reason": "no station/AP rule matched"}

