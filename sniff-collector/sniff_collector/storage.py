from __future__ import annotations

import hashlib
from datetime import timedelta
from typing import Any

from .classifier import classify_direction, is_known_ap, update_ap_evidence
from .clock import unwrap_rx_timestamp
from .config import settings
from .database import get_engine
from .events import now_utc
from .identity import ssid_values, upsert_mac, upsert_sender
from .models import ingest_batches, wifi_frame_payloads, wifi_frames
from .wifi import is_local_admin_mac, parse_management_frame


def device_id_from_request(request_meta: dict[str, Any], parsed: dict[str, Any] | None) -> str:
    sender_status = parsed.get("sender_status", {}) if parsed else {}
    return (
        sender_status.get("device_id")
        or request_meta.get("device_id_header")
        or request_meta.get("client_host")
        or "unknown"
    )


def insert_ingest_batch(
    conn: Any,
    sender_id: int,
    request_meta: dict[str, Any],
    body: bytes,
    parsed: dict[str, Any] | None,
    parse_error: str | None,
) -> int:
    header = parsed["header"] if parsed else {}
    return int(
        conn.execute(
            ingest_batches.insert()
            .values(
                sender_id=sender_id,
                received_at=now_utc(),
                client_host=request_meta.get("client_host"),
                body_len=len(body),
                body_sha256=hashlib.sha256(body).digest(),
                content_type=request_meta.get("content_type"),
                batch_seq=header.get("batch_seq"),
                declared_record_count=header.get("record_count"),
                parsed_record_count=parsed.get("parsed_record_count") if parsed else None,
                payload_len=header.get("payload_len"),
                sender_uptime_ms=header.get("uptime_ms"),
                parse_ok=parsed is not None,
                parse_error=parse_error,
                sender_status=parsed.get("sender_status") if parsed else None,
                raw_body=body if settings.store_raw_body else None,
            )
            .returning(ingest_batches.c.id)
        ).scalar_one()
    )


def prepare_frame(
    conn: Any,
    sender_id: int,
    record: dict[str, Any],
    batch_header: dict[str, Any],
    now: Any,
) -> dict[str, Any]:
    snif = record["header"]
    frame = record["frame_bytes"]
    source_id = int(record["source_id"])
    rx_ts_us_32 = int(snif["ts_us"])
    rx_ts_unwrapped = unwrap_rx_timestamp(conn, sender_id, source_id, rx_ts_us_32, now)
    wifi = parse_management_frame(frame)
    ssid_hash, ssid_text = ssid_values(wifi.get("ssid"))

    ids = {
        "addr1_id": upsert_mac(conn, wifi.get("addr1"), now),
        "addr2_id": upsert_mac(conn, wifi.get("addr2"), now),
        "addr3_id": upsert_mac(conn, wifi.get("addr3"), now),
    }

    for mac_id in {ids["addr2_id"], ids["addr3_id"]}:
        update_ap_evidence(
            conn,
            mac_id,
            wifi.get("mgmt_subtype"),
            int(snif["channel"]),
            ssid_hash,
            now,
        )

    known_ap_ids = {
        mac_id for mac_id in ids.values() if mac_id is not None and is_known_ap(conn, mac_id)
    }
    return {
        "record": record,
        "frame": frame,
        "snif": snif,
        "wifi": wifi,
        "ids": ids,
        "direction": classify_direction(wifi, ids, known_ap_ids),
        "ssid_hash": ssid_hash,
        "ssid_text": ssid_text,
        "sender_uptime_ms": batch_header.get("uptime_ms"),
        "rx_ts_unwrapped": rx_ts_unwrapped,
    }


def insert_frame(
    conn: Any,
    batch_id: int,
    sender_id: int,
    item: dict[str, Any],
    max_rx_ts: int,
    now: Any,
) -> None:
    record = item["record"]
    frame = item["frame"]
    snif = item["snif"]
    wifi = item["wifi"]
    observed_at = now - timedelta(microseconds=max_rx_ts - item["rx_ts_unwrapped"])
    frame_id = conn.execute(
        wifi_frames.insert()
        .values(
            batch_id=batch_id,
            record_index=record["index"],
            sender_id=sender_id,
            source_id=record["source_id"],
            received_at=now,
            observed_at=observed_at,
            sender_uptime_ms=item["sender_uptime_ms"],
            rx_ts_us_32=snif["ts_us"],
            rx_ts_us_unwrapped=item["rx_ts_unwrapped"],
            snif_seq=snif["seq"],
            channel=snif["channel"],
            rssi=snif["rssi"],
            frame_len=snif["frame_len"],
            truncated=bool(snif["flags"] & 1),
            crc16=snif["crc16"],
            frame_control=wifi.get("frame_control"),
            mgmt_subtype=wifi.get("mgmt_subtype"),
            mgmt_subtype_name=wifi.get("mgmt_subtype_name"),
            duration_id=wifi.get("duration_id"),
            seq_num=wifi.get("seq_num"),
            frag_num=wifi.get("frag_num"),
            retry=wifi.get("retry"),
            protected=wifi.get("protected"),
            **item["ids"],
            station_mac_id=item["direction"]["station_mac_id"],
            ap_mac_id=item["direction"]["ap_mac_id"],
            ssid_hash=item["ssid_hash"],
            ssid_text=item["ssid_text"],
            ssid_len=wifi.get("ssid_len"),
            ssid_is_wildcard=wifi.get("ssid_is_wildcard"),
            ie_ids=wifi.get("ie_ids") or [],
            vendor_ouis=[oui.hex() for oui in wifi.get("vendor_ouis", [])],
            fixed_fields=wifi.get("fixed_fields") or {},
            parse_ok=wifi.get("parse_ok", False),
            parse_error=wifi.get("parse_error"),
            is_station_originated=item["direction"]["is_station_originated"],
            direction=item["direction"]["direction"],
            direction_confidence=item["direction"]["direction_confidence"],
            direction_reason=item["direction"]["direction_reason"],
            src_is_randomized=is_local_admin_mac(wifi.get("addr2")),
        )
        .returning(wifi_frames.c.id)
    ).scalar_one()

    if settings.store_raw_frames:
        conn.execute(
            wifi_frame_payloads.insert().values(
                frame_id=frame_id,
                raw_frame=frame,
                raw_frame_sha256=hashlib.sha256(frame).digest(),
            )
        )


def persist_batch(
    request_meta: dict[str, Any],
    body: bytes,
    parsed: dict[str, Any] | None,
    parse_error: str | None,
) -> dict[str, Any]:
    engine = get_engine()
    if engine is None:
        return {"database_enabled": False}

    now = now_utc()
    device_id = device_id_from_request(request_meta, parsed)

    with engine.begin() as conn:
        sender_id = upsert_sender(conn, device_id, now)
        batch_id = insert_ingest_batch(conn, sender_id, request_meta, body, parsed, parse_error)
        if not parsed:
            return {"database_enabled": True, "batch_id": batch_id, "frames_inserted": 0}

        batch_header = parsed["header"]
        pending_frames = [
            prepare_frame(conn, sender_id, record, batch_header, now)
            for record in parsed["records"]
        ]
        max_rx_ts = max((item["rx_ts_unwrapped"] for item in pending_frames), default=0)
        for item in pending_frames:
            insert_frame(conn, batch_id, sender_id, item, max_rx_ts, now)

    return {
        "database_enabled": True,
        "batch_id": batch_id,
        "frames_inserted": len(pending_frames),
    }

