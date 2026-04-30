from __future__ import annotations

import hashlib
from typing import Any

from fastapi import Request

from .events import bytes_summary


def packet_summary(
    request: Request,
    body: bytes,
    parsed: dict[str, Any] | None,
    parse_error: str | None,
    storage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "client": request.client.host if request.client else None,
        "bytes": len(body),
        "sha256": hashlib.sha256(body).hexdigest()[:16],
        "content_type": request.headers.get("content-type"),
        "device_id_header": request.headers.get("x-device-id"),
        "batch_seq_header": request.headers.get("x-batch-seq"),
        "record_count_header": request.headers.get("x-record-count"),
        "parsed": parsed is not None,
        "parse_error": parse_error,
    }

    if storage is not None:
        summary["storage"] = storage

    if parsed is None:
        return summary

    header = parsed["header"]
    summary["batch"] = {
        "seq": header["batch_seq"],
        "version": header["version"],
        "magic_ok": header["magic_ok"],
        "version_ok": header["version_ok"],
        "uptime_ms": header["uptime_ms"],
        "payload_bytes": header["payload_len"],
        "body_len_ok": parsed["body_len_matches_header"],
        "declared_records": header["record_count"],
        "parsed_records": parsed["parsed_record_count"],
        "unparsed_payload_bytes": parsed["unparsed_payload_bytes"],
        "trailing_body_bytes": parsed["trailing_body_bytes"],
    }

    if sender_status := parsed.get("sender_status"):
        summary["sender"] = {
            "device_id": sender_status.get("device_id"),
            "uptime_ms": sender_status.get("uptime_ms"),
            "wifi_connected": bool(sender_status.get("wifi_connected")),
            "wifi_rssi": sender_status.get("wifi_rssi"),
            "heap_free": sender_status.get("heap_free"),
            "queue_depth": sender_status.get("upload_queue_depth"),
            "queue_capacity": sender_status.get("upload_queue_capacity"),
            "records_queued": sender_status.get("upload_records_queued"),
            "records_dropped": sender_status.get("upload_records_dropped"),
            "http_attempts": sender_status.get("upload_http_attempts"),
            "http_successes": sender_status.get("upload_http_successes"),
            "http_failures": sender_status.get("upload_http_failures"),
            "retry_pending": bool(sender_status.get("upload_retry_pending")),
            "sniffer_count": sender_status.get("sniffer_count"),
        }

    records = []
    for record in parsed["records"]:
        record_header = record["header"]
        frame = record["frame_bytes"]
        records.append(
            {
                "index": record["index"],
                "source_id": record["source_id"],
                "seq": record_header["seq"],
                "ts_us": record_header["ts_us"],
                "channel": record_header["channel"],
                "rssi": record_header["rssi"],
                "frame_len": record_header["frame_len"],
                "frame_len_ok": record["frame_len_matches_header"],
                "crc16": f"0x{record_header['crc16']:04x}",
                "truncated": bool(record_header["flags"] & 1),
                "magic_ok": record_header["magic_ok"],
                "frame": bytes_summary(frame),
            }
        )
    summary["records"] = records
    return summary

