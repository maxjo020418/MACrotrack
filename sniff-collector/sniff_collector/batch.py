from __future__ import annotations

import struct
from typing import Any

from .events import clean_c_string


BATCH_MAGIC = 0x534E5042
BATCH_VERSION = 1
BATCH_FLAG_HAS_SENDER_STATUS = 1 << 0
SENDER_STATUS_MAGIC = 0x48544C48
SNIFF_RECORD_MAGIC = 0x534E4946
SNIFFER_STATUS_MAGIC = 0x53544154

BATCH_HEADER_FORMAT = "<IHHIIIIII"
BATCH_HEADER_FIELDS = (
    "magic",
    "version",
    "header_len",
    "batch_seq",
    "record_count",
    "payload_len",
    "uptime_ms",
    "flags",
    "status_len",
)
BATCH_HEADER_SIZE = struct.calcsize(BATCH_HEADER_FORMAT)

SNIFF_RECORD_FORMAT = "<IHHIIbBHHH"
SNIFF_RECORD_FIELDS = (
    "magic",
    "version",
    "header_len",
    "seq",
    "ts_us",
    "rssi",
    "channel",
    "frame_len",
    "flags",
    "crc16",
)
SNIFF_RECORD_SIZE = struct.calcsize(SNIFF_RECORD_FORMAT)

SNIFFER_STATUS_FORMAT = "<IHHIIIIHHIIB3s"
SNIFFER_STATUS_FIELDS = (
    "magic",
    "version",
    "header_len",
    "packets_captured",
    "records_queued",
    "records_dropped",
    "spi_send_failures",
    "queue_depth",
    "max_queue_depth",
    "status_packets",
    "wifi_init_error",
    "wifi_ready",
    "reserved",
)
SNIFFER_STATUS_SIZE = struct.calcsize(SNIFFER_STATUS_FORMAT)

SENDER_STATUS_PREFIX_FORMAT = (
    "<IHHI32s"
    + ("I" * 23)
    + "i"
    + ("I" * 5)
    + "BBbBB3s"
)
SENDER_STATUS_PREFIX_FIELDS = (
    "magic",
    "version",
    "struct_len",
    "uptime_ms",
    "device_id",
    "heap_size",
    "heap_free",
    "heap_min_free",
    "heap_max_alloc",
    "upload_queue_depth",
    "upload_queue_capacity",
    "upload_queue_max_depth",
    "upload_queue_oldest_ms",
    "upload_records_queued",
    "upload_records_dropped",
    "upload_records_batched",
    "upload_batches_built",
    "upload_dry_run_batches",
    "upload_http_attempts",
    "upload_http_successes",
    "upload_http_failures",
    "upload_bytes_sent",
    "upload_bytes_dry_run",
    "upload_retry_batch_seq",
    "upload_retry_records",
    "upload_retry_bytes",
    "upload_retry_attempts",
    "upload_retry_failures",
    "upload_retry_last_code",
    "sender_records_received",
    "sender_crc_errors",
    "sender_bad_packets",
    "sender_spi_errors",
    "sender_ready_timeouts",
    "upload_enabled",
    "wifi_connected",
    "wifi_rssi",
    "upload_retry_pending",
    "sniffer_count",
    "reserved",
)
SENDER_STATUS_PREFIX_SIZE = struct.calcsize(SENDER_STATUS_PREFIX_FORMAT)

BATCH_SNIFFER_STATUS_PREFIX_FORMAT = "<HBBIIIIII"
BATCH_SNIFFER_STATUS_PREFIX_FIELDS = (
    "source_id",
    "enabled",
    "status_seen",
    "status_age_ms",
    "sender_records_received",
    "sender_crc_errors",
    "sender_bad_packets",
    "sender_spi_errors",
    "sender_ready_timeouts",
)
BATCH_SNIFFER_STATUS_SIZE = (
    struct.calcsize(BATCH_SNIFFER_STATUS_PREFIX_FORMAT) + SNIFFER_STATUS_SIZE
)

UPLOAD_RECORD_PREFIX_FORMAT = "<HH"
UPLOAD_RECORD_PREFIX_FIELDS = ("source_id", "record_len")
UPLOAD_RECORD_PREFIX_SIZE = struct.calcsize(UPLOAD_RECORD_PREFIX_FORMAT)


class PayloadParseError(ValueError):
    pass


def unpack_named(fmt: str, fields: tuple[str, ...], data: bytes, offset: int) -> dict[str, Any]:
    size = struct.calcsize(fmt)
    if offset + size > len(data):
        raise PayloadParseError(
            f"not enough bytes for {fields[0]} block at offset {offset}: "
            f"need {size}, have {len(data) - offset}"
        )
    values = struct.unpack_from(fmt, data, offset)
    return dict(zip(fields, values, strict=True))


def magic_text(value: int, byteorder: str) -> str:
    try:
        text = value.to_bytes(4, byteorder).decode("ascii")
    except UnicodeDecodeError:
        return f"0x{value:08x}"
    if not text.isprintable():
        return f"0x{value:08x}"
    return text


def add_magic_ascii(payload: dict[str, Any]) -> None:
    payload["magic_ascii_le"] = magic_text(payload["magic"], "little")
    payload["magic_ascii_be"] = magic_text(payload["magic"], "big")


def normalize_bytes_fields(payload: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(payload)
    for key, value in payload.items():
        if isinstance(value, bytes):
            if key == "device_id":
                normalized[key] = clean_c_string(value)
            else:
                normalized[key] = value.hex(" ")
    return normalized


def parse_sniffer_status(data: bytes, offset: int) -> dict[str, Any]:
    status_block = unpack_named(SNIFFER_STATUS_FORMAT, SNIFFER_STATUS_FIELDS, data, offset)
    status_block = normalize_bytes_fields(status_block)
    add_magic_ascii(status_block)
    status_block["magic_ok"] = status_block["magic"] == SNIFFER_STATUS_MAGIC
    return status_block


def parse_sender_status(data: bytes, offset: int, status_len: int) -> dict[str, Any]:
    if status_len < SENDER_STATUS_PREFIX_SIZE:
        raise PayloadParseError(
            f"sender status too short at offset {offset}: "
            f"need at least {SENDER_STATUS_PREFIX_SIZE}, have {status_len}"
        )

    status_end = offset + status_len
    if status_end > len(data):
        raise PayloadParseError(
            f"sender status exceeds body: ends at {status_end}, body has {len(data)} bytes"
        )

    sender_status = unpack_named(
        SENDER_STATUS_PREFIX_FORMAT,
        SENDER_STATUS_PREFIX_FIELDS,
        data,
        offset,
    )
    sender_status = normalize_bytes_fields(sender_status)
    add_magic_ascii(sender_status)
    sender_status["magic_ok"] = sender_status["magic"] == SENDER_STATUS_MAGIC

    sniffers = []
    sniffer_offset = offset + SENDER_STATUS_PREFIX_SIZE
    available_slots = (status_end - sniffer_offset) // BATCH_SNIFFER_STATUS_SIZE
    sniffer_count = min(sender_status.get("sniffer_count", 0), available_slots)

    for index in range(sniffer_count):
        current = sniffer_offset + index * BATCH_SNIFFER_STATUS_SIZE
        sniffer = unpack_named(
            BATCH_SNIFFER_STATUS_PREFIX_FORMAT,
            BATCH_SNIFFER_STATUS_PREFIX_FIELDS,
            data,
            current,
        )
        sniffer["last_status"] = parse_sniffer_status(
            data,
            current + struct.calcsize(BATCH_SNIFFER_STATUS_PREFIX_FORMAT),
        )
        sniffers.append(sniffer)

    sender_status["sniffers"] = sniffers
    sender_status["sniffer_slots_available"] = available_slots
    sender_status["parsed_len"] = SENDER_STATUS_PREFIX_SIZE + (
        len(sniffers) * BATCH_SNIFFER_STATUS_SIZE
    )
    return sender_status


def parse_record(data: bytes, offset: int, record_index: int) -> tuple[dict[str, Any], int]:
    prefix = unpack_named(UPLOAD_RECORD_PREFIX_FORMAT, UPLOAD_RECORD_PREFIX_FIELDS, data, offset)
    record_len = prefix["record_len"]
    record_start = offset + UPLOAD_RECORD_PREFIX_SIZE
    record_end = record_start + record_len

    if record_len < SNIFF_RECORD_SIZE:
        raise PayloadParseError(
            f"record {record_index} too short at offset {offset}: "
            f"declared {record_len}, minimum {SNIFF_RECORD_SIZE}"
        )
    if record_end > len(data):
        raise PayloadParseError(
            f"record {record_index} exceeds body: ends at {record_end}, body has {len(data)} bytes"
        )

    header = unpack_named(SNIFF_RECORD_FORMAT, SNIFF_RECORD_FIELDS, data, record_start)
    add_magic_ascii(header)
    header["magic_ok"] = header["magic"] == SNIFF_RECORD_MAGIC

    frame_offset = record_start + header["header_len"]
    if frame_offset > record_end:
        raise PayloadParseError(
            f"record {record_index} header_len exceeds record_len: "
            f"header_len={header['header_len']} record_len={record_len}"
        )

    frame = data[frame_offset:record_end]
    record = {
        "index": record_index,
        **prefix,
        "header": header,
        "frame_bytes": frame,
        "frame_len_matches_header": len(frame) == header["frame_len"],
    }
    return record, record_end


def parse_batch_payload(data: bytes) -> dict[str, Any]:
    header = unpack_named(BATCH_HEADER_FORMAT, BATCH_HEADER_FIELDS, data, 0)
    add_magic_ascii(header)
    header["magic_ok"] = header["magic"] == BATCH_MAGIC
    header["version_ok"] = header["version"] == BATCH_VERSION
    header["has_sender_status_flag"] = bool(header["flags"] & BATCH_FLAG_HAS_SENDER_STATUS)

    if header["header_len"] < BATCH_HEADER_SIZE:
        raise PayloadParseError(
            f"batch header_len too short: {header['header_len']} < {BATCH_HEADER_SIZE}"
        )
    if header["header_len"] > len(data):
        raise PayloadParseError(
            f"batch header_len exceeds body: {header['header_len']} > {len(data)}"
        )

    expected_body_len = header["header_len"] + header["payload_len"]
    payload_end = min(expected_body_len, len(data))
    offset = header["header_len"]

    parsed: dict[str, Any] = {
        "header": header,
        "expected_body_len": expected_body_len,
        "body_len_matches_header": expected_body_len == len(data),
        "records": [],
    }

    if header["status_len"]:
        parsed["sender_status"] = parse_sender_status(data, offset, header["status_len"])
        offset += header["status_len"]

    records = []
    for record_index in range(header["record_count"]):
        if offset >= payload_end:
            raise PayloadParseError(
                f"record {record_index} starts at {offset}, beyond payload end {payload_end}"
            )
        record, offset = parse_record(data[:payload_end], offset, record_index)
        records.append(record)

    parsed["records"] = records
    parsed["parsed_record_count"] = len(records)
    parsed["unparsed_payload_bytes"] = max(payload_end - offset, 0)
    parsed["trailing_body_bytes"] = max(len(data) - expected_body_len, 0)
    return parsed
