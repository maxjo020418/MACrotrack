from __future__ import annotations

import struct
from typing import Any


MGMT_SUBTYPES = {
    0: "Association Request",
    1: "Association Response",
    2: "Reassociation Request",
    3: "Reassociation Response",
    4: "Probe Request",
    5: "Probe Response",
    8: "Beacon",
    9: "ATIM",
    10: "Disassociation",
    11: "Authentication",
    12: "Deauthentication",
    13: "Action",
    14: "Action No Ack",
}

AP_ORIGINATED_SUBTYPES = {1, 3, 5, 8}
STATION_REQUEST_SUBTYPES = {0, 2, 4}
CONTROL_EXCHANGE_SUBTYPES = {10, 11, 12, 13, 14}

IE_OFFSETS = {
    0: 28,
    1: 30,
    2: 34,
    3: 30,
    4: 24,
    5: 36,
    8: 36,
    10: 26,
    11: 30,
    12: 26,
}


def is_multicast_mac(mac: bytes | None) -> bool:
    return bool(mac and (mac[0] & 0x01))


def is_local_admin_mac(mac: bytes | None) -> bool:
    return bool(mac and (mac[0] & 0x02))


def is_zero_mac(mac: bytes | None) -> bool:
    return mac == b"\x00\x00\x00\x00\x00\x00"


def mac_text(mac: bytes) -> str:
    return ":".join(f"{part:02x}" for part in mac)


def parse_tagged_ies(frame: bytes, offset: int) -> dict[str, Any]:
    ie_ids: list[int] = []
    vendor_ouis: list[bytes] = []
    ssid: bytes | None = None
    truncated = False

    while offset + 2 <= len(frame):
        ie_id = frame[offset]
        ie_len = frame[offset + 1]
        payload_start = offset + 2
        payload_end = payload_start + ie_len
        if payload_end > len(frame):
            truncated = True
            break

        payload = frame[payload_start:payload_end]
        ie_ids.append(ie_id)
        if ie_id == 0 and ssid is None:
            ssid = payload
        if ie_id == 221 and len(payload) >= 3:
            vendor_ouis.append(payload[:3])
        offset = payload_end

    if offset != len(frame):
        truncated = True

    return {
        "ie_ids": ie_ids,
        "vendor_ouis": vendor_ouis,
        "ssid": ssid,
        "ssid_len": len(ssid) if ssid is not None else None,
        "ssid_is_wildcard": ssid == b"" if ssid is not None else None,
        "ies_truncated": truncated,
    }


def parse_fixed_fields(frame: bytes, subtype: int) -> dict[str, Any]:
    fixed: dict[str, Any] = {}
    if subtype in {5, 8} and len(frame) >= 36:
        timestamp, beacon_interval, capabilities = struct.unpack_from("<QHH", frame, 24)
        fixed.update(
            {
                "timestamp": timestamp,
                "beacon_interval": beacon_interval,
                "capabilities": capabilities,
            }
        )
    elif subtype == 0 and len(frame) >= 28:
        capabilities, listen_interval = struct.unpack_from("<HH", frame, 24)
        fixed.update({"capabilities": capabilities, "listen_interval": listen_interval})
    elif subtype == 2 and len(frame) >= 34:
        capabilities, listen_interval = struct.unpack_from("<HH", frame, 24)
        fixed.update(
            {
                "capabilities": capabilities,
                "listen_interval": listen_interval,
                "current_ap": mac_text(frame[28:34]),
            }
        )
    elif subtype in {1, 3} and len(frame) >= 30:
        capabilities, status_code, aid = struct.unpack_from("<HHH", frame, 24)
        fixed.update({"capabilities": capabilities, "status_code": status_code, "aid": aid})
    elif subtype == 11 and len(frame) >= 30:
        algorithm, auth_seq, status_code = struct.unpack_from("<HHH", frame, 24)
        fixed.update(
            {
                "auth_algorithm": algorithm,
                "auth_sequence": auth_seq,
                "status_code": status_code,
            }
        )
    elif subtype in {10, 12} and len(frame) >= 26:
        (reason_code,) = struct.unpack_from("<H", frame, 24)
        fixed["reason_code"] = reason_code
    elif subtype in {13, 14} and len(frame) >= 25:
        fixed["category"] = frame[24]
        if len(frame) >= 26:
            fixed["action"] = frame[25]
    return fixed


def parse_management_frame(frame: bytes) -> dict[str, Any]:
    parsed: dict[str, Any] = {
        "parse_ok": False,
        "parse_error": None,
        "addr1": None,
        "addr2": None,
        "addr3": None,
        "ssid": None,
        "ssid_len": None,
        "ssid_is_wildcard": None,
        "ie_ids": [],
        "vendor_ouis": [],
        "fixed_fields": {},
    }

    if len(frame) < 24:
        parsed["parse_error"] = f"management frame too short: {len(frame)} < 24"
        return parsed

    frame_control, duration_id = struct.unpack_from("<HH", frame, 0)
    frame_type = (frame_control >> 2) & 0b11
    subtype = (frame_control >> 4) & 0b1111
    sequence_control = struct.unpack_from("<H", frame, 22)[0]

    parsed.update(
        {
            "frame_control": frame_control,
            "frame_type": frame_type,
            "mgmt_subtype": subtype,
            "mgmt_subtype_name": MGMT_SUBTYPES.get(subtype, f"Management subtype {subtype}"),
            "duration_id": duration_id,
            "seq_num": sequence_control >> 4,
            "frag_num": sequence_control & 0x0F,
            "retry": bool(frame_control & (1 << 11)),
            "protected": bool(frame_control & (1 << 14)),
            "addr1": frame[4:10],
            "addr2": frame[10:16],
            "addr3": frame[16:22],
        }
    )

    if frame_type != 0:
        parsed["parse_error"] = f"not a management frame: type={frame_type}"
        return parsed

    fixed_fields = parse_fixed_fields(frame, subtype)
    ie_offset = IE_OFFSETS.get(subtype)
    if ie_offset is not None:
        if len(frame) < ie_offset:
            parsed["parse_error"] = (
                f"frame too short for {parsed['mgmt_subtype_name']} fixed fields: "
                f"{len(frame)} < {ie_offset}"
            )
            parsed["fixed_fields"] = fixed_fields
            return parsed
        ies = parse_tagged_ies(frame, ie_offset)
        parsed.update(ies)

    parsed["fixed_fields"] = fixed_fields
    parsed["parse_ok"] = True
    return parsed

