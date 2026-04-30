from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import select, update

from .models import sniffer_clock_state


RX_TS_WRAP = 1 << 32
RX_TS_HALF_WRAP = 1 << 31


def unwrap_rx_timestamp(conn: Any, sender_id: int, source_id: int, rx_ts_us_32: int, now: datetime) -> int:
    row = (
        conn.execute(
            select(sniffer_clock_state)
            .where(
                sniffer_clock_state.c.sender_id == sender_id,
                sniffer_clock_state.c.source_id == source_id,
            )
            .with_for_update()
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        conn.execute(
            sniffer_clock_state.insert().values(
                sender_id=sender_id,
                source_id=source_id,
                last_rx_ts_us_32=rx_ts_us_32,
                wrap_count=0,
                updated_at=now,
            )
        )
        return rx_ts_us_32

    wrap_count = int(row["wrap_count"])
    last_rx = int(row["last_rx_ts_us_32"])
    if rx_ts_us_32 < last_rx and (last_rx - rx_ts_us_32) > RX_TS_HALF_WRAP:
        wrap_count += 1

    unwrapped = (wrap_count * RX_TS_WRAP) + rx_ts_us_32
    previous_unwrapped = (int(row["wrap_count"]) * RX_TS_WRAP) + last_rx
    if unwrapped >= previous_unwrapped:
        conn.execute(
            update(sniffer_clock_state)
            .where(
                sniffer_clock_state.c.sender_id == sender_id,
                sniffer_clock_state.c.source_id == source_id,
            )
            .values(
                last_rx_ts_us_32=rx_ts_us_32,
                wrap_count=wrap_count,
                updated_at=now,
            )
        )
    return unwrapped

