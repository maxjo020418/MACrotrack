from __future__ import annotations

from typing import Any


def sanitize_text(value: str) -> str:
    return value.replace("\x00", "\\0")


def sanitize_json(value: Any) -> Any:
    if isinstance(value, str):
        return sanitize_text(value)
    if isinstance(value, list):
        return [sanitize_json(item) for item in value]
    if isinstance(value, tuple):
        return [sanitize_json(item) for item in value]
    if isinstance(value, dict):
        return {sanitize_text(str(key)): sanitize_json(item) for key, item in value.items()}
    return value
