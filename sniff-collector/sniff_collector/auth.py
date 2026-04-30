from __future__ import annotations

import base64
import secrets

from fastapi import HTTPException, Request, status

from .config import settings


SENSITIVE_HEADERS = {"authorization", "x-api-token", "cookie", "set-cookie"}


def sanitize_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        key: ("<redacted>" if key.lower() in SENSITIVE_HEADERS else value)
        for key, value in headers.items()
    }


def token_from_basic_auth(encoded: str) -> str | None:
    try:
        decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None

    username, separator, password = decoded.partition(":")
    if not separator:
        return username
    return password or username


def request_token(request: Request) -> str | None:
    x_api_token = request.headers.get("x-api-token")
    if x_api_token:
        return x_api_token.strip()

    authorization = request.headers.get("authorization", "")
    scheme, separator, credential = authorization.partition(" ")
    if not separator:
        return None

    scheme = scheme.lower()
    credential = credential.strip()
    if scheme in {"bearer", "token"}:
        return credential
    if scheme == "basic":
        return token_from_basic_auth(credential)
    return None


def require_auth(request: Request) -> None:
    if not settings.auth_required:
        return
    valid_tokens = settings.valid_api_tokens
    if not valid_tokens:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="COLLECTOR_API_TOKENS is not configured",
        )

    token = request_token(request)
    if token and any(secrets.compare_digest(token, valid) for valid in valid_tokens):
        return

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="invalid or missing API token",
        headers={"WWW-Authenticate": "Bearer"},
    )

