from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, status

from .auth import require_auth, sanitize_headers
from .batch import PayloadParseError, parse_batch_payload
from .config import settings
from .database import database_health, init_database
from .events import print_event
from .storage import persist_batch
from .summary import packet_summary


app = FastAPI(title=settings.app_name)


@app.on_event("startup")
def startup() -> None:
    init_database()


@app.get("/")
def root() -> dict[str, Any]:
    return {
        "service": settings.app_name,
        "endpoints": {
            "health": "/health",
            "batch": "/api/sniff/batch",
        },
    }


@app.get("/health")
def health() -> dict[str, Any]:
    db = database_health()
    return {
        "ok": db.get("ok") is not False,
        "auth_required": settings.auth_required,
        "auth_configured": bool(settings.valid_api_tokens),
        "max_body_bytes": settings.max_body_bytes,
        "database": db,
    }


@app.post("/api/sniff/batch")
async def receive_sniff_batch(
    request: Request,
    _: None = Depends(require_auth),
) -> dict[str, Any]:
    body = await request.body()
    if len(body) > settings.max_body_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"body is {len(body)} bytes; max is {settings.max_body_bytes}",
        )

    try:
        parsed = parse_batch_payload(body)
        parse_error = None
    except PayloadParseError as exc:
        parsed = None
        parse_error = str(exc)

    request_meta = {
        "client_host": request.client.host if request.client else None,
        "content_type": request.headers.get("content-type"),
        "device_id_header": request.headers.get("x-device-id"),
    }
    storage = persist_batch(request_meta, body, parsed, parse_error)
    summary = packet_summary(request, body, parsed, parse_error, storage)

    if settings.log_headers:
        summary["headers"] = sanitize_headers(dict(request.headers))
    print_event("sniff_batch_received", summary)

    return {
        "ok": True,
        "bytes_received": len(body),
        "parsed": parsed is not None,
        "parse_error": parse_error,
        "summary": summary,
    }


def main() -> None:
    import uvicorn

    uvicorn.run(app, host=settings.host, port=settings.port, log_level=settings.log_level)

