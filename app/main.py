"""RPKI 路由起源核对 Web 应用。

两个 Web 进程（docker compose 中的 web-a / web-b）打开同一个位于
共享卷上的 SQLite 文件，同步状态与授权数据持久共享。
"""

from __future__ import annotations

import os
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from app.storage import RPKIStore, VersionInfo
from app.sync import SyncManager
from app.validator import ValidationInputError, evaluate

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

# 固定的可信 RTR 源（手动同步的唯一目标，不接受页面指定其他源）。
RTR_HOST = os.environ.get("RTR_HOST", "rtr-source")
RTR_PORT = int(os.environ.get("RTR_PORT", "8210"))


def _default_db_path() -> str:
    for candidate in ("/data/rpki.db", str(BASE_DIR.parent / "data" / "rpki.db")):
        parent = Path(candidate).parent
        try:
            parent.mkdir(parents=True, exist_ok=True)
            probe = parent / ".write-probe"
            probe.touch()
            probe.unlink()
            return candidate
        except OSError:
            continue
    return str(BASE_DIR.parent / "data" / "rpki.db")


DB_PATH = os.environ.get("RPKI_DB_PATH", _default_db_path())

store = RPKIStore(DB_PATH)
sync_manager = SyncManager(store, RTR_HOST, RTR_PORT)

app = FastAPI(
    title="BGP 路由起源 RPKI 核对",
    description="通过固定可信 RTR 源（RFC 8210 v1 Reset Query）同步 IPv4 授权并核对前缀/ASN。",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
    openapi_url="/api/openapi.json",
)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; base-uri 'none'; "
        "form-action 'self'; frame-ancestors 'none'"
    )
    return response


def _version_payload(version: VersionInfo | None, now: float) -> dict | None:
    if version is None:
        return None
    return {
        "version_id": version.version_id,
        "session_id": version.session_id,
        "serial": version.serial,
        "expire_interval": version.expire_interval,
        "synced_at": version.synced_at,
        "expires_at": version.expires_at,
        "roa_count": version.roa_count,
        "expired": version.is_expired(now),
    }


@app.get("/", include_in_schema=False)
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/healthz", include_in_schema=False)
async def healthz() -> dict:
    return {"status": "ok"}


@app.get("/api/status", summary="同步状态与当前数据版本")
async def status() -> dict:
    now = time.time()
    version = store.current_version()
    payload = _version_payload(version, now)
    usable = payload is not None and not payload["expired"]
    return {
        "rtr_source": {"host": RTR_HOST, "port": RTR_PORT},
        "sync": sync_manager.status.snapshot(),
        "version": payload,
        "query_available": usable,
        "message": (
            "可以核对"
            if usable
            else ("当前授权已过期，无法核对"
                  if payload is not None
                  else "尚未同步授权数据，无法核对")
        ),
    }


@app.post("/api/sync", summary="手动触发 RTR 全量同步（后台执行）")
async def trigger_sync() -> dict:
    if not sync_manager.start_sync():
        raise HTTPException(
            status_code=409,
            detail={"code": "sync_in_progress", "message": "已有同步在进行中"},
        )
    return {"started": True, "message": "同步已在后台开始，查询不受影响"}


class ValidateRequest(BaseModel):
    prefix: str
    asn: str | int


@app.post("/api/validate", summary="核对 IPv4 前缀与起源 ASN")
async def validate(request: ValidateRequest) -> dict:
    now = time.time()
    version = store.current_version()
    if version is None:
        return {
            "available": False,
            "state": "Unavailable",
            "message": "尚未同步授权数据，无法核对，请先执行同步",
        }
    if version.is_expired(now):
        return {
            "available": False,
            "state": "Unavailable",
            "message": "当前授权版本已过期，无法核对，请重新同步",
            "version": _version_payload(version, now),
        }

    try:
        roas = store.load_roas(version.version_id)
        result = evaluate(request.prefix, request.asn, roas, version)
    except ValidationInputError as exc:
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_input", "message": str(exc)},
        ) from exc

    return {
        "available": True,
        "state": result.state,
        "prefix": result.prefix,
        "asn": result.asn,
        "reason": result.reason,
        "covering": [
            {
                "prefix": item.prefix,
                "asn": item.asn,
                "max_length": item.max_length,
                "asn_matches": item.asn_matches,
                "length_allowed": item.length_allowed,
            }
            for item in result.covering
        ],
        "version": {
            "version_id": result.version_id,
            "session_id": result.session_id,
            "serial": result.serial,
            "expires_at": result.expires_at,
        },
    }
