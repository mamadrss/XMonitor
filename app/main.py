"""XMonitor - Lightweight Real-Time Server Monitoring Dashboard."""

import asyncio
import json
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import (
    Cookie,
    Depends,
    FastAPI,
    HTTPException,
    Request,
    Response,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .auth import (
    authenticate,
    check_ip_whitelist,
    check_rate_limit,
    create_token,
    decode_token,
    record_attempt,
    verify_password,
)
from .collector import collect_all, collect_vnstat, get_interfaces
from .config import get_config, load_config

# ---------------------------------------------------------------------------
# History ring buffer
# ---------------------------------------------------------------------------
MAX_HISTORY = 1440  # 24h at 60s interval

_history: list[dict] = []
_ws_clients: set[WebSocket] = set()

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "static"


# ---------------------------------------------------------------------------
# Background tasks
# ---------------------------------------------------------------------------
async def _live_broadcast():
    """Collect and push metrics to all WebSocket clients every interval."""
    cfg = get_config()
    interval = cfg["monitoring"].get("collection_interval", 2)
    while True:
        try:
            snapshot = await collect_all()
            envelope = _envelope(snapshot)
            payload = json.dumps(envelope, default=str)

            dead = set()
            for ws in _ws_clients.copy():
                try:
                    await ws.send_text(payload)
                except Exception:
                    dead.add(ws)
            _ws_clients -= dead
        except Exception as e:
            print(f"[XMonitor] Broadcast error: {e}")
        await asyncio.sleep(interval)


async def _history_collector():
    """Store a metrics snapshot every history_interval for the REST API."""
    cfg = get_config()
    interval = cfg["monitoring"].get("history_collection_interval", 60)
    while True:
        try:
            snapshot = await collect_all()
            # Strip live_history to save memory
            snapshot.pop("live_history", None)
            _history.append({
                "timestamp": time.time(),
                "data": snapshot,
            })
            # Prune
            retention = cfg["monitoring"].get("history_retention_days", 30)
            max_entries = int(retention * 24 * 60)  # 1 per minute
            while len(_history) > max_entries:
                _history.pop(0)
        except Exception as e:
            print(f"[XMonitor] History collection error: {e}")
        await asyncio.sleep(interval)


@asynccontextmanager
async def lifespan(app: FastAPI):
    load_config()
    t1 = asyncio.create_task(_live_broadcast())
    t2 = asyncio.create_task(_history_collector())
    yield
    t1.cancel()
    t2.cancel()


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(title="XMonitor", version="1.0.0", lifespan=lifespan, docs_url=None, redoc_url=None)

# Static files
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


def _envelope(data, status: str = "ok") -> dict:
    cfg = get_config()
    return {
        "status": status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "server_id": cfg["master_server"].get("server_id", ""),
        "data": data,
    }


# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------
@app.post("/api/v1/auth/login")
async def login(request: Request, response: Response):
    check_ip_whitelist(request)
    client_ip = request.client.host if request.client else "unknown"
    check_rate_limit(client_ip)

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    username = body.get("username", "")
    password = body.get("password", "")

    cfg = get_config()["auth"]
    if username != cfg["username"] or not verify_password(password, cfg["password_hash"]):
        record_attempt(client_ip)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access = create_token(username, "access")
    refresh = create_token(username, "refresh")

    response = JSONResponse(content=_envelope({"message": "Login successful"}))
    response.set_cookie(
        "access_token", access,
        httponly=True, samesite="lax", max_age=900, path="/",
    )
    response.set_cookie(
        "refresh_token", refresh,
        httponly=True, samesite="lax", max_age=604800, path="/",
    )
    return response


@app.post("/api/v1/auth/refresh")
async def refresh(request: Request):
    token = request.cookies.get("refresh_token")
    if not token:
        raise HTTPException(status_code=401, detail="No refresh token")

    payload = decode_token(token)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid token type")

    access = create_token(payload["sub"], "access")
    response = JSONResponse(content=_envelope({"message": "Token refreshed"}))
    response.set_cookie(
        "access_token", access,
        httponly=True, samesite="lax", max_age=900, path="/",
    )
    return response


@app.post("/api/v1/auth/logout")
async def logout():
    response = JSONResponse(content=_envelope({"message": "Logged out"}))
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/")
    return response


# ---------------------------------------------------------------------------
# Metrics API
# ---------------------------------------------------------------------------
@app.get("/api/v1/metrics/current")
async def metrics_current(request: Request):
    authenticate(request)
    snapshot = await collect_all()
    return _envelope(snapshot)


@app.get("/api/v1/metrics/history")
async def metrics_history(request: Request, minutes: int = 60):
    authenticate(request)
    cutoff = time.time() - (minutes * 60)
    filtered = [h for h in _history if h["timestamp"] >= cutoff]
    return _envelope(filtered)


@app.get("/api/v1/metrics/vnstat")
async def metrics_vnstat(request: Request):
    authenticate(request)
    data = await collect_vnstat()
    return _envelope(data)


@app.get("/api/v1/metrics/interfaces")
async def metrics_interfaces(request: Request):
    authenticate(request)
    return _envelope({"interfaces": get_interfaces()})


# Future master-server registration (disabled by default)
@app.post("/api/v1/register")
async def register(request: Request):
    cfg = get_config()
    if not cfg["master_server"].get("enabled", False):
        raise HTTPException(status_code=404, detail="Registration not enabled")
    body = await request.json()
    return _envelope({"registered": True, "server_id": cfg["master_server"]["server_id"]})


# ---------------------------------------------------------------------------
# WebSocket
# ---------------------------------------------------------------------------
@app.websocket("/ws/metrics")
async def ws_metrics(ws: WebSocket):
    # Try cookie first, then query param
    token = ws.cookies.get("access_token") or ws.query_params.get("token")

    # Accept connection first (required for proper close handshake)
    await ws.accept()

    if not token:
        # Wait for auth message from client as last resort
        try:
            msg = await asyncio.wait_for(ws.receive_text(), timeout=5)
            data = json.loads(msg)
            token = data.get("token")
        except Exception:
            await ws.close(code=4001, reason="Not authenticated")
            return

    if not token:
        await ws.close(code=4001, reason="Not authenticated")
        return

    try:
        payload = decode_token(token)
        if payload.get("type") != "access":
            await ws.close(code=4001, reason="Invalid token")
            return
    except HTTPException:
        await ws.close(code=4001, reason="Invalid token")
        return

    # Send confirmation so client knows auth succeeded
    await ws.send_text('{"type":"auth_ok"}')

    _ws_clients.add(ws)
    try:
        while True:
            data = await ws.receive_text()
            if data == "ping":
                await ws.send_text('{"type":"pong"}')
    except WebSocketDisconnect:
        pass
    finally:
        _ws_clients.discard(ws)


# ---------------------------------------------------------------------------
# Page routes
# ---------------------------------------------------------------------------
@app.get("/login")
async def login_page():
    return FileResponse(STATIC_DIR / "login.html", media_type="text/html")


@app.get("/")
async def dashboard_page(request: Request):
    # If not authenticated, redirect to login
    token = request.cookies.get("access_token")
    if not token:
        return HTMLResponse(
            status_code=302,
            headers={"Location": "/login"},
            content="",
        )
    try:
        p = decode_token(token)
        if p.get("type") != "access":
            raise Exception()
    except Exception:
        return HTMLResponse(
            status_code=302,
            headers={"Location": "/login"},
            content="",
        )
    return FileResponse(STATIC_DIR / "dashboard.html", media_type="text/html")


# ---------------------------------------------------------------------------
# Health check (no auth)
# ---------------------------------------------------------------------------
@app.get("/api/v1/health")
async def health():
    return _envelope({"status": "healthy"})
