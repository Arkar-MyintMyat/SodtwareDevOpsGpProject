"""
Cloud telemetry service.

Receives readings forwarded by edge gateways and keeps the most recent ones
in memory. Storage is deliberately simple for the baseline; persistence is
listed as known technical debt.

Run:
    uvicorn cloud_service.app:app --port 8000
"""

import logging
import os
import threading
from collections import deque
from datetime import datetime, timezone

from fastapi import FastAPI, Header, HTTPException, status
from pydantic import BaseModel, Field

log = logging.getLogger("cloud-service")

# Must match GATEWAY_TOKEN in edge_gateway/gateway.py. Static shared secret,
# no rotation - part of the legacy baseline we are asked to improve.
EXPECTED_TOKEN = os.environ.get("GATEWAY_TOKEN", "legacy-gateway-token")

MAX_STORED_READINGS = 1000

app = FastAPI(
    title="PQC Modernization - Cloud Telemetry Service",
    version="0.1.0",
)

_readings: deque[dict] = deque(maxlen=MAX_STORED_READINGS)
_lock = threading.Lock()
_started_at = datetime.now(timezone.utc)


class Reading(BaseModel):
    """One sensor reading as forwarded by a gateway."""

    device_id: str = Field(min_length=1, max_length=64)
    seq: int = Field(ge=0)
    temp_c: float = Field(ge=-50.0, le=150.0)
    humidity: float = Field(ge=0.0, le=100.0)
    uptime_s: int = Field(ge=0)


def _require_token(token: str | None) -> None:
    if token != EXPECTED_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or missing gateway token",
        )


@app.get("/health")
def health() -> dict:
    """Liveness and readiness probe."""
    with _lock:
        stored = len(_readings)
    return {
        "status": "ok",
        "uptime_s": int((datetime.now(timezone.utc) - _started_at)
                        .total_seconds()),
        "stored_readings": stored,
    }


@app.post("/api/v1/telemetry", status_code=status.HTTP_202_ACCEPTED)
def ingest(reading: Reading,
           x_gateway_token: str | None = Header(default=None)) -> dict:
    """Accept one reading from a gateway."""
    _require_token(x_gateway_token)

    record = reading.model_dump()
    record["received_at"] = datetime.now(timezone.utc).isoformat()

    with _lock:
        _readings.append(record)

    log.info("ingested %s seq=%d", reading.device_id, reading.seq)
    return {"accepted": True, "device_id": reading.device_id,
            "seq": reading.seq}


@app.get("/api/v1/telemetry")
def list_readings(limit: int = 20, device_id: str | None = None) -> dict:
    """Most recent readings first, optionally filtered by device."""
    limit = max(1, min(limit, MAX_STORED_READINGS))

    with _lock:
        items = list(_readings)

    if device_id:
        items = [r for r in items if r["device_id"] == device_id]

    return {"count": len(items[-limit:]), "readings": items[-limit:][::-1]}


@app.get("/api/v1/devices")
def list_devices() -> dict:
    """Summary of every device seen since start-up."""
    with _lock:
        items = list(_readings)

    devices: dict[str, dict] = {}
    for reading in items:
        entry = devices.setdefault(
            reading["device_id"], {"device_id": reading["device_id"],
                                   "readings": 0}
        )
        entry["readings"] += 1
        entry["last_seq"] = reading["seq"]
        entry["last_temp_c"] = reading["temp_c"]
        entry["last_seen"] = reading["received_at"]

    return {"count": len(devices), "devices": list(devices.values())}
