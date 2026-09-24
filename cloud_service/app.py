"""
Cloud telemetry service.

WHAT THIS IS
    The far end of the chain. Gateways POST readings here; operators and other
    systems read them back. FastAPI generates an interactive API console at
    /docs from the type annotations below, which is how we demonstrate the
    system without writing a UI. 

WHY IT IS SHAPED LIKE THIS
    Small on purpose. The project brief asks us to keep the system plain, and
    the interesting work is the cryptography and the operations around it, not
    the data platform.

ITS ROLE IN THE MIGRATION
    This is the side that will hold the ML-KEM key pair. A gateway will fetch
    the public key, encapsulate against it, and both ends will derive an
    AES-256-GCM session key. That replaces the static token below and also
    fixes the lack of authentication on this hop.

KNOWN TECHNICAL DEBT (tracked in README.md)
    * Storage is an in-memory deque, so every reading is lost on restart.
    * Authentication is one static shared token, with no rotation and no
      per-gateway identity.
    * Served over plain HTTP.
    * No /metrics endpoint yet; only /health.

Run:
    python -m uvicorn cloud_service.app:app --host 127.0.0.1 --port 8000
"""

import logging
import os
import threading
from collections import deque
from datetime import datetime, timezone

from fastapi import FastAPI, Header, HTTPException, status
from pydantic import BaseModel, Field

log = logging.getLogger("cloud-service")

# Must match GATEWAY_TOKEN in edge_gateway/gateway.py.
#
# Read from the environment so a deployment can override it without editing
# code, but it still defaults to a value committed to the repository - which is
# exactly the weakness we are documenting. Session keys derived from ML-KEM
# replace this entirely.
EXPECTED_TOKEN = os.environ.get("GATEWAY_TOKEN", "legacy-gateway-token")

# Ring-buffer size. Bounded so a long demo cannot exhaust memory; old readings
# are silently discarded once it is full, which is acceptable only because
# nothing here is the system of record.
MAX_STORED_READINGS = 1000

app = FastAPI(
    title="PQC Modernization - Cloud Telemetry Service",
    description="Receives sensor readings forwarded by edge gateways.",
    version="0.1.0",
)

# Module-level state. A deque with maxlen drops the oldest entry automatically
# when full, so no eviction logic is needed.
#
# Uvicorn may serve requests from multiple threads, so every access is guarded.
# deque.append is itself atomic, but read paths below copy the whole deque and
# would otherwise be able to observe a partially-updated structure.
_readings: deque[dict] = deque(maxlen=MAX_STORED_READINGS) 
_lock = threading.Lock()

# Recorded at import time so /health can report uptime.
_started_at = datetime.now(timezone.utc)


class Reading(BaseModel):
    """One sensor reading, as forwarded by a gateway.

    Pydantic validates incoming JSON against these annotations and returns a
    422 with a field-level explanation when it does not fit, so no manual
    checking is needed in the endpoint.

    The bounds are a second line of defence. The gateway already parses and
    range-limits readings, but the gateway is not the only thing that can post
    here - anyone holding the static token can - so the cloud does not trust
    its caller. Note that validation is not authentication: well-formed fake
    data still gets stored, which is the point of weakness 3 in README.md.
    """

    device_id: str = Field(min_length=1, max_length=64,
                           description="Identity claimed by the device")
    seq: int = Field(ge=0, description="Monotonic counter from the device")

    # Wider than any real indoor range: the sensor's own error range matters
    # less here than catching obvious corruption such as -273 or 1e9.
    temp_c: float = Field(ge=-50.0, le=150.0, description="Degrees Celsius")

    # Relative humidity is a percentage, so this bound is physical, not
    # heuristic.
    humidity: float = Field(ge=0.0, le=100.0, description="Percent RH")

    uptime_s: int = Field(ge=0, description="Seconds since device boot")


def _require_token(token: str | None) -> None:
    """Reject a request that does not carry the shared gateway token.

    A plain equality check. A real implementation would use a constant-time
    comparison to avoid leaking the token through response timing, and per-
    gateway credentials rather than one shared string - both noted as
    remaining risks in the technical documentation.

    Raises:
        HTTPException: 401 if the token is missing or wrong.
    """
    if token != EXPECTED_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or missing gateway token",
        )


@app.get("/health")
def health() -> dict:
    """Liveness and readiness probe.

    Deliberately unauthenticated: container orchestrators and uptime monitors
    need to reach it without credentials, and it exposes nothing sensitive.
    Returning the stored count as well as a status makes it useful during a
    demo - you can watch the number climb.
    """
    with _lock:
        stored = len(_readings)

    return {
        "status": "ok",
        "uptime_s": int(
            (datetime.now(timezone.utc) - _started_at).total_seconds()
        ),
        "stored_readings": stored,
    }


@app.post("/api/v1/telemetry", status_code=status.HTTP_202_ACCEPTED)
def ingest(reading: Reading,
           x_gateway_token: str | None = Header(default=None)) -> dict:
    """Accept one reading from a gateway.

    Returns 202 Accepted rather than 201 Created because the reading is
    recorded but nothing durable has been created - an honest status code for
    in-memory storage.

    FastAPI maps the x_gateway_token parameter to the X-Gateway-Token header
    automatically, converting underscores to hyphens.
    """
    _require_token(x_gateway_token)

    record = reading.model_dump()

    # Server-side receive time, kept separate from the device's own uptime
    # field. Device clocks cannot be trusted - many have none at all - so
    # ordering and freshness are judged by when the cloud saw the reading.
    record["received_at"] = datetime.now(timezone.utc).isoformat()

    with _lock:
        _readings.append(record)

    log.info("ingested %s seq=%d", reading.device_id, reading.seq)
    return {"accepted": True, "device_id": reading.device_id,
            "seq": reading.seq}


@app.get("/api/v1/telemetry")
def list_readings(limit: int = 20, device_id: str | None = None) -> dict:
    """Return recent readings, newest first.

    Args:
        limit: how many readings to return. Clamped rather than rejected, so a
            careless caller gets a sensible page instead of a 422.
        device_id: optional exact-match filter.
    """
    limit = max(1, min(limit, MAX_STORED_READINGS))

    # Copy under the lock, then work on the copy. Filtering while holding the
    # lock would block ingestion for no benefit.
    with _lock:
        items = list(_readings)

    if device_id:
        items = [r for r in items if r["device_id"] == device_id]

    # The deque is in arrival order, so the newest entries are at the end:
    # take the last `limit`, then reverse to present newest first.
    page = items[-limit:]
    return {"count": len(page), "readings": page[::-1]}


@app.get("/api/v1/devices")
def list_devices() -> dict:
    """Summarise every device seen since start-up.

    Computed on demand by walking the stored readings. That is fine for a
    1000-entry buffer and avoids a second data structure to keep in sync; a
    real system would maintain a device table instead.
    """
    with _lock:
        items = list(_readings)

    devices: dict[str, dict] = {}
    for reading in items:
        entry = devices.setdefault(
            reading["device_id"],
            {"device_id": reading["device_id"], "readings": 0},
        )
        entry["readings"] += 1

        # Readings are iterated in arrival order, so each assignment overwrites
        # the previous one and the last write wins - leaving the most recent
        # values without needing an explicit comparison.
        entry["last_seq"] = reading["seq"]
        entry["last_temp_c"] = reading["temp_c"]
        entry["last_humidity"] = reading["humidity"]
        entry["last_seen"] = reading["received_at"]

    return {"count": len(devices), "devices": list(devices.values())}
