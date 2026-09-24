"""
Integration tests for the ML-KEM path: the real gateway uplink against the
real cloud service.

The cloud runs in-process through FastAPI's TestClient, which the gateway's
PqcUplink accepts in place of the requests module. Every byte of the
handshake and every sealed message goes through the actual endpoint code, but
no ports or background servers are needed.
"""

import socket
import threading
import time

import pytest
from fastapi.testclient import TestClient

from cloud_service import app as cloud
from edge_gateway import gateway as gw
from legacy_device.protocol import build_reading, encrypt_frame
from pqc_channel import channel

BASE = "http://testserver"

READING = {"device_id": "dev-001", "seq": 1, "temp_c": 21.5,
           "humidity": 44.2, "uptime_s": 12}


@pytest.fixture(autouse=True)
def clean_cloud():
    """Each test starts with no readings and no sessions."""
    def reset():
        with cloud._lock:
            cloud._readings.clear()
        with cloud._sessions_lock:
            cloud._sessions.clear()
    reset()
    yield
    reset()


@pytest.fixture
def client():
    return TestClient(cloud.app)


class RecordingClient:
    """Wraps TestClient and remembers every request the gateway sends.

    Lets tests capture a sealed message and replay or tamper with it, the way
    an attacker on the network would.
    """

    def __init__(self, inner: TestClient) -> None:
        self.inner = inner
        self.posts: list[tuple[str, dict]] = []

    def get(self, url, **kwargs):
        return self.inner.get(url, **kwargs)

    def post(self, url, json=None, **kwargs):
        self.posts.append((url, json))
        return self.inner.post(url, json=json, **kwargs)


def make_uplink(client, **kwargs):
    stats = gw.GatewayStats()
    return gw.PqcUplink(BASE, stats, http=client, **kwargs), stats


def stored(client):
    return client.get("/api/v1/telemetry").json()["readings"]


# --------------------------------------------------------------------------
# Happy path
# --------------------------------------------------------------------------

def test_reading_arrives_over_the_mlkem_channel(client):
    uplink, stats = make_uplink(client)

    uplink.send(READING)

    readings = stored(client)
    assert len(readings) == 1
    assert readings[0]["device_id"] == "dev-001"
    assert readings[0]["channel"] == "mlkem"
    assert stats.snapshot()["handshakes_ok"] == 1


def test_one_handshake_serves_many_readings(client):
    """The handshake cost is paid once per session, not once per reading."""
    uplink, stats = make_uplink(client)

    for seq in range(1, 11):
        uplink.send({**READING, "seq": seq})

    assert len(stored(client)) == 10
    assert stats.snapshot()["handshakes_ok"] == 1


def test_correct_pin_is_accepted(client):
    uplink, stats = make_uplink(client,
                                pinned_fingerprint=cloud.KEM_FINGERPRINT)

    uplink.send(READING)

    assert stats.snapshot()["handshakes_ok"] == 1


def test_health_publishes_the_fingerprint_operators_pin(client):
    health = client.get("/health").json()["pqc"]
    key = client.get("/api/v2/pqc/public-key").json()

    assert health["algorithm"] == "ML-KEM-768"
    assert health["public_key_fingerprint"] == channel.fingerprint(
        channel.b64decode(key["public_key"]))


def test_no_token_is_sent_on_the_wire(client):
    """The static token never appears in any request on the ML-KEM path."""
    recorder = RecordingClient(client)
    uplink, _ = make_uplink(recorder)

    uplink.send(READING)

    for _, body in recorder.posts:
        assert gw.GATEWAY_TOKEN not in str(body)


# --------------------------------------------------------------------------
# Attacks and failures
# --------------------------------------------------------------------------

def test_wrong_pin_refuses_to_connect(client):
    """A substituted cloud key (man in the middle) is caught by the pin."""
    uplink, stats = make_uplink(client, pinned_fingerprint="0" * 64)

    with pytest.raises(gw.UplinkError, match="does not match the pinned"):
        uplink.send(READING)

    assert stats.snapshot()["handshakes_failed"] == 1
    assert stored(client) == []


class TamperingClient(RecordingClient):
    """Alters one field of the cloud's handshake reply in transit."""

    def __init__(self, inner, field_name):
        super().__init__(inner)
        self.field_name = field_name

    def post(self, url, json=None, **kwargs):
        real = super().post(url, json=json, **kwargs)
        if not url.endswith("/api/v2/pqc/session"):
            return real
        body = real.json()
        value = bytearray(channel.b64decode(body[self.field_name]))
        value[0] ^= 0x01
        body[self.field_name] = channel.b64encode(bytes(value))

        class _Resp:
            status_code = real.status_code

            def json(self):
                return body
        return _Resp()


@pytest.mark.parametrize("field_name", ["confirmation", "ephemeral_ciphertext"])
def test_tampered_handshake_reply_fails_confirmation(client, field_name):
    """The gateway must not trust a session it cannot confirm.

    Added after mutation testing showed that disabling the confirmation check
    left every other test passing: a tampered reply was only caught later,
    when the first reading bounced. This asserts the handshake itself fails.
    """
    uplink, stats = make_uplink(TamperingClient(client, field_name))

    with pytest.raises(gw.UplinkError, match="confirmation failed"):
        uplink.send(READING)

    assert stats.snapshot()["handshakes_failed"] == 1
    assert stats.snapshot()["handshakes_ok"] == 0


def test_wrong_gateway_token_is_rejected(client):
    uplink, stats = make_uplink(client, token="not-the-token")

    with pytest.raises(gw.UplinkError, match="HTTP 401"):
        uplink.send(READING)

    assert stats.snapshot()["handshakes_failed"] == 1
    assert stored(client) == []


def test_replayed_message_is_rejected(client):
    """Capturing and resending a sealed reading does not duplicate it."""
    recorder = RecordingClient(client)
    uplink, _ = make_uplink(recorder)
    uplink.send(READING)
    url, captured = recorder.posts[-1]

    response = client.post(url, json=captured)

    assert response.status_code == 409
    assert len(stored(client)) == 1


def test_tampered_message_is_rejected(client):
    """The counterpart of the legacy IV-tampering finding, now closed."""
    recorder = RecordingClient(client)
    uplink, _ = make_uplink(recorder)
    uplink.send(READING)
    url, captured = recorder.posts[-1]

    sealed = bytearray(channel.b64decode(captured["ciphertext"]))
    sealed[8] ^= 0x09
    forged = {**captured, "ciphertext": channel.b64encode(bytes(sealed)),
              # A fresh counter, so the rejection is due to tampering and not
              # to replay detection.
              "nonce": channel.b64encode(channel.nonce_for(999))}

    response = client.post(url, json=forged)

    assert response.status_code == 400
    assert len(stored(client)) == 1, "only the genuine reading"


def test_unknown_session_is_rejected(client):
    response = client.post("/api/v2/telemetry", json={
        "session_id": "f" * 32,
        "nonce": channel.b64encode(channel.nonce_for(0)),
        "ciphertext": channel.b64encode(b"x" * 40),
    })

    assert response.status_code == 401


def test_gateway_recovers_when_the_cloud_forgets_its_session(client):
    """A cloud restart wipes sessions; the gateway re-handshakes by itself."""
    uplink, stats = make_uplink(client)
    uplink.send({**READING, "seq": 1})

    with cloud._sessions_lock:
        cloud._sessions.clear()
    uplink.send({**READING, "seq": 2})

    assert [r["seq"] for r in stored(client)] == [2, 1]
    assert stats.snapshot()["handshakes_ok"] == 2


def test_session_is_renewed_after_it_expires(client, monkeypatch):
    uplink, stats = make_uplink(client)
    uplink.send({**READING, "seq": 1})

    # Push the gateway's clock past the session deadline.
    real = time.monotonic
    monkeypatch.setattr(gw.time, "monotonic", lambda: real() + 10_000)
    uplink.send({**READING, "seq": 2})

    assert stats.snapshot()["handshakes_ok"] == 2


def test_malformed_handshake_is_rejected_cleanly(client):
    response = client.post("/api/v2/pqc/session", json={
        "static_ciphertext": "AAAA",
        "ephemeral_public_key": "AAAA",
        "gateway_proof": "AAAA",
    })

    assert response.status_code == 400


def test_legacy_ingest_can_be_switched_off(client, monkeypatch):
    """The end state of the migration: only the ML-KEM path is accepted."""
    monkeypatch.setattr(cloud, "LEGACY_INGEST_ENABLED", False)

    legacy = client.post("/api/v1/telemetry", json=READING,
                         headers={"X-Gateway-Token": cloud.EXPECTED_TOKEN})
    uplink, _ = make_uplink(client)
    uplink.send(READING)

    assert legacy.status_code == 410
    assert [r["channel"] for r in stored(client)] == ["mlkem"]


@pytest.mark.security
def test_finding_unpinned_gateway_trusts_the_first_key_it_sees(client):
    """Residual risk: trust on first use without --cloud-key-fingerprint.

    Here an attacker answers the very first public-key request with their own
    key. An unpinned gateway accepts it and pins the attacker's fingerprint,
    so from then on it would hand its readings to the attacker. The
    handshake with the real cloud then fails (the attacker's key does not
    match the cloud's private key), which limits the damage in this setup -
    but a full impostor cloud would succeed. Pinning closes this.
    """
    attacker_pk, _ = channel.generate_keypair()

    class Impostor(RecordingClient):
        def get(self, url, **kwargs):
            real = self.inner.get(url, **kwargs)
            body = {**real.json(),
                    "public_key": channel.b64encode(attacker_pk)}

            class _Resp:
                status_code = 200

                def json(self):
                    return body
            return _Resp()

    uplink, _ = make_uplink(Impostor(client))

    with pytest.raises(gw.UplinkError):
        uplink.send(READING)

    assert uplink.pinned == channel.fingerprint(attacker_pk)


# --------------------------------------------------------------------------
# Full chain: device frame -> gateway -> ML-KEM -> cloud
# --------------------------------------------------------------------------

def test_device_frame_reaches_the_cloud_over_mlkem(client):
    """The whole migrated system: the device is untouched, the long hop is PQC."""
    stats = gw.GatewayStats()
    uplink = gw.PqcUplink(BASE, stats, http=client,
                          pinned_fingerprint=cloud.KEM_FINGERPRINT)
    server = gw.GatewayServer(("127.0.0.1", 0), uplink, stats)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
            for seq in (1, 2, 3):
                sock.sendall(encrypt_frame(
                    build_reading("dev-001", seq, 21.5, 44.2, seq)))
            sock.shutdown(socket.SHUT_WR)
            sock.recv(1)

        deadline = time.monotonic() + 10
        while (stats.snapshot()["forwarded_ok"] < 3
               and time.monotonic() < deadline):
            time.sleep(0.01)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    readings = stored(client)
    assert sorted(r["seq"] for r in readings) == [1, 2, 3]
    assert {r["channel"] for r in readings} == {"mlkem"}
    assert stats.snapshot()["handshakes_ok"] == 1
