"""
Edge gateway.

Terminates the legacy device protocol on one side and talks to the cloud
service over HTTP on the other. Every device connection is handled in its
own thread.

This component is the pivot of the whole modernization: because the legacy
devices cannot be upgraded, the gateway is where post-quantum key
establishment will eventually be introduced (gateway <-> cloud), while the
device <-> gateway hop stays on the legacy pre-shared key.

Run:
    python -m edge_gateway.gateway
"""

import argparse
import logging
import socketserver
import threading
from dataclasses import dataclass, field

import requests

from legacy_device.protocol import decrypt_frame, parse_reading

log = logging.getLogger("edge-gateway")

# Static bearer token shared with the cloud service. Another piece of legacy
# debt: no rotation, no per-gateway identity. Documented in docs/architecture.md.
GATEWAY_TOKEN = "legacy-gateway-token"

CLOUD_TIMEOUT_S = 5.0
MAX_FRAME_BYTES = 4096


@dataclass
class GatewayStats:
    """Counters for the readings that pass through this gateway."""

    frames_received: int = 0
    frames_rejected: int = 0
    forwarded_ok: int = 0
    forward_failed: int = 0
    replays_dropped: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def bump(self, name: str) -> None:
        with self._lock:
            setattr(self, name, getattr(self, name) + 1)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "frames_received": self.frames_received,
                "frames_rejected": self.frames_rejected,
                "forwarded_ok": self.forwarded_ok,
                "forward_failed": self.forward_failed,
                "replays_dropped": self.replays_dropped,
            }


class SequenceTracker:
    """Rejects non-increasing sequence numbers - crude replay protection."""

    def __init__(self) -> None:
        self._seen: dict[str, int] = {}
        self._lock = threading.Lock()

    def accept(self, device_id: str, seq: int) -> bool:
        with self._lock:
            last = self._seen.get(device_id)
            if last is not None and seq <= last:
                return False
            self._seen[device_id] = seq
            return True


class DeviceHandler(socketserver.StreamRequestHandler):
    """Reads newline-delimited legacy frames from one device connection."""

    def handle(self) -> None:
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        log.info("device connected from %s", peer)

        try:
            for raw in self.rfile:
                if len(raw) > MAX_FRAME_BYTES:
                    log.warning("oversized frame from %s, dropping", peer)
                    self.server.stats.bump("frames_rejected")
                    continue

                self.server.stats.bump("frames_received")
                self._process(raw, peer)
        except OSError as exc:
            # A field device losing power resets the connection rather than
            # closing it. Without this the handler thread dies with a
            # traceback, which is noise an operator would have to triage.
            log.info("device %s link reset: %s", peer, exc)
            return

        log.info("device %s disconnected", peer)

    def _process(self, raw: bytes, peer: str) -> None:
        try:
            reading = parse_reading(decrypt_frame(raw))
        except ValueError as exc:
            # Could be corruption, or a tampering attempt - AES-CBC without a
            # MAC cannot tell us which. That ambiguity is a finding, not a bug.
            log.warning("undecodable frame from %s: %s", peer, exc)
            self.server.stats.bump("frames_rejected")
            return

        if not self.server.sequences.accept(reading["device_id"],
                                            reading["seq"]):
            log.warning("replayed or stale seq=%d from %s",
                        reading["seq"], reading["device_id"])
            self.server.stats.bump("replays_dropped")
            return

        self._forward(reading)

    def _forward(self, reading: dict) -> None:
        try:
            response = requests.post(
                f"{self.server.cloud_url}/api/v1/telemetry",
                json=reading,
                headers={"X-Gateway-Token": GATEWAY_TOKEN},
                timeout=CLOUD_TIMEOUT_S,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            # No store-and-forward queue yet: readings are lost if the cloud
            # is unreachable. Logged as known technical debt.
            log.error("forward failed for %s seq=%d: %s",
                      reading["device_id"], reading["seq"], exc)
            self.server.stats.bump("forward_failed")
            return

        self.server.stats.bump("forwarded_ok")
        log.info("forwarded %s seq=%d temp=%.2f",
                 reading["device_id"], reading["seq"], reading["temp_c"])


class GatewayServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address: tuple[str, int], cloud_url: str) -> None:
        super().__init__(address, DeviceHandler)
        self.cloud_url = cloud_url.rstrip("/")
        self.stats = GatewayStats()
        self.sequences = SequenceTracker()


def main() -> None:
    parser = argparse.ArgumentParser(description="Edge gateway")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--cloud-url", default="http://127.0.0.1:8000")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    server = GatewayServer((args.host, args.port), args.cloud_url)
    log.info("gateway listening on %s:%d, cloud at %s",
             args.host, args.port, server.cloud_url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("gateway stopping, stats=%s", server.stats.snapshot())
        server.shutdown()


if __name__ == "__main__":
    main()
