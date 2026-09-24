"""
Edge gateway - the pivot of the whole modernization.

WHAT THIS IS
    A small Linux box physically near the devices. It terminates the legacy
    device protocol on one side and talks HTTP to the cloud on the other, with
    one thread per connected device.

WHY IT EXISTS AT ALL
    Devices this constrained cannot talk to the internet safely or efficiently:
    no TLS stack, no DNS, no retry logic worth the name. A gateway does that
    work on their behalf and aggregates many devices onto one uplink.

WHY IT MATTERS FOR THIS PROJECT
    The gateway is the only component in the chain that we can actually
    upgrade. The devices cannot be re-flashed, so post-quantum key
    establishment has to terminate here:

        device  --legacy AES-PSK-->  GATEWAY  --ML-KEM + AES-GCM-->  cloud
                  (never changes)    (upgraded)

    The gateway becomes a crypto-translating proxy. The long-haul hop - the one
    an attacker can realistically record today and decrypt in twenty years -
    becomes quantum-safe, while the short local hop stays legacy and is
    documented as accepted residual risk.

WHAT IS STILL MISSING (known technical debt, tracked in README.md)
    * No store-and-forward queue: readings are lost when the cloud is down.
    * No TLS to the cloud, and a static shared token instead of real identity.
    * Replay state is in memory only, so a restart forgets every sequence
      number and briefly drops traffic from devices that keep counting.
    * No /health or /metrics endpoint of its own yet - stats are only logged.

Run:
    python -m edge_gateway.gateway --cloud-url http://127.0.0.1:8000
"""

import argparse
import logging
import socketserver
import threading
from dataclasses import dataclass, field

import requests

# Imported rather than duplicated so there is exactly one definition of the
# wire format. It does couple two separately deployable services, which is
# weakness 8 in README.md; the fix is to extract a shared package, and we have
# deliberately left it visible rather than hiding it.
from legacy_device.protocol import decrypt_frame, parse_reading

log = logging.getLogger("edge-gateway")

# Static bearer token shared with the cloud service. More legacy debt: one
# string for every gateway, no rotation, no per-gateway identity. Anyone who
# learns it can inject telemetry, which is demonstrable by hand through the
# cloud's own /docs page. ML-KEM-derived session keys are what replace it.
GATEWAY_TOKEN = "legacy-gateway-token"

# Give up on a cloud request rather than holding a device thread open forever.
CLOUD_TIMEOUT_S = 5.0

# Frame-size ceiling on the gateway side. Deliberately larger than the
# device's 256-byte buffer: the gateway is not memory-constrained, and a
# generous limit here means a misbehaving or hostile client is bounded without
# rejecting anything a legitimate device could send.
MAX_FRAME_BYTES = 4096


@dataclass
class GatewayStats:
    """Counters describing what passed through this gateway.

    These are the numbers that become Prometheus metrics in the operations
    phase. Keeping them in one object now means adding a /metrics endpoint
    later is a rendering change, not a refactor.

    Every device runs on its own thread, so all mutation goes through a lock.
    Without it, two threads incrementing the same counter can lose an update.
    """

    frames_received: int = 0
    frames_rejected: int = 0
    forwarded_ok: int = 0
    forward_failed: int = 0
    replays_dropped: int = 0

    # repr=False keeps the lock out of log lines when the dataclass is printed.
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def bump(self, name: str) -> None:
        """Increment one counter by name."""
        with self._lock:
            setattr(self, name, getattr(self, name) + 1)

    def snapshot(self) -> dict:
        """Return a consistent copy of all counters.

        Taken under the lock so a reader never sees a half-updated set, which
        would make the totals fail to add up in a report.
        """
        with self._lock:
            return {
                "frames_received": self.frames_received,
                "frames_rejected": self.frames_rejected,
                "forwarded_ok": self.forwarded_ok,
                "forward_failed": self.forward_failed,
                "replays_dropped": self.replays_dropped,
            }


class SequenceTracker:
    """Rejects frames whose sequence number has not increased.

    This is the baseline system's entire replay protection, and it is weak on
    purpose:

    * State is in memory, so a gateway restart forgets every device's
      high-water mark.
    * It is per-device and unbounded, so a hostile client can grow the dict by
      inventing device IDs.
    * It only proves ordering, not authenticity. Because frames are not
      authenticated, an attacker who can modify traffic can also rewrite the
      sequence number.

    Real authentication - AES-GCM with keys from ML-KEM - is what actually
    fixes this. We keep the tracker because it demonstrates the gap.
    """

    def __init__(self) -> None:
        self._seen: dict[str, int] = {}
        self._lock = threading.Lock()

    def accept(self, device_id: str, seq: int) -> bool:
        """Record and accept seq, or return False if it is stale.

        Returns:
            True if this sequence number is higher than anything seen from this
            device, False if it is a replay or arrives out of order.
        """
        with self._lock:
            last = self._seen.get(device_id)
            if last is not None and seq <= last:
                return False
            self._seen[device_id] = seq
            return True


class DeviceHandler(socketserver.StreamRequestHandler):
    """Handles one device connection for its whole lifetime.

    socketserver creates one instance per connection and, because the server
    below is a ThreadingTCPServer, runs each on its own thread. self.server is
    the shared GatewayServer, which is where the stats and sequence tracker
    live.
    """

    def handle(self) -> None:
        """Read newline-delimited frames until the device goes away."""
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        log.info("device connected from %s", peer)

        try:
            # Iterating over rfile yields one line per frame, which is exactly
            # the legacy framing. It blocks between readings, which is fine
            # because this thread serves only this device.
            for raw in self.rfile:
                if len(raw) > MAX_FRAME_BYTES:
                    log.warning("oversized frame from %s (%d bytes), dropping",
                                peer, len(raw))
                    self.server.stats.bump("frames_rejected")
                    continue

                self.server.stats.bump("frames_received")
                self._process(raw, peer)
        except OSError as exc:
            # A field device losing power resets the connection instead of
            # closing it cleanly. Without this handler the thread died with a
            # ConnectionResetError traceback - noise an on-call operator would
            # have to triage for a routine event. Found by failure testing, not
            # by reading the code; written up in docs/brief.html.
            log.info("device %s link reset: %s", peer, exc)
            return

        log.info("device %s disconnected", peer)

    def _process(self, raw: bytes, peer: str) -> None:
        """Decrypt, validate and forward a single frame."""
        try:
            reading = parse_reading(decrypt_frame(raw))
        except ValueError as exc:
            # This could be line noise, a truncated frame, or an active
            # tampering attempt. AES-CBC without a MAC cannot tell us which,
            # so we log the ambiguity rather than claiming to know. That
            # ambiguity is itself a finding for the report, not a bug here.
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
        """POST one reading to the cloud service.

        Sends synchronously on the device's own thread. That is acceptable at
        this scale and keeps the code readable, but it does mean a slow cloud
        slows down the device that triggered the request - worth noting as a
        scaling limit in the final evaluation.
        """
        try:
            response = requests.post(
                f"{self.server.cloud_url}/api/v1/telemetry",
                json=reading,
                headers={"X-Gateway-Token": GATEWAY_TOKEN},
                timeout=CLOUD_TIMEOUT_S,
            )
            # Covers 4xx and 5xx: a 401 from a wrong token must not be logged
            # as a success.
            response.raise_for_status()
        except requests.RequestException as exc:
            # There is no queue, so the reading is now permanently lost. We
            # count it so the loss is at least visible, and store-and-forward
            # is on the backlog.
            log.error("forward failed for %s seq=%d: %s",
                      reading["device_id"], reading["seq"], exc)
            self.server.stats.bump("forward_failed")
            return

        self.server.stats.bump("forwarded_ok")
        log.info("forwarded %s seq=%d temp=%.2f",
                 reading["device_id"], reading["seq"], reading["temp_c"])


class GatewayServer(socketserver.ThreadingTCPServer):
    """TCP server holding the state shared by all device connections."""

    # Lets the gateway restart immediately after a crash instead of waiting
    # for the kernel's TIME_WAIT to expire - important during development and
    # for fast container restarts.
    allow_reuse_address = True

    # Device threads are daemons so shutdown is not blocked by a device that
    # is idle between readings.
    daemon_threads = True

    def __init__(self, address: tuple[str, int], cloud_url: str) -> None:
        super().__init__(address, DeviceHandler)

        # rstrip so that "http://host:8000/" and "http://host:8000" both build
        # correct URLs below.
        self.cloud_url = cloud_url.rstrip("/")

        # Shared by every handler thread; both are internally locked.
        self.stats = GatewayStats()
        self.sequences = SequenceTracker()


def main() -> None:
    parser = argparse.ArgumentParser(description="Edge gateway")
    parser.add_argument("--host", default="0.0.0.0",
                        help="interface to listen on for devices")
    parser.add_argument("--port", type=int, default=9000,
                        help="TCP port devices connect to")
    parser.add_argument("--cloud-url", default="http://127.0.0.1:8000",
                        help="base URL of the cloud service")
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
        # Print the counters on the way out: during a demo this is the only
        # summary of what the run actually did.
        log.info("gateway stopping, stats=%s", server.stats.snapshot())
        server.shutdown()


if __name__ == "__main__":
    main()
