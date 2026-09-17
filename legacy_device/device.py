"""
Simulated legacy edge device (Arduino-class sensor node).

Models a constrained microcontroller that cannot be re-flashed in the field:
it holds one hardcoded pre-shared key, performs no key establishment, and
speaks a minimal newline-delimited frame protocol over a raw TCP socket.

Run:
    python -m legacy_device.device --device-id dev-001
"""

import argparse
import logging
import random
import socket
import time

from legacy_device.protocol import build_reading, encrypt_frame

log = logging.getLogger("legacy-device")

RECONNECT_DELAY_S = 5.0


class SensorSimulator:
    """A slow random walk, so readings look like a real environment sensor."""

    def __init__(self, temp_c: float = 21.0, humidity: float = 45.0) -> None:
        self.temp_c = temp_c
        self.humidity = humidity

    def read(self) -> tuple[float, float]:
        self.temp_c = round(
            min(35.0, max(5.0, self.temp_c + random.uniform(-0.3, 0.3))), 2
        )
        self.humidity = round(
            min(95.0, max(10.0, self.humidity + random.uniform(-0.8, 0.8))), 2
        )
        return self.temp_c, self.humidity


class LegacyDevice:
    def __init__(self, device_id: str, host: str, port: int,
                 interval_s: float) -> None:
        self.device_id = device_id
        self.host = host
        self.port = port
        self.interval_s = interval_s
        self.sensor = SensorSimulator()
        self.seq = 0
        self.booted_at = time.monotonic()

    def _uptime_s(self) -> int:
        return int(time.monotonic() - self.booted_at)

    def _send_forever(self, sock: socket.socket) -> None:
        """Send readings until the socket breaks."""
        while True:
            temp_c, humidity = self.sensor.read()
            self.seq += 1

            record = build_reading(
                self.device_id, self.seq, temp_c, humidity, self._uptime_s()
            )
            sock.sendall(encrypt_frame(record))
            log.info("sent seq=%d temp=%.2f humidity=%.2f",
                     self.seq, temp_c, humidity)

            time.sleep(self.interval_s)

    def run(self) -> None:
        """Connect to the gateway, retrying forever - devices never give up."""
        log.info("device %s starting, target %s:%d",
                 self.device_id, self.host, self.port)
        while True:
            try:
                with socket.create_connection((self.host, self.port),
                                              timeout=10) as sock:
                    log.info("connected to gateway")
                    self._send_forever(sock)
            except OSError as exc:
                log.warning("link down (%s), retrying in %.0fs",
                            exc, RECONNECT_DELAY_S)
                time.sleep(RECONNECT_DELAY_S)


def main() -> None:
    parser = argparse.ArgumentParser(description="Simulated legacy device")
    parser.add_argument("--device-id", default="dev-001")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--interval", type=float, default=2.0,
                        help="seconds between readings")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    try:
        LegacyDevice(args.device_id, args.host, args.port, args.interval).run()
    except KeyboardInterrupt:
        log.info("device stopped")


if __name__ == "__main__":
    main()
