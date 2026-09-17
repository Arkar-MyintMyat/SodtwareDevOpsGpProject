"""
Legacy wire protocol and crypto for the simulated Arduino-class device.

WARNING - this module deliberately reproduces the weaknesses of the legacy
system. It is the BASELINE we are asked to modernize, not a target design.

Known weaknesses (intentional, documented in docs/architecture.md):
  * The AES key is hardcoded in firmware and shared by every device.
  * There is NO key establishment of any kind. The key never rotates.
  * Frames are unauthenticated: AES-CBC gives confidentiality only, so a
    man-in-the-middle can tamper with ciphertext undetected.
  * Replay protection relies only on a plaintext sequence counter.
"""

import os

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Burned into the firmware image of every device in the fleet.
LEGACY_PSK = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

FIELD_SEP = "|"
FRAME_SEP = ":"

# The real constraint that drives our whole migration strategy: this class of
# device has a 256-byte serial/TCP buffer. ML-KEM-768 needs 1184 bytes for an
# encapsulation key and 1088 for a ciphertext, so post-quantum key exchange
# physically cannot run on the device itself. See docs/architecture.md.
MAX_FRAME_BYTES = 256


def encrypt_frame(plaintext: str, key: bytes = LEGACY_PSK) -> bytes:
    """Encrypt one reading into a newline-terminated ASCII frame."""
    iv = os.urandom(16)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(plaintext.encode("ascii")) + padder.finalize()

    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    frame = f"{iv.hex()}{FRAME_SEP}{ciphertext.hex()}\n".encode("ascii")
    if len(frame) > MAX_FRAME_BYTES:
        raise ValueError(
            f"frame is {len(frame)} bytes, device buffer is {MAX_FRAME_BYTES}"
        )
    return frame


def decrypt_frame(frame: bytes, key: bytes = LEGACY_PSK) -> str:
    """Reverse of encrypt_frame. Raises ValueError on a malformed frame."""
    try:
        iv_hex, ct_hex = frame.decode("ascii").strip().split(FRAME_SEP)
        iv, ciphertext = bytes.fromhex(iv_hex), bytes.fromhex(ct_hex)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError(f"malformed frame: {exc}") from exc

    if len(iv) != 16 or not ciphertext or len(ciphertext) % 16:
        raise ValueError("bad IV or ciphertext length")

    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return (unpadder.update(padded) + unpadder.finalize()).decode("ascii")


def build_reading(device_id: str, seq: int, temp_c: float, humidity: float,
                  uptime_s: int) -> str:
    """Format one sensor reading as the legacy pipe-delimited record."""
    return FIELD_SEP.join([
        "DEV", device_id, str(seq), f"{temp_c:.2f}",
        f"{humidity:.2f}", str(uptime_s),
    ])


def parse_reading(record: str) -> dict:
    """Parse a legacy record. Raises ValueError if it does not conform."""
    parts = record.split(FIELD_SEP)
    if len(parts) != 6 or parts[0] != "DEV":
        raise ValueError(f"unexpected record shape: {record!r}")

    _, device_id, seq, temp_c, humidity, uptime_s = parts
    return {
        "device_id": device_id,
        "seq": int(seq),
        "temp_c": float(temp_c),
        "humidity": float(humidity),
        "uptime_s": int(uptime_s),
    }
