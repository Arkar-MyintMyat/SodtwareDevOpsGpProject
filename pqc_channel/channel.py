"""
Post-quantum secure channel for the gateway <-> cloud hop.

WHAT THIS IS
    The cryptography shared by the edge gateway and the cloud service: an
    ML-KEM-768 handshake that produces a fresh AES-256-GCM session key, and
    the functions that seal and open messages under that key. Both services
    import this one module, so there is exactly one definition of the
    handshake and the message format.

    This is a separate package on purpose. The legacy wire format lives in
    legacy_device/ and the gateway imports it from there, which couples two
    deployable services (weakness 8 in README.md). New shared code does not
    repeat that pattern.

THE HANDSHAKE (one round trip after the public key is known)

    gateway                                             cloud
    -------                                             -----
                                                        long-term (ek_c, dk_c)
    GET  /api/v2/pqc/public-key   <---------------      ek_c
    check fingerprint(ek_c) against the pinned value
    ss1, ct1 = Encaps(ek_c)
    ek_g, dk_g = KeyGen()          (ephemeral, this session only)
    proof = HMAC(gateway_token, ct1 || ek_g)
    POST /api/v2/pqc/session  --- ct1, ek_g, proof -->
                                                        check proof
                                                        ss1 = Decaps(dk_c, ct1)
                                                        ss2, ct2 = Encaps(ek_g)
                                                        derive keys
                              <-- session_id, ct2, confirmation
    ss2 = Decaps(dk_g, ct2); forget dk_g
    derive keys; check confirmation

    Both sides derive the keys from ss1 AND ss2 together, so:

    * ss1 authenticates the cloud. Only the holder of dk_c can recover ss1,
      so a correct confirmation tag proves the gateway is talking to the real
      cloud rather than a man in the middle - provided the gateway checked
      ek_c against a pinned fingerprint. ML-KEM on its own authenticates
      nobody; the pin is what makes this work.
    * ss2 gives forward secrecy. dk_g exists only for one handshake, so an
      attacker who records traffic today and steals the cloud's long-term key
      later still cannot recover ss2, and therefore cannot decrypt the
      recording. That is the "harvest now, decrypt later" threat this project
      exists to address.
    * proof authenticates the gateway, weakly. It shows the gateway knows the
      shared gateway token without sending it. The token is still one static
      secret shared by every gateway (weakness carried over from the
      baseline), but it no longer crosses the network in any form an
      eavesdropper can reuse.

MESSAGES
    AES-256-GCM, which authenticates as well as encrypts: any modified byte
    makes decryption fail. This closes the tampering weakness that AES-CBC
    left open on the legacy hop. The 12-byte nonce is a per-session message
    counter, which guarantees nonces never repeat under one key (repeating a
    GCM nonce is catastrophic) and lets the cloud reject replays exactly.

NOT PRODUCTION CRYPTOGRAPHY
    kyber-py is a pure-Python ML-KEM implementation. Its own documentation
    says it is not constant-time and not intended for production use. It is
    used here because the brief asks for an existing implementation and this
    one installs anywhere with no native build. A production deployment
    would swap in liboqs (or an audited equivalent) behind these same
    functions; nothing outside this module would change.
"""

import base64
import binascii
import hashlib
import hmac
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from kyber_py.ml_kem import ML_KEM_768

ALGORITHM = "ML-KEM-768"

# Sizes from NIST FIPS 203, Table 3. Checked explicitly on every input from
# the network so a malformed value fails with a clear message here rather
# than somewhere inside the library.
PUBLIC_KEY_BYTES = 1184
CIPHERTEXT_BYTES = 1088
SHARED_SECRET_BYTES = 32

# Binds the derived keys to this protocol and version. If the handshake ever
# changes, bumping this string guarantees old and new code can never derive
# the same key by accident.
PROTOCOL_LABEL = b"sdmo-pqc-channel v1"

AES_KEY_BYTES = 32   # AES-256
NONCE_BYTES = 12     # the size GCM is designed for


class ChannelError(ValueError):
    """A handshake or message failed a cryptographic check.

    Subclasses ValueError so callers that already treat bad input as
    ValueError keep working.
    """


# --------------------------------------------------------------------------
# Encoding helpers
# --------------------------------------------------------------------------

def b64encode(data: bytes) -> str:
    """Bytes to standard base64 text, for JSON bodies."""
    return base64.b64encode(data).decode("ascii")


def b64decode(text: str, expected_len: int | None = None) -> bytes:
    """Strict base64 decode, optionally checking the decoded length.

    validate=True rejects characters outside the base64 alphabet instead of
    silently skipping them, so garbage input cannot decode to something
    plausible.

    Raises:
        ChannelError: if the text is not valid base64 or has the wrong length.
    """
    try:
        data = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ChannelError(f"invalid base64: {exc}") from exc
    if expected_len is not None and len(data) != expected_len:
        raise ChannelError(f"expected {expected_len} bytes, got {len(data)}")
    return data


def fingerprint(public_key: bytes) -> str:
    """SHA-256 of a public key, as hex.

    This is what operators pin in the gateway configuration. Comparing 64 hex
    characters is practical; comparing a 1184-byte key is not.
    """
    return hashlib.sha256(public_key).hexdigest()


# --------------------------------------------------------------------------
# ML-KEM wrappers
# --------------------------------------------------------------------------

def generate_keypair() -> tuple[bytes, bytes]:
    """Return (public encapsulation key, private decapsulation key)."""
    return ML_KEM_768.keygen()


def encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """Return (shared_secret, ciphertext) for the holder of public_key.

    Raises:
        ChannelError: if the public key fails the FIPS 203 input checks.
    """
    if len(public_key) != PUBLIC_KEY_BYTES:
        raise ChannelError(f"public key is {len(public_key)} bytes, "
                           f"expected {PUBLIC_KEY_BYTES}")
    try:
        # kyber-py returns (key, ciphertext) in that order.
        return ML_KEM_768.encaps(public_key)
    except ValueError as exc:
        raise ChannelError(f"public key rejected: {exc}") from exc


def decapsulate(private_key: bytes, ciphertext: bytes) -> bytes:
    """Recover the shared secret from a ciphertext.

    Note on failure: ML-KEM uses "implicit rejection". A tampered ciphertext
    of the right length does NOT raise; it quietly yields a different,
    random-looking secret. That is deliberate in the standard (it stops an
    attacker learning anything from error messages), and it is why the
    handshake needs the explicit confirmation tag below - otherwise a
    tampered handshake would only be noticed at the first message.

    Raises:
        ChannelError: only for a ciphertext of the wrong length.
    """
    if len(ciphertext) != CIPHERTEXT_BYTES:
        raise ChannelError(f"ciphertext is {len(ciphertext)} bytes, "
                           f"expected {CIPHERTEXT_BYTES}")
    try:
        return ML_KEM_768.decaps(private_key, ciphertext)
    except ValueError as exc:
        raise ChannelError(f"ciphertext rejected: {exc}") from exc


# --------------------------------------------------------------------------
# Handshake pieces
# --------------------------------------------------------------------------

def gateway_proof(gateway_token: str, static_ct: bytes,
                  ephemeral_pk: bytes) -> bytes:
    """HMAC showing the gateway knows the shared token, bound to this handshake.

    Bound to the handshake values so a proof captured from one handshake is
    useless in any other.
    """
    return hmac.new(gateway_token.encode("utf-8"), static_ct + ephemeral_pk,
                    hashlib.sha256).digest()


def derive_session_keys(static_ss: bytes, ephemeral_ss: bytes,
                        transcript: bytes) -> tuple[bytes, bytes]:
    """Turn the two ML-KEM secrets into (aead_key, confirm_key).

    HKDF rather than using a shared secret directly, for two reasons: it
    combines both secrets so the session is safe if either one is, and it
    yields two independent keys - one for messages, one only for the
    confirmation tag - so the two uses can never interfere.

    The salt is a hash of every public handshake value (the transcript). If an
    attacker altered any of them in transit, the two sides derive different
    keys and the confirmation check fails.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=2 * AES_KEY_BYTES,
        salt=hashlib.sha256(transcript).digest(),
        info=PROTOCOL_LABEL,
    )
    okm = hkdf.derive(static_ss + ephemeral_ss)
    return okm[:AES_KEY_BYTES], okm[AES_KEY_BYTES:]


def transcript(cloud_pk: bytes, static_ct: bytes, ephemeral_pk: bytes,
               ephemeral_ct: bytes) -> bytes:
    """Concatenate the public handshake values in a fixed order.

    Every field has a fixed length, so plain concatenation is unambiguous.
    """
    return cloud_pk + static_ct + ephemeral_pk + ephemeral_ct


def confirmation_tag(confirm_key: bytes, session_id: str) -> bytes:
    """The cloud's proof that it derived the same keys."""
    return hmac.new(confirm_key, b"cloud-confirm|" + session_id.encode(),
                    hashlib.sha256).digest()


def verify_confirmation(confirm_key: bytes, session_id: str,
                        tag: bytes) -> None:
    """Check the cloud's confirmation tag in constant time.

    Raises:
        ChannelError: if the tag does not match, meaning the peer does not
            hold the private key for the pinned public key, or the handshake
            was modified in transit.
    """
    expected = confirmation_tag(confirm_key, session_id)
    if not hmac.compare_digest(expected, tag):
        raise ChannelError("handshake confirmation failed")


def new_session_id() -> str:
    """Unguessable session identifier. 128 bits, as hex."""
    return secrets.token_hex(16)


# --------------------------------------------------------------------------
# Messages
# --------------------------------------------------------------------------

def nonce_for(counter: int) -> bytes:
    """Encode a message counter as a 12-byte GCM nonce."""
    return counter.to_bytes(NONCE_BYTES, "big")


def counter_from(nonce: bytes) -> int:
    """Decode a GCM nonce back into the sender's message counter."""
    if len(nonce) != NONCE_BYTES:
        raise ChannelError(f"nonce is {len(nonce)} bytes, "
                           f"expected {NONCE_BYTES}")
    return int.from_bytes(nonce, "big")


def seal(key: bytes, counter: int, session_id: str,
         plaintext: bytes) -> tuple[bytes, bytes]:
    """Encrypt and authenticate one message. Returns (nonce, ciphertext).

    The session id is authenticated as associated data, so a message cannot
    be lifted from one session and replayed into another.
    """
    nonce = nonce_for(counter)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, session_id.encode())
    return nonce, ciphertext


def open_sealed(key: bytes, nonce: bytes, session_id: str,
                ciphertext: bytes) -> bytes:
    """Decrypt one message, verifying it was not modified.

    Raises:
        ChannelError: if the message was tampered with, belongs to another
            session, or was sealed under a different key. GCM cannot tell
            these apart, and it does not need to - all of them mean reject.
    """
    counter_from(nonce)  # length check with a readable error
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, session_id.encode())
    except InvalidTag as exc:
        raise ChannelError("message authentication failed") from exc
