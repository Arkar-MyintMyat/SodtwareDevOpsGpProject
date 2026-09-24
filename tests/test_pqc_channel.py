"""
Unit tests for the post-quantum channel primitives in pqc_channel/channel.py.

These run both halves of the handshake in one process, with no network, so a
failure here means the cryptography is wrong rather than the plumbing.
"""

import pytest

from pqc_channel import channel


def run_handshake(token_gateway="t0ken", token_cloud="t0ken"):
    """Both sides of the handshake, exactly as gateway and cloud perform it.

    Returns a dict with each side's derived keys and the public values, so
    tests can tamper with or inspect any step.
    """
    cloud_pk, cloud_sk = channel.generate_keypair()

    # Gateway
    static_ss_g, static_ct = channel.encapsulate(cloud_pk)
    eph_pk, eph_sk = channel.generate_keypair()
    proof = channel.gateway_proof(token_gateway, static_ct, eph_pk)

    # Cloud
    proof_ok = proof == channel.gateway_proof(token_cloud, static_ct, eph_pk)
    static_ss_c = channel.decapsulate(cloud_sk, static_ct)
    eph_ss_c, eph_ct = channel.encapsulate(eph_pk)
    t = channel.transcript(cloud_pk, static_ct, eph_pk, eph_ct)
    cloud_keys = channel.derive_session_keys(static_ss_c, eph_ss_c, t)

    # Gateway again
    eph_ss_g = channel.decapsulate(eph_sk, eph_ct)
    gateway_keys = channel.derive_session_keys(static_ss_g, eph_ss_g, t)

    return {
        "cloud_pk": cloud_pk, "cloud_sk": cloud_sk,
        "static_ct": static_ct, "eph_pk": eph_pk, "eph_ct": eph_ct,
        "static_ss": static_ss_c, "proof_ok": proof_ok,
        "cloud_keys": cloud_keys, "gateway_keys": gateway_keys,
    }


# --------------------------------------------------------------------------
# ML-KEM itself
# --------------------------------------------------------------------------

def test_key_and_ciphertext_sizes_match_fips_203():
    """ML-KEM-768 sizes from FIPS 203 Table 3, measured from the library.

    tests/test_protocol.py asserts these numbers are too big for the device;
    this test proves they are the numbers the library really produces.
    """
    public_key, private_key = channel.generate_keypair()
    secret, ciphertext = channel.encapsulate(public_key)

    assert len(public_key) == channel.PUBLIC_KEY_BYTES == 1184
    assert len(private_key) == 2400
    assert len(ciphertext) == channel.CIPHERTEXT_BYTES == 1088
    assert len(secret) == channel.SHARED_SECRET_BYTES == 32


def test_encapsulate_and_decapsulate_agree():
    public_key, private_key = channel.generate_keypair()
    secret, ciphertext = channel.encapsulate(public_key)

    assert channel.decapsulate(private_key, ciphertext) == secret


def test_encapsulate_rejects_a_truncated_public_key():
    public_key, _ = channel.generate_keypair()

    with pytest.raises(channel.ChannelError):
        channel.encapsulate(public_key[:-1])


def test_decapsulate_rejects_a_truncated_ciphertext():
    public_key, private_key = channel.generate_keypair()
    _, ciphertext = channel.encapsulate(public_key)

    with pytest.raises(channel.ChannelError):
        channel.decapsulate(private_key, ciphertext[:-1])


def test_tampered_kem_ciphertext_is_rejected_implicitly():
    """ML-KEM does not raise on a modified ciphertext; it returns garbage.

    This is FIPS 203's "implicit rejection". It is why the handshake has an
    explicit confirmation step: without one, tampering would only surface at
    the first message.
    """
    public_key, private_key = channel.generate_keypair()
    secret, ciphertext = channel.encapsulate(public_key)
    tampered = bytes([ciphertext[0] ^ 0x01]) + ciphertext[1:]

    assert channel.decapsulate(private_key, tampered) != secret


# --------------------------------------------------------------------------
# Handshake
# --------------------------------------------------------------------------

def test_handshake_gives_both_sides_the_same_keys():
    h = run_handshake()

    assert h["gateway_keys"] == h["cloud_keys"]
    aead_key, confirm_key = h["gateway_keys"]
    assert len(aead_key) == 32, "AES-256"
    assert aead_key != confirm_key, "the two derived keys must be independent"


def test_two_handshakes_give_different_keys():
    """Fresh randomness every time: no two sessions share a key."""
    assert run_handshake()["gateway_keys"] != run_handshake()["gateway_keys"]


def test_gateway_proof_fails_with_the_wrong_token():
    assert run_handshake("t0ken", "t0ken")["proof_ok"] is True
    assert run_handshake("wrong", "t0ken")["proof_ok"] is False


def test_gateway_proof_is_bound_to_its_handshake():
    """A proof captured from one handshake is useless for another."""
    a, b = run_handshake(), run_handshake()

    proof_a = channel.gateway_proof("t0ken", a["static_ct"], a["eph_pk"])
    proof_b = channel.gateway_proof("t0ken", b["static_ct"], b["eph_pk"])

    assert proof_a != proof_b


def test_confirmation_tag_verifies_with_matching_keys():
    h = run_handshake()
    _, cloud_confirm = h["cloud_keys"]
    _, gateway_confirm = h["gateway_keys"]

    tag = channel.confirmation_tag(cloud_confirm, "a" * 32)
    channel.verify_confirmation(gateway_confirm, "a" * 32, tag)  # no raise


def test_confirmation_fails_if_the_peer_lacks_the_private_key():
    """What a man in the middle without the cloud's private key produces.

    The impostor cannot decapsulate the gateway's static ciphertext, so it
    derives different keys and cannot produce a valid confirmation tag.
    """
    h = run_handshake()
    _, gateway_confirm = h["gateway_keys"]

    impostor_keys = channel.derive_session_keys(
        b"\x00" * 32,  # the impostor's best guess at the static secret
        b"\x00" * 32,
        channel.transcript(h["cloud_pk"], h["static_ct"], h["eph_pk"],
                           h["eph_ct"]),
    )
    tag = channel.confirmation_tag(impostor_keys[1], "a" * 32)

    with pytest.raises(channel.ChannelError):
        channel.verify_confirmation(gateway_confirm, "a" * 32, tag)


def test_stolen_long_term_key_does_not_decrypt_recorded_traffic():
    """Forward secrecy, the property that answers "harvest now, decrypt later".

    An attacker records a session, then later steals the cloud's long-term
    private key. That recovers the static secret, but not the ephemeral one,
    whose private key existed only for the handshake. The recording stays
    unreadable.
    """
    h = run_handshake()
    aead_key, _ = h["gateway_keys"]
    nonce, recorded = channel.seal(aead_key, 0, "s" * 32, b"secret reading")

    # Later: the attacker has the cloud's private key.
    stolen_static_ss = channel.decapsulate(h["cloud_sk"], h["static_ct"])
    assert stolen_static_ss == h["static_ss"], "the long-term key does leak ss1"

    # Without the ephemeral secret, every guess derives the wrong key.
    attacker_key, _ = channel.derive_session_keys(
        stolen_static_ss, b"\x00" * 32,
        channel.transcript(h["cloud_pk"], h["static_ct"], h["eph_pk"],
                           h["eph_ct"]),
    )
    with pytest.raises(channel.ChannelError):
        channel.open_sealed(attacker_key, nonce, "s" * 32, recorded)


# --------------------------------------------------------------------------
# Messages
# --------------------------------------------------------------------------

@pytest.fixture
def key():
    return run_handshake()["gateway_keys"][0]


def test_seal_and_open_round_trip(key):
    nonce, sealed = channel.seal(key, 7, "s" * 32, b'{"seq":1}')

    assert channel.open_sealed(key, nonce, "s" * 32, sealed) == b'{"seq":1}'
    assert channel.counter_from(nonce) == 7


def test_any_modified_byte_is_detected(key):
    """The fix for the legacy hop's worst weakness.

    tests/test_protocol.py shows that flipping one byte of a legacy AES-CBC
    frame silently rewrites the reading. Under AES-GCM, flipping any byte of
    the ciphertext makes decryption fail.
    """
    nonce, sealed = channel.seal(key, 0, "s" * 32, b'{"device_id":"dev-001"}')

    for i in range(len(sealed)):
        tampered = sealed[:i] + bytes([sealed[i] ^ 0x01]) + sealed[i + 1:]
        with pytest.raises(channel.ChannelError):
            channel.open_sealed(key, nonce, "s" * 32, tampered)


def test_message_cannot_be_moved_to_another_session(key):
    nonce, sealed = channel.seal(key, 0, "a" * 32, b"reading")

    with pytest.raises(channel.ChannelError):
        channel.open_sealed(key, nonce, "b" * 32, sealed)


def test_message_cannot_be_opened_with_a_different_nonce(key):
    _, sealed = channel.seal(key, 0, "s" * 32, b"reading")

    with pytest.raises(channel.ChannelError):
        channel.open_sealed(key, channel.nonce_for(1), "s" * 32, sealed)


def test_counters_give_distinct_nonces():
    """Nonce reuse under one GCM key is catastrophic; counters prevent it."""
    nonces = {channel.nonce_for(i) for i in range(1000)}

    assert len(nonces) == 1000
    assert all(len(n) == channel.NONCE_BYTES for n in nonces)


# --------------------------------------------------------------------------
# Encoding
# --------------------------------------------------------------------------

def test_b64decode_rejects_non_base64_characters():
    with pytest.raises(channel.ChannelError):
        channel.b64decode("not*base64!")


def test_b64decode_checks_length():
    with pytest.raises(channel.ChannelError):
        channel.b64decode(channel.b64encode(b"abc"), expected_len=4)


def test_fingerprint_is_stable_sha256_hex():
    public_key, _ = channel.generate_keypair()

    assert channel.fingerprint(public_key) == channel.fingerprint(public_key)
    assert len(channel.fingerprint(public_key)) == 64
