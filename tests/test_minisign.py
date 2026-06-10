"""minisign sign/verify unit tests (KAN-359). No network, no minisign binary."""

from __future__ import annotations

import base64
import os

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from asset_discovery.shared.crypto import minisign


def _keypair() -> tuple[str, str]:
    """Return (public_key_file, secret_b64) for a fresh Ed25519 key in our
    minisign-compatible public format + compact secret format."""
    sk = Ed25519PrivateKey.generate()
    seed = sk.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    pub = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key_id = os.urandom(8)
    pub_file = (
        "untrusted comment: test key\n"
        + base64.standard_b64encode(b"Ed" + key_id + pub).decode()
        + "\n"
    )
    secret = base64.standard_b64encode(key_id + seed).decode()
    return pub_file, secret


def test_sign_then_verify_roundtrip() -> None:
    pub, sec = _keypair()
    data = b"satellite binary bytes" * 500
    sig = minisign.sign(data, sec, trusted_comment="satellite 0.2.1 linux-x86_64")
    assert minisign.verify(data, sig, pub) is True


def test_tampered_data_fails() -> None:
    pub, sec = _keypair()
    data = b"original"
    sig = minisign.sign(data, sec, trusted_comment="x")
    assert minisign.verify(data + b"!", sig, pub) is False


def test_wrong_key_fails() -> None:
    _pub_a, sec_a = _keypair()
    pub_b, _ = _keypair()
    data = b"payload"
    sig = minisign.sign(data, sec_a, trusted_comment="x")
    # Different key entirely (different key_id) — rejected at the key_id check.
    assert minisign.verify(data, sig, pub_b) is False


def test_tampered_trusted_comment_fails() -> None:
    pub, sec = _keypair()
    data = b"payload"
    sig = minisign.sign(data, sec, trusted_comment="satellite 0.2.1 linux-x86_64")
    tampered = sig.replace("linux-x86_64", "linux-arm64")
    # The global signature binds the trusted comment, so this is rejected.
    assert minisign.verify(data, tampered, pub) is False


def test_public_key_roundtrips_key_id() -> None:
    pub, _ = _keypair()
    parsed = minisign.parse_public_key(pub)
    assert len(parsed.key_id) == 8
    assert len(parsed.public_key) == 32


def test_malformed_blobs_raise() -> None:
    with pytest.raises(minisign.MinisignError):
        minisign.parse_public_key("untrusted comment: x\nnot-base64!!!\n")
    with pytest.raises(minisign.MinisignError):
        minisign.parse_signature("untrusted comment: x\n")  # missing lines


def test_trusted_comment_must_be_single_line() -> None:
    _, sec = _keypair()
    with pytest.raises(minisign.MinisignError):
        minisign.sign(b"x", sec, trusted_comment="line1\nline2")


def test_committed_release_public_key_parses() -> None:
    """The public key embedded in the satellite + committed at
    deploy/satellite/minisign.pub must be a well-formed Ed25519 minisign key."""
    from asset_discovery.satellite.selfupdate import _RELEASE_PUBLIC_KEY

    parsed = minisign.parse_public_key(_RELEASE_PUBLIC_KEY)
    assert len(parsed.public_key) == 32
