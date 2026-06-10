"""Pure-Python minisign signing + verification (KAN-359, ADR-0016).

Satellite release binaries are signed at build time and verified by the
satellite *before* it swaps its own binary. minisign was chosen for its tiny,
offline-verifiable Ed25519 signatures with no CA or transparency-log
dependency — the public key embeds directly in the frozen satellite binary.

We implement the minisign format in Python (over ``cryptography``'s Ed25519,
already a dependency via Fernet) rather than shelling out to the ``minisign``
binary, because:

* the satellite is a frozen PyInstaller binary and can't rely on a ``minisign``
  executable being present on the host, and
* signing and verification then share one tested code path.

Signatures are minisign-format and cross-verifiable with the ``minisign`` CLI
(``minisign -Vm <file> -p minisign.pub``).

## Formats

Public-key file (second line)::

    base64( sig_alg[2] + key_id[8] + ed25519_public_key[32] )

Signature file::

    untrusted comment: <text>
    base64( sig_alg[2] + key_id[8] + ed25519_signature[64] )
    trusted comment: <text>
    base64( ed25519_signature[64] over (signature || trusted_comment_bytes) )

``sig_alg`` is ``b"Ed"`` for a signature over the raw file bytes (what we use)
or ``b"ED"`` for one over the BLAKE2b-512 prehash of the file (also accepted on
verify).

The **secret** consumed by :func:`sign` is *not* a minisign secret-key file
(those are scrypt-encrypted with a fiddly layout). It is our own compact,
password-less form — ``base64(key_id[8] + ed25519_seed[32])`` — read only by
this module's signer in CI. The *public key* and *signature* it emits are
standard minisign format, so operators can independently verify a release with
the upstream tool.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

_SIG_ALG_PURE = b"Ed"  # signature over the raw file bytes
_SIG_ALG_PREHASHED = b"ED"  # signature over BLAKE2b-512(file)


class MinisignError(Exception):
    """A signature/key blob was malformed or failed verification."""


@dataclass(frozen=True)
class _PublicKey:
    key_id: bytes  # 8 bytes
    public_key: bytes  # 32 bytes


@dataclass(frozen=True)
class _Signature:
    sig_alg: bytes  # 2 bytes
    key_id: bytes  # 8 bytes
    signature: bytes  # 64 bytes
    trusted_comment: str
    global_signature: bytes  # 64 bytes


def _b64decode(text: str) -> bytes:
    try:
        return base64.standard_b64decode(text.strip())
    except (ValueError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
        raise MinisignError(f"invalid base64: {exc}") from exc


def parse_public_key(text: str) -> _PublicKey:
    """Parse a minisign public-key file (comment line + base64 line)."""
    lines = [ln for ln in text.strip().splitlines() if ln.strip()]
    if not lines:
        raise MinisignError("empty public key")
    blob = _b64decode(lines[-1])  # last non-empty line is the key (skip comment)
    if len(blob) != 42:
        raise MinisignError(f"public key blob is {len(blob)} bytes, expected 42")
    if blob[:2] != _SIG_ALG_PURE:
        raise MinisignError("unsupported public-key algorithm (expected Ed25519 'Ed')")
    return _PublicKey(key_id=blob[2:10], public_key=blob[10:42])


def parse_signature(text: str) -> _Signature:
    """Parse a minisign signature file (4 meaningful lines)."""
    lines = [ln for ln in text.strip().splitlines()]
    # Expected: comment, sig-b64, trusted-comment, global-sig-b64.
    b64_lines = [
        ln for ln in lines if ln and not ln.startswith(("untrusted comment:", "trusted comment:"))
    ]
    trusted = next(
        (
            ln[len("trusted comment:") :].strip()
            for ln in lines
            if ln.startswith("trusted comment:")
        ),
        "",
    )
    if len(b64_lines) < 2:
        raise MinisignError("signature file missing signature or global-signature line")
    sig_blob = _b64decode(b64_lines[0])
    global_sig = _b64decode(b64_lines[1])
    if len(sig_blob) != 74:
        raise MinisignError(f"signature blob is {len(sig_blob)} bytes, expected 74")
    if len(global_sig) != 64:
        raise MinisignError(f"global signature is {len(global_sig)} bytes, expected 64")
    sig_alg = sig_blob[:2]
    if sig_alg not in (_SIG_ALG_PURE, _SIG_ALG_PREHASHED):
        raise MinisignError("unsupported signature algorithm")
    return _Signature(
        sig_alg=sig_alg,
        key_id=sig_blob[2:10],
        signature=sig_blob[10:74],
        trusted_comment=trusted,
        global_signature=global_sig,
    )


def _prehash(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.BLAKE2b(64))
    digest.update(data)
    return digest.finalize()


def verify(data: bytes, signature_file: str, public_key_file: str) -> bool:
    """Return ``True`` iff ``signature_file`` is a valid minisign signature of
    ``data`` under ``public_key_file``. Never raises on a bad signature —
    returns ``False`` — so callers can treat verification failure as a normal
    (fail-closed) outcome. Raises :class:`MinisignError` only when a blob is so
    malformed it can't be parsed.
    """
    pub = parse_public_key(public_key_file)
    sig = parse_signature(signature_file)
    if sig.key_id != pub.key_id:
        return False  # signed by a different key than we trust
    key = Ed25519PublicKey.from_public_bytes(pub.public_key)
    message = data if sig.sig_alg == _SIG_ALG_PURE else _prehash(data)
    try:
        key.verify(sig.signature, message)
        # The global signature binds the trusted comment to the file signature,
        # so a tampered trusted comment is rejected too (minisign semantics).
        key.verify(sig.global_signature, sig.signature + sig.trusted_comment.encode())
    except InvalidSignature:
        return False
    return True


def sign(
    data: bytes,
    secret_key_b64: str,
    *,
    trusted_comment: str,
    untrusted_comment: str = "signature from asset-discovery",
) -> str:
    """Produce a minisign signature file for ``data`` (CI build-time signer).

    ``secret_key_b64`` is our compact form: ``base64(key_id[8] + seed[32])``.
    ``trusted_comment`` must be single-line (e.g. ``"satellite 0.2.1 linux-x86_64"``).
    """
    if "\n" in trusted_comment or "\r" in trusted_comment:
        raise MinisignError("trusted_comment must be single-line")
    raw = _b64decode(secret_key_b64)
    if len(raw) != 40:
        raise MinisignError(f"secret key is {len(raw)} bytes, expected 40 (key_id[8]+seed[32])")
    key_id, seed = raw[:8], raw[8:40]
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    sig = sk.sign(data)  # pure 'Ed' over the raw bytes
    sig_line = base64.standard_b64encode(_SIG_ALG_PURE + key_id + sig).decode()
    global_sig = sk.sign(sig + trusted_comment.encode())
    global_line = base64.standard_b64encode(global_sig).decode()
    return (
        f"untrusted comment: {untrusted_comment}\n"
        f"{sig_line}\n"
        f"trusted comment: {trusted_comment}\n"
        f"{global_line}\n"
    )
