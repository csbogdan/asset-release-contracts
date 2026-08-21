"""Re-export shim: minisign moved to :mod:`asset_release.minisign`.

The signing format is part of the release CONTRACT — the build signs with it,
the supervisor verifies with it, and the ontology repo needs the identical
implementation. It now lives in `asset_release` so those consumers can share one
implementation across repositories rather than keeping copies that drift.

This module re-exports it so every existing
``from asset_discovery.shared.crypto import minisign`` site keeps working.
"""

from asset_release.minisign import (
    MinisignError,
    parse_public_key,
    parse_signature,
    sign,
    verify,
)

__all__ = ["MinisignError", "parse_public_key", "parse_signature", "sign", "verify"]
