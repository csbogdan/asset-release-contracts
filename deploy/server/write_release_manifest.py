#!/usr/bin/env python3
"""CLI shim: the manifest writer lives in :mod:`asset_release.writer`.

There used to be two copies of this file — this one and a full copy in the
ontology repository, kept in step by hand. They stopped being in step: a port
was corrected here and not there, and a customer's ontology installed, started,
and then failed every health probe for a day because the manifest it was handed
named a port nginx already held. One implementation, consumed by every producer.

WHY THE sys.path LINE BELOW IS NOT OPTIONAL. Three release workflows invoke this
file as a bare script — `python deploy/server/write_release_manifest.py` — on a
runner that has installed `cryptography` and nothing else. There is no editable
install and no package on the path, deliberately: the writer is stdlib-only so
that every dependency added to it does not become a dependency of the release.
Importing `asset_release` in that environment raises ModuleNotFoundError and
takes the whole release job with it. It works from a developer's virtualenv,
which is exactly how a break like this reaches CI unnoticed.

WHY THE RE-EXPORTS ARE SPELLED OUT AND CARRY `noqa: F401`. Callers reach for
private names here — the test suite for `_validate_profile_shape`, tooling for
`_build_arg_parser` and `_SCHEMA_VERSION_MODULE` — and `import *` does not carry
underscore-prefixed names. They were listed once already and then SILENTLY
DELETED by `ruff check --fix`, which correctly saw imports nothing in this file
uses and removed them; the module's whole job is to re-export, so "unused" is
the point. The suppression is what stops the next `--fix` from doing it again.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from asset_release.writer import *  # noqa: F403
from asset_release.writer import (  # noqa: F401
    _SCHEMA_VERSION_MODULE,
    _build_arg_parser,
    _validate_profile_shape,
    build_manifest,
    build_signature_entry,
    main,
    profile_for,
    read_schema_constants,
    sha256_hex,
)

if __name__ == "__main__":
    sys.exit(main())
