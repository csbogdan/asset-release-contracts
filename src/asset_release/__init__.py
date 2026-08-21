"""The release CONTRACT: the format producers write and verifiers check.

This package exists because four separate things must agree byte-for-byte on
what a release is — the build that signs one, the vendor console that stores
and serves it, the supervisor that verifies and installs it, and the ontology
sidecar that publishes its own. They will not all live in one repository, and
the last time two of them kept private copies of this format the copies drifted
and a customer install failed a health probe for a day.

WHAT IS DELIBERATELY NOT HERE: trust anchors. This package knows how to VERIFY
a signature against a key it is handed; it does not know which keys are
trusted. That decision belongs to the verifier — the supervisor compiles its
anchors in and passes one to :func:`~asset_release.minisign.verify`.
Keeping the keys out means a version bump of this package can never change what
a deployment trusts, which is the one change nobody should be able to make by
upgrading a dependency.

So: format, serialization, validation and the verification ALGORITHM live here.
Authority lives with the caller.
"""

from asset_release.component import normalise_component
from asset_release.schema_window import DEFAULT_SCHEMA_WINDOW, SchemaWindow

__all__ = [
    "DEFAULT_SCHEMA_WINDOW",
    "SchemaWindow",
    "normalise_component",
]
