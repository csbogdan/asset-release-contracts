"""Re-export shim: schema windows moved to :mod:`asset_release.schema_window`.

The four numbers that say what a build runs against and migrates to are read by
the producer that writes them and the supervisor that refuses on them.
See :mod:`asset_release` for why the contract is its own package.
"""

from asset_release.schema_window import *  # noqa: F403
from asset_release.schema_window import __all__  # noqa: F401
