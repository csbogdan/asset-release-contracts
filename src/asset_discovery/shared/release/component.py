"""Re-export shim: component naming moved to :mod:`asset_release.component`.

Producers stamp a component into a signed manifest and verifiers compare it to
what they are configured to be, so the normalisation rule has to be one rule.
See :mod:`asset_release` for why the contract is its own package.
"""

from asset_release.component import *  # noqa: F403
from asset_release.component import __all__  # noqa: F401
