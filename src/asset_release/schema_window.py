"""The four schema numbers a signed manifest carries, and the one rule about them.

Delivery v2 §4 replaced the single ``schema_min``/``schema_max`` pair with two
DIFFERENT questions, because they were always two questions wearing one answer:

* ``runs_against_min`` / ``runs_against_max`` — what this build OPERATES ON
  without migrating. Eligibility to RUN is tested against these.
* ``migrates_from_min`` / ``migrates_to`` — what it will CHANGE if allowed to.

Two consumers read the same four numbers out of the same signed document — the
supervisor (``asset_discovery.supervisor.manifest``) on a customer's machine and
the vendor console (``asset_discovery.vendor.service.releases``) at publish — and
they must never disagree about what a manifest means. So the parse rule and the
inequalities live HERE, once, rather than being implemented on both sides and
drifting the first time one of them is edited.

Stdlib only, and imports nothing from ``server``, ``vendor`` or ``supervisor``:
the console is meant to be liftable into its own repository and the supervisor
ships inside a customer image.

Backward compatibility is load-bearing, not a nicety
----------------------------------------------------
Release ``1.2.2`` is already published and already SIGNED, without any of these
fields. Re-signing it is impossible (the signature covers bytes that exist), so a
parser that demanded them would make an installed, working release uninstallable.
Absent therefore means "the pre-v2 default", :data:`DEFAULT_SCHEMA_WINDOW` — all
four at 1.

A PARTIAL set is refused. Three-of-four is not an old manifest, it is a broken
new one, and silently defaulting the fourth would invent a claim about a
customer's database that no build ever made.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final

#: The manifest keys, in the order they are stamped and reported.
SCHEMA_WINDOW_FIELDS: Final[tuple[str, ...]] = (
    "runs_against_min",
    "runs_against_max",
    "migrates_from_min",
    "migrates_to",
)


class SchemaWindowError(ValueError):
    """A manifest's schema fields are partial, non-integer, or negative."""


@dataclass(frozen=True, slots=True)
class SchemaWindow:
    """What one build says about the schema revisions it can run on and move to."""

    runs_against_min: int
    runs_against_max: int
    migrates_from_min: int
    migrates_to: int

    def as_dict(self) -> dict[str, int]:
        return {
            "runs_against_min": self.runs_against_min,
            "runs_against_max": self.runs_against_max,
            "migrates_from_min": self.migrates_from_min,
            "migrates_to": self.migrates_to,
        }

    def runs_against(self, current: int) -> bool:
        """Is a database at ``current`` one this build operates on as-is?"""
        return self.runs_against_min <= current <= self.runs_against_max

    def migrates_from(self, current: int) -> bool:
        """Is a database at ``current`` one this build will migrate?"""
        return self.migrates_from_min <= current <= self.migrates_to


#: What a manifest predating delivery v2 means. See the module docstring for why
#: this is not a lenient default but the only correct reading of an old release.
DEFAULT_SCHEMA_WINDOW: Final[SchemaWindow] = SchemaWindow(
    runs_against_min=1,
    runs_against_max=1,
    migrates_from_min=1,
    migrates_to=1,
)


def parse_schema_window(obj: dict[str, Any]) -> SchemaWindow:
    """Read the four fields out of a parsed manifest object.

    * all four absent  -> :data:`DEFAULT_SCHEMA_WINDOW`
    * all four present -> those values
    * anything else    -> :class:`SchemaWindowError`, naming what was missing

    Ordering is NOT checked here: an already-signed manifest cannot be fixed by
    refusing to read it, and the console refuses such a release at PUBLISH with
    a message naming the numbers (:func:`schema_window_violations`). Parsing and
    admitting are different decisions and are made in different places.
    """
    present = [name for name in SCHEMA_WINDOW_FIELDS if name in obj]
    if not present:
        return DEFAULT_SCHEMA_WINDOW
    if len(present) != len(SCHEMA_WINDOW_FIELDS):
        missing = [name for name in SCHEMA_WINDOW_FIELDS if name not in obj]
        raise SchemaWindowError(
            "a manifest declares all four schema fields or none of them; this one declares "
            f"{', '.join(present)} and is missing {', '.join(missing)}. Three-of-four is not "
            "an older release, it is a broken newer one."
        )
    values = {name: _int_field(obj, name) for name in SCHEMA_WINDOW_FIELDS}
    return SchemaWindow(**values)


def schema_window_violations(window: SchemaWindow) -> list[str]:
    """Every publish-time inequality this window breaks, each naming its numbers.

    Empty means publishable. The middle rule is the one with teeth: without it a
    build may migrate a database to a schema IT CANNOT ITSELF RUN ON — permitted,
    applied, and then dead, with the supervisor's own revert refused by the same
    guard because the data has already moved past the older build.
    """
    problems: list[str] = []
    if window.runs_against_min > window.runs_against_max:
        problems.append(
            f"runs_against_min ({window.runs_against_min}) is above runs_against_max "
            f"({window.runs_against_max}): the build claims to run on no schema at all"
        )
    if not (window.runs_against_min <= window.migrates_to <= window.runs_against_max):
        problems.append(
            f"migrates_to ({window.migrates_to}) is outside runs_against "
            f"{window.runs_against_min}-{window.runs_against_max}: this build would migrate a "
            "database to a schema it cannot itself run on, and the migration cannot be undone"
        )
    if window.migrates_from_min > window.migrates_to:
        problems.append(
            f"migrates_from_min ({window.migrates_from_min}) is above migrates_to "
            f"({window.migrates_to}): the build claims to upgrade nothing"
        )
    return problems


def _int_field(obj: dict[str, Any], name: str) -> int:
    value = obj.get(name)
    # ``bool`` is an ``int`` in Python and ``True`` would silently read as 1.
    if isinstance(value, bool) or not isinstance(value, int):
        raise SchemaWindowError(f"manifest field {name!r} must be an integer, got {value!r}")
    if value < 0:
        raise SchemaWindowError(f"manifest field {name!r} must be >= 0, got {value}")
    return value


__all__ = [
    "DEFAULT_SCHEMA_WINDOW",
    "SCHEMA_WINDOW_FIELDS",
    "SchemaWindow",
    "SchemaWindowError",
    "parse_schema_window",
    "schema_window_violations",
]
