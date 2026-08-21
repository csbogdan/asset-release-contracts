"""What a release's ``component`` is, canonically — for BOTH sides of the seam.

A component name ("server", "ontology") is written down twice, by two parties
that never speak to each other:

* A **release** gets its component from a SIGNED MANIFEST that CI stamps from the
  build's source tree. The vendor console derives a column from it; the manifest
  bytes themselves are stored and relayed verbatim.
* A **deployment** gets its component from an OPERATOR registering an
  installation in the console, and — separately — from the supervisor's own
  configuration inside the customer's environment.

Three places then compare those strings with EXACT equality:

1. ``vendor/service/tracks.py`` filters the entitled list on
   ``Release.component == deployment.component``.
2. ``vendor/service/tracks.py::is_entitled`` refuses a mismatch by name.
3. ``supervisor/service.py`` refuses to install a release whose manifest
   component is not the component it is configured as.

Nothing made the four writers agree on shape. ``"Ontology"`` and ``"ontology"``
are different strings, and the failure is SILENT in the worst direction: a
mismatch at (1) produces an EMPTY LIST, which is a legitimate 200 meaning "your
component has no releases yet" (SPEC §3). An operator sees a deployment entitled
to nothing and no error anywhere explaining why.

Normalising in only ONE of those places is worse than normalising in none: the
console would offer a release the supervisor then refuses at install time, which
moves the failure from the console (where somebody is looking) to a customer's
environment (where nobody is). So this module is the single definition, it lives
in ``shared/`` because the import-poor supervisor image ships it, and both sides
call it.

``casefold`` rather than ``lower``: these are identifiers, and ``lower`` leaves
``"STRASSE"`` and ``"Straße"`` unequal. The grammar check keeps the question
academic — a component is an ASCII slug — but the two are written to agree.
"""

from __future__ import annotations

import re

#: The component a release or deployment is when nothing says otherwise. Every
#: row predating the four-field delivery-v2 manifest is backfilled to this.
DEFAULT_COMPONENT = "server"

#: A component is a short ASCII slug. Deliberately NOT an enum: SPEC §3 allows a
#: component whose release pipeline does not exist yet, so a new name must be
#: registerable before any build of it does — an enum would refuse exactly the
#: case the rule exists to permit. The grammar is what keeps "open vocabulary"
#: from meaning "any bytes at all".
_COMPONENT_RE = re.compile(r"^[a-z0-9]+(?:[-_][a-z0-9]+)*$")

#: Longer than any real component and short enough that the column, the log line
#: and the refusal message stay readable.
MAX_COMPONENT_LENGTH = 64


class ComponentError(ValueError):
    """A component name that cannot be canonicalised. Carries an operator-facing message."""


def normalise_component(value: str | None) -> str:
    """The canonical form used for COMPARISON. Never raises.

    Used on both sides of every equality check above, and on the way into the
    database. ``None`` and blank become :data:`DEFAULT_COMPONENT` because that is
    what an ABSENT component has always meant — an omitted field, and every row
    that predates the field existing.

    Use :func:`parse_component` instead when a human supplied the value: an
    operator who typed whitespace has made a mistake, and silently turning that
    into "server" would hand them server builds.
    """
    cleaned = (value or "").strip().casefold()
    return cleaned or DEFAULT_COMPONENT


def parse_component(value: object, *, field: str = "component") -> str:
    """Canonicalise a component a HUMAN supplied, refusing what cannot be one.

    Raises :class:`ComponentError` rather than falling back, because every
    fallback here is silent and wrong in the same direction: a deployment
    declared as something unmatched is entitled to nothing and says so with an
    empty list, and a deployment quietly defaulted to "server" is offered server
    builds it may not be.
    """
    if value is None:
        raise ComponentError(
            f"`{field}` cannot be null. Omit it entirely to accept the default "
            f"({DEFAULT_COMPONENT!r}); sending null asks for a component that does not exist."
        )
    if not isinstance(value, str):
        raise ComponentError(f"`{field}` must be a name, not {type(value).__name__}")
    cleaned = value.strip().casefold()
    if not cleaned:
        raise ComponentError(
            f"`{field}` cannot be blank. Omit it entirely to accept the default "
            f"({DEFAULT_COMPONENT!r}) — a blank component matches no release, so the "
            "deployment would be entitled to nothing and nothing would say why."
        )
    if len(cleaned) > MAX_COMPONENT_LENGTH:
        raise ComponentError(
            f"`{field}` is {len(cleaned)} characters; the limit is {MAX_COMPONENT_LENGTH}"
        )
    if not _COMPONENT_RE.match(cleaned):
        raise ComponentError(
            f"`{field}` must be a slug like 'server' or 'ontology' — lowercase letters, "
            f"digits, and single - or _ between them. Got {value!r}."
        )
    return cleaned


__all__ = [
    "DEFAULT_COMPONENT",
    "MAX_COMPONENT_LENGTH",
    "ComponentError",
    "normalise_component",
    "parse_component",
]
