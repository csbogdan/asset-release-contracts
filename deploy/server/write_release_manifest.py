#!/usr/bin/env python3
"""Write ``release.json`` for a set of already-built server release artifacts.

Run by ``server-release.yml``'s build job after the tarball (and, once the
sign job has run, its ``.minisig``) exist. Stdlib only — no ``cryptography``
import here, unlike ``sign_release.py`` — this tool only *describes* artifacts
that already exist on disk (path, size, sha256, expected signature filename);
it never signs or verifies anything itself.

Two other things in this repo generate an artifact index and could look like
this at a glance, but solve a different problem:

* ``deploy/publish/publish_releases.py`` builds ``index/satellites.json`` from
  what is ACTUALLY SITTING in the vendor's blob store after a publish — its
  entries are read back from uploaded blob metadata, and it is deliberately
  decoupled from ``asset_discovery.server.*``.
* This script writes a per-release manifest from LOCAL BUILD OUTPUT, before
  anything is published anywhere. ``publish_release.py`` — the next step in
  the same workflow — reads what this writes: it relays these exact bytes
  (and their detached signature) to the vendor console, never a
  re-serialised copy, because the signature covers the bytes.

Usage::

    python write_release_manifest.py --version 0.1.0 --output dist/release.json \\
        dist/asset-discovery-server-0.1.0-linux-x86_64.tar.zst

    # Fail if a listed artifact has no sibling .minisig yet (post-sign use):
    python write_release_manifest.py --version 0.1.0 --output dist/release.json \\
        --require-signatures dist/asset-discovery-server-0.1.0-linux-x86_64.tar.zst
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

_SIGNATURE_SUFFIX = ".minisig"

#: Where the four schema numbers come from: the SOURCE TREE, read at build time.
#: Nothing types them. They used to be ``schema_min``/``schema_max``
#: ``workflow_dispatch`` inputs defaulting to "0"/"0" — free text, typed at
#: dispatch, compared against a fleet reporting "unknown", so the check they
#: existed for never once fired. Delivery v2 deletes those inputs; a build's
#: claim about the database is now whatever its own code says.
_SCHEMA_VERSION_MODULE = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "asset_discovery"
    / "shared"
    / "inventory"
    / "schema_version.py"
)

#: Read out of that module and stamped into the manifest, under these names.
_SCHEMA_CONSTANTS: tuple[str, ...] = (
    "RUNS_AGAINST_MIN",
    "RUNS_AGAINST_MAX",
    "MIGRATES_FROM_MIN",
    "MIGRATES_TO",
)


class ReleaseManifestError(Exception):
    """A manifest precondition failed. Always fatal — the caller exits non-zero."""


@dataclass(frozen=True, slots=True)
class ArtifactEntry:
    name: str
    size: int
    sha256: str

    def to_dict(self) -> dict[str, object]:
        return {"name": self.name, "size": self.size, "sha256": self.sha256}


def read_schema_constants(module_path: Path | None = None) -> dict[str, int]:
    """Parse ``schema_version.py`` with ``ast`` and return its integer constants.

    Parsed, not IMPORTED, and that is the whole reason this is twenty lines
    rather than one. This script is deliberately stdlib-only — it runs on a CI
    runner with no ``pip install`` step, because every dependency added here
    becomes a dependency of the release — so it cannot ``import
    asset_discovery``. ``ast`` reads the same file the application compiles from,
    with no import side effects and no chance of picking up a different
    installed copy.

    Refuses loudly on a missing name or a non-literal value: a build that
    silently defaulted one of these would stamp a claim about a customer's
    database that no code ever made.
    """
    path = module_path or _SCHEMA_VERSION_MODULE
    if not path.is_file():
        raise ReleaseManifestError(
            f"cannot read the schema constants: {path} does not exist. The manifest's "
            "runs_against/migrates fields come from the source tree, not from an input."
        )
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: dict[str, int] = {}
    wanted = {"SCHEMA_VERSION", *_SCHEMA_CONSTANTS}
    for node in tree.body:
        if isinstance(node, ast.AnnAssign):
            targets = [node.target]
            value = node.value
        elif isinstance(node, ast.Assign):
            targets = list(node.targets)
            value = node.value
        else:
            continue
        for target in targets:
            if not isinstance(target, ast.Name) or target.id not in wanted:
                continue
            if not isinstance(value, ast.Constant) or not isinstance(value.value, int):
                raise ReleaseManifestError(
                    f"{path.name}: {target.id} must be a plain integer literal so this "
                    f"stdlib-only script can read it without importing the package; found "
                    f"{ast.dump(value) if value is not None else 'no value'}"
                )
            found[target.id] = int(value.value)
    missing = sorted(wanted - set(found))
    if missing:
        raise ReleaseManifestError(
            f"{path.name} does not define {', '.join(missing)}. The manifest's schema fields "
            "are derived from that module and there is no fallback — a defaulted value here "
            "would be exactly the invented number delivery v2 removed."
        )
    return found


def sha256_hex(path: Path) -> str:
    """Streaming sha256 — artifacts here are tens to hundreds of MB; never
    read a whole one into memory just to hash it."""
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_artifact_entry(artifact: Path, *, require_signature: bool) -> ArtifactEntry:
    if not artifact.is_file():
        raise ReleaseManifestError(f"artifact not found: {artifact}")
    sig_path = artifact.with_name(artifact.name + _SIGNATURE_SUFFIX)
    if require_signature and not sig_path.is_file():
        raise ReleaseManifestError(
            f"{artifact}: no sibling {sig_path.name} found — refusing to write a manifest "
            "for an unsigned artifact (drop --require-signatures to allow a pre-sign preview)"
        )
    # The NAME, not the local build path: the manifest is read on a customer's
    # machine, where this build directory does not exist. Where to FETCH it from
    # is resolved per request by the vendor console — a signed document cannot
    # carry a short-lived URL.
    return ArtifactEntry(
        name=artifact.name,
        size=artifact.stat().st_size,
        sha256=sha256_hex(artifact),
    )


def build_signature_entry(artifact: Path) -> ArtifactEntry | None:
    """The archive's ``.minisig`` as an artifact in its own right, or None.

    WHY THIS EXISTS, found in the field rather than in review: the manifest
    named the three platform archives and NOT their signatures, so the console
    stored three archives and no ``.minisig``. A customer's server then
    downloaded all three (130 MB + 72 MB + 72 MB), found no signature to verify
    them against, and refused every one:

        release.sync.unsigned_refused  kind=satellite platform=linux-x86_64
        release.sync.completed  candidates=3 refused=3 synced=0

    The refusal was CORRECT — ``requires_signature`` is True and unsigned
    binaries must not reach a customer's fleet. The pipeline was simply never
    shipping the thing that would let them pass.

    Naming the signature here is what puts it in ``artifact_urls``, which is the
    only route by which the console can serve it. A signature that exists only
    on the build runner protects nobody.
    """
    sig_path = artifact.with_name(artifact.name + _SIGNATURE_SUFFIX)
    if not sig_path.is_file():
        return None
    return ArtifactEntry(
        name=sig_path.name,
        size=sig_path.stat().st_size,
        sha256=sha256_hex(sig_path),
    )


# --------------------------------------------------------------------------- #
# Component profiles                                                            #
#                                                                               #
# A component is not a LABEL on an otherwise-identical manifest. It decides how  #
# the thing RUNS: its entrypoint, its port, its readiness path, and whether the  #
# four schema numbers mean anything for it at all.                              #
#                                                                               #
# So `--component` selects a PROFILE rather than overwriting a field. The        #
# alternative — a bare flag over server-shaped defaults — would let CI stamp a   #
# SERVER build as `component: ontology`: correctly signed, correctly published,  #
# offered to an ontology deployment, and wrong in the one way nothing downstream #
# can detect, because every check would pass. An unknown component is REFUSED    #
# rather than defaulted for the same reason.                                     #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class ComponentProfile:
    """How one component is packaged and, if anything runs it, run."""

    typ: str
    #: Whether a SUPERVISOR starts this component and waits for it to be ready.
    #:
    #: False for a RELAYED component (ADR-0039). A satellite is not started by
    #: anything in the customer's environment that we ship: the customer's
    #: server hands the archive to a machine, and an installer on that machine
    #: puts it under systemd or a Windows service. There is no slot to
    #: substitute, no port to bind, and no readiness endpoint to poll.
    #:
    #: The three fields below are None exactly when this is False. Filling them
    #: in with plausible values would be three facts nothing will ever read —
    #: the same shape as a guard that reads a field nothing can set: it looks
    #: configured, it is wrong, and it can never fire.
    supervised: bool
    entrypoint: tuple[str, ...] | None
    port: int | None
    ready_path: str | None
    #: Whether this component owns the product database. Only a component that
    #: MIGRATES the schema has a meaningful `runs_against` / `migrates` window;
    #: for anything else the four numbers would be a claim about a database it
    #: never touches. The ontology sidecar ships its own read-only graph
    #: (`ontology.db`) and never migrates the server's schema.
    has_schema_window: bool


_SERVER_PROFILE = ComponentProfile(
    typ="AD-SERVER-RELEASE",
    entrypoint=(
        "{slot}/asset-discovery-server/asset-discovery-server",
        "serve",
        "--host",
        # S104 is about a service unintentionally exposed on every interface.
        # Here the interface IS the container boundary: the process binds inside
        # its own network namespace and is reachable only through the ingress in
        # front of it.
        "0.0.0.0",  # noqa: S104 - binds inside a container, not on a host NIC
        "--port",
        "{port}",
        "--tls-terminated",
    ),
    port=8000,
    ready_path="/api/ready",
    supervised=True,
    has_schema_window=True,
)

#: Read from the sidecar's own source, not invented here: `Dockerfile` declares
#: `EXPOSE 8080` and `CMD ["serve-ontology"]`, and `src/asset_ontology/serve.py`
#: serves `/health`. It carries a ~107MB read-only `ontology.db` and migrates
#: nothing, hence `has_schema_window=False`.
_ONTOLOGY_PROFILE = ComponentProfile(
    typ="AD-ONTOLOGY-RELEASE",
    entrypoint=("{slot}/asset-ontology/serve-ontology",),
    # 8090, NOT the 8080 its own Dockerfile EXPOSEs. That number is right for a
    # standalone container and wrong here: inside the supervisor container nginx
    # already binds 8080 as the ingress, so a child told to take 8080 can never
    # start. The server profile uses 8000 and never met this.
    #
    # The service reads ONTOLOGY_PORT (defaulting to 8080), so the deployment
    # template sets it to match — see install.bicep. Manifest and env have to
    # agree: the supervisor probes and proxies the port the MANIFEST names, and
    # the application binds the port the ENV names.
    port=8090,
    ready_path="/health",
    supervised=True,
    has_schema_window=False,
)

#: The two RELAYED components (ADR-0039). Nothing supervises them: the
#: customer's server fetches the archive and serves it to a machine, whose own
#: installer (`install.sh` / `install.ps1`, shipped inside the archive) puts the
#: binary under systemd or a Windows service. So no entrypoint, no port, no
#: readiness path — and no schema window either, since neither touches the
#: product database.
#:
#: They keep their EXISTING signing keys, which are already compiled into the
#: customer's server (`server/releases/source.py::release_public_key`). This
#: adds a manifest around an artifact that was already built and already signed;
#: it does not introduce a new trust root.
_SATELLITE_PROFILE = ComponentProfile(
    typ="AD-SATELLITE-RELEASE",
    supervised=False,
    entrypoint=None,
    port=None,
    ready_path=None,
    has_schema_window=False,
)

_AGENT_PROFILE = ComponentProfile(
    typ="AD-AGENT-RELEASE",
    supervised=False,
    entrypoint=None,
    port=None,
    ready_path=None,
    has_schema_window=False,
)

PROFILES: dict[str, ComponentProfile] = {
    "server": _SERVER_PROFILE,
    "ontology": _ONTOLOGY_PROFILE,
    "satellite": _SATELLITE_PROFILE,
    "agent": _AGENT_PROFILE,
}


def _validate_profile_shape(component: str, profile: ComponentProfile) -> None:
    """A profile must be entirely supervised or entirely not — never half.

    Extracted so the invariant has a name and can be tested directly. The two
    halves fail differently and both matter:

    * a SUPERVISED component missing an entrypoint, port or readiness path
      produces a manifest the thin layer cannot start;
    * a RELAYED component CARRYING one is a profile somebody edited without
      deciding which kind of component it is, and a manifest naming a port
      nothing binds is a lie a reader would reasonably believe.

    The second is refused rather than ignored for that reason.
    """
    if profile.supervised:
        if not profile.ready_path or not profile.ready_path.startswith("/"):
            raise ReleaseManifestError(
                f"ready_path must start with '/': {profile.ready_path!r} (component {component!r})"
            )
        if profile.port is None or not 1 <= profile.port <= 65535:
            raise ReleaseManifestError(
                f"port out of range: {profile.port} (component {component!r})"
            )
        if not profile.entrypoint:
            raise ReleaseManifestError(
                f"a supervised component needs an entrypoint (component {component!r})"
            )
        return
    if profile.entrypoint or profile.port or profile.ready_path:
        raise ReleaseManifestError(
            f"component {component!r} is not supervised, so it must declare no entrypoint, "
            "port or ready_path — nothing starts it, and those fields would describe a "
            "process that does not exist"
        )


def profile_for(component: str) -> ComponentProfile:
    """The profile for ``component``, or a refusal naming what is registered."""
    try:
        return PROFILES[component]
    except KeyError:
        known = ", ".join(sorted(PROFILES))
        raise ReleaseManifestError(
            f"no build profile for component {component!r}. Known: {known}. A component "
            "is not a label — it decides the entrypoint, port, readiness path and whether "
            "the schema window applies, so a manifest cannot be stamped for one that has "
            "no profile. Register it in write_release_manifest.py::PROFILES."
        ) from None


def build_manifest(
    version: str,
    artifacts: list[Path],
    *,
    require_signature: bool,
    component: str = "server",
    required_settings: tuple[str, ...] = (),
    # entrypoint / port / ready_path are NOT parameters any more. They come from
    # the component's PROFILE, because they are properties of the component and
    # not of the invocation — see PROFILES above. Passing them alongside
    # `component` is exactly how a server build gets stamped `ontology`: every
    # signature and every check still passes, and the manifest is wrong in the
    # one way nothing downstream can detect.
    #
    # The server profile records what a customer install measured the hard way:
    # the frozen artifact is a Typer CLI, so invoked bare it prints help and
    # exits 2 — which the supervisor sees as a child that started and stopped
    #
    #     supervisor.child.probe_failed exit_code=2
    #       reason='child exited before becoming ready'
    #
    # `--host 0.0.0.0` because the CLI default of 127.0.0.1 binds to the
    # container's loopback, where nothing outside — including the platform's own
    # probe — can reach it. `--tls-terminated` because the application refuses to
    # bind without TLS unless told something in front of it terminates TLS.
    # What a FORK is based on, e.g. "v1.2.2". Passed by the build (a tag, a
    # merge-base), never typed on a form: the console joins it to customers to
    # answer "who is running a build without this patch". None on mainline.
    upstream_ref: str | None = None,
    # Injected only by the tests that need a fixture module. Production always
    # reads the real `schema_version.py` next to the application source.
    schema_module: Path | None = None,
) -> dict[str, object]:
    if not version.strip():
        raise ReleaseManifestError("version must not be blank")
    if not artifacts:
        raise ReleaseManifestError("no artifacts given — refusing to write an empty manifest")
    entries = [build_artifact_entry(a, require_signature=require_signature) for a in artifacts]
    # Each archive's `.minisig` is named too, so the console stores and serves
    # it. Appended rather than interleaved so the archives keep their given
    # order, and `bundle_digest` below hashes over BOTH — the signatures are
    # part of what this release IS.
    entries += [e for e in (build_signature_entry(a) for a in artifacts) if e is not None]
    # Refuses an unregistered component — see PROFILES.
    profile = profile_for(component)
    # The profiles are constants, so these can only fire on a badly written one.
    # They are kept because a profile is the thing a new component author adds,
    # and a readiness path without a leading slash produces a supervisor that
    # probes the wrong URL forever rather than an error anyone can read.
    _validate_profile_shape(component, profile)
    # The digest of the release as a whole — what a deployment reports as
    # ASSDISC_BUNDLE_DIGEST, and what the fleet table compares against to tell a
    # deployment running what we think it is from one that is not.
    bundle = hashlib.sha256()
    for e in entries:
        bundle.update(e.sha256.encode())
    manifest: dict[str, object] = {
        "typ": profile.typ,
        "version": version,
        "component": component,
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "bundle_digest": "sha256:" + bundle.hexdigest(),
        # NAMES ONLY. What the release cannot start without — never what the
        # values are. Values exist solely in the customer's key vault; putting
        # one here would ship a customer's credential inside an artifact that
        # every customer receives.
        "required_settings": list(required_settings),
        "artifacts": [e.to_dict() for e in entries],
    }
    # The four schema numbers, read out of the source tree. ALL FOUR OR NONE —
    # the parser on the far side refuses a partial set, because three-of-four is
    # not an older release, it is a broken newer one.
    #
    # Emitted only for a component that OWNS the product database. For anything
    # else they would be a claim about a schema it never touches: the ontology
    # sidecar ships its own read-only graph and migrates nothing, so stamping a
    # migration range on it would invite the console's two-question guard to
    # reason about a migration that cannot happen. Absent is the honest value,
    # and the manifest parser already treats absent as "pre-v2 / unstated".
    # How the thin layer actually RUNS this release. It cannot know these
    # itself: the image is a runtime, and the entrypoint belongs to the
    # application that was packaged. `{slot}` is substituted with the unpacked
    # slot directory.
    #
    # Omitted entirely for a relayed component. Absent is the honest value —
    # the same choice the schema window already makes below — and it is what
    # lets a reader tell "nothing starts this" from "this starts on port 0".
    if profile.supervised:
        manifest["entrypoint"] = list(profile.entrypoint or ())
        manifest["port"] = profile.port
        manifest["ready_path"] = profile.ready_path
    if profile.has_schema_window:
        schema = read_schema_constants(schema_module)
        manifest["runs_against_min"] = schema["RUNS_AGAINST_MIN"]
        manifest["runs_against_max"] = schema["RUNS_AGAINST_MAX"]
        manifest["migrates_from_min"] = schema["MIGRATES_FROM_MIN"]
        manifest["migrates_to"] = schema["MIGRATES_TO"]
    if upstream_ref:
        manifest["upstream_ref"] = upstream_ref
    return manifest


def write_manifest(manifest: dict[str, object], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def _log(msg: str) -> None:
    """Human-readable progress to stdout — the feed an operator/CI run reads."""
    print(f"[release-manifest] {msg}", flush=True)


def _build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Write release.json (path/size/sha256/signature per artifact) for the "
        "server release artifacts already built on disk."
    )
    ap.add_argument("--version", required=True, help="release version, e.g. 0.1.0")
    ap.add_argument(
        "--component",
        default="server",
        help=(
            "which component this release IS. Selects a build PROFILE (entrypoint, port, "
            "readiness path, whether the schema window applies) — not just a label, so a "
            "server build cannot be stamped as another component. Known: "
            + ", ".join(sorted(PROFILES))
        ),
    )
    ap.add_argument("--output", required=True, type=Path, help="release.json path to write")
    ap.add_argument(
        "--require-signatures",
        action="store_true",
        help="fail if any artifact has no sibling .minisig (use after the sign job has run)",
    )
    ap.add_argument(
        "--required-setting",
        action="append",
        default=[],
        metavar="NAME",
        dest="required_settings",
        help="NAME of an application setting this release cannot start without "
        "(repeatable). NAMES ONLY — never a value: this manifest ships to every "
        "customer, and their values live only in their own key vault.",
    )
    ap.add_argument(
        "--upstream-ref",
        default="",
        metavar="REF",
        help="what a FORK is based on, e.g. v1.2.2 (mainline builds omit it). Recorded so "
        "the console can answer 'who is running a build without this patch'.",
    )
    ap.add_argument("artifacts", nargs="+", type=Path, help="artifact file(s) to describe")
    return ap


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    _log(f"describing {len(args.artifacts)} artifact(s) for version {args.version}")
    if args.required_settings:
        _log(f"required settings (names only): {', '.join(args.required_settings)}")
    else:
        _log(
            "WARNING: no --required-setting given — this release declares that it needs "
            "nothing, so a deployment missing its database URL or master key will start "
            "and fail rather than being refused with a useful message"
        )
    try:
        manifest = build_manifest(
            args.version,
            args.artifacts,
            require_signature=args.require_signatures,
            component=args.component,
            required_settings=tuple(args.required_settings),
            upstream_ref=args.upstream_ref or None,
        )
    except ReleaseManifestError as exc:
        print(f"[release-manifest] ERROR: {exc}", file=sys.stderr)
        return 1
    _log(f"component: {manifest['component']} (typ {manifest['typ']})")
    if "runs_against_min" in manifest:
        _log(
            "schema window (read from the source tree, not typed): runs against "
            f"{manifest['runs_against_min']}-{manifest['runs_against_max']}, migrates from "
            f"{manifest['migrates_from_min']} to {manifest['migrates_to']}"
        )
    else:
        _log(
            f"no schema window: {manifest['component']} does not own the product database, "
            "so a migration range would be a claim about a schema it never touches"
        )
    if manifest.get("upstream_ref"):
        _log(f"fork build based on {manifest['upstream_ref']}")
    artifacts = manifest["artifacts"]
    assert isinstance(artifacts, list)
    for entry in artifacts:
        assert isinstance(entry, dict)
        _log(f"{entry['name']}: {entry['size']} bytes, sha256={entry['sha256'][:12]}…")
    write_manifest(manifest, args.output)
    _log(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
