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


def build_manifest(
    version: str,
    artifacts: list[Path],
    *,
    require_signature: bool,
    component: str = "server",
    required_settings: tuple[str, ...] = (),
    # The COMPLETE command, not just the binary. The frozen artifact is a Typer
    # CLI: invoked bare it prints its help and exits 2, which a supervisor sees
    # as a child that started and immediately stopped. Measured on a customer
    # install — the release was fetched, verified, unpacked and exec'd perfectly,
    # and the application printed usage:
    #
    #     supervisor.child.probe_failed exit_code=2
    #       reason='child exited before becoming ready'
    #
    # `--host 0.0.0.0` because it binds inside a container and the CLI default is
    # 127.0.0.1, which nothing outside the container could reach.
    #
    # `--tls-terminated` because the application REFUSES to bind without TLS
    # unless told something in front of it terminates TLS. Every supported
    # deployment puts it behind an ingress that does exactly that, which is what
    # makes this the honest flag rather than --insecure-allow-http — that one
    # exists for development and renders a warning on every page.
    entrypoint: tuple[str, ...] = (
        "{slot}/asset-discovery-server/asset-discovery-server",
        "serve",
        "--host",
        # S104 is about a service unintentionally exposed on every interface.
        # Here the interface IS the container boundary: the process binds inside
        # its own network namespace and is reachable only through the ingress in
        # front of it. The CLI default of 127.0.0.1 would bind to the container's
        # loopback, where nothing outside the container — including the
        # platform's own health probe — could ever reach it.
        "0.0.0.0",  # noqa: S104 - binds inside a container, not on a host NIC
        "--port",
        "{port}",
        "--tls-terminated",
    ),
    port: int = 8000,
    ready_path: str = "/api/ready",
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
    if not ready_path.startswith("/"):
        raise ReleaseManifestError(f"ready_path must start with '/': {ready_path!r}")
    if not 1 <= port <= 65535:
        raise ReleaseManifestError(f"port out of range: {port}")
    # The digest of the release as a whole — what a deployment reports as
    # ASSDISC_BUNDLE_DIGEST, and what the fleet table compares against to tell a
    # deployment running what we think it is from one that is not.
    bundle = hashlib.sha256()
    for e in entries:
        bundle.update(e.sha256.encode())
    schema = read_schema_constants(schema_module)
    manifest: dict[str, object] = {
        "typ": "AD-SERVER-RELEASE",
        "version": version,
        "component": component,
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        # How the thin layer actually RUNS this release. It cannot know these
        # itself: the image is a runtime, and the entrypoint belongs to the
        # application that was packaged. `{slot}` is substituted with the
        # unpacked slot directory.
        "entrypoint": list(entrypoint),
        "port": port,
        "ready_path": ready_path,
        "bundle_digest": "sha256:" + bundle.hexdigest(),
        # NAMES ONLY. What the release cannot start without — never what the
        # values are. Values exist solely in the customer's key vault; putting
        # one here would ship a customer's credential inside an artifact that
        # every customer receives.
        "required_settings": list(required_settings),
        "artifacts": [e.to_dict() for e in entries],
        # The four schema numbers, read out of the source tree above. All four
        # or none — the parser on the far side refuses a partial set, because
        # three-of-four is not an older release, it is a broken newer one.
        "runs_against_min": schema["RUNS_AGAINST_MIN"],
        "runs_against_max": schema["RUNS_AGAINST_MAX"],
        "migrates_from_min": schema["MIGRATES_FROM_MIN"],
        "migrates_to": schema["MIGRATES_TO"],
    }
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
            required_settings=tuple(args.required_settings),
            upstream_ref=args.upstream_ref or None,
        )
    except ReleaseManifestError as exc:
        print(f"[release-manifest] ERROR: {exc}", file=sys.stderr)
        return 1
    _log(
        "schema window (read from the source tree, not typed): runs against "
        f"{manifest['runs_against_min']}-{manifest['runs_against_max']}, migrates from "
        f"{manifest['migrates_from_min']} to {manifest['migrates_to']}"
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
