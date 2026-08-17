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
  anything is published anywhere. Publishing the server artifact (item 3 in
  the delivery-loop scope) is a separate, not-yet-built piece of work; this
  manifest is what that future publish step would read.

Usage::

    python write_release_manifest.py --version 0.1.0 --output dist/release.json \\
        dist/asset-discovery-server-0.1.0-linux-x86_64.tar.zst

    # Fail if a listed artifact has no sibling .minisig yet (post-sign use):
    python write_release_manifest.py --version 0.1.0 --output dist/release.json \\
        --require-signatures dist/asset-discovery-server-0.1.0-linux-x86_64.tar.zst
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

_SIGNATURE_SUFFIX = ".minisig"


class ReleaseManifestError(Exception):
    """A manifest precondition failed. Always fatal — the caller exits non-zero."""


@dataclass(frozen=True, slots=True)
class ArtifactEntry:
    name: str
    size: int
    sha256: str

    def to_dict(self) -> dict[str, object]:
        return {"name": self.name, "size": self.size, "sha256": self.sha256}


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
    entrypoint: tuple[str, ...] = ("{slot}/asset-discovery-server/asset-discovery-server",),
    port: int = 8000,
    ready_path: str = "/api/ready",
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
    return {
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
        "artifacts": [e.to_dict() for e in entries],
    }


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
    ap.add_argument("artifacts", nargs="+", type=Path, help="artifact file(s) to describe")
    return ap


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    _log(f"describing {len(args.artifacts)} artifact(s) for version {args.version}")
    try:
        manifest = build_manifest(
            args.version, args.artifacts, require_signature=args.require_signatures
        )
    except ReleaseManifestError as exc:
        print(f"[release-manifest] ERROR: {exc}", file=sys.stderr)
        return 1
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
