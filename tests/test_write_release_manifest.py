"""``deploy/server/write_release_manifest.py`` — the server release.json generator.

Loaded as a module the same way ``tests/test_publish_releases.py`` loads
``deploy/publish/publish_releases.py``: it lives under ``deploy/``, not
``src/``, so it isn't part of the installed ``asset_discovery`` package.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

_MODULE_PATH = (
    Path(__file__).resolve().parents[1] / "deploy" / "server" / "write_release_manifest.py"
)
_spec = importlib.util.spec_from_file_location("write_release_manifest", _MODULE_PATH)
assert _spec is not None and _spec.loader is not None
wrm = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = wrm
_spec.loader.exec_module(wrm)


def _write(path: Path, content: bytes) -> Path:
    path.write_bytes(content)
    return path


def test_sha256_hex_matches_hashlib(tmp_path: Path) -> None:
    artifact = _write(tmp_path / "a.tar.zst", b"some artifact bytes" * 1000)
    assert wrm.sha256_hex(artifact) == hashlib.sha256(artifact.read_bytes()).hexdigest()


def test_sha256_hex_streams_without_loading_whole_file(tmp_path: Path) -> None:
    # Not literally provable without instrumenting the read loop, but a
    # multi-chunk file (> the 1 MiB read size) exercises the loop at least
    # twice, which is the behaviour that matters.
    big = _write(tmp_path / "big.bin", b"\x00" * (1024 * 1024 * 2 + 17))
    assert wrm.sha256_hex(big) == hashlib.sha256(big.read_bytes()).hexdigest()


def test_build_artifact_entry_basic_fields(tmp_path: Path) -> None:
    artifact = _write(tmp_path / "asset-discovery-server-0.1.0-linux-x86_64.tar.zst", b"payload")
    entry = wrm.build_artifact_entry(artifact, require_signature=False)
    assert entry.name == artifact.name
    assert entry.size == len(b"payload")
    assert entry.sha256 == hashlib.sha256(b"payload").hexdigest()
    # The signature is a sibling file the publisher uploads; the manifest
    # names the artifact, and the digest is what a supervisor verifies.
    assert entry.sha256 == wrm.sha256_hex(artifact)


def test_build_artifact_entry_missing_artifact_raises(tmp_path: Path) -> None:
    missing = tmp_path / "nope.tar.zst"
    with pytest.raises(wrm.ReleaseManifestError, match="artifact not found"):
        wrm.build_artifact_entry(missing, require_signature=False)


def test_build_artifact_entry_require_signature_missing_raises(tmp_path: Path) -> None:
    artifact = _write(tmp_path / "a.tar.zst", b"payload")
    with pytest.raises(wrm.ReleaseManifestError, match="no sibling"):
        wrm.build_artifact_entry(artifact, require_signature=True)


def test_build_artifact_entry_require_signature_present_ok(tmp_path: Path) -> None:
    artifact = _write(tmp_path / "a.tar.zst", b"payload")
    _write(tmp_path / "a.tar.zst.minisig", b"fake signature contents")
    entry = wrm.build_artifact_entry(artifact, require_signature=True)
    # The signature is a sibling file the publisher uploads; the manifest
    # names the artifact, and the digest is what a supervisor verifies.
    assert entry.sha256 == wrm.sha256_hex(artifact)


def test_build_manifest_blank_version_raises(tmp_path: Path) -> None:
    artifact = _write(tmp_path / "a.tar.zst", b"payload")
    with pytest.raises(wrm.ReleaseManifestError, match="version"):
        wrm.build_manifest("  ", [artifact], require_signature=False)


def test_build_manifest_no_artifacts_raises() -> None:
    with pytest.raises(wrm.ReleaseManifestError, match="no artifacts"):
        wrm.build_manifest("0.1.0", [], require_signature=False)


def test_build_manifest_shape(tmp_path: Path) -> None:
    a = _write(tmp_path / "asset-discovery-server-0.1.0-linux-x86_64.tar.zst", b"aaa")
    b = _write(tmp_path / "asset-discovery-server-0.1.0-linux-arm64.tar.zst", b"bbbb")
    manifest = wrm.build_manifest("0.1.0", [a, b], require_signature=False)

    assert manifest["typ"] == "AD-SERVER-RELEASE"
    assert manifest["version"] == "0.1.0"
    assert isinstance(manifest["generated_at"], str)
    assert manifest["generated_at"].endswith("Z")  # UTC, ISO 8601

    artifacts = manifest["artifacts"]
    assert isinstance(artifacts, list)
    assert len(artifacts) == 2
    # A NAME, not a build path and not a URL: this document is read on a
    # customer's machine months later, where neither exists.
    assert artifacts[0] == {
        "name": a.name,
        "size": 3,
        "sha256": hashlib.sha256(b"aaa").hexdigest(),
    }
    assert artifacts[1]["size"] == 4


def test_write_manifest_round_trips_through_json(tmp_path: Path) -> None:
    a = _write(tmp_path / "a.tar.zst", b"payload")
    manifest = wrm.build_manifest("0.1.0", [a], require_signature=False)
    out = tmp_path / "nested" / "release.json"
    wrm.write_manifest(manifest, out)

    loaded = json.loads(out.read_text(encoding="utf-8"))
    assert loaded == manifest
    assert out.read_text(encoding="utf-8").endswith("\n")


def test_main_writes_manifest_and_returns_zero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    a = _write(tmp_path / "a.tar.zst", b"payload")
    out = tmp_path / "release.json"

    rc = wrm.main(["--version", "0.1.0", "--output", str(out), str(a)])

    assert rc == 0
    assert out.is_file()
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["version"] == "0.1.0"
    assert len(doc["artifacts"]) == 1
    captured = capsys.readouterr()
    assert "wrote" in captured.out


def test_main_require_signatures_missing_returns_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    a = _write(tmp_path / "a.tar.zst", b"payload")
    out = tmp_path / "release.json"

    rc = wrm.main(["--version", "0.1.0", "--output", str(out), "--require-signatures", str(a)])

    assert rc == 1
    assert not out.exists()
    captured = capsys.readouterr()
    assert "no sibling" in captured.err


def test_main_require_signatures_present_returns_zero(tmp_path: Path) -> None:
    a = _write(tmp_path / "a.tar.zst", b"payload")
    _write(tmp_path / "a.tar.zst.minisig", b"sig")
    out = tmp_path / "release.json"

    rc = wrm.main(["--version", "0.1.0", "--output", str(out), "--require-signatures", str(a)])

    assert rc == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    # --require-signatures still demands a sibling .minisig exists at build
    # time; it simply is not carried in the manifest, because the manifest
    # itself is what gets signed.
    assert doc["artifacts"][0]["name"] == a.name
