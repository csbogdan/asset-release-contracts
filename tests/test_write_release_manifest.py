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


def test_required_settings_carry_names_and_never_values(tmp_path: Path) -> None:
    """The manifest says what a release NEEDS, never what the value is.

    Values live only in the customer's key vault. One in here would ship a
    single customer's credential inside an artifact every customer receives.
    """
    a = _write(tmp_path / "a.tar.zst", b"payload")

    manifest = wrm.build_manifest(
        "0.1.0",
        [a],
        require_signature=False,
        required_settings=("ASSDISC_DATABASE_URL", "ASSDISC_MASTER_KEY"),
    )

    assert manifest["required_settings"] == ["ASSDISC_DATABASE_URL", "ASSDISC_MASTER_KEY"]
    # Names only — nothing that could be a value.
    assert all(isinstance(n, str) for n in manifest["required_settings"])


def test_required_settings_come_from_the_command_line(tmp_path: Path) -> None:
    """CI declares what a release needs; the manifest carries it to the customer.

    The supervisor's side of this already worked — it validates required
    settings against the customer's vault and refuses to start the application
    when one is missing. But nothing ever POPULATED the list, so every published
    manifest declared that the release needed nothing and the check had nothing
    to enforce. A deployment missing its database URL started and died on boot
    instead of being refused with a message naming the problem.
    """
    a = _write(tmp_path / "a.tar.zst", b"payload")
    out = tmp_path / "release.json"

    rc = wrm.main(
        [
            "--version",
            "0.1.0",
            "--output",
            str(out),
            "--required-setting",
            "ASSDISC_DATABASE_URL",
            "--required-setting",
            "ASSDISC_MASTER_KEY",
            str(a),
        ]
    )

    assert rc == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["required_settings"] == ["ASSDISC_DATABASE_URL", "ASSDISC_MASTER_KEY"]


def test_a_manifest_with_no_required_settings_says_so_out_loud(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Declaring nothing is legal but is almost never what was meant."""
    a = _write(tmp_path / "a.tar.zst", b"payload")
    out = tmp_path / "release.json"

    rc = wrm.main(["--version", "0.1.0", "--output", str(out), str(a)])

    assert rc == 0
    assert json.loads(out.read_text(encoding="utf-8"))["required_settings"] == []
    assert "WARNING" in capsys.readouterr().out


def test_the_entrypoint_is_a_complete_command_not_just_the_binary(tmp_path: Path) -> None:
    """A bare binary path starts, prints help, and exits — twice now.

    The frozen artifact is a Typer CLI. Invoked with no subcommand it writes its
    usage to stdout and exits 2, which a supervisor observes as a child that
    started and immediately stopped: `probe_failed exit_code=2, reason='child
    exited before becoming ready'`. Everything upstream of that — fetch, verify,
    digest, unpack — worked perfectly, which is what makes it expensive to
    diagnose and worth pinning here.
    """
    a = _write(tmp_path / "a.tar.zst", b"payload")

    entrypoint = wrm.build_manifest("0.1.0", [a], require_signature=False)["entrypoint"]

    assert isinstance(entrypoint, list)
    assert entrypoint[1] == "serve", "a subcommand is required or the CLI just prints help"
    # Binds inside a container: the CLI default of 127.0.0.1 is unreachable there.
    assert "--host" in entrypoint and "0.0.0.0" in entrypoint
    # The port is substituted from the manifest, never hardcoded twice.
    assert "{port}" in entrypoint
    # The app refuses to bind without TLS unless told the ingress terminates it.
    assert "--tls-terminated" in entrypoint


# --------------------------------------------------------------------------- #
# Delivery v2: the four schema fields come from the SOURCE TREE                 #
# --------------------------------------------------------------------------- #


def test_the_manifest_carries_the_four_schema_fields(tmp_path: Path) -> None:
    """Stamped from ``shared/inventory/schema_version.py``, not from an input.

    They used to be ``--schema-min``/``--schema-max``, typed at workflow
    dispatch, defaulting to "0". A number a human types about a database they
    are not looking at is not a fact, and the fleet check comparing against it
    never fired once.
    """
    artifact = _write(tmp_path / "server-1.0.0.tar.zst", b"x")
    manifest = wrm.build_manifest("1.0.0", [artifact], require_signature=False)

    constants = wrm.read_schema_constants()
    assert manifest["runs_against_min"] == constants["RUNS_AGAINST_MIN"]
    assert manifest["runs_against_max"] == constants["RUNS_AGAINST_MAX"]
    assert manifest["migrates_from_min"] == constants["MIGRATES_FROM_MIN"]
    assert manifest["migrates_to"] == constants["MIGRATES_TO"]


def test_all_four_are_present_or_the_build_fails(tmp_path: Path) -> None:
    """Never three. A partial set is refused by every parser downstream, so a
    writer that could emit one would produce an unusable signed release."""
    artifact = _write(tmp_path / "server-1.0.0.tar.zst", b"x")
    manifest = wrm.build_manifest("1.0.0", [artifact], require_signature=False)

    present = [
        name
        for name in (
            "runs_against_min",
            "runs_against_max",
            "migrates_from_min",
            "migrates_to",
        )
        if name in manifest
    ]
    assert len(present) == 4


def test_the_constants_are_read_without_importing_the_package(tmp_path: Path) -> None:
    """``ast``, not ``import``. The writer runs on a CI runner with no
    ``pip install`` step, because every dependency here becomes a dependency of
    the release."""
    module = tmp_path / "schema_version.py"
    module.write_text(
        "SCHEMA_VERSION: int = 4\n"
        "RUNS_AGAINST_MIN: int = 2\n"
        "RUNS_AGAINST_MAX: int = 4\n"
        "MIGRATES_FROM_MIN: int = 3\n"
        "MIGRATES_TO: int = 4\n",
        encoding="utf-8",
    )

    assert wrm.read_schema_constants(module) == {
        "SCHEMA_VERSION": 4,
        "RUNS_AGAINST_MIN": 2,
        "RUNS_AGAINST_MAX": 4,
        "MIGRATES_FROM_MIN": 3,
        "MIGRATES_TO": 4,
    }


def test_a_missing_constant_fails_loudly(tmp_path: Path) -> None:
    """No fallback. A defaulted value here would be exactly the invented number
    delivery v2 removed — stamped into a SIGNED document, so unfixable after."""
    module = tmp_path / "schema_version.py"
    module.write_text("SCHEMA_VERSION: int = 1\nRUNS_AGAINST_MIN: int = 1\n", encoding="utf-8")

    with pytest.raises(wrm.ReleaseManifestError) as excinfo:
        wrm.read_schema_constants(module)
    assert "MIGRATES_TO" in str(excinfo.value)


def test_a_non_literal_constant_fails_loudly(tmp_path: Path) -> None:
    """``MIGRATES_TO = SCHEMA_VERSION`` reads better and cannot be parsed."""
    module = tmp_path / "schema_version.py"
    module.write_text(
        "SCHEMA_VERSION: int = 1\n"
        "RUNS_AGAINST_MIN: int = 1\n"
        "RUNS_AGAINST_MAX: int = 1\n"
        "MIGRATES_FROM_MIN: int = 1\n"
        "MIGRATES_TO = SCHEMA_VERSION\n",
        encoding="utf-8",
    )

    with pytest.raises(wrm.ReleaseManifestError) as excinfo:
        wrm.read_schema_constants(module)
    assert "integer literal" in str(excinfo.value)


def test_a_missing_schema_module_fails_loudly(tmp_path: Path) -> None:
    with pytest.raises(wrm.ReleaseManifestError) as excinfo:
        wrm.read_schema_constants(tmp_path / "does-not-exist.py")
    assert "does not exist" in str(excinfo.value)


def test_upstream_ref_is_present_only_for_a_fork_build(tmp_path: Path) -> None:
    """A mainline build is based on nothing, and a key present-but-null would
    make every consumer write a null check for a case that cannot happen."""
    artifact = _write(tmp_path / "server-1.0.0.tar.zst", b"x")

    mainline = wrm.build_manifest("1.0.0", [artifact], require_signature=False)
    assert "upstream_ref" not in mainline

    fork = wrm.build_manifest("1.0.0", [artifact], require_signature=False, upstream_ref="v1.2.2")
    assert fork["upstream_ref"] == "v1.2.2"


def test_the_manifest_the_writer_emits_parses_as_the_supervisor_reads_it(
    tmp_path: Path,
) -> None:
    """The two halves of the contract, measured against each other.

    The writer and the parser are in different packages, shipped in different
    artifacts, and a disagreement between them surfaces as an unverifiable
    release on a customer's machine. This is the only test that has both.
    """
    from asset_discovery.shared.release.schema_window import parse_schema_window

    artifact = _write(tmp_path / "server-1.0.0.tar.zst", b"x")
    manifest = wrm.build_manifest("1.0.0", [artifact], require_signature=False)

    window = parse_schema_window(manifest)
    constants = wrm.read_schema_constants()
    assert window.runs_against_min == constants["RUNS_AGAINST_MIN"]
    assert window.migrates_to == constants["MIGRATES_TO"]


# --------------------------------------------------------------------------- #
# A component is a PROFILE, not a label.                                        #
#                                                                               #
# The obvious way to add ontology support is a `--component` flag over the       #
# existing server-shaped defaults. That is the dangerous way: CI would stamp a   #
# SERVER build as `component: ontology` — correctly signed, correctly published, #
# offered to an ontology deployment — and every downstream check would pass,     #
# because the only thing wrong is the one field nothing verifies against the     #
# bytes. So the flag selects entrypoint, port, readiness path and whether the    #
# schema window applies, and an unregistered component is REFUSED.               #
# --------------------------------------------------------------------------- #


def test_the_component_decides_the_shape_not_just_the_label(tmp_path: Path) -> None:
    art = _write(tmp_path / "asset-discovery-server-1.0.0-linux-x86_64.tar.zst", b"x")
    server = wrm.build_manifest("1.0.0", [art], require_signature=False)
    onto = wrm.build_manifest("1.0.0", [art], require_signature=False, component="ontology")

    # The label moved...
    assert server["component"] == "server"
    assert onto["component"] == "ontology"
    # ...and so did everything that decides how it RUNS.
    assert server["entrypoint"] != onto["entrypoint"]
    assert server["port"] != onto["port"]
    assert server["ready_path"] != onto["ready_path"]
    assert server["typ"] != onto["typ"]


def test_an_unregistered_component_is_refused(tmp_path: Path) -> None:
    """Fail closed. A component with no profile has no packaging rules at all,
    so a manifest for it could only be another component's manifest wearing a
    different name.

    The example used to be ``satellite``. It is now a REGISTERED relayed
    component (ADR-0039), so this test needed a genuinely unknown name — a test
    that pins a limitation stops testing anything the moment the limitation is
    lifted, and would have silently become an assertion about nothing.
    """
    art = _write(tmp_path / "asset-discovery-server-1.0.0-linux-x86_64.tar.zst", b"x")
    with pytest.raises(wrm.ReleaseManifestError) as excinfo:
        wrm.build_manifest("1.0.0", [art], require_signature=False, component="collector")
    assert "no build profile" in str(excinfo.value)
    assert "server" in str(excinfo.value)  # names what IS registered
    assert "satellite" in str(excinfo.value)


# --------------------------------------------------------------------------- #
# Relayed components (ADR-0039): nothing supervises them.                      #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("component", ["satellite", "agent"])
def test_a_relayed_component_declares_no_process(tmp_path: Path, component: str) -> None:
    """No entrypoint, no port, no ready_path — because nothing starts it.

    The customer's server hands the archive to a machine, and the installer
    inside the archive puts it under systemd or a Windows service. Emitting a
    port here would be a fact nothing reads and nothing can honour: the same
    shape as a guard that reads a field nothing can set.
    """
    art = _write(tmp_path / f"asset-discovery-{component}-1.0.0-linux-x86_64.tar.gz", b"x")
    manifest = wrm.build_manifest("1.0.0", [art], require_signature=False, component=component)

    assert manifest["component"] == component
    for field in ("entrypoint", "port", "ready_path"):
        assert field not in manifest, f"{component} must not declare {field}"


@pytest.mark.parametrize("component", ["satellite", "agent"])
def test_a_relayed_component_has_no_schema_window(tmp_path: Path, component: str) -> None:
    """Neither owns or migrates the product database."""
    art = _write(tmp_path / f"asset-discovery-{component}-1.0.0-linux-x86_64.tar.gz", b"x")
    manifest = wrm.build_manifest("1.0.0", [art], require_signature=False, component=component)

    for field in ("runs_against_min", "runs_against_max", "migrates_from_min", "migrates_to"):
        assert field not in manifest


def test_every_component_has_its_own_typ(tmp_path: Path) -> None:
    """A shared `typ` across components is a correctly-signed manifest that is
    wrong in the one way nothing downstream detects."""
    art = _write(tmp_path / "asset-discovery-server-1.0.0-linux-x86_64.tar.zst", b"x")
    typs = {
        c: wrm.build_manifest("1.0.0", [art], require_signature=False, component=c)["typ"]
        for c in wrm.PROFILES
    }
    assert len(set(typs.values())) == len(typs), typs


def test_a_relayed_profile_carrying_a_port_is_refused() -> None:
    """A profile that says `supervised=False` and still names a port is one
    somebody edited without deciding what kind of component it is. Refused
    rather than ignored, because a manifest naming a port nothing binds is a
    lie a reader would reasonably believe."""
    bad = wrm.ComponentProfile(
        typ="AD-BROKEN-RELEASE",
        supervised=False,
        entrypoint=None,
        port=9000,
        ready_path=None,
        has_schema_window=False,
    )
    with pytest.raises(wrm.ReleaseManifestError) as excinfo:
        wrm._validate_profile_shape("broken", bad)  # type: ignore[attr-defined]
    assert "not supervised" in str(excinfo.value)


def test_only_a_component_that_owns_the_database_gets_a_schema_window(
    tmp_path: Path,
) -> None:
    """The four numbers are a claim about the PRODUCT DATABASE. The ontology
    sidecar ships its own read-only graph and migrates nothing, so stamping a
    migration range on it would invite the console's two-question guard to
    reason about a migration that cannot happen."""
    art = _write(tmp_path / "asset-discovery-server-1.0.0-linux-x86_64.tar.zst", b"x")
    server = wrm.build_manifest("1.0.0", [art], require_signature=False)
    onto = wrm.build_manifest("1.0.0", [art], require_signature=False, component="ontology")

    for field in ("runs_against_min", "runs_against_max", "migrates_from_min", "migrates_to"):
        assert field in server
        assert field not in onto


def test_the_ontology_profile_matches_the_sidecar_it_describes() -> None:
    """These are read from `assets_llm`, not invented: its Dockerfile declares
    `EXPOSE 8080` and `CMD ["serve-ontology"]`, and `serve.py` serves `/health`.
    If the sidecar moves, this is the test that should fail."""
    profile = wrm.profile_for("ontology")
    assert profile.port == 8080
    assert profile.ready_path == "/health"
    assert any("serve-ontology" in part for part in profile.entrypoint)
    assert profile.has_schema_window is False
