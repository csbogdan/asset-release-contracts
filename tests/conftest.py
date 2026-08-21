"""Give the contract's own tests a schema module to read.

`build_manifest(component="server")` reads four numbers out of the application's
`schema_version.py`. That file lives in the runtime repository, which this
package deliberately does not depend on — so here the tests get a fixture with
the same shape.

This is not a second source of truth. Real builds pass `--schema-module` and
read the application's actual file; a build that silently defaulted these would
stamp a claim about a customer's database that no code ever made, which is the
failure `read_schema_constants` refuses loudly to allow.
"""

from __future__ import annotations

import pytest

from asset_release import writer


@pytest.fixture(autouse=True)
def _schema_fixture(tmp_path_factory, monkeypatch):
    d = tmp_path_factory.mktemp("schema")
    f = d / "schema_version.py"
    f.write_text(
        "SCHEMA_VERSION = 1\n"
        "RUNS_AGAINST_MIN = 1\n"
        "RUNS_AGAINST_MAX = 1\n"
        "MIGRATES_FROM_MIN = 1\n"
        "MIGRATES_TO = 1\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(writer, "_SCHEMA_VERSION_MODULE", f)
