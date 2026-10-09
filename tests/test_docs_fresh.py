"""Documentation that quotes real command output / links must not drift from the code."""
import contextlib
import io
import re

import pytest

from soclab import cli, db, generator, ingest
from soclab.paths import DOCS_DIR, ROOT
from soclab.sigma import load_rules
from soclab.paths import RULES_DIR


def _slug(heading: str) -> str:  # GitHub heading anchor rule (sufficient for our ASCII headings)
    return re.sub(r"[^a-z0-9 _-]", "", heading.strip().lower()).replace(" ", "-")


def test_runbook_links_resolve_to_headings():
    # Regression: headings like "## SOC-CLOUD-003 (admin policy ...)" produced anchors that did not match x-soclab.runbook.
    for r in (r for r in load_rules(RULES_DIR).values() if r.alerting):
        path, _, anchor = r.ext["runbook"].partition("#")
        text = (ROOT / path).read_text(encoding="utf-8")
        anchors = {_slug(m.group(1)) for m in re.finditer(r"^#+ (.+)$", text, re.M)}
        assert anchor in anchors, f"{r.rule_id}: {r.ext['runbook']} does not resolve (have {sorted(anchors)})"


@pytest.fixture(scope="module")
def conn(tmp_path_factory):
    d = tmp_path_factory.mktemp("fresh")
    generator.generate(d / "raw")
    c = db.connect(d / "t.db")
    ingest.ingest_dir(d / "raw", c)
    ingest.ingest_labels(d / "raw", c)
    cli.run_detection(c)
    return d / "t.db"


def _run(dbpath, *argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        cli.main(["--db", str(dbpath), *argv])
    return buf.getvalue()


def test_documented_investigation_output_matches_real_output(conn):
    inv = _run(conn, "investigate", "INC-0022")
    assert inv == (DOCS_DIR / "investigations/chain-01-output.txt").read_text(encoding="utf-8")
    assert "".join(inv.splitlines(True)[:14]) == (DOCS_DIR / "examples/incident-head.txt").read_text(encoding="utf-8")
    assert _run(conn, "alerts", "--id", "ALR-0013") == (DOCS_DIR / "examples/alert-detail.txt").read_text(encoding="utf-8")


def test_analyst_commands_work(conn):
    assert "ALR-0001" in _run(conn, "alerts")
    assert "203.0.113.50" in _run(conn, "pivot", "--ip", "203.0.113.50", "--limit", "3")
    assert _run(conn, "pivot", "--user", "adm-mpatel", "--limit", "3").strip()
    for f in sorted((ROOT / "sql").glob("*.sql")):
        _run(conn, "sql", str(f))  # every shipped hunting query executes
