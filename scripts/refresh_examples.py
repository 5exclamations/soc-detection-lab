"""Regenerate the captured terminal output in docs/examples and docs/investigations from a fresh run.

Run: python -m soclab run-all && python scripts/refresh_examples.py   (tests fail if these files go stale)
"""
import contextlib, io, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from soclab.cli import main  # noqa: E402


INCIDENT_HEAD_LINES = 14


def capture(*argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        main(list(argv))
    return buf.getvalue()


if __name__ == "__main__":
    inv = capture("investigate", "INC-0022")
    (ROOT / "docs/investigations/chain-01-output.txt").write_text(inv, encoding="utf-8")
    (ROOT / "docs/examples/incident-head.txt").write_text("".join(inv.splitlines(True)[:INCIDENT_HEAD_LINES]), encoding="utf-8")
    (ROOT / "docs/examples/alert-detail.txt").write_text(capture("alerts", "--id", "ALR-0013"), encoding="utf-8")
    print("examples refreshed")
