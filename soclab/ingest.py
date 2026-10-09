"""Ingest raw JSONL logs into the normalized store."""
from __future__ import annotations

import json
from pathlib import Path

from . import db
from .normalize import ParseError, normalize_line
from .schema import SOURCES


def ingest_dir(raw_dir: Path, conn, reset: bool = True) -> dict:
    if reset:
        db.reset(conn, ("events", "ingest_errors"))
    stats = {}
    for source in SOURCES:
        path = Path(raw_dir) / f"{source}.jsonl"
        ok, bad, events = 0, 0, []
        if not path.exists():
            stats[source] = {"ok": 0, "errors": 0, "missing": True}
            continue
        with path.open() as fh:
            for n, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                try:
                    events.append(normalize_line(source, line, n))
                    ok += 1
                except (ParseError, KeyError, TypeError, ValueError) as exc:
                    bad += 1
                    conn.execute("INSERT INTO ingest_errors VALUES (?,?,?,?)",
                                 (source, n, str(exc), line[:500]))
        db.insert_events(conn, events)
        stats[source] = {"ok": ok, "errors": bad}
    conn.commit()
    return stats


def ingest_labels(raw_dir: Path, conn):
    labels = [json.loads(l) for l in (Path(raw_dir) / "labels.jsonl").read_text().splitlines() if l.strip()]
    scenarios = json.loads((Path(raw_dir) / "scenarios.json").read_text())
    db.save_labels(conn, labels, scenarios)
    return len(labels), len(scenarios)
