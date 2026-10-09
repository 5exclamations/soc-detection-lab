"""SQLite persistence for events, alerts, incidents and labels."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .schema import DDL, FIELDS


def connect(path: Path | str) -> sqlite3.Connection:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.executescript(DDL)
    return conn


def reset(conn: sqlite3.Connection, tables=("events", "ingest_errors", "alerts", "alert_events",
                                            "incidents", "incident_alerts", "labels", "scenarios")):
    for t in tables:
        conn.execute(f"DELETE FROM {t}")
    conn.commit()


def insert_events(conn, events):
    cols = list(FIELDS)
    conn.executemany(
        f"INSERT INTO events ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
        [tuple(e[c] for c in cols) for e in events],
    )
    conn.commit()


def load_events(conn) -> list[dict]:
    return [dict(r) for r in conn.execute("SELECT * FROM events ORDER BY epoch, event_id")]


def save_alerts(conn, alerts, incidents):
    conn.execute("DELETE FROM alerts")
    conn.execute("DELETE FROM alert_events")
    conn.execute("DELETE FROM incidents")
    conn.execute("DELETE FROM incident_alerts")
    for a in alerts:
        conn.execute(
            "INSERT INTO alerts VALUES (?,?,?,?,?,?,?,?,?)",
            (a["alert_id"], a["rule_id"], a["rule_name"], a["severity"], a["first_seen"],
             a["last_seen"], json.dumps(a["entities"]), a["explanation"], json.dumps(a)),
        )
        conn.executemany("INSERT INTO alert_events VALUES (?,?)",
                         [(a["alert_id"], e) for e in a["evidence_event_ids"]])
    for i in incidents:
        conn.execute("INSERT INTO incidents VALUES (?,?,?,?,?,?)",
                     (i["incident_id"], i["severity"], i["first_seen"], i["last_seen"],
                      i["title"], json.dumps(i)))
        conn.executemany("INSERT INTO incident_alerts VALUES (?,?)",
                         [(i["incident_id"], a) for a in i["alert_ids"]])
    conn.commit()


def load_alerts(conn) -> list[dict]:
    return [json.loads(r["body"]) for r in conn.execute("SELECT body FROM alerts ORDER BY first_seen, alert_id")]


def load_incidents(conn) -> list[dict]:
    return [json.loads(r["body"]) for r in conn.execute("SELECT body FROM incidents ORDER BY incident_id")]


def save_labels(conn, labels, scenarios):
    conn.execute("DELETE FROM labels")
    conn.execute("DELETE FROM scenarios")
    conn.executemany("INSERT INTO labels VALUES (?,?,?,?)",
                     [(l["event_id"], l["scenario"], int(l["malicious"]), json.dumps(l["expected_rules"]))
                      for l in labels])
    conn.executemany("INSERT INTO scenarios VALUES (?,?,?,?)",
                     [(s["scenario"], s["category"], s["description"], json.dumps(s["expected_rules"]))
                      for s in scenarios])
    conn.commit()
