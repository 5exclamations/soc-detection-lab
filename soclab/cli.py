"""soclab command line: generate | ingest | detect | validate | alerts | investigate | pivot | sql | run-all"""
from __future__ import annotations

import argparse
import json
import sys

from . import db, generator, ingest, validate
from .engine import Engine, build_incidents
from .paths import DB_PATH, RAW_DIR, REPORTS_DIR, RULES_DIR
from .sigma import load_rules


def _conn(a): return db.connect(a.db)


def cmd_generate(a):
    print(json.dumps(generator.generate(RAW_DIR, a.seed, a.days)))


def cmd_ingest(a):
    c = _conn(a)
    print(json.dumps(ingest.ingest_dir(RAW_DIR, c)))
    if (RAW_DIR / "labels.jsonl").exists():
        ingest.ingest_labels(RAW_DIR, c)


def run_detection(conn):
    alerts = Engine(load_rules(RULES_DIR)).run(db.load_events(conn))
    incidents = build_incidents(alerts)
    db.save_alerts(conn, alerts, incidents)
    return alerts, incidents


def cmd_detect(a):
    alerts, inc = run_detection(_conn(a))
    print(f"{len(alerts)} alerts, {len(inc)} incidents")


def run_validation(conn):
    labels = [{"event_id": r["event_id"], "scenario": r["scenario"], "malicious": bool(r["malicious"]),
               "expected_rules": json.loads(r["expected_rules"])} for r in conn.execute("SELECT * FROM labels")]
    scns = [dict(r) for r in conn.execute("SELECT * FROM scenarios")]
    rules = [r.rule_id for r in load_rules(RULES_DIR).values() if r.alerting]
    return validate.evaluate(db.load_alerts(conn), labels, scns, rules)


def cmd_validate(a):
    rep = run_validation(_conn(a))
    REPORTS_DIR.mkdir(exist_ok=True)
    (REPORTS_DIR / "validation.json").write_text(json.dumps(rep, indent=2) + "\n")
    (REPORTS_DIR / "validation.md").write_text(validate.to_markdown(rep))
    print(validate.to_markdown(rep))


def cmd_alerts(a):
    for al in db.load_alerts(_conn(a)):
        if a.id and al["alert_id"] != a.id:
            continue
        print(f"{al['alert_id']} [{al['severity'].upper()}] {al['rule_id']} {al['first_seen']}  {al['rule_name']}")
        if a.id:
            print(" ", al["explanation"], "\n  MITRE:", al["mitre"], "\n  Runbook:", al["runbook"])
            for t in al["timeline"]:
                print("   ", t["ts"], t["event_id"], t["summary"])


def cmd_investigate(a):
    c = _conn(a)
    inc = next((i for i in db.load_incidents(c) if i["incident_id"] == a.incident), None)
    if not inc:
        sys.exit("unknown incident")
    alerts = {x["alert_id"]: x for x in db.load_alerts(c)}
    print(f"{inc['incident_id']} [{inc['severity'].upper()}] {inc['first_seen']} -> {inc['last_seen']}  ({inc['severity_reason']})")
    print("Tactics:", ", ".join(inc["tactics"]), "\nEntities:", json.dumps(inc["entities"]))
    print("\nTimeline:")
    seen = {}
    for i in inc["alert_ids"]:
        for t in alerts[i]["timeline"]:
            seen.setdefault(t["event_id"], [t["ts"], t["summary"], []])[2].append(alerts[i]["rule_id"])
    for eid, (ts, summ, rl) in sorted(seen.items(), key=lambda kv: kv[1][0]):
        print(" ", ts, eid, summ, "<=", ",".join(sorted(set(rl))))
    print("\nAlerts / runbooks:")
    for i in inc["alert_ids"]:
        print(f"  {i} [{alerts[i]['severity']}] {alerts[i]['rule_id']}: {alerts[i]['explanation']}  -> {alerts[i]['runbook']}")
    for ip in [x for x in inc["entities"].get("src_ip", []) if not x.startswith("10.")][:3]:
        print(f"\nPivot ip={ip}: events by source")
        for r in c.execute("SELECT source, COUNT(*) n, MIN(ts) a, MAX(ts) b FROM events WHERE src_ip=? GROUP BY source", (ip,)):
            print("  ", r["source"], r["n"], r["a"], r["b"])


def cmd_pivot(a):
    col, val = ("src_ip", a.ip) if a.ip else ("user", a.user)
    for r in _conn(a).execute(f"SELECT ts, source, action, outcome, user, src_ip, http_path FROM events WHERE {col}=? ORDER BY epoch LIMIT ?", (val, a.limit)):
        print(*tuple(r))


def cmd_sql(a):
    q = open(a.query).read() if a.query.endswith(".sql") else a.query
    for r in _conn(a).execute(q):
        print(" | ".join(str(x) for x in tuple(r)))


def cmd_docs(a):
    from . import docgen
    docgen.write_all(); print("docs generated")


def cmd_fixtures(a):
    from . import testcases
    from .paths import DATASETS_DIR
    print(testcases.export(DATASETS_DIR), "fixture files written")


def cmd_all(a):
    cmd_generate(a); cmd_ingest(a); cmd_detect(a); cmd_validate(a)


def main(argv=None):
    p = argparse.ArgumentParser(prog="soclab")
    p.add_argument("--db", default=str(DB_PATH))
    p.add_argument("--seed", type=int, default=generator.DEFAULT_SEED)
    p.add_argument("--days", type=int, default=3)
    sp = p.add_subparsers(dest="cmd", required=True)
    for n, f in (("generate", cmd_generate), ("ingest", cmd_ingest), ("detect", cmd_detect),
                 ("validate", cmd_validate), ("run-all", cmd_all), ("docs", cmd_docs), ("fixtures", cmd_fixtures)):
        sp.add_parser(n).set_defaults(fn=f)
    s = sp.add_parser("alerts"); s.add_argument("--id"); s.set_defaults(fn=cmd_alerts)
    s = sp.add_parser("investigate"); s.add_argument("incident"); s.set_defaults(fn=cmd_investigate)
    s = sp.add_parser("pivot"); s.add_argument("--ip"); s.add_argument("--user"); s.add_argument("--limit", type=int, default=50); s.set_defaults(fn=cmd_pivot)
    s = sp.add_parser("sql"); s.add_argument("query"); s.set_defaults(fn=cmd_sql)
    a = p.parse_args(argv)
    a.fn(a)
