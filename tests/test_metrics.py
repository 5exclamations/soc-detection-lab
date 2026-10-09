"""Protect the metric definitions with hand-computed cases."""
import json
from soclab.validate import evaluate

SC = [{"scenario": "A1", "category": "attack"}, {"scenario": "A2", "category": "attack"},
      {"scenario": "E1", "category": "evasion"}, {"scenario": "H1", "category": "hard_negative"},
      {"scenario": "H2", "category": "hard_negative"}]
L = [  # event, scenario, malicious, expected
    ("e1", "A1", True, ["R1"]), ("e2", "A1", True, ["R2"]), ("e3", "A2", True, ["R1"]),
    ("e4", "E1", True, ["R1"]), ("e5", "H1", False, []), ("e6", "H2", False, [])]
LABELS = [dict(event_id=e, scenario=s, malicious=m, expected_rules=x) for e, s, m, x in L]


def alert(i, rule, *evs):
    return {"alert_id": f"ALR-{i}", "rule_id": rule, "evidence_event_ids": list(evs)}


def run(alerts):
    return evaluate(alerts, LABELS, SC, ["R1", "R2"])


def test_hand_computed_case():
    alerts = [alert(1, "R1", "e1"),          # TP  (A1,R1)
              alert(2, "R1", "e1", "e2"),    # TP  duplicate alert for the same pair: counts as TP alert, one detection
              alert(3, "R2", "e3"),          # FP  rule not expected on A2 event (unexpected_on_attack)
              alert(4, "R1", "e5"),          # FP  hard negative H1
              alert(5, "R1", "zzz")]         # FP  no labeled evidence (baseline noise)
    r = run(alerts)
    o = r["overall"]
    assert (o["tp_alerts"], o["fp_alerts"]) == (2, 3)
    assert o["precision"] == 0.4
    # expected pairs: (A1,R1) (A1,R2) (A2,R1) (E1,R1); only (A1,R1) detected
    assert (o["expected_pairs"], o["detected_pairs"], o["fn"]) == (4, 1, 3)
    assert o["recall"] == 0.25
    assert {f["context"].split(":")[0] for f in r["false_positives"]} == {"unexpected_on_attack", "hard_negative", "baseline_noise"}
    sm = r["scenario_confusion"]
    assert (sm["tp"], sm["fn"], sm["fp"], sm["tn"]) == (1, 2, 1, 1)   # A1 / A2,E1 / H1 / H2
    assert sm["scenarios"] == len(SC)


def test_no_alerts():
    r = run([])
    assert r["overall"]["precision"] is None and r["overall"]["recall"] == 0.0
    assert r["scenario_confusion"]["fn"] == 3 and r["scenario_confusion"]["tn"] == 2


def test_perfect_case():
    r = run([alert(1, "R1", "e1"), alert(2, "R2", "e2"), alert(3, "R1", "e3"), alert(4, "R1", "e4")])
    assert r["overall"]["precision"] == 1.0 and r["overall"]["recall"] == 1.0
    assert r["scenario_confusion"]["fp"] == 0 and r["scenario_confusion"]["tn"] == 2
