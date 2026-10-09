"""Score alerts against the labeled synthetic dataset."""
from __future__ import annotations

from collections import defaultdict


def evaluate(alerts, labels, scenarios, rules_alerting):
    """labels: list of {event_id, scenario, malicious, expected_rules}."""
    lab = {l["event_id"]: l for l in labels}
    cat = {s["scenario"]: s["category"] for s in scenarios}
    expected = set()                       # (scenario, rule)
    for l in labels:
        if l["malicious"]:
            for r in l["expected_rules"]:
                expected.add((l["scenario"], r))
    detected, per = set(), defaultdict(lambda: {"tp": 0, "fp": 0})
    fp_detail = []
    for a in alerts:
        scns = {lab[e]["scenario"] for e in a["evidence_event_ids"] if e in lab}
        hit = {(lab[e]["scenario"], a["rule_id"]) for e in a["evidence_event_ids"]
               if e in lab and lab[e]["malicious"] and a["rule_id"] in lab[e]["expected_rules"]}
        if hit:
            per[a["rule_id"]]["tp"] += 1
            detected |= hit
        else:
            per[a["rule_id"]]["fp"] += 1
            kind = ("hard_negative:" + ",".join(sorted(scns))) if scns else "baseline_noise"
            if any(cat.get(s) in ("attack", "evasion") for s in scns):
                kind = "unexpected_on_attack:" + ",".join(sorted(scns))
            fp_detail.append({"alert_id": a["alert_id"], "rule_id": a["rule_id"], "context": kind})
    fn = sorted(expected - detected)
    rules = {}
    for r in sorted(set(rules_alerting) | set(per)):
        exp = {p for p in expected if p[1] == r}
        det = {p for p in detected if p[1] == r}
        tp, fp = per[r]["tp"], per[r]["fp"]
        rules[r] = {"tp_alerts": tp, "fp_alerts": fp, "expected": len(exp), "detected": len(det),
                    "fn": len(exp - det),
                    "precision": round(tp / (tp + fp), 3) if tp + fp else None,
                    "recall": round(len(det) / len(exp), 3) if exp else None}
    tp = sum(v["tp_alerts"] for v in rules.values()); fp = sum(v["fp_alerts"] for v in rules.values())
    # Scenario-level confusion matrix: one unit (scenario) for all four cells.
    # alerted = at least one alert's evidence overlaps any event labeled with the scenario.
    ev_scn = defaultdict(set)
    for l in labels:
        ev_scn[l["scenario"]].add(l["event_id"])
    alerted = {s for a in alerts for e in a["evidence_event_ids"] if e in lab for s in [lab[e]["scenario"]]}
    mal = {s for s, c in cat.items() if c in ("attack", "evasion")}
    # a malicious scenario counts as detected only if an *expected* (scenario, rule) pair was detected
    det_scn = {s for s, _ in detected}
    sm = {"tp": len(mal & det_scn), "fn": len(mal - det_scn),
          "fp": len((set(cat) - mal) & alerted), "tn": len((set(cat) - mal) - alerted)}
    sm["scenarios"] = sum(sm.values())
    sm["precision"] = round(sm["tp"] / (sm["tp"] + sm["fp"]), 3) if sm["tp"] + sm["fp"] else None
    sm["recall"] = round(sm["tp"] / (sm["tp"] + sm["fn"]), 3) if sm["tp"] + sm["fn"] else None
    return {
        "scenario_confusion": sm,
        "overall": {"alerts": len(alerts), "tp_alerts": tp, "fp_alerts": fp,
                    "expected_pairs": len(expected), "detected_pairs": len(detected), "fn": len(fn),
                    "precision": round(tp / (tp + fp), 3) if tp + fp else None,
                    "recall": round(len(detected) / len(expected), 3) if expected else None},
        "rules": rules, "false_negatives": [{"scenario": s, "rule": r, "category": cat.get(s)} for s, r in fn],
        "false_positives": fp_detail,
    }


def to_markdown(rep):
    o = rep["overall"]
    out = ["# Detection validation report", "",
           f"Labeled synthetic dataset. Alerts: {o['alerts']}; TP alerts {o['tp_alerts']}, FP alerts {o['fp_alerts']}; "
           f"expected (scenario, rule) pairs {o['expected_pairs']}, detected {o['detected_pairs']}, missed {o['fn']}.",
           f"Precision **{o['precision']}**, recall **{o['recall']}**. These measure the rules against *this* synthetic data only.", "",
           "**Units.** Precision = TP alerts / all alerts (unit: alert). Recall = detected / expected (scenario, rule) pairs (unit: pair). "
           "Scenario confusion matrix (unit: scenario): " + ", ".join(f"{k.upper()} {v}" for k, v in rep["scenario_confusion"].items() if k in ("tp", "fp", "fn", "tn"))
           + f"; scenario precision {rep['scenario_confusion']['precision']}, recall {rep['scenario_confusion']['recall']}.", "",
           "| Rule | TP alerts | FP alerts | Expected | Missed | Precision | Recall |", "|---|---|---|---|---|---|---|"]
    for r, v in rep["rules"].items():
        out.append(f"| {r} | {v['tp_alerts']} | {v['fp_alerts']} | {v['expected']} | {v['fn']} | {v['precision']} | {v['recall']} |")
    out += ["", "## False positives", ""] + [f"- {f['alert_id']} {f['rule_id']}: {f['context']}" for f in rep["false_positives"]]
    out += ["", "## False negatives", ""] + [f"- {f['scenario']} ({f['category']}): {f['rule']}" for f in rep["false_negatives"]]
    return "\n".join(out) + "\n"
