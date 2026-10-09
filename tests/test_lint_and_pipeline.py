import json, re, uuid
import pytest
from soclab import db, generator, ingest
from soclab.cli import run_detection, run_validation
from soclab.paths import RULES_DIR, ROOT
from soclab.sigma import LEVELS, RuleError, compile_detection, load_rules

RULES = load_rules(RULES_DIR)


@pytest.mark.parametrize("rule", [r for r in RULES.values() if r.alerting], ids=lambda r: r.rule_id)
def test_rule_metadata(rule):
    d = rule.doc
    for k in ("title", "id", "status", "description", "logsource", "level", "tags", "falsepositives"):
        assert d.get(k), f"{rule.rule_id} missing {k}"
    uuid.UUID(d["id"])
    assert d["level"] in LEVELS
    assert rule.techniques, "needs an ATT&CK technique tag"
    assert rule.tactics, "needs an ATT&CK tactic tag"
    for k in ("explanation", "runbook", "limitations"):
        assert rule.ext.get(k), f"{rule.rule_id} missing x-soclab.{k}"
    assert re.fullmatch(r"SOC-[A-Z]+-\d{3}", rule.rule_id)


def test_rule_ids_unique():
    ids = [r.rule_id for r in RULES.values()]
    assert len(ids) == len(set(ids))


def test_sigma_condition_errors():
    with pytest.raises(RuleError):
        compile_detection({"s": {"a": 1}, "condition": "s and nope"})
    with pytest.raises(RuleError):
        compile_detection({"s": {"a|bogus": 1}, "condition": "s"})


@pytest.fixture(scope="module")
def pipeline(tmp_path_factory):
    d = tmp_path_factory.mktemp("lab")
    generator.generate(d / "raw")
    conn = db.connect(d / "t.db")
    stats = ingest.ingest_dir(d / "raw", conn)
    ingest.ingest_labels(d / "raw", conn)
    alerts, incidents = run_detection(conn)
    return stats, alerts, incidents, run_validation(conn)


def test_ingest_counts_and_errors(pipeline):
    stats = pipeline[0]
    assert stats["web"]["errors"] == 1 and stats["auth"]["errors"] == 1
    assert sum(s["errors"] for s in stats.values()) == 2


def test_generation_is_deterministic(tmp_path):
    generator.generate(tmp_path / "a"); generator.generate(tmp_path / "b")
    for f in ("auth.jsonl", "api.jsonl", "labels.jsonl"):
        assert (tmp_path / "a" / f).read_text() == (tmp_path / "b" / f).read_text()


def test_alert_shape(pipeline):
    for a in pipeline[1]:
        for k in ("alert_id", "rule_id", "severity", "explanation", "evidence_event_ids", "timeline", "mitre", "runbook"):
            assert a[k], k


def test_chain_becomes_one_critical_incident(pipeline):
    inc = [i for i in pipeline[2] if len(i["rule_ids"]) >= 8]
    assert len(inc) == 1 and inc[0]["severity"] == "critical"


def test_metrics_match_baseline_gate(pipeline):
    """Regression gate: update tests/expected_metrics.json deliberately when rules or data change."""
    rep = pipeline[3]
    exp = json.loads((ROOT / "tests" / "expected_metrics.json").read_text())
    o = rep["overall"]
    assert o["fn"] <= exp["max_false_negatives"]
    assert o["fp_alerts"] <= exp["max_false_positives"]
    assert o["precision"] >= exp["min_precision"] and o["recall"] >= exp["min_recall"]
    assert {(f["scenario"], f["rule"]) for f in rep["false_negatives"]} == {tuple(x) for x in exp["known_false_negatives"]}
    assert not [f for f in rep["false_positives"] if f["context"].startswith(("baseline", "unexpected"))]
