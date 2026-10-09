import pytest
from soclab.engine import Engine
from soclab.paths import RULES_DIR
from soclab.sigma import load_rules
from soclab.testcases import cases

RULES = load_rules(RULES_DIR)
CASES = [(r, k, n, evs) for r, ks in cases().items() for k, cs in ks.items() for n, evs in cs.items()]


@pytest.mark.parametrize("rule,kind,name,events", CASES, ids=[f"{c[0]}-{c[1]}-{c[2]}" for c in CASES])
def test_fixture(rule, kind, name, events):
    fired = {a["rule_id"] for a in Engine(RULES).run(events)}
    assert (rule in fired) == (kind == "positive"), f"{rule} fired={rule in fired} on {kind} case {name}"


def test_every_alerting_rule_has_positive_and_negative_cases():
    c = cases()
    for r in RULES.values():
        if r.alerting:
            assert c[r.rule_id]["positive"], r.rule_id
            assert c[r.rule_id]["negative"], r.rule_id
