import json
import shutil

from soclab import attack, docgen
from soclab.paths import RULES_DIR, REPORTS_DIR


def test_rule_mappings_valid_for_pinned_attack_version():
    assert attack.check_rules() == []


def test_revoked_technique_and_retired_tactic_are_rejected(tmp_path):
    # Regression: T1562.008 was revoked (-> T1685.002) and defense-evasion was split in ATT&CK v19.
    for f in RULES_DIR.glob("*.yml"):
        shutil.copy(f, tmp_path / f.name)
    cloud = tmp_path / "cloud.yml"
    cloud.write_text(cloud.read_text().replace("attack.t1685.002", "attack.t1562.008").replace("attack.defense-impairment", "attack.defense-evasion"))
    problems = attack.check_rules(rules_dir=tmp_path)
    assert any("T1562.008" in p for p in problems)
    assert any("defense-evasion" in p for p in problems)


def test_navigator_layer_is_current_and_valid():
    layer = json.loads((REPORTS_DIR / "attack-navigator-layer.json").read_text())
    assert attack.check_layer(layer) == []
    assert layer["versions"]["attack"] == "19"
    assert layer == docgen.navigator()  # committed layer is not stale vs. rules


def test_layer_check_catches_bad_layer():
    bad = {"name": "x", "domain": "enterprise-attack", "versions": {"attack": "16", "navigator": "5", "layer": "4.5"},
           "techniques": [{"techniqueID": "T1562.008", "score": 1}]}
    assert len(attack.check_layer(bad)) == 2
