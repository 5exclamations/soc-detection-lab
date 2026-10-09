"""ATT&CK mapping validation against a pinned subset of the official Enterprise catalog.

The subset (soclab/data/attack_enterprise_subset.json) is generated from MITRE's
attack-stix-data; `python -m soclab attack-check --stix enterprise-attack.json` re-validates
the rules against a full, freshly downloaded catalog (revoked/deprecated techniques included).
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from .paths import RULES_DIR
from .sigma import load_rules

SUBSET_PATH = Path(__file__).parent / "data" / "attack_enterprise_subset.json"
LAYER_VERSION, NAVIGATOR_VERSION = "4.5", "5.3.2"


def load_subset() -> dict:
    return json.loads(SUBSET_PATH.read_text(encoding="utf-8"))


def attack_major(subset: dict | None = None) -> str:
    return (subset or load_subset())["attack_version"].split(".")[0]


def check_rules(subset: dict | None = None, rules_dir: Path = RULES_DIR) -> list[str]:
    """Return problems: unknown/revoked technique, unknown tactic, tactic not valid for any mapped technique."""
    subset = subset or load_subset()
    problems = []
    for r in load_rules(rules_dir).values():
        if not r.alerting:
            continue
        if not r.techniques:
            problems.append(f"{r.rule_id}: no ATT&CK technique tag")
        allowed = set()
        for t in r.techniques:
            info = subset["techniques"].get(t)
            if info is None:
                problems.append(f"{r.rule_id}: {t} is not an active technique in ATT&CK {subset['attack_version']}")
            else:
                allowed |= set(info["tactics"])
        for tac in r.tactics:
            if tac not in subset["tactics"]:
                problems.append(f"{r.rule_id}: unknown tactic {tac!r}")
            elif r.techniques and tac not in allowed:
                problems.append(f"{r.rule_id}: tactic {tac!r} is not a tactic of {', '.join(r.techniques)}")
    return problems


def check_layer(layer: dict, subset: dict | None = None) -> list[str]:
    """Structural check against the Navigator layer format v4.5 fields this lab emits."""
    subset = subset or load_subset()
    p = []
    v = layer.get("versions", {})
    if not all(k in v for k in ("attack", "navigator", "layer")):
        p.append("versions needs attack, navigator, layer")
    if v.get("layer") != LAYER_VERSION:
        p.append(f"layer format {v.get('layer')} != {LAYER_VERSION}")
    if v.get("attack") != attack_major(subset):
        p.append(f"attack version {v.get('attack')} != {attack_major(subset)}")
    if layer.get("domain") != "enterprise-attack":
        p.append("domain must be enterprise-attack")
    if not layer.get("name"):
        p.append("name required")
    for t in layer.get("techniques", []):
        tid = t.get("techniqueID", "")
        if not re.fullmatch(r"T\d{4}(\.\d{3})?", tid):
            p.append(f"bad techniqueID {tid!r}")
        elif tid not in subset["techniques"]:
            p.append(f"{tid} not in ATT&CK {subset['attack_version']} subset")
        if not isinstance(t.get("score", 0), (int, float)):
            p.append(f"{tid}: score must be numeric")
    return p


def check_against_stix(stix_path: str, rules_dir: Path = RULES_DIR, write_subset: bool = False) -> list[str]:
    """Validate rules against a full enterprise-attack.json; optionally rewrite the pinned subset."""
    d = json.loads(Path(stix_path).read_text(encoding="utf-8"))
    ext = lambda o: next((x["external_id"] for x in o.get("external_references", []) if x.get("source_name") == "mitre-attack"), None)
    coll = next(o for o in d["objects"] if o["type"] == "x-mitre-collection")
    active = {ext(o): o for o in d["objects"] if o["type"] == "attack-pattern"
              and not o.get("revoked") and not o.get("x_mitre_deprecated") and ext(o)}
    tactics = sorted(o["x_mitre_shortname"] for o in d["objects"] if o["type"] == "x-mitre-tactic")
    used = sorted({t for r in load_rules(rules_dir).values() if r.alerting for t in r.techniques})
    subset = {"attack_version": coll["x_mitre_version"], "domain": "enterprise-attack",
              "source": "https://github.com/mitre-attack/attack-stix-data (enterprise-attack.json)",
              "note": "Subset of the official catalog limited to techniques referenced by lab rules; regenerate with: "
                      "python -m soclab attack-check --stix <enterprise-attack.json> --write-subset",
              "tactics": tactics, "techniques": {}}
    for t in used:
        if t in active:
            o = active[t]
            name = o["name"] if "." not in t else f"{active[t.split('.')[0]]['name']}: {o['name']}"
            subset["techniques"][t] = {"name": name, "tactics": sorted(p["phase_name"] for p in o["kill_chain_phases"])}
    problems = check_rules(subset, rules_dir)
    if write_subset and not problems:
        SUBSET_PATH.write_text(json.dumps(subset, indent=2) + "\n", encoding="utf-8")
    return problems
