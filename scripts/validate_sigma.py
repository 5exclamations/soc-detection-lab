"""Validate rules/*.yml with the official pySigma parser and validators.

Run: pip install -r requirements-dev.txt && python scripts/validate_sigma.py
`attacktag` is skipped because it downloads the ATT&CK catalog at runtime; ATT&CK mappings are
checked offline by `python -m soclab attack-check` instead. Exits non-zero on any parse error or issue.
"""
import sys
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.plugins import InstalledSigmaPlugins
from sigma.validation import SigmaValidator

SKIP = {"attacktag"}
files = sorted((Path(__file__).resolve().parent.parent / "rules").glob("*.yml"))
collection = SigmaCollection.from_yaml("\n---\n".join(f.read_text(encoding="utf-8") for f in files))
validators = {n: c for n, c in InstalledSigmaPlugins.autodiscover().validators.items() if n not in SKIP}
issues = SigmaValidator(list(validators.values())).validate_rules(collection)
print(f"pySigma: {len(collection.rules)} rules/correlations parsed, {len(collection.errors)} parse errors, "
      f"{len(issues)} validator issues ({len(validators)} validators, skipped: {', '.join(sorted(SKIP))})")
for e in collection.errors:
    print("  parse error:", e)
for i in issues:
    print("  issue:", i)
sys.exit(1 if collection.errors or issues else 0)
