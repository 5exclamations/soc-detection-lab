"""A small Sigma-subset evaluator.

Supported
  * detection: named selections (map = AND, list of maps = OR), condition expressions with
    and / or / not / parentheses / "1 of sel*" / "all of them"
  * field modifiers: contains, startswith, endswith, re, all, cidr, gt, gte, lt, lte, exists
  * null matching, '*' and '?' wildcards in plain equality values (case-insensitive)
  * correlation documents: event_count, value_count, temporal_ordered (see engine.py)
Not supported: keyword (field-less) searches, `fieldref`, base64 modifiers, aggregations in
conditions (`| count()`); use correlation documents instead.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

LEVELS = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_COMPARE = {"gt", "gte", "lt", "lte"}
_STRING_OPS = {"contains", "startswith", "endswith", "re", "cidr", "exists"} | _COMPARE


class RuleError(ValueError):
    pass


def parse_timespan(spec) -> int:
    m = re.fullmatch(r"(\d+)\s*([smhd])", str(spec).strip())
    if not m:
        raise RuleError(f"bad timespan {spec!r}")
    return int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


def _wild(pattern: str):
    return re.compile(fnmatch.translate(pattern), re.I)


def _predicate(op: str, expected):
    if op == "exists":
        want = bool(expected)
        return lambda v: (v is not None) == want
    if op == "cidr":
        net = ipaddress.ip_network(expected, strict=False)

        def _cidr(v):
            try:
                return v is not None and ipaddress.ip_address(v) in net
            except ValueError:
                return False
        return _cidr
    if op == "re":
        rx = re.compile(str(expected), re.I)
        return lambda v: v is not None and rx.search(str(v)) is not None
    if op in _COMPARE:
        thr = float(expected)

        def _cmp(v):
            try:
                x = float(v)
            except (TypeError, ValueError):
                return False
            return {"gt": x > thr, "gte": x >= thr, "lt": x < thr, "lte": x <= thr}[op]
        return _cmp
    if op in ("contains", "startswith", "endswith"):
        needle = str(expected).lower()
        fn = {"contains": lambda s: needle in s, "startswith": lambda s: s.startswith(needle),
              "endswith": lambda s: s.endswith(needle)}[op]
        return lambda v: v is not None and fn(str(v).lower())
    # plain equality
    if expected is None:
        return lambda v: v is None or v == ""
    if isinstance(expected, bool):
        return lambda v: v is not None and bool(v) == expected and not isinstance(v, str)
    if isinstance(expected, (int, float)):
        def _num(v):
            try:
                return v is not None and float(v) == float(expected)
            except (TypeError, ValueError):
                return False
        return _num
    text = str(expected)
    if "*" in text or "?" in text:
        rx = _wild(text)
        return lambda v: v is not None and rx.match(str(v)) is not None
    low = text.lower()
    return lambda v: v is not None and str(v).lower() == low


def _compile_field(spec: str, value):
    name, *mods = spec.split("|")
    bad = [m for m in mods if m not in _STRING_OPS | {"all"}]
    if bad:
        raise RuleError(f"unsupported modifier(s) {bad} on field {name!r}")
    op = next((m for m in mods if m != "all"), "equals")
    values = value if isinstance(value, list) else [value]
    preds = [_predicate(op, v) for v in values]
    combine = all if "all" in mods else any

    def match(event):
        v = event.get(name)
        return combine(p(v) for p in preds)
    return match


def _compile_selection(sel):
    if isinstance(sel, dict):
        fields = [_compile_field(k, v) for k, v in sel.items()]
        return lambda e: all(f(e) for f in fields)
    if isinstance(sel, list) and all(isinstance(s, dict) for s in sel):
        alts = [_compile_selection(s) for s in sel]
        return lambda e: any(a(e) for a in alts)
    raise RuleError("selections must be maps or lists of maps (keyword searches unsupported)")


_TOKEN = re.compile(r"(?:1|all)\s+of\s+[\w*]+|\(|\)|\w+")


def _compile_condition(expr: str, names: list[str]):
    toks = _TOKEN.findall(expr)
    pos = 0

    def peek():
        return toks[pos] if pos < len(toks) else None

    def eat():
        nonlocal pos
        pos += 1
        return toks[pos - 1]

    def quant(tok):
        q, pat = re.fullmatch(r"(1|all)\s+of\s+([\w*]+)", tok).groups()
        sel = names if pat == "them" else [n for n in names if fnmatch.fnmatch(n, pat)]
        if not sel:
            raise RuleError(f"quantifier {tok!r} matches no selections")
        agg = any if q == "1" else all
        return lambda r: agg(r[n] for n in sel)

    def atom():
        t = peek()
        if t is None:
            raise RuleError(f"unexpected end of condition {expr!r}")
        if t == "(":
            eat()
            f = or_()
            if eat() != ")":
                raise RuleError("missing ')'")
            return f
        eat()
        if re.match(r"(?:1|all)\s+of", t):
            return quant(t)
        if t not in names:
            raise RuleError(f"condition references unknown selection {t!r}")
        return lambda r, n=t: r[n]

    def not_():
        if peek() == "not":
            eat()
            inner = not_()
            return lambda r: not inner(r)
        return atom()

    def and_():
        parts = [not_()]
        while peek() == "and":
            eat()
            parts.append(not_())
        return lambda r: all(p(r) for p in parts)

    def or_():
        parts = [and_()]
        while peek() == "or":
            eat()
            parts.append(and_())
        return lambda r: any(p(r) for p in parts)

    fn = or_()
    if pos != len(toks):
        raise RuleError(f"trailing tokens in condition {expr!r}")
    return fn


def compile_detection(detection: dict):
    det = dict(detection)
    cond = det.pop("condition", None)
    det.pop("timeframe", None)
    if cond is None:
        raise RuleError("detection has no condition")
    sels = {k: _compile_selection(v) for k, v in det.items()}
    conds = [_compile_condition(c, list(sels)) for c in (cond if isinstance(cond, list) else [cond])]

    def match(event):
        results = {n: s(event) for n, s in sels.items()}
        return any(c(results) for c in conds)
    return match


@dataclass
class Rule:
    doc: dict
    path: Path
    kind: str                 # detection | correlation
    name: str
    rule_id: str              # SOC-... identifier
    matcher: object = None
    ext: dict = field(default_factory=dict)

    @property
    def title(self): return self.doc.get("title", self.name)
    @property
    def level(self): return self.doc.get("level", "medium")
    @property
    def alerting(self): return self.ext.get("alert", True)
    @property
    def tags(self): return self.doc.get("tags", [])
    @property
    def techniques(self):
        return sorted({t.split(".", 1)[1].upper() if t.count(".") == 1 else t[len("attack."):].upper()
                       for t in self.tags if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t)})
    @property
    def tactics(self):
        return [t[len("attack."):] for t in self.tags
                if t.startswith("attack.") and not re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t)]


def load_rules(rules_dir: Path) -> dict[str, Rule]:
    rules: dict[str, Rule] = {}
    for path in sorted(Path(rules_dir).rglob("*.yml")):
        for doc in yaml.safe_load_all(path.read_text()):
            if not doc:
                continue
            ext = doc.get("x-soclab", {}) or {}
            if "detection" in doc:
                kind, matcher = "detection", compile_detection(doc["detection"])
            elif "correlation" in doc:
                kind, matcher = "correlation", None
            else:
                raise RuleError(f"{path}: document has neither detection nor correlation")
            name = doc.get("name") or ext.get("rule_id")
            if not name:
                raise RuleError(f"{path}: rule needs a `name` or x-soclab.rule_id")
            if name in rules:
                raise RuleError(f"duplicate rule name {name!r}")
            rules[name] = Rule(doc=doc, path=path, kind=kind, name=name,
                               rule_id=ext.get("rule_id", name), matcher=matcher, ext=ext)
    for r in rules.values():
        if r.kind == "correlation":
            for dep in r.doc["correlation"]["rules"]:
                if dep not in rules:
                    raise RuleError(f"{r.name}: references unknown rule {dep!r}")
    return rules
