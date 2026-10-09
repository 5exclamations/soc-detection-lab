"""Detection engine: evaluates Sigma detections and correlations, emits alerts and incidents."""
from __future__ import annotations

import ipaddress
from collections import defaultdict, deque
from datetime import datetime, timezone

from .sigma import LEVELS, Rule, RuleError, parse_timespan

LEVEL_NAMES = {v: k for k, v in LEVELS.items()}
PRIVILEGED_PREFIXES = ("adm-", "root")
MAX_EVIDENCE_SAMPLE = 12


class Match:
    """A rule hit: which events, for which group key, and when."""
    __slots__ = ("first", "last", "detected", "key", "ids", "detail")

    def __init__(self, first, last, detected, key, ids, detail=None):
        self.first, self.last, self.detected = first, last, detected
        self.key, self.ids, self.detail = key, ids, detail or {}


def _fmt_ts(epoch):
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class _Safe(dict):
    def __missing__(self, k):
        return "?"


def summarize_event(e: dict) -> str:
    s = e["source"]
    if s == "auth":
        return f"{e['action']} {e['outcome']} user={e['user']} ip={e['src_ip']} country={e['src_country']} mfa={e['mfa']}"
    if s == "web":
        return f"{e['http_method']} {e['http_path']} -> {e['http_status']} ip={e['src_ip']} ua={e['user_agent']}"
    if s == "api":
        return (f"{e['http_method']} {e['http_path']} -> {e['http_status']} key={e['api_key_id']} "
                f"user={e['user']} ip={e['src_ip']} bytes={e['bytes_out']}")
    if s == "admin":
        return f"{e['action']} actor={e['user']} target={e['target']} role={e['target_role']} ticket={e['ticket']} host={e['host']}"
    return (f"{e['cloud_event']} user={e['user']} ip={e['src_ip']} target={e['target']} "
            f"mfa={e['mfa']} error={e['cloud_error']}")


class Engine:
    def __init__(self, rules: dict[str, Rule]):
        self.rules = rules
        self._cache: dict = {}
        self.events: list[dict] = []
        self.by_id: dict[str, dict] = {}

    # ---------- evaluation ----------
    def run(self, events: list[dict]) -> list[dict]:
        self.events = sorted(events, key=lambda e: (e["epoch"], e["event_id"]))
        self.by_id = {e["event_id"]: e for e in self.events}
        self._cache = {}
        raw = []
        for rule in self.rules.values():
            if not rule.alerting:
                continue
            gb = tuple(rule.doc["correlation"].get("group-by", ())) if rule.kind == "correlation" else ()
            for m in self._eval(rule.name, gb):
                raw.append((rule, m))
        raw.sort(key=lambda rm: (rm[1].detected, rm[0].rule_id))
        alerts = [self._alert(i + 1, r, m) for i, (r, m) in enumerate(raw)]
        return alerts

    def _eval(self, name: str, group_by: tuple) -> list[Match]:
        ck = (name, group_by)
        if ck in self._cache:
            return self._cache[ck]
        rule = self.rules[name]
        if rule.kind == "detection":
            out = []
            for e in self.events:
                if rule.matcher(e):
                    key = tuple(e.get(f) for f in group_by)
                    if group_by and any(k is None for k in key):
                        continue
                    out.append(Match(e["epoch"], e["epoch"], e["epoch"], key, [e["event_id"]]))
        else:
            c = rule.doc["correlation"]
            own_gb = tuple(c.get("group-by", ()))
            if group_by and own_gb != group_by:
                raise RuleError(f"{name}: group-by {own_gb} differs from parent {group_by}")
            typ = c["type"]
            span = parse_timespan(c["timespan"])
            if typ in ("event_count", "value_count"):
                kids = []
                for dep in c["rules"]:
                    if self.rules[dep].kind != "detection":
                        raise RuleError(f"{name}: {typ} must reference detection rules")
                    kids.extend(self._eval(dep, own_gb))
                kids.sort(key=lambda m: m.first)
                out = self._count(kids, span, c["condition"], typ == "value_count")
            elif typ == "temporal_ordered":
                seqs = [self._eval(dep, own_gb) for dep in c["rules"]]
                acc = seqs[0]
                for nxt in seqs[1:]:
                    acc = self._ordered(acc, nxt, span)
                out = acc
            else:
                raise RuleError(f"{name}: unsupported correlation type {typ!r}")
        self._cache[ck] = out
        return out

    def _count(self, kids, span, cond, distinct) -> list[Match]:
        gte = cond["gte"]
        field = cond.get("field")
        by_key = defaultdict(list)
        for m in kids:
            by_key[m.key].append(m)
        out = []
        for key, lst in by_key.items():
            win, open_ = deque(), None
            for m in lst:
                win.append(m)
                while m.first - win[0].first > span:
                    win.popleft()
                if distinct:
                    vals = {self.by_id[x.ids[0]].get(field) for x in win} - {None}
                    n = len(vals)
                else:
                    n = len(win)
                if n < gte:
                    continue
                if open_ is not None and m.first - open_.last <= span:
                    for x in win:   # merge the continuing burst into one alert
                        if x.ids[0] not in open_.detail["_seen"]:
                            open_.ids.append(x.ids[0])
                            open_.detail["_seen"].add(x.ids[0])
                    open_.last = m.first
                    open_.detail["count"] = len(open_.ids)
                    if distinct:
                        open_.detail["distinct_values"] |= vals
                else:
                    ids = [x.ids[0] for x in win]
                    open_ = Match(win[0].first, m.first, m.first, key, ids,
                                  {"count": len(ids), "_seen": set(ids),
                                   "distinct_values": set(vals) if distinct else set(),
                                   "threshold": gte, "window": span})
                    out.append(open_)
        return out

    def _ordered(self, first, second, span) -> list[Match]:
        by_key = defaultdict(list)
        for m in first:
            by_key[m.key].append(m)
        used, out = set(), []
        for b in sorted(second, key=lambda m: m.first):
            for a in by_key.get(b.key, []):
                if id(a) in used or a.last > b.first or b.first - a.last > span:
                    continue
                used.add(id(a))
                ids = list(dict.fromkeys(a.ids + b.ids))
                out.append(Match(a.first, b.last, b.first, b.key, ids,
                                 {"count": len(ids), "first_stage_events": len(a.ids), **{
                                     k: v for k, v in a.detail.items() if k in ("distinct_values",)}}))
                break
        return out

    # ---------- alerts ----------
    def _alert(self, n: int, rule: Rule, m: Match) -> dict:
        evs = sorted((self.by_id[i] for i in m.ids), key=lambda e: (e["epoch"], e["event_id"]))
        entities = {}
        for f in ("src_ip", "user", "api_key_id", "target"):
            vals = list(dict.fromkeys(e[f] for e in evs if e.get(f)))
            if vals:
                entities[f] = vals[:10]
        base = LEVELS[rule.level]
        sev, reason = base, "rule level"
        if rule.ext.get("escalate_privileged") and any(
                str(u).lower().startswith(PRIVILEGED_PREFIXES) for u in entities.get("user", [])):
            sev, reason = min(base + 1, 4), "escalated: privileged account involved"
        gb = rule.doc["correlation"].get("group-by", []) if rule.kind == "correlation" else []
        ctx = _Safe(
            count=len(evs), first_seen=_fmt_ts(m.first), last_seen=_fmt_ts(m.last),
            actions=", ".join(dict.fromkeys(str(e['action']) for e in evs))[:120], key=dict(zip(gb, m.key)), threshold=m.detail.get("threshold", ""),
            window=m.detail.get("window", ""), distinct=len(m.detail.get("distinct_values", ()) or ()),
            values=", ".join(sorted(map(str, m.detail.get("distinct_values", ()) or ()))[:8]),
            **{k: ", ".join(map(str, v)) for k, v in entities.items()},
        )
        tmpl = rule.ext.get("explanation", rule.doc.get("description", ""))
        sample = evs if len(evs) <= MAX_EVIDENCE_SAMPLE else evs[:6] + evs[-6:]
        return {
            "alert_id": f"ALR-{n:04d}",
            "rule_id": rule.rule_id,
            "rule_name": rule.title,
            "rule_uuid": rule.doc.get("id"),
            "severity": LEVEL_NAMES[sev],
            "base_severity": rule.level,
            "severity_reason": reason,
            "first_seen": _fmt_ts(m.first),
            "last_seen": _fmt_ts(m.last),
            "detected_at": _fmt_ts(m.detected),
            "entities": entities,
            "explanation": tmpl.format_map(ctx).strip(),
            "mitre": {"techniques": rule.techniques, "tactics": rule.tactics},
            "runbook": rule.ext.get("runbook"),
            "evidence_count": len(evs),
            "evidence_event_ids": [e["event_id"] for e in evs],
            "evidence_sample": [{"event_id": e["event_id"], "ts": e["ts"], "summary": summarize_event(e)}
                                for e in sample],
            "evidence_truncated": len(evs) > len(sample),
            "timeline": [{"ts": e["ts"], "event_id": e["event_id"], "source": e["source"],
                          "summary": summarize_event(e)} for e in sample],
        }


def _linkable(ip):
    try:
        return not ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def build_incidents(alerts: list[dict], gap_seconds: int = 7200) -> list[dict]:
    """Group alerts that share a user / external IP / API key and are close in time."""
    n = len(alerts)
    parent = list(range(n))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def keys(a):
        e = a["entities"]
        return ({("ip", i) for i in e.get("src_ip", []) if _linkable(i)}
                | {("user", u) for u in e.get("user", [])}
                | {("key", k) for k in e.get("api_key_id", [])})

    ts = lambda s: datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
    ks = [keys(a) for a in alerts]
    for i in range(n):
        for j in range(i + 1, n):
            if ks[i] & ks[j]:
                a, b = alerts[i], alerts[j]
                if max(ts(a["first_seen"]), ts(b["first_seen"])) - min(ts(a["last_seen"]), ts(b["last_seen"])) <= gap_seconds:
                    parent[find(i)] = find(j)
    groups = defaultdict(list)
    for i in range(n):
        groups[find(i)].append(alerts[i])
    incidents = []
    for members in sorted(groups.values(), key=lambda g: min(a["first_seen"] for a in g)):
        sev = max(LEVELS[a["severity"]] for a in members)
        rules = sorted({a["rule_id"] for a in members})
        tactics = sorted({t for a in members for t in a["mitre"]["tactics"]})
        escalated = len(tactics) >= 3
        if escalated:
            sev = min(sev + 1, 4)
        ents = defaultdict(list)
        for a in members:
            for k, v in a["entities"].items():
                ents[k].extend(x for x in v if x not in ents[k])
        incidents.append({
            "incident_id": f"INC-{len(incidents) + 1:04d}",
            "severity": LEVEL_NAMES[sev],
            "severity_reason": f"multi-tactic activity ({len(tactics)} tactics)" if escalated else "highest alert severity",
            "first_seen": min(a["first_seen"] for a in members),
            "last_seen": max(a["last_seen"] for a in members),
            "title": f"{len(members)} alert(s): " + ", ".join(rules[:4]) + ("…" if len(rules) > 4 else ""),
            "alert_ids": [a["alert_id"] for a in sorted(members, key=lambda a: a["first_seen"])],
            "rule_ids": rules, "tactics": tactics, "entities": dict(ents),
        })
    return incidents
