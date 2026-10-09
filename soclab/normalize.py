"""Per-source parsers that map native JSON log lines onto the common schema."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from .schema import FIELDS


class ParseError(ValueError):
    pass


def parse_ts(value) -> float:
    """Accept epoch numbers or ISO-8601 strings (Z or offset); return UTC epoch."""
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ParseError(f"bad timestamp {value!r}") from exc
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    raise ParseError(f"missing/unsupported timestamp {value!r}")


def finalize(source: str, epoch: float, fields: dict, raw: str = "", event_id: str = "") -> dict:
    """Build a complete normalized event (all schema keys present)."""
    ev = {k: None for k in FIELDS}
    ev.update({k: v for k, v in fields.items() if k in FIELDS})
    dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
    ev.update(
        event_id=event_id, source=source, epoch=epoch, raw=raw,
        ts=dt.strftime("%Y-%m-%dT%H:%M:%SZ"), hour_utc=dt.hour,
    )
    if ev["target"] is not None and ev["user"] is not None:
        ev["self_action"] = int(ev["target"] == ev["user"])
    return ev


def _bool(v):
    if v is None:
        return None
    if isinstance(v, str):
        return int(v.strip().lower() in ("true", "1", "yes", "y"))
    return int(bool(v))


def _req(d: dict, *keys):
    for k in keys:
        if k not in d:
            raise ParseError(f"missing field {k!r}")


def parse_auth(d: dict) -> dict:
    _req(d, "timestamp", "event", "outcome", "username", "source_ip")
    if d["outcome"] not in ("success", "failure"):
        raise ParseError(f"unknown outcome {d['outcome']!r}")
    return dict(
        epoch=parse_ts(d["timestamp"]),
        fields=dict(
            category="authentication", action=d["event"], outcome=d["outcome"],
            user=d["username"], src_ip=d["source_ip"], src_country=d.get("country"),
            host=d.get("app"), mfa=_bool(d.get("mfa")),
        ),
    )


def parse_web(d: dict) -> dict:
    _req(d, "time_iso8601", "remote_addr", "request_method", "uri", "status")
    user = d.get("remote_user")
    status = int(d["status"])
    return dict(
        epoch=parse_ts(d["time_iso8601"]),
        fields=dict(
            category="web", action="http_request", outcome="success" if status < 400 else "failure",
            user=None if user in (None, "-", "") else user, src_ip=d["remote_addr"],
            host=d.get("server_name"), http_method=d["request_method"], http_path=d["uri"],
            http_status=status, bytes_out=int(d.get("body_bytes_sent", 0)),
            user_agent=d.get("http_user_agent"),
        ),
    )


def parse_api(d: dict) -> dict:
    _req(d, "ts", "api_key_id", "route", "status", "client_ip")
    status = int(d["status"])
    return dict(
        epoch=parse_ts(d["ts"]),
        fields=dict(
            category="api", action="api_call", outcome="success" if status < 400 else "failure",
            user=d.get("principal"), src_ip=d["client_ip"], api_key_id=d["api_key_id"],
            http_method=d.get("method"), http_path=d["route"], http_status=status,
            bytes_out=int(d.get("bytes_out", 0)), host=d.get("service"),
        ),
    )


def parse_admin(d: dict) -> dict:
    _req(d, "time", "actor", "action")
    detail = d.get("detail") or {}
    return dict(
        epoch=parse_ts(d["time"]),
        fields=dict(
            category="admin", action=d["action"], outcome="success", user=d["actor"],
            target=d.get("target"), target_role=detail.get("role"),
            ticket=d.get("ticket") or None, host=d.get("host"),
        ),
    )


def _public_exposure(params: dict) -> int:
    blob = json.dumps(params or {}).replace(" ", "")
    return int('"Principal":"*"' in blob or "AllUsers" in blob or "AuthenticatedUsers" in blob)


def parse_cloud(d: dict) -> dict:
    _req(d, "eventTime", "eventName", "userIdentity")
    ident = d["userIdentity"] or {}
    params = d.get("requestParameters") or {}
    resp = d.get("responseElements") or {}
    err = d.get("errorCode")
    outcome = "failure" if err else "success"
    if d["eventName"] == "ConsoleLogin":
        outcome = "success" if resp.get("ConsoleLogin") == "Success" else "failure"
    target = params.get("userName") or params.get("bucketName") or params.get("roleName")
    return dict(
        epoch=parse_ts(d["eventTime"]),
        fields=dict(
            category="cloud", action=d["eventName"], outcome=outcome,
            user=ident.get("userName") or ident.get("type"),
            src_ip=d.get("sourceIPAddress"), host=d.get("eventSource"),
            cloud_event=d["eventName"], cloud_error=err, target=target,
            mfa=_bool(ident.get("mfaAuthenticated")), policy=params.get("policyArn"),
            public_exposure=_public_exposure(params) if "Bucket" in d["eventName"] else None,
            user_agent=d.get("userAgent"),
        ),
    )


PARSERS = {
    "auth": parse_auth, "web": parse_web, "api": parse_api,
    "admin": parse_admin, "cloud": parse_cloud,
}


def normalize_line(source: str, line: str, line_no: int) -> dict:
    try:
        d = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ParseError(f"invalid JSON: {exc.msg}") from exc
    if not isinstance(d, dict):
        raise ParseError("log line is not a JSON object")
    parsed = PARSERS[source](d)
    return finalize(source, parsed["epoch"], parsed["fields"], raw=line.strip(),
                    event_id=f"{source}-{line_no:06d}")
