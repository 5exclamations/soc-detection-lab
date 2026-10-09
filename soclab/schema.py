"""Common event schema (ECS-inspired) and SQLite DDL.

Sigma rules in ./rules reference these normalized field names.
"""

SOURCES = ("auth", "web", "api", "admin", "cloud")

# field -> (sqlite type, description)
FIELDS = {
    "event_id": ("TEXT PRIMARY KEY", "<source>-<line number> within the raw file"),
    "ts": ("TEXT NOT NULL", "UTC ISO-8601 timestamp"),
    "epoch": ("REAL NOT NULL", "UTC epoch seconds"),
    "hour_utc": ("INTEGER", "Hour of day, 0-23 UTC (derived at ingest)"),
    "source": ("TEXT NOT NULL", "auth | web | api | admin | cloud"),
    "category": ("TEXT", "authentication | web | api | admin | cloud"),
    "action": ("TEXT", "Normalized verb, e.g. login, http_request, role_assign"),
    "outcome": ("TEXT", "success | failure"),
    "user": ("TEXT", "Acting principal"),
    "src_ip": ("TEXT", "Client / source address"),
    "src_country": ("TEXT", "GeoIP country supplied by the source"),
    "host": ("TEXT", "Application, server or service name"),
    "http_method": ("TEXT", ""),
    "http_path": ("TEXT", "URI path (+query) or API route"),
    "http_status": ("INTEGER", ""),
    "bytes_out": ("INTEGER", "Response size in bytes"),
    "user_agent": ("TEXT", ""),
    "api_key_id": ("TEXT", "API credential identifier"),
    "target": ("TEXT", "Object acted upon (user, group, bucket ...)"),
    "target_role": ("TEXT", "Role/group granted (admin events)"),
    "self_action": ("INTEGER", "1 if target == user (derived)"),
    "ticket": ("TEXT", "Change ticket reference, NULL if none"),
    "mfa": ("INTEGER", "1/0 whether MFA was used (auth/cloud)"),
    "cloud_event": ("TEXT", "Provider API name, e.g. StopLogging"),
    "cloud_error": ("TEXT", "Provider error code, NULL on success"),
    "policy": ("TEXT", "Policy ARN / name referenced"),
    "public_exposure": ("INTEGER", "1 if a bucket policy/ACL grants public access (derived)"),
    "raw": ("TEXT", "Original JSON line"),
}

BOOL_FIELDS = {"mfa", "self_action", "public_exposure"}

DDL = f"""
CREATE TABLE IF NOT EXISTS events (
  {", ".join(f"{k} {v[0]}" for k, v in FIELDS.items())}
);
CREATE INDEX IF NOT EXISTS ix_events_epoch ON events(epoch);
CREATE INDEX IF NOT EXISTS ix_events_src_ip ON events(src_ip);
CREATE INDEX IF NOT EXISTS ix_events_user ON events(user);
CREATE INDEX IF NOT EXISTS ix_events_source ON events(source);

CREATE TABLE IF NOT EXISTS ingest_errors (
  source TEXT, line_no INTEGER, error TEXT, line TEXT
);
CREATE TABLE IF NOT EXISTS alerts (
  alert_id TEXT PRIMARY KEY, rule_id TEXT, rule_name TEXT, severity TEXT,
  first_seen TEXT, last_seen TEXT, entities TEXT, explanation TEXT, body TEXT
);
CREATE TABLE IF NOT EXISTS alert_events (alert_id TEXT, event_id TEXT);
CREATE INDEX IF NOT EXISTS ix_alert_events ON alert_events(alert_id);
CREATE TABLE IF NOT EXISTS incidents (
  incident_id TEXT PRIMARY KEY, severity TEXT, first_seen TEXT, last_seen TEXT,
  title TEXT, body TEXT
);
CREATE TABLE IF NOT EXISTS incident_alerts (incident_id TEXT, alert_id TEXT);
CREATE TABLE IF NOT EXISTS labels (
  event_id TEXT, scenario TEXT, malicious INTEGER, expected_rules TEXT
);
CREATE INDEX IF NOT EXISTS ix_labels_event ON labels(event_id);
CREATE TABLE IF NOT EXISTS scenarios (
  scenario TEXT PRIMARY KEY, category TEXT, description TEXT, expected_rules TEXT
);
"""
