"""Per-rule positive and negative fixtures (normalized events). Positive: rule MUST fire. Negative: near-miss, rule MUST NOT fire."""
from __future__ import annotations

from .normalize import finalize

T0 = 1_772_000_000.0 - (1_772_000_000 % 86400) + 10 * 3600   # 10:00 UTC on some day


class B:
    def __init__(self): self.n = 0; self.evs = []
    def add(self, source, t, **f):
        self.n += 1
        self.evs.append(finalize(source, T0 + t, f, event_id=f"{source}-{self.n:06d}", raw=""))


def auth(b, t, user="u.a", outcome="failure", ip="203.0.113.5", country="US", mfa=1):
    b.add("auth", t, category="authentication", action="login", outcome=outcome, user=user, src_ip=ip, src_country=country, mfa=mfa)


def web(b, t, path, status, ip="203.0.113.5"):
    b.add("web", t, category="web", action="http_request", http_method="GET", http_path=path, http_status=status, src_ip=ip)


def api(b, t, status=200, ip="203.0.113.5", key="k1", path="/api/v1/orders", nbytes=100, user="u.a"):
    b.add("api", t, category="api", action="api_call", http_status=status, src_ip=ip, api_key_id=key, http_path=path, bytes_out=nbytes, user=user)


def admin(b, t, action="role_assign", role="admin", ticket=None, user="adm-x"):
    b.add("admin", t, category="admin", action=action, target_role=role, ticket=ticket, user=user, target="u.b")


def cloud(b, t, name, user="adm-x", **f):
    b.add("cloud", t, category="cloud", action=name, cloud_event=name, outcome=f.pop("outcome", "success"), user=user, src_ip="203.0.113.5", **f)


def cases():
    C = {}

    def case(rule, kind, name):
        def deco(fn):
            b = B(); fn(b)
            C.setdefault(rule, {"positive": {}, "negative": {}})[kind][name] = b.evs
            return fn
        return deco
    P, N = "positive", "negative"

    @case("SOC-AUTH-001", P, "10_failures_same_user_ip_4min")
    def _(b): [auth(b, i * 25) for i in range(10)]
    @case("SOC-AUTH-001", N, "9_failures")
    def _(b): [auth(b, i * 25) for i in range(9)]
    @case("SOC-AUTH-001", N, "10_failures_over_15min")
    def _(b): [auth(b, i * 90) for i in range(10)]
    @case("SOC-AUTH-001", N, "10_failures_different_users")
    def _(b): [auth(b, i * 10, user=f"u.{i}") for i in range(10)]
    @case("SOC-AUTH-002", P, "6_users_one_ip")
    def _(b): [auth(b, i * 30, user=f"u.{i}") for i in range(6)]
    @case("SOC-AUTH-002", N, "5_users")
    def _(b): [auth(b, i * 30, user=f"u.{i}") for i in range(5)]
    @case("SOC-AUTH-002", N, "6_users_spread_over_1h")
    def _(b): [auth(b, i * 900, user=f"u.{i}") for i in range(6)]
    @case("SOC-AUTH-002", N, "6_users_6_ips")
    def _(b): [auth(b, i * 30, user=f"u.{i}", ip=f"203.0.113.{i}") for i in range(6)]
    @case("SOC-AUTH-003", P, "8_failures_then_success")
    def _(b):
        [auth(b, i * 20) for i in range(8)]; auth(b, 400, outcome="success")
    @case("SOC-AUTH-003", N, "7_failures_then_success")
    def _(b):
        [auth(b, i * 20) for i in range(7)]; auth(b, 400, outcome="success")
    @case("SOC-AUTH-003", N, "success_before_failures")
    def _(b):
        auth(b, 0, outcome="success"); [auth(b, 60 + i * 20) for i in range(8)]
    @case("SOC-AUTH-003", N, "success_from_other_ip")
    def _(b):
        [auth(b, i * 20) for i in range(8)]; auth(b, 400, outcome="success", ip="203.0.113.99")
    @case("SOC-AUTH-003", N, "success_after_30min")
    def _(b):
        [auth(b, i * 20) for i in range(8)]; auth(b, 2200, outcome="success")
    @case("SOC-AUTH-004", P, "two_countries_20min")
    def _(b):
        auth(b, 0, outcome="success", country="US"); auth(b, 1200, outcome="success", country="RO", ip="203.0.113.9")
    @case("SOC-AUTH-004", N, "same_country")
    def _(b):
        auth(b, 0, outcome="success", country="US"); auth(b, 1200, outcome="success", country="US", ip="203.0.113.9")
    @case("SOC-AUTH-004", N, "two_countries_3h_apart")
    def _(b):
        auth(b, 0, outcome="success", country="US"); auth(b, 10800, outcome="success", country="RO")
    @case("SOC-AUTH-004", N, "second_login_failed")
    def _(b):
        auth(b, 0, outcome="success", country="US"); auth(b, 600, outcome="failure", country="RO")
    @case("SOC-AUTH-005", P, "admin_at_03")
    def _(b): auth(b, -7 * 3600, user="adm-x", outcome="success")
    @case("SOC-AUTH-005", P, "admin_at_22")
    def _(b): auth(b, 12 * 3600, user="adm-x", outcome="success")
    @case("SOC-AUTH-005", N, "admin_at_10")
    def _(b): auth(b, 0, user="adm-x", outcome="success")
    @case("SOC-AUTH-005", N, "nonadmin_at_03")
    def _(b): auth(b, -7 * 3600, user="u.a", outcome="success")
    @case("SOC-AUTH-005", N, "admin_failure_at_03")
    def _(b): auth(b, -7 * 3600, user="adm-x", outcome="failure")
    @case("SOC-PRIV-001", P, "admin_role_no_ticket")
    def _(b): admin(b, 0)
    @case("SOC-PRIV-001", N, "admin_role_with_ticket")
    def _(b): admin(b, 0, ticket="CHG-1")
    @case("SOC-PRIV-001", N, "developer_role_no_ticket")
    def _(b): admin(b, 0, role="developer")
    @case("SOC-PRIV-002", P, "sudoers_no_ticket")
    def _(b): admin(b, 0, action="sudoers_modified", role=None)
    @case("SOC-PRIV-002", N, "sudoers_with_ticket")
    def _(b): admin(b, 0, action="sudoers_modified", role=None, ticket="INC-1")
    @case("SOC-WEB-001", P, "15_distinct_404")
    def _(b): [web(b, i * 5, f"/p{i}", 404) for i in range(15)]
    @case("SOC-WEB-001", N, "14_distinct_404")
    def _(b): [web(b, i * 5, f"/p{i}", 404) for i in range(14)]
    @case("SOC-WEB-001", N, "same_path_repeated")
    def _(b): [web(b, i * 5, "/p", 404) for i in range(40)]
    @case("SOC-WEB-001", N, "allowlisted_scanner")
    def _(b): [web(b, i * 2, f"/p{i}", 404, ip="10.20.8.5") for i in range(40)]
    @case("SOC-WEB-002", P, "traversal")
    def _(b): web(b, 0, "/dl?f=../../etc/passwd", 400)
    @case("SOC-WEB-002", P, "sqli_case_insensitive")
    def _(b): web(b, 0, "/i?id=1 UNION SELECT 1", 200)
    @case("SOC-WEB-002", N, "benign_path")
    def _(b): web(b, 0, "/products/123?sort=price", 200)
    @case("SOC-WEB-002", N, "allowlisted_scanner")
    def _(b): web(b, 0, "/dl?f=../../etc/passwd", 400, ip="10.20.8.5")
    @case("SOC-WEB-003", P, "external_admin_200")
    def _(b): web(b, 0, "/admin/users", 200)
    @case("SOC-WEB-003", N, "internal_admin_200")
    def _(b): web(b, 0, "/admin/users", 200, ip="10.20.5.4")
    @case("SOC-WEB-003", N, "external_admin_403")
    def _(b): web(b, 0, "/admin/users", 403)
    @case("SOC-API-001", P, "30_errors_in_1m")
    def _(b): [api(b, i, status=404) for i in range(30)]
    @case("SOC-API-001", N, "29_errors")
    def _(b): [api(b, i, status=404) for i in range(29)]
    @case("SOC-API-001", N, "30_errors_over_10m")
    def _(b): [api(b, i * 20, status=404) for i in range(30)]
    @case("SOC-API-001", N, "500s_not_counted")
    def _(b): [api(b, i, status=500) for i in range(40)]
    @case("SOC-API-002", P, "60MB_export")
    def _(b): api(b, 0, path="/api/v1/export/all", nbytes=60_000_000)
    @case("SOC-API-002", N, "49MB_export")
    def _(b): api(b, 0, path="/api/v1/export/all", nbytes=49_000_000)
    @case("SOC-API-002", N, "allowlisted_bi")
    def _(b): api(b, 0, path="/api/v1/export/weekly", nbytes=120_000_000, user="svc-bi", ip="10.20.3.5")
    @case("SOC-API-002", N, "large_non_export_route")
    def _(b): api(b, 0, path="/api/v1/orders", nbytes=120_000_000)
    @case("SOC-API-003", P, "key_from_3_ips")
    def _(b): [api(b, i * 60, ip=f"203.0.113.{i}") for i in range(3)]
    @case("SOC-API-003", N, "key_from_2_ips")
    def _(b): [api(b, i * 60, ip=f"203.0.113.{i}") for i in range(2)]
    @case("SOC-API-003", N, "3_ips_over_1h")
    def _(b): [api(b, i * 1800, ip=f"203.0.113.{i}") for i in range(3)]
    @case("SOC-API-003", N, "3_ips_3_keys")
    def _(b): [api(b, i * 60, ip=f"203.0.113.{i}", key=f"k{i}") for i in range(3)]
    @case("SOC-CLOUD-001", P, "stop_logging")
    def _(b): cloud(b, 0, "StopLogging")
    @case("SOC-CLOUD-001", N, "stop_logging_denied")
    def _(b): cloud(b, 0, "StopLogging", outcome="failure", cloud_error="AccessDenied")
    @case("SOC-CLOUD-001", N, "start_logging")
    def _(b): cloud(b, 0, "StartLogging")
    @case("SOC-CLOUD-002", P, "console_no_mfa")
    def _(b): cloud(b, 0, "ConsoleLogin", mfa=0)
    @case("SOC-CLOUD-002", N, "console_with_mfa")
    def _(b): cloud(b, 0, "ConsoleLogin", mfa=1)
    @case("SOC-CLOUD-002", N, "console_failed_login")
    def _(b): cloud(b, 0, "ConsoleLogin", mfa=0, outcome="failure")
    @case("SOC-CLOUD-003", P, "attach_admin_policy")
    def _(b): cloud(b, 0, "AttachUserPolicy", policy="arn:aws:iam::aws:policy/AdministratorAccess", target="u.b")
    @case("SOC-CLOUD-003", P, "create_key_for_other")
    def _(b): cloud(b, 0, "CreateAccessKey", target="svc-b", user="adm-x")
    @case("SOC-CLOUD-003", N, "create_key_for_self")
    def _(b): cloud(b, 0, "CreateAccessKey", target="adm-x", user="adm-x")
    @case("SOC-CLOUD-003", N, "attach_readonly")
    def _(b): cloud(b, 0, "AttachUserPolicy", policy="arn:aws:iam::aws:policy/ReadOnlyAccess", target="u.b")
    @case("SOC-CLOUD-004", P, "public_policy")
    def _(b): cloud(b, 0, "PutBucketPolicy", public_exposure=1, target="bkt")
    @case("SOC-CLOUD-004", N, "private_policy")
    def _(b): cloud(b, 0, "PutBucketPolicy", public_exposure=0, target="bkt")
    return C


def export(out_dir):
    import json
    from pathlib import Path
    n = 0
    for rule, kinds in cases().items():
        for kind, cs in kinds.items():
            for name, evs in cs.items():
                p = Path(out_dir) / kind / rule
                p.mkdir(parents=True, exist_ok=True)
                (p / f"{name}.jsonl").write_text("".join(json.dumps(e) + "\n" for e in evs)); n += 1
    return n
