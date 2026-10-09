"""Deterministic synthetic telemetry generator.

Everything here is fabricated. Addresses come from documentation / benchmarking ranges
(203.0.113.0/24, 198.51.100.0/24, 192.0.2.0/24, 198.18.0.0/15) and RFC1918 space.

Output (data/raw):
  auth.jsonl web.jsonl api.jsonl admin.jsonl cloud.jsonl   native, differently-shaped JSON logs
  labels.jsonl      event_id -> scenario / malicious / expected_rules
  scenarios.json    scenario catalog (category: attack | evasion | hard_negative)
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_SEED = 1337
START = datetime(2026, 3, 2, tzinfo=timezone.utc).timestamp()   # a Monday
DAY = 86400
SURNAMES = ["nguyen", "okafor", "silva", "chen", "kim", "park", "garcia", "mueller", "singh", "rossi",
            "tanaka", "ali", "jones", "brown", "lopez", "dubois", "ivanov", "cohen", "haddad", "novak",
            "olsen", "santos", "wang", "young"]
HOME_COUNTRY = {"silva": "BR", "tanaka": "JP", "mueller": "DE", "singh": "IN", "rossi": "IT", "dubois": "FR",
                "jones": "GB", "brown": "GB", "ali": "GB", "okafor": "US", "novak": "CZ", "olsen": "NO"}
ADMINS = {"adm-jlee": "10.20.5.4", "adm-mpatel": "10.20.5.5", "adm-kwong": "10.20.5.7"}
UAS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0", "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) Safari/605.1.15",
       "Mozilla/5.0 (X11; Linux x86_64) Firefox/125.0", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4) Mobile Safari/604.1"]
WEB_PATHS = ["/", "/products", "/products/123", "/products/456", "/cart", "/checkout", "/login", "/search?q=shoes",
             "/static/app.js", "/static/site.css", "/favicon.ico", "/about", "/help", "/account/orders"]
WORDLIST = ["admin", "backup", "config", "db", "dev", "old", "test", "tmp", "upload", "wp-admin", "phpmyadmin",
            ".git/config", ".env", "server-status", "console", "api-docs", "swagger", "debug", "staging", "private"]


def at(day: int, hhmmss: str) -> float:
    h, m, *s = (int(x) for x in hhmmss.split(":"))
    return START + day * DAY + h * 3600 + m * 60 + (s[0] if s else 0)


def iso_ms(e): return datetime.fromtimestamp(e, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{int(e % 1 * 1000):03d}Z"
def iso_z(e): return datetime.fromtimestamp(e, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
def iso_off(e): return datetime.fromtimestamp(e, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")


class World:
    def __init__(self, seed: int):
        self.rng = random.Random(seed)
        self.items = {s: [] for s in ("auth", "web", "api", "admin", "cloud")}
        self.scenarios: dict[str, dict] = {}
        self.users = {}
        for i, s in enumerate(SURNAMES):
            self.users[f"u.{s}"] = {"country": HOME_COUNTRY.get(s, "US"), "ip": f"198.18.{10 + i}.{self.rng.randint(2, 250)}",
                                    "key": f"key-{s}"}

    # --- registry ---
    def scenario(self, sid, category, description):
        self.scenarios[sid] = {"scenario": sid, "category": category, "description": description, "expected_rules": set()}

    def add(self, source, epoch, native, scn=None, exp=(), mal=None):
        if scn and mal is None:
            mal = self.scenarios[scn]["category"] in ("attack", "evasion")
        if scn and mal:
            self.scenarios[scn]["expected_rules"].update(exp)
        self.items[source].append({"epoch": epoch, "native": native, "scn": scn, "exp": list(exp), "mal": bool(mal)})

    # --- native log builders ---
    def auth(self, e, user, outcome, ip, country, mfa=True, **lab):
        self.add("auth", e, {"timestamp": iso_ms(e), "event": "login", "username": user, "outcome": outcome,
                             "reason": None if outcome == "success" else "bad_credentials", "source_ip": ip,
                             "country": country, "mfa": mfa, "app": "sso"}, **lab)

    def web(self, e, ip, method, uri, status, ua=None, user="-", size=None, **lab):
        self.add("web", e, {"time_iso8601": iso_off(e), "remote_addr": ip, "request_method": method, "uri": uri,
                            "status": status, "body_bytes_sent": size if size is not None else self.rng.randint(200, 40000),
                            "http_user_agent": ua or self.rng.choice(UAS), "remote_user": user, "server_name": "www"}, **lab)

    def api(self, e, key, principal, ip, method, route, status, nbytes=None, **lab):
        self.add("api", e, {"ts": round(e + self.rng.random() * 0.9, 3), "api_key_id": key, "principal": principal,
                            "client_ip": ip, "method": method, "route": route, "status": status,
                            "bytes_out": nbytes if nbytes is not None else int(self.rng.lognormvariate(7.5, 1)),
                            "latency_ms": self.rng.randint(8, 400), "service": "core-api"}, **lab)

    def admin(self, e, actor, action, target, role=None, ticket=None, host="iam-01", **lab):
        d = {"time": iso_off(e), "actor": actor, "action": action, "target": target, "host": host,
             "detail": {"role": role} if role else {}}
        if ticket:
            d["ticket"] = ticket
        self.add("admin", e, d, **lab)

    def cloud(self, e, user, name, ip, params=None, error=None, mfa=True, console_ok=None, **lab):
        d = {"eventTime": iso_z(e), "eventName": name, "eventSource": "iam.amazonaws.com" if "Policy" in name or "Key" in name
             else "cloudtrail.amazonaws.com" if name in ("StopLogging", "DeleteTrail") else "signin.amazonaws.com" if name == "ConsoleLogin" else "s3.amazonaws.com",
             "userIdentity": {"type": "IAMUser", "userName": user, "mfaAuthenticated": "true" if mfa else "false"},
             "sourceIPAddress": ip, "userAgent": "aws-cli/2.15", "requestParameters": params or {}}
        if error:
            d["errorCode"] = error
        if name == "ConsoleLogin":
            d["responseElements"] = {"ConsoleLogin": "Success" if console_ok is not False else "Failure"}
        self.add("cloud", e, d, **lab)


# ---------------------------------------------------------------------------------------------
# baseline (benign) traffic
# ---------------------------------------------------------------------------------------------
def baseline(w: World, days: int):
    r = w.rng
    for day in range(days):
        d0 = START + day * DAY
        for user, u in w.users.items():
            for _ in range(r.randint(1, 3)):
                t = d0 + r.randint(8 * 3600, 18 * 3600)
                if r.random() < 0.08:                       # fat-fingered password
                    for k in range(r.randint(1, 3)):
                        w.auth(t, user, "failure", u["ip"], u["country"])
                        t += r.randint(15, 60)
                w.auth(t, user, "success", u["ip"], u["country"])
        for adm, ip in ADMINS.items():
            w.auth(d0 + r.randint(8 * 3600, 17 * 3600), adm, "success", ip, "US")
        for svc, ip in (("svc-ci", "10.20.9.11"), ("svc-backup", "10.20.4.8")):
            w.auth(d0 + r.randint(0, 80000), svc, "success", ip, "US", mfa=False)

        # web
        cust = [f"198.18.{100 + i // 250}.{i % 250 + 2}" for i in range(80)]
        for _ in range(2500):
            t = d0 + int(r.triangular(6 * 3600, 23 * 3600, 14 * 3600))
            p = r.choice(WEB_PATHS)
            roll = r.random()
            status, path = (404, f"/old/{r.randint(1, 500)}") if roll < 0.02 else (500, p) if roll < 0.004 + 0.02 else (200 if roll < 0.9 else 304, p)
            w.web(t, r.choice(cust), "GET", path, status)
        for adm, ip in ADMINS.items():                        # internal admin console use
            for _ in range(5):
                w.web(d0 + r.randint(8 * 3600, 17 * 3600), ip, "GET", r.choice(["/admin/dashboard", "/admin/users", "/admin/audit"]), 200, user=adm)

        # api
        for _ in range(1500):
            t = d0 + int(r.triangular(5 * 3600, 23 * 3600, 13 * 3600))
            c = r.random()
            if c < 0.35:
                key, princ, ip = "key-web", "svc-web", r.choice(["10.20.1.10", "10.20.1.11"])
            elif c < 0.45:
                key, princ, ip = "key-bi", "svc-bi", "10.20.3.5"
            else:
                user, u = r.choice(list(w.users.items()))
                key, princ, ip = u["key"], user, u["ip"]
            route = r.choice(["/api/v1/orders", f"/api/v1/orders/{r.randint(1, 9000)}", f"/api/v1/customers/{r.randint(1, 9000)}",
                              "/api/v1/products", "/api/v1/cart"])
            roll = r.random()
            w.api(t, key, princ, ip, r.choice(["GET", "GET", "GET", "POST"]), route,
                  401 if roll < 0.005 else 404 if roll < 0.015 else 200)
        w.api(d0 + 3600, "key-bi", "svc-bi", "10.20.3.5", "GET", "/api/v1/export/daily", 200, nbytes=r.randint(4_000_000, 9_000_000))
        for i, hh in enumerate((9, 13, 17)):                  # CI builds, one runner at a time
            runner = f"10.20.9.{11 + (i + day) % 3}"
            for k in range(20):
                w.api(d0 + hh * 3600 + k * 7, "key-ci", "svc-ci", runner, "POST", "/api/v1/deployments", 200)

        # admin (always ticketed)
        for _ in range(8):
            t = d0 + r.randint(8 * 3600, 17 * 3600)
            actor = r.choice(list(ADMINS))
            kind = r.choice(["group_add", "group_add", "role_assign", "sudoers_modified", "user_create", "config_change"])
            tgt = r.choice(list(w.users))
            role = r.choice(["developer", "support", "admin"]) if kind in ("group_add", "role_assign") else None
            w.admin(t, actor, kind, tgt if kind != "sudoers_modified" else f"app-0{r.randint(1, 4)}", role=role,
                    ticket=f"CHG-{r.randint(4000, 4999)}", host="iam-01" if kind != "sudoers_modified" else "bastion-01")

        # cloud
        for _ in range(80):
            t = d0 + r.randint(0, 86000)
            who = r.choice(list(ADMINS) + ["svc-backup", "svc-ci"])
            ip = ADMINS.get(who, "10.20.4.8")
            name = r.choice(["DescribeInstances", "ListBuckets", "GetObject", "PutObject", "AssumeRole", "DescribeSecurityGroups"])
            w.cloud(t, who, name, ip, {"bucketName": "app-data"} if "Object" in name else {})
        for adm, ip in ADMINS.items():
            w.cloud(d0 + r.randint(8 * 3600, 12 * 3600), adm, "ConsoleLogin", ip, mfa=True, console_ok=True)
        w.cloud(d0 + 40000, "svc-backup", "CreateAccessKey", "10.20.4.8", {"userName": "svc-backup"})       # self rotation
        w.cloud(d0 + 41000, "adm-jlee", "AttachUserPolicy", "10.20.5.4", {"userName": "u.chen", "policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"})
        w.cloud(d0 + 42000, "adm-kwong", "PutBucketPolicy", "10.20.5.7",
                {"bucketName": "app-data", "bucketPolicy": {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::111122223333:root"}, "Action": "s3:GetObject"}]}})


# ---------------------------------------------------------------------------------------------
# attack scenarios
# ---------------------------------------------------------------------------------------------
def attacks(w: World):
    r = w.rng
    A = "attack"

    w.scenario("ATK-01", A, "Online password guessing: 40 failures against one account from one IP in ~4 minutes, no success.")
    for i in range(40):
        w.auth(at(0, "03:20:00") + i * 6, "u.nguyen", "failure", "203.0.113.10", "RU", scn="ATK-01", exp=["SOC-AUTH-001"])

    w.scenario("ATK-02", A, "Password spray: one IP tries 25 accounts once each, then one account succeeds.")
    users = list(w.users)[:25]
    t = at(0, "04:30:00")
    for i, u in enumerate(users):
        w.auth(t + i * 12, u, "failure", "198.51.100.23", "NL", scn="ATK-02", exp=["SOC-AUTH-002"])
    w.auth(t + 25 * 12 + 20, "u.garcia", "success", "198.51.100.23", "NL", scn="ATK-02", exp=["SOC-AUTH-003"])

    w.scenario("ATK-03", A, "Account takeover: 12 failures then success from RU while the real user logged in from home 19 minutes earlier.")
    w.auth(at(1, "05:25:00"), "u.okafor", "success", w.users["u.okafor"]["ip"], "US", scn="ATK-03", exp=["SOC-AUTH-004"], mal=False)
    for i in range(12):
        w.auth(at(1, "05:40:00") + i * 10, "u.okafor", "failure", "203.0.113.77", "RU", scn="ATK-03", exp=["SOC-AUTH-001"])
    w.auth(at(1, "05:44:00"), "u.okafor", "success", "203.0.113.77", "RU", mfa=False, scn="ATK-03", exp=["SOC-AUTH-003", "SOC-AUTH-004"])

    w.scenario("ATK-04", A, "Impossible travel: successful logins from BR and RO 25 minutes apart.")
    w.auth(at(2, "04:10:00"), "u.silva", "success", w.users["u.silva"]["ip"], "BR", scn="ATK-04", mal=False)
    w.auth(at(2, "04:35:00"), "u.silva", "success", "203.0.113.31", "RO", scn="ATK-04", exp=["SOC-AUTH-004"])

    w.scenario("ATK-05", A, "Web recon and exploitation attempts: 120 wordlist 404s in ~80s, then traversal/SQLi probes.")
    for i in range(120):
        w.web(at(0, "14:00:00") + i * 0.7, "192.0.2.99", "GET", f"/{r.choice(WORDLIST)}{i}", 404, ua="gobuster/3.6", scn="ATK-05", exp=["SOC-WEB-001"])
    for i, p in enumerate(["/download?file=../../etc/passwd", "/search?q=1' or '1'='1", "/item?id=1 union select user,pass from users",
                           "/page?x=<script>alert(1)</script>", "/cgi-bin/..%2f..%2fetc/passwd", "/static/%2e%2e/%2e%2e/app.conf"]):
        w.web(at(0, "14:03:00") + i * 8, "192.0.2.99", "GET", p, 400, ua="sqlmap/1.8", scn="ATK-05", exp=["SOC-WEB-002"])

    w.scenario("ATK-06", A, "Admin console reached from an external address with HTTP 200.")
    for i, p in enumerate(["/admin/login", "/admin/users", "/admin/audit"]):
        w.web(at(1, "22:15:00") + i * 20, "203.0.113.140", "GET", p, 200, scn="ATK-06", exp=["SOC-WEB-003"])

    w.scenario("ATK-07", A, "API object-ID enumeration: 120 requests in 60s, mostly 403/404, using a low-privilege key.")
    for i in range(120):
        w.api(at(1, "11:30:00") + i * 0.5, "key-park", "u.park", "192.0.2.150", "GET", f"/api/v1/customers/{1000 + i}",
              200 if i % 20 == 0 else r.choice([403, 404]), scn="ATK-07", exp=["SOC-API-001"])

    w.scenario("ATK-08", A, "Bulk export: three ~180 MB downloads from an external address with a user key.")
    for i in range(3):
        w.api(at(2, "15:20:00") + i * 120, "key-kim", "u.kim", "198.51.100.200", "GET", "/api/v1/export/customers", 200,
              nbytes=180_000_000 + i * 1_000_000, scn="ATK-08", exp=["SOC-API-002"])

    w.scenario("ATK-09", A, "Stolen API key used from four IPs in six minutes.")
    for i, ip in enumerate(["203.0.113.60", "203.0.113.61", "203.0.113.62", "203.0.113.63"]):
        for k in range(5):
            w.api(at(0, "19:40:00") + i * 90 + k * 5, "key-partner-9", "partner-acme", ip, "GET", "/api/v1/orders", 200, scn="ATK-09", exp=["SOC-API-003"])

    w.scenario("ATK-10", A, "Unticketed privilege grant and sudoers change by a misused admin account.")
    w.admin(at(1, "16:45:00"), "adm-kwong", "role_assign", "u.park", role="admin", scn="ATK-10", exp=["SOC-PRIV-001"])
    w.admin(at(1, "16:49:00"), "adm-kwong", "sudoers_modified", "app-02", host="bastion-01", scn="ATK-10", exp=["SOC-PRIV-002"])

    w.scenario("ATK-11", A, "Cloud persistence and defense evasion by a compromised admin: no-MFA console login, key/policy abuse, public bucket, logging stopped.")
    ip = "203.0.113.201"
    w.cloud(at(0, "18:30:00"), "adm-jlee", "ConsoleLogin", ip, mfa=False, console_ok=True, scn="ATK-11", exp=["SOC-CLOUD-002"])
    w.cloud(at(0, "18:33:00"), "adm-jlee", "CreateAccessKey", ip, {"userName": "svc-backup"}, mfa=False, scn="ATK-11", exp=["SOC-CLOUD-003"])
    w.cloud(at(0, "18:34:00"), "adm-jlee", "AttachUserPolicy", ip, {"userName": "svc-backup", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}, mfa=False, scn="ATK-11", exp=["SOC-CLOUD-003"])
    w.cloud(at(0, "18:36:00"), "adm-jlee", "PutBucketPolicy", ip, {"bucketName": "corp-customer-exports",
            "bucketPolicy": {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}]}}, mfa=False, scn="ATK-11", exp=["SOC-CLOUD-004"])
    w.cloud(at(0, "18:38:00"), "adm-jlee", "StopLogging", ip, {"name": "main-trail"}, mfa=False, scn="ATK-11", exp=["SOC-CLOUD-001"])

    w.scenario("ATK-12", A, "Privileged account login at 01:50 UTC from a foreign address.")
    w.auth(at(1, "01:50:00"), "adm-mpatel", "success", "203.0.113.99", "UA", scn="ATK-12", exp=["SOC-AUTH-005"])

    w.scenario("CHAIN-01", A, "Multi-stage intrusion: guess admin password, enter admin console, grant backdoor role, "
               "tamper with cloud IAM/logging, export data. Shared attacker IP 203.0.113.50 and account adm-mpatel.")
    ip, u = "203.0.113.50", "adm-mpatel"
    for i in range(14):
        w.auth(at(2, "02:10:00") + i * 15, u, "failure", ip, "RO", scn="CHAIN-01", exp=["SOC-AUTH-001"])
    w.auth(at(2, "02:14:00"), u, "success", ip, "RO", mfa=False, scn="CHAIN-01", exp=["SOC-AUTH-003", "SOC-AUTH-005"])
    for i, p in enumerate(["/admin/login", "/admin/users"]):
        w.web(at(2, "02:18:00") + i * 30, ip, "GET", p, 200, user=u, scn="CHAIN-01", exp=["SOC-WEB-003"])
    w.admin(at(2, "02:24:00"), u, "role_assign", "svc-backup2", role="admin", scn="CHAIN-01", exp=["SOC-PRIV-001"])
    w.cloud(at(2, "02:28:00"), u, "ConsoleLogin", ip, mfa=False, console_ok=True, scn="CHAIN-01", exp=["SOC-CLOUD-002"])
    w.cloud(at(2, "02:30:00"), u, "CreateAccessKey", ip, {"userName": "svc-backup2"}, mfa=False, scn="CHAIN-01", exp=["SOC-CLOUD-003"])
    w.cloud(at(2, "02:31:00"), u, "AttachUserPolicy", ip, {"userName": "svc-backup2", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}, mfa=False, scn="CHAIN-01", exp=["SOC-CLOUD-003"])
    w.cloud(at(2, "02:33:00"), u, "StopLogging", ip, {"name": "main-trail"}, mfa=False, scn="CHAIN-01", exp=["SOC-CLOUD-001"])
    for i in range(3):
        w.api(at(2, "02:42:00") + i * 90, "key-mpatel-new", u, ip, "GET", "/api/v1/export/customers", 200, nbytes=200_000_000, scn="CHAIN-01", exp=["SOC-API-002"])


def evasions(w: World):
    E = "evasion"
    w.scenario("EVA-01", E, "Low-and-slow guessing: one failure every 9 minutes for 14 hours against one account.")
    for i in range(93):
        w.auth(at(0, "06:00:00") + i * 540, "u.chen", "failure", "203.0.113.250", "RU", scn="EVA-01", exp=["SOC-AUTH-001"])
    w.scenario("EVA-02", E, "Distributed guessing: 40 IPs, 2 failures each, one privileged account, within 10 minutes.")
    for i in range(40):
        for k in range(2):
            w.auth(at(1, "07:00:00") + i * 14 + k * 200, "adm-mpatel", "failure", f"192.0.2.{i + 1}", "VN", scn="EVA-02", exp=["SOC-AUTH-001"])


def hard_negatives(w: World):
    r = w.rng
    H = "hard_negative"
    w.scenario("HN-01", H, "Forgetful user: 6 wrong passwords in 4 minutes, then success. Should NOT alert.")
    u = w.users["u.lopez"]
    for i in range(6):
        w.auth(at(0, "09:30:00") + i * 40, "u.lopez", "failure", u["ip"], u["country"], scn="HN-01")
    w.auth(at(0, "09:35:00"), "u.lopez", "success", u["ip"], u["country"], scn="HN-01")

    w.scenario("HN-02", H, "Service account with stale password retries 45 times, then is fixed (known FP source for AUTH-001/003).")
    for i in range(45):
        w.auth(at(1, "03:00:00") + i * 6.5, "svc-batch", "failure", "10.20.7.9", "US", mfa=False, scn="HN-02")
    w.auth(at(1, "03:06:00"), "svc-batch", "success", "10.20.7.9", "US", mfa=False, scn="HN-02")

    w.scenario("HN-03", H, "Legitimate VPN exit change: JP login then DE VPN exit 20 minutes later (known FP source for AUTH-004).")
    u = w.users["u.tanaka"]
    w.auth(at(1, "13:00:00"), "u.tanaka", "success", u["ip"], "JP", scn="HN-03")
    w.auth(at(1, "13:20:00"), "u.tanaka", "success", "198.18.200.9", "DE", scn="HN-03")

    w.scenario("HN-04", H, "On-call admin responds to a page at 03:10 UTC with a ticketed change (known FP source for AUTH-005).")
    w.auth(at(0, "03:10:00"), "adm-kwong", "success", "10.20.5.7", "US", scn="HN-04")
    w.admin(at(0, "03:18:00"), "adm-kwong", "sudoers_modified", "app-03", ticket="INC-7781", host="bastion-01", scn="HN-04")

    w.scenario("HN-05", H, "Authorized internal vulnerability scan (allowlisted 10.20.8.0/28): 200 distinct 404s and injection strings. Must be suppressed by filters.")
    for i in range(200):
        w.web(at(1, "20:00:00") + i * 0.9, "10.20.8.5", "GET", f"/{r.choice(WORDLIST)}{i}", 404, ua="Nessus", scn="HN-05")
    for i, p in enumerate(["/x?f=../../etc/passwd", "/y?q=1 union select 1", "/z?c=<script>"]):
        w.web(at(1, "20:04:00") + i, "10.20.8.5", "GET", p, 400, ua="Nessus", scn="HN-05")

    w.scenario("HN-06", H, "Ticketed admin grant (CHG-4821). Should NOT alert.")
    w.admin(at(2, "11:00:00"), "adm-jlee", "role_assign", "u.santos", role="admin", ticket="CHG-4821", scn="HN-06")

    w.scenario("HN-07", H, "Weekly 120 MB BI export by the allowlisted service. Must be suppressed.")
    w.api(at(2, "01:00:00"), "key-bi", "svc-bi", "10.20.3.5", "GET", "/api/v1/export/weekly", 200, nbytes=120_000_000, scn="HN-07")

    w.scenario("HN-08", H, "CI fan-out: one shared key from three runners within 4 minutes (known FP source for API-003).")
    for i, ip in enumerate(["10.20.9.11", "10.20.9.12", "10.20.9.13"]):
        for k in range(6):
            w.api(at(1, "12:00:00") + i * 80 + k * 5, "key-ci", "svc-ci", ip, "POST", "/api/v1/deployments", 200, scn="HN-08")

    w.scenario("HN-09", H, "Search-engine crawler hits 12 stale URLs in 90 seconds. Below threshold; should NOT alert.")
    for i in range(12):
        w.web(at(0, "11:15:00") + i * 7, "198.18.250.4", "GET", f"/old-product-{i}", 404, ua="Googlebot/2.1", scn="HN-09")

    w.scenario("HN-10", H, "Client with an expired token gets 25 x 401 in 50 seconds. Below threshold; should NOT alert.")
    u = w.users["u.chen"]
    for i in range(25):
        w.api(at(2, "14:05:00") + i * 2, "key-chen", "u.chen", u["ip"], "GET", "/api/v1/orders", 401, scn="HN-10")


def inject_malformed(w: World):
    """A couple of corrupt lines to exercise ingestion error handling."""
    for src, line in (("web", '{"time_iso8601": "2026-03-02T10:00:00+00:00", "remote_addr": '),
                      ("auth", json.dumps({"timestamp": "2026-03-02T10:00:00.000Z", "event": "login"}))):
        w.items[src].append({"epoch": START + 36000, "native": line, "scn": None, "exp": [], "mal": False})


def generate(out_dir: Path, seed: int = DEFAULT_SEED, days: int = 3) -> dict:
    w = World(seed)
    baseline(w, days)
    attacks(w)
    evasions(w)
    hard_negatives(w)
    inject_malformed(w)

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    labels, counts = [], {}
    for source, items in w.items.items():
        items.sort(key=lambda it: it["epoch"])
        with (out_dir / f"{source}.jsonl").open("w") as fh:
            for n, it in enumerate(items, 1):
                fh.write((it["native"] if isinstance(it["native"], str) else json.dumps(it["native"])) + "\n")
                if it["scn"]:
                    labels.append({"event_id": f"{source}-{n:06d}", "scenario": it["scn"], "malicious": it["mal"],
                                   "expected_rules": it["exp"]})
        counts[source] = len(items)
    with (out_dir / "labels.jsonl").open("w") as fh:
        for l in labels:
            fh.write(json.dumps(l) + "\n")
    scenarios = [{**s, "expected_rules": sorted(s["expected_rules"])} for s in w.scenarios.values()]
    (out_dir / "scenarios.json").write_text(json.dumps(scenarios, indent=2) + "\n")
    return {"seed": seed, "days": days, "events": counts, "labels": len(labels), "scenarios": len(scenarios)}
