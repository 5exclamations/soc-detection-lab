# Web alert triage

## SOC-WEB-001

_Content discovery._
Check UA and whether any 200/301 followed on sensitive paths. Authorized scanner? (allowlist is 10.20.8.0/28.) Block/rate-limit if external; low priority unless followed by SOC-WEB-002/003.

## SOC-WEB-002

_Injection/traversal markers._
A match is an attempt, not success. Check response status and size for the same request and subsequent requests from the IP; review app/WAF logs. Success indicators (200 with large body, 500 errors) → escalate to app owner and IR.

## SOC-WEB-003

_External admin access._
Confirm whether the source is an unlisted VPN/jump host. If not: treat as potential credential compromise, check auth logs for the same IP (`pivot --ip`), restrict /admin to internal ranges, rotate credentials. **Escalate**.
