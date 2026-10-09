# API alert triage

## SOC-API-001

_Enumeration._
Mix of 403/404 across sequential IDs = probing; uniform 401 = broken client. Identify key owner, check whether any requests succeeded (200s on other users' objects = authorization flaw). Throttle/revoke key if abusive.

## SOC-API-002

_Bulk export._
Confirm business justification with the key owner. Check source IP vs principal's normal IP. If unexplained: revoke key, preserve logs, assess data exposure and notification duties with legal/IR.

## SOC-API-003

_Key on many IPs._
Is it a known shared CI/service key (known FP, HN-08)? If not: treat key as stolen, rotate, review all calls made with the key.
