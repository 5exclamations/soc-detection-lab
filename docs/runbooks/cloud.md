# Cloud audit alert triage

## SOC-CLOUD-001

_Logging tampering; severity critical._
Assume active attacker. Re-enable logging immediately (restoring evidence trail), identify actor session and source IP, disable/rotate actor credentials, review everything since the actor's first anomalous event, start IR.

## SOC-CLOUD-002

_Console login without MFA._
Verify federated-MFA exemption; otherwise contact user, revoke sessions, enforce MFA.

## SOC-CLOUD-003

_Admin policy / key for another principal._
Identify the created key/attached policy, disable the key and detach the policy, check what the new key was used for, review actor session.

## SOC-CLOUD-004

_Public bucket._
Block public access, snapshot the policy for evidence, check access logs for external reads since the change, assess data classification.
