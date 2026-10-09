# Cloud audit alert triage

## SOC-CLOUD-001 (logging tampering) - critical
Assume active attacker. Re-enable logging immediately (restoring evidence trail), identify actor session and source IP, disable/rotate actor credentials, review everything since the actor's first anomalous event, start IR.

## SOC-CLOUD-002 (console login without MFA)
Verify federated-MFA exemption; otherwise contact user, revoke sessions, enforce MFA.

## SOC-CLOUD-003 (admin policy / key for another principal)
Identify the created key/attached policy, disable the key and detach the policy, check what the new key was used for, review actor session.

## SOC-CLOUD-004 (public bucket)
Block public access, snapshot the policy for evidence, check access logs for external reads since the change, assess data classification.
