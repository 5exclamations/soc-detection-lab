# Privilege change triage

## SOC-PRIV-001
**Meaning:** privileged role/group granted with no ticket.
1. Does a change ticket exist elsewhere (filed late / break-glass)? Ask the actor and their manager via a known channel. 2. Was the actor's account active from an unusual IP/time (check SOC-AUTH alerts for the actor)? 3. If unauthorized: revert the grant, disable target if it is a new/unknown account, review what the target did since. **Escalate** immediately if the actor session is suspect.

## SOC-PRIV-002
**Meaning:** sudoers modified without ticket. 1. Retrieve the diff from the host (auditd/FIM or config management). 2. Compare to CM repo. 3. Revert if unauthorized, review logins to the host.
