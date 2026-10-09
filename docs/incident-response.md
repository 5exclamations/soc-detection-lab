# Incident Response Procedure (lab)

Lifecycle based on preparation → detection → containment → eradication → recovery → lessons learned.

1. **Detect/triage.** Alert → runbook for its rule family. Decide: false positive (document in tuning backlog), benign true positive, or incident.
2. **Declare.** Open an incident when an alert is critical, confirmed malicious, or ≥2 related alerts cover different tactics (the lab auto-groups these: `python -m soclab investigate INC-xxxx`). Assign a lead; record start time (UTC).
3. **Scope.** Pivot on every entity (IP, user, key). Build the timeline from raw events, not only alerts. Answer: initial access, accounts touched, data touched, persistence created.
4. **Contain** (least disruptive effective action first): revoke sessions/keys, disable account, block IP, detach policies, restore logging. Preserve evidence before destructive steps.
5. **Eradicate.** Remove attacker-created users, keys, role grants, bucket policies; reset credentials; close the entry vector.
6. **Recover.** Restore services, monitor the entities for 7 days with tightened thresholds.
7. **Lessons learned.** Within 5 working days: timeline, detection gaps (what fired late/not at all), new/tuned rules, new fixtures in `testcases.py`.

Severity guide: **critical** audit tampering or multi-tactic activity; **high** confirmed credential misuse or bulk data access; **medium** suspicious, unconfirmed; **low** recon.
