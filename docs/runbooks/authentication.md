# Authentication alert triage

Common first steps: open the alert (`python -m soclab alerts --id ALR-xxxx`), note `src_ip`, `user`, window; pivot (`python -m soclab pivot --ip <ip>` / `--user <u>`). Do not lock or reset accounts without owner/IR approval for privileged or service accounts.

## SOC-AUTH-001
**Meaning:** ≥10 failures for one account from one IP in 5 min.
1. Is `src_ip` internal and is the user a `svc-*` account? Likely a stale credential: contact owner (known FP, see HN-02).
2. Any success from this IP afterwards? (`sql/successes_after_failures.sql`) → treat as SOC-AUTH-003.
3. External IP + real user: check for lockout, notify user, block IP at edge, check other accounts targeted from the IP.
**Escalate** if success followed or account is privileged.

## SOC-AUTH-002
**Meaning:** one IP failed against ≥6 accounts in 10 min (spray).
1. List targeted accounts; any success from the IP? 2. Check whether IP is an authorized scanner or corporate NAT. 3. If external: block, force reset + MFA check for any account that succeeded. **Escalate** on any success.

## SOC-AUTH-003
**Meaning:** success following a failure burst from the same IP. Assume compromise until disproved.
1. Confirm with the user out-of-band. 2. Revoke sessions/tokens, reset credential, verify MFA devices. 3. Review everything the account and IP did afterward (admin, API, cloud). 4. Open an incident (see `incident-response.md`).

## SOC-AUTH-004
**Meaning:** successes from ≥2 countries within 1 h. Check VPN egress ranges first (known FP, HN-03). If not VPN: contact user, review the second session, revoke if unrecognized.

## SOC-AUTH-005
**Meaning:** `adm-*` login 22:00–05:59 UTC. Check on-call roster / page ticket (known FP, HN-04). If no explanation: contact admin, review all admin/cloud actions by the account in the session, consider disabling.
