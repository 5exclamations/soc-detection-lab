# Investigation walkthrough: CHAIN-01 (INC-0022)

Reproduce: `make lab && python -m soclab investigate INC-0022`. Real output of that command is in [chain-01-output.txt](chain-01-output.txt).

**Starting point.** The incident was raised as *critical*: 13 alerts over 35 minutes, 7 ATT&CK tactics, one external IP (203.0.113.50) and one privileged user (adm-mpatel).

| Step | Question | How | Finding |
|---|---|---|---|
| 1 | How did they get in? | Alerts SOC-AUTH-001 then SOC-AUTH-003 | 14 failures then success from RO at 02:14 UTC, no MFA |
| 2 | Was this normal for the account? | SOC-AUTH-005; `sql: SELECT ts,src_ip,src_country FROM events WHERE user='adm-mpatel' AND category='authentication' AND outcome='success'` | Only login from this IP/country, 02:14 UTC; other logins are 08–17 UTC from 10.20.5.5 |
| 3 | What did they reach? | SOC-WEB-003; `python -m soclab pivot --ip 203.0.113.50` | Admin console from an external address |
| 4 | Persistence? | SOC-PRIV-001, SOC-CLOUD-003 | Backdoor `svc-backup2` given admin role, access key created, AdministratorAccess attached |
| 5 | Defense evasion? | SOC-CLOUD-001 | Trail stopped at 02:33 |
| 6 | Data impact? | SOC-API-002 | 3 × 200 MB exports with a new key `key-mpatel-new` |
| 7 | Contain | Runbooks: authentication, cloud, api | Disable adm-mpatel and svc-backup2, revoke `key-mpatel-new`, re-enable logging, block IP |

Note the gap: between 02:33 and the end of logging, cloud events after StopLogging would be missing in a real environment; treat the later API exports as the only evidence for that window (see limitations).
