# ATT&CK Coverage

_Generated. Mappings mean the rule is **relevant to** the technique, not that it fully covers it. Validated against ATT&CK Enterprise v19.2 (see `python -m soclab attack-check`)._

| Technique | Name | Rules |
|---|---|---|
| T1078 | Valid Accounts | SOC-AUTH-003, SOC-AUTH-004, SOC-AUTH-005, SOC-WEB-003 |
| T1078.004 | Valid Accounts: Cloud Accounts | SOC-CLOUD-002 |
| T1098 | Account Manipulation | SOC-PRIV-001 |
| T1098.001 | Account Manipulation: Additional Cloud Credentials | SOC-CLOUD-003 |
| T1098.003 | Account Manipulation: Additional Cloud Roles | SOC-CLOUD-003 |
| T1110 | Brute Force | SOC-AUTH-003 |
| T1110.001 | Brute Force: Password Guessing | SOC-AUTH-001 |
| T1110.003 | Brute Force: Password Spraying | SOC-AUTH-002 |
| T1190 | Exploit Public-Facing Application | SOC-WEB-002 |
| T1213 | Data from Information Repositories | SOC-API-002 |
| T1530 | Data from Cloud Storage | SOC-CLOUD-004 |
| T1548.003 | Abuse Elevation Control Mechanism: Sudo and Sudo Caching | SOC-PRIV-002 |
| T1550.001 | Use Alternate Authentication Material: Application Access Token | SOC-API-003 |
| T1595 | Active Scanning | SOC-API-001 |
| T1595.003 | Active Scanning: Wordlist Scanning | SOC-WEB-001 |
| T1685.002 | Disable or Modify Tools: Disable or Modify Cloud Log | SOC-CLOUD-001 |
