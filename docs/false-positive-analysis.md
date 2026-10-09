# False-positive analysis

Source: `reports/validation.md` (regenerate with `make lab`). Seed 1337: 48 alerts, 43 true-positive, **5 false-positive**; 31 expected scenario/rule detections, **2 missed**.

## False positives (all from deliberately planted benign scenarios; zero from baseline noise)
| Alert | Scenario | Why it fires | Tuning option | Trade-off |
|---|---|---|---|---|
| SOC-AUTH-001 + SOC-AUTH-003 | HN-02 service account retry storm, then fixed | 45 failures from one internal IP, then success | Suppress `svc-*` from internal ranges after owner confirmation | A compromised service account on the internal network would be hidden |
| SOC-AUTH-004 | HN-03 VPN exit change JP→DE | Two countries in 20 min | Exclude VPN egress ranges | Attacker using the same VPN is hidden |
| SOC-AUTH-005 | HN-04 on-call admin at 03:10 | Global night window | Join with on-call roster | Needs roster data feed |
| SOC-API-003 | HN-08 CI runners share a key | 3 IPs in 4 min | Per-runner keys or allowlist runner CIDR | Allowlist can mask theft from inside the CIDR |

## Suppressions that work (tuned in rule logic)
HN-05 (allowlisted scanner) and HN-07 (allowlisted BI export) produce no alerts because of explicit `filter_*` selections. Near-miss scenarios HN-01, HN-06, HN-09, HN-10 stay under thresholds or carry tickets.

## False negatives
EVA-01 and EVA-02 (see limitations). They are tracked in `tests/expected_metrics.json`; the CI gate fails if the set changes, so improvements and regressions are both deliberate.

## Reading the numbers
A true-positive count above the expected count (e.g. SOC-API-002: 6 alerts for 2 scenarios) means single-event rules alert once per event; consider aggregation to reduce analyst load.
