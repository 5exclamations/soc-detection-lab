# Sigma subset: compatibility and limits

The engine (`soclab/sigma.py`, `soclab/engine.py`) evaluates Sigma-*style* rules. It is **not** a conformant Sigma backend and has not been validated against the official Sigma test suite or pySigma.

| Feature | Status |
|---|---|
| Named selections: map (AND), list of maps (OR) | Supported |
| `condition`: `and`, `or`, `not`, parentheses, `1 of x*`, `all of x*`, `them` | Supported |
| Modifiers: `contains`, `startswith`, `endswith`, `re`, `all`, `cidr`, `gt/gte/lt/lte`, `exists` | Supported |
| `null` matching, `*` / `?` wildcards, case-insensitive equality | Supported |
| Correlation: `event_count`, `value_count`, `temporal_ordered` | Supported (subset: see below) |
| Keyword (field-less) searches, `fieldref`, base64/windash/utf16 modifiers | Not supported (rejected at load) |
| `timeframe` / aggregation in conditions (`\| count()`) | Not supported; use correlation documents |
| `temporal` (unordered), `value_sum`, `value_avg`, `value_percentile` | Not supported |
| Rule `id` as UUID, `status`, `tags`, `falsepositives`, `level` | Supported/validated by tests |
| pySigma pipelines / backend conversion | Not provided; field names are the lab schema, so rules will not run on a SIEM without mapping |

Behavior that differs from or extends the spec
- Correlations with `group-by` require the same group-by across referenced correlations. `event_count`/`value_count` may only reference detection rules (not other correlations).
- Burst merging: events that keep satisfying the threshold within the timespan extend one alert instead of producing a new alert per event.
- `temporal_ordered` pairs each first-stage match with at most one second-stage match.
- Lab extensions live under `x-soclab` (rule_id, explanation, runbook, tuning, limitations, `alert: false`, `escalate_privileged`).
- Batch evaluation over sorted events; no streaming, late-arrival or state expiry.

## ATT&CK mapping review
Mappings were reviewed for fit, and `docs/mitre-mapping.md` is generated from the rule tags. Judgement calls: SOC-API-001 maps to T1595 (no exact API-enumeration technique); SOC-PRIV-002 maps sudoers edits to T1548.003 (closest fit); SOC-WEB-003 maps to T1078 only, because an authenticated admin page load is not evidence of exploitation; SOC-API-002 maps to T1213 only, because a download through the victim's own API is collection, not proof of exfiltration to an attacker service. Technique IDs should be re-checked against the current ATT&CK release before external use; the Navigator layer's `attack` version field is set to 16 as a placeholder.
