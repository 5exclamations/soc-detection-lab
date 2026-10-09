# SOC Lab: detection engineering with synthetic data

A self-contained defensive lab: generate synthetic security logs, normalize them, run Sigma-style detections with correlation, score the results against labels, and investigate the resulting incidents. **All data is fabricated** (documentation IP ranges, invented users).

## Quick start
```bash
make setup      # venv + deps (Python ≥3.10)
make lab        # generate → ingest → detect → validate (prints the report)
make test       # 87 tests: per-rule positive/negative fixtures, rule lint, pipeline, metric gate
python -m soclab alerts                    # list alerts
python -m soclab alerts --id ALR-0012      # explanation, evidence, timeline
python -m soclab investigate INC-0022      # the multi-stage intrusion
python -m soclab pivot --ip 203.0.113.50
python -m soclab sql sql/hunting.sql
```
Docker: `docker compose run --rm lab` and `docker compose run --rm test`.

## Layout
`rules/` Sigma rules (17 alerting + helpers) · `soclab/` pipeline · `tests/` pytest · `datasets/` exported positive/negative fixtures (`soclab fixtures`) · `sql/` hunting queries · `docs/` catalog, ATT&CK, runbooks, IR, FP analysis, limitations, architecture · `reports/` validation + ATT&CK Navigator layer.

## Current results (seed 1337)
Precision 0.896, recall 0.935 on the labeled synthetic set; 5 false positives and 2 false negatives, every one traced to a planted scenario. See [docs/false-positive-analysis.md](docs/false-positive-analysis.md). These numbers say nothing about production performance.

## Extending
Add a rule in `rules/*.yml` (with `x-soclab` metadata), add positive and negative cases in `soclab/testcases.py`, run `make test docs`. If metrics move, update `tests/expected_metrics.json` deliberately.

Docs: [architecture](docs/architecture.md) · [catalog](docs/detection-catalog.md) · [ATT&CK](docs/mitre-mapping.md) · [IR](docs/incident-response.md) · [limitations](docs/limitations.md) · [investigation](docs/investigations/chain-01.md)
