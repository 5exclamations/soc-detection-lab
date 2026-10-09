PY ?= .venv/bin/python

.PHONY: setup lab test docs fixtures clean
setup:
	python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
lab:        ## generate -> ingest -> detect -> validate
	$(PY) -m soclab run-all
docs:
	$(PY) -m soclab docs
fixtures:
	$(PY) -m soclab fixtures
test:
	$(PY) -m pytest -q
clean:
	rm -rf data/raw data/soclab.db reports/validation.* .pytest_cache
