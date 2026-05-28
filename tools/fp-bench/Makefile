# fp-bench — false-positive / true-positive measurement harness.
#
# Typical flow:
#   make fetch    # refresh corpora (once a day is enough)
#   make bench    # run engine against all URLs, write reports/
#   make gate     # CI gate — exits non-zero if accuracy regressed
#
# Quick smoke:
#   make smoke    # 50-URL subset for fast iteration

BASE        ?= http://localhost:18080
CONCURRENCY ?= 4
TIMEOUT     ?= 60

PY := python3

.PHONY: fetch bench smoke gate report clean help

help:
	@echo "Targets:"
	@echo "  fetch        Refresh benign + malicious corpora"
	@echo "  bench        Full benchmark, writes reports/bench-*.{json,md}"
	@echo "  smoke        50-URL/label smoke test (fast iteration)"
	@echo "  gate         Pass/fail gate against latest report"
	@echo "  report       Print latest report to stdout"
	@echo "  all          fetch + bench + gate"
	@echo ""
	@echo "Vars: BASE=$(BASE) CONCURRENCY=$(CONCURRENCY) TIMEOUT=$(TIMEOUT)"

fetch:
	$(PY) fetch_corpus.py

bench:
	$(PY) run_bench.py --base $(BASE) --concurrency $(CONCURRENCY) --timeout $(TIMEOUT)

smoke:
	$(PY) run_bench.py --base $(BASE) --concurrency $(CONCURRENCY) --timeout $(TIMEOUT) --limit 50

gate:
	$(PY) gate.py

report:
	@cat reports/bench-latest.md

all: fetch bench gate

clean:
	rm -rf reports/bench-2*.{json,md}
