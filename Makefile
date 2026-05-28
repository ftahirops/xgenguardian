.PHONY: help build test lint dev dev-backend dev-portal migrate seed-brands test-doh clean proto fetch-blocklists eval smoke bringup dev-certs dev-up dev-down doctor healthcheck bulk-scan scheduler smoke-scan dnstwist-cron fp-bench fp-bench-fetch fp-bench-gate fp-bench-all

help:
	@echo "XGenGuardian — make targets"
	@echo "  build         build all services"
	@echo "  test          run unit tests"
	@echo "  lint          run linters"
	@echo "  dev           bring up full local stack"
	@echo "  dev-backend   start backend services (resolver, verdict-api, sandbox-render, visual-match)"
	@echo "  dev-portal    start Next.js portal on :3000"
	@echo "  migrate       run Postgres migrations"
	@echo "  seed-brands   seed Brand Registry from tools/brand-seeder/brands.yaml"
	@echo "  test-doh      send a test DoH query (URL=...)"
	@echo "  clean         remove build artifacts"

build:
	go build ./services/...
	cd apps/portal && npm run build

test:
	go test ./services/...

# Race-detector run — required green before merging any concurrent code.
# Catches data races like the Tier-1 signals-append bug fixed 2026-05-28.
test-race:
	cd services/verdict-api && go test -race ./...
	cd services/resolver && go test -race ./...
	cd services/scheduler && go test -race ./...
	cd services/sandbox-render && pytest -q
	cd services/visual-match && pytest -q

lint:
	golangci-lint run ./services/...
	cd apps/portal && npm run lint

dev:
	docker compose up -d
	$(MAKE) migrate
	$(MAKE) dev-backend &
	$(MAKE) dev-portal

dev-backend:
	@echo "Starting backend services..."
	(cd services/resolver && air) &
	(cd services/verdict-api && air) &
	(cd services/scheduler && air) &
	(cd services/sandbox-render && uvicorn app.main:app --reload --port 8002) &
	(cd services/visual-match && uvicorn app.main:app --reload --port 8003) &
	wait

scheduler:
	cd services/scheduler && go run ./cmd/scheduler

smoke-scan:
	python3 tools/smoke-scan/scan.py $(ARGS)

dnstwist-cron:
	python3 tools/dnstwist-cron/run.py $(ARGS)

dev-portal:
	cd apps/portal && npm run dev

migrate:
	migrate -path migrations -database "postgres://xgg:xgg@localhost:15432/xgg?sslmode=disable" up

seed-brands:
	cd tools/brand-seeder && python seed.py

test-doh:
	curl -H 'accept: application/dns-message' \
	  "https://localhost:8443/dns-query?dns=$$(echo -n '$(URL)' | base64 -w0)"

proto:
	./scripts/gen-proto.sh

smoke:
	./scripts/smoke.sh

bringup:
	./scripts/bringup.sh

dev-certs:
	./scripts/gen-dev-certs.sh

dev-up:
	./scripts/dev-up.sh

dev-down:
	-tmux kill-session -t xgg 2>/dev/null
	-overmind quit 2>/dev/null
	docker compose down

fetch-blocklists:
	python tools/blocklist-fetcher/fetch.py

eval:
	python tools/eval/run.py

# fp-bench — accuracy harness. Required gate for any detection change.
# Targets: fp-bench-fetch / fp-bench / fp-bench-gate / fp-bench-all
fp-bench-fetch:
	$(MAKE) -C tools/fp-bench fetch

fp-bench:
	$(MAKE) -C tools/fp-bench bench BASE=$(BASE)

fp-bench-gate:
	$(MAKE) -C tools/fp-bench gate

fp-bench-all:
	$(MAKE) -C tools/fp-bench all BASE=$(BASE)

doctor:
	./scripts/doctor.sh

healthcheck:
	go run ./services/healthcheck/cmd/healthcheck

bulk-scan:
	python tools/bulk-scan/scan.py $(FILE)

clean:
	rm -rf bin/ dist/ apps/portal/.next
