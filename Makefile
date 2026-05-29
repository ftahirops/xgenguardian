.PHONY: help build test lint dev dev-backend dev-portal migrate seed-brands test-doh clean proto fetch-blocklists eval smoke bringup dev-certs dev-up dev-down doctor healthcheck bulk-scan scheduler smoke-scan dnstwist-cron fp-bench fp-bench-fetch fp-bench-gate fp-bench-all backup restore cleanup

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
	@echo "  backup        dump Postgres to /var/backups/xgg-postgres/"
	@echo "  restore       restore a dump (FILE=/path/to/file.dump.gz)"
	@echo "  cleanup       delete expired evidence rows and orphaned MinIO objects"

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

# ── operational tooling ───────────────────────────────────────────────────────

# Run a Postgres backup to /var/backups/xgg-postgres/
# Requires PGPASSWORD env (or ~/.pgpass). Optional: DATABASE_URL, BACKUP_RETENTION_DAYS.
backup:
	bash /home/xgenguardian/code/scripts/pg-backup.sh

# Restore a Postgres dump. Usage: make restore FILE=/path/to/file.dump.gz
# Requires XGG_RESTORE_CONFIRM=yes and PGPASSWORD env.
restore:
	@test -n "$(FILE)" || (echo "Usage: make restore FILE=/path/to/dump.dump.gz" && exit 1)
	bash /home/xgenguardian/code/scripts/pg-restore.sh "$(FILE)"

# Run evidence retention cleanup (SQL + MinIO orphan sweep).
# Dry-run by default. Set CLEANUP_CONFIRM=yes to commit deletes.
cleanup:
	bash /home/xgenguardian/code/scripts/cleanup-expired.sh
	python3 /home/xgenguardian/code/scripts/cleanup-minio.py

# ---- Maturity testing ----------------------------------------------------
# Single command that runs the full release-gate suite documented in
# docs/maturity-testing-blueprint.md §3. Updates tools/maturity/status.md
# as components are verified. Exit code is non-zero if any required gate
# fails.
maturity-test: maturity-test-go maturity-test-py maturity-test-extension maturity-test-bench maturity-test-status

# Race tests across Go services (P0).
maturity-test-go:
	@echo "==> Go race tests"
	@cd services/verdict-api && go test -race ./... 2>&1 | tail -20 && echo "verdict-api OK"
	@cd services/portal-api && go test -race ./... 2>&1 | tail -10 && echo "portal-api OK"
	@cd services/resolver && go test -race ./... 2>&1 | tail -10 && echo "resolver OK"

# Python service tests (ruff + module compile).
maturity-test-py:
	@echo "==> Python service sanity"
	@python3 -m py_compile services/sandbox-render/app/main.py && echo "sandbox-render compile OK"
	@python3 -m py_compile services/visual-match/app/main.py && echo "visual-match compile OK"

# Extension E2E (Playwright + loaded extension, P0 hang test).
maturity-test-extension:
	@echo "==> Extension E2E (Playwright)"
	@if [ -f tools/maturity/extension-e2e.py ]; then \
		Xvfb :99 -screen 0 1366x768x24 -nolisten tcp & XVFBPID=$$!; sleep 2; \
		DISPLAY=:99 python3 tools/maturity/extension-e2e.py; RC=$$?; \
		kill $$XVFBPID 2>/dev/null; exit $$RC; \
	else echo "(extension-e2e.py not present — see tools/maturity/status.md row 'Extension no-hang E2E')"; fi

# False-positive / false-negative bench against curated corpus.
maturity-test-bench:
	@echo "==> FP-bench"
	@if [ -f tools/fp-bench/run.py ]; then \
		python3 tools/fp-bench/run.py; \
	else echo "(fp-bench not present — see tools/maturity/status.md row 'Benign real-world corpus')"; fi

# Print the current maturity-status tracker.
maturity-test-status:
	@echo ""
	@echo "==> Maturity status (tools/maturity/status.md)"
	@cat tools/maturity/status.md 2>/dev/null || echo "(status.md not present)"

# ---- Real-User Acceptance Test (RUAT) ------------------------------------
# Human-driven counterpart to make maturity-test. See
# docs/real-user-acceptance-test-plan.md for the 10-phase protocol.

# Create a new dated session log from the template. If today's session
# file already exists, suffix the new one with HHMMSS so multiple sessions
# per day each get their own file (matches Phase 9 "3 days of soak" cadence
# where you may run 2-3 sessions per day).
ruat-new-session:
	@mkdir -p tools/maturity/sessions
	@TODAY=$$(date +%F); \
	BASE=tools/maturity/sessions/$$TODAY-session; \
	if [ -f $$BASE.md ]; then \
		SESSION_FILE=$$BASE-$$(date +%H%M%S).md; \
	else \
		SESSION_FILE=$$BASE.md; \
	fi; \
	sed "s/{SESSION_DATE}/$$TODAY/" tools/maturity/real-user-log-template.md > $$SESSION_FILE; \
	echo "Created $$SESSION_FILE"; \
	echo "Open it in your editor and fill it in as you test."

# Run the verdict-api against every URL in tools/maturity/personal-100.md.
# Reports verdict per URL plus a summary.
ruat-personal-100:
	@echo "==> Personal-100 RUAT — Safe mode against your daily-use URLs"
	@if [ ! -f tools/maturity/personal-100.md ]; then \
		echo "Missing tools/maturity/personal-100.md — copy the template and customize."; \
		exit 1; \
	fi
	@grep -E "^https?://" tools/maturity/personal-100.md | while read url; do \
		out=$$(curl -s --max-time 30 -H 'content-type: application/json' \
			-d "{\"url\":\"$$url\",\"mode\":\"safe\",\"client_id\":\"ruat-personal-100\"}" \
			http://127.0.0.1:18080/v1/check 2>&1); \
		v=$$(echo "$$out" | python3 -c "import sys,json; r=json.loads(sys.stdin.read()); print(r.get('verdict','?'))" 2>/dev/null); \
		case "$$v" in \
			ALLOW|CLEAN) printf "  \033[32mPASS\033[0m  %s\n" "$$url" ;; \
			WARN)       printf "  \033[33mWARN\033[0m  %s\n" "$$url" ;; \
			BLOCK)      printf "  \033[31mBLOCK\033[0m %s\n" "$$url" ;; \
			ISOLATE)    printf "  \033[35mISOL\033[0m  %s\n" "$$url" ;; \
			*)          printf "  \033[31m?\033[0m     %s — %s\n" "$$url" "$$v" ;; \
		esac; \
	done

# Run the known-bad checklist (Phase 4). Verdicts should NOT be ALLOW.
ruat-known-bad:
	@echo "==> Known-bad RUAT — these MUST not ALLOW"
	@for url in \
		"https://thepiratebay.org/" \
		"http://1.1.1.1/" \
		"https://1337x.to/" ; do \
		out=$$(curl -s --max-time 30 -H 'content-type: application/json' \
			-d "{\"url\":\"$$url\",\"mode\":\"safe\",\"client_id\":\"ruat-known-bad\"}" \
			http://127.0.0.1:18080/v1/check); \
		v=$$(echo "$$out" | python3 -c "import sys,json; r=json.loads(sys.stdin.read()); print(r.get('verdict','?'),r.get('reason_codes',[]))" 2>/dev/null); \
		case "$$v" in \
			ALLOW*) printf "  \033[31mFAIL\033[0m  %s ALLOWed — false negative\n" "$$url" ;; \
			*)      printf "  \033[32mPASS\033[0m  %s -> %s\n" "$$url" "$$v" ;; \
		esac; \
	done

# Phase B connection-identity RUAT. Exercises the
# browser_remote_ip → PUBLIC_DOMAIN_PRIVATE_IP scoring path end-to-end
# against the running verdict-api. The cases simulate a hijacked DNS path
# by passing a private/wrong IP in the verdict request — no actual network
# attack is staged. Each row is (URL, browser_remote_ip, expected verdict
# prefix, label).
ruat-connection-identity:
	@echo "==> Connection-identity RUAT — simulate DNS hijack / rebind / CDN"
	@printf '%s\n' \
		"https://example.com|10.0.0.5|BLOCK|public domain -> RFC1918 IP (hosts hijack)" \
		"https://example.com|192.168.1.50|BLOCK|public domain -> home LAN IP (router hijack)" \
		"https://example.com|127.0.0.1|BLOCK|public domain -> loopback (hosts file)" \
		"https://example.com|100.64.0.5|BLOCK|public domain -> CGNAT range" \
		"http://router.local|192.168.1.1|ALLOW|local-namespace -> LAN IP (legit)" \
		"https://example.com|203.0.113.10|ALLOW|public domain -> public IP (legit)" \
		"https://example.com||ALLOW|no browser_remote_ip - identity absent" \
	| while IFS='|' read url cip exp label; do \
		if [ -n "$$cip" ]; then \
			body="{\"url\":\"$$url\",\"mode\":\"safe\",\"client_id\":\"ruat-connid\",\"browser_remote_ip\":\"$$cip\",\"force_rescan\":true}"; \
		else \
			body="{\"url\":\"$$url\",\"mode\":\"safe\",\"client_id\":\"ruat-connid\",\"force_rescan\":true}"; \
		fi; \
		out=$$(curl -s --max-time 30 -H 'content-type: application/json' -d "$$body" http://127.0.0.1:18080/v1/check); \
		v=$$(echo "$$out" | python3 -c "import sys,json; r=json.loads(sys.stdin.read()); print(r.get('verdict','?'))" 2>/dev/null); \
		codes=$$(echo "$$out" | python3 -c "import sys,json; r=json.loads(sys.stdin.read()); print(','.join(r.get('reason_codes',[])))" 2>/dev/null); \
		case "$$v" in \
			$$exp*) printf "  \033[32mPASS\033[0m  %-7s ip=%-15s -> %s [%s] — %s\n" "$$exp" "$$cip" "$$v" "$$codes" "$$label" ;; \
			*)      printf "  \033[31mFAIL\033[0m  want=%s got=%s ip=%s codes=[%s] — %s\n" "$$exp" "$$v" "$$cip" "$$codes" "$$label" ;; \
		esac; \
	done

# Help text for RUAT.
ruat-help:
	@echo "Real-User Acceptance Testing targets:"
	@echo "  make ruat-new-session            create a dated session log file"
	@echo "  make ruat-personal-100           run your personal 100-URL acceptance set"
	@echo "  make ruat-known-bad              quick check that known-bad URLs still block"
	@echo "  make ruat-connection-identity    Phase B: DNS hijack / rebind / CDN sims"
	@echo ""
	@echo "Full protocol: docs/real-user-acceptance-test-plan.md"
