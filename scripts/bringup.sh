#!/usr/bin/env bash
# XGenGuardian — one-shot bring-it-up for internal testing.
#
# Goal: from a fresh clone on a laptop, get to a working DoH endpoint
# and live activity feed in under 5 minutes.
#
# Run from repo root:    ./scripts/bringup.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

c_green="\033[32m"; c_red="\033[31m"; c_yellow="\033[33m"; c_blue="\033[36m"; c_off="\033[0m"

step()  { echo -e "${c_blue}▸${c_off} $*"; }
ok()    { echo -e "  ${c_green}✓${c_off} $*"; }
warn()  { echo -e "  ${c_yellow}!${c_off} $*"; }
die()   { echo -e "  ${c_red}✗${c_off} $*"; exit 1; }

# 1. preflight
step "Preflight"
command -v docker >/dev/null || die "docker not installed"
docker compose version >/dev/null 2>&1 || die "docker compose plugin missing (need Docker Desktop or compose-plugin)"
command -v openssl >/dev/null || die "openssl missing"
command -v curl    >/dev/null || die "curl missing"
ok "deps present"

# 2. dev TLS certs
step "Dev TLS certs"
if [ ! -f "$ROOT/tls/cert.pem" ]; then
  bash "$ROOT/scripts/gen-dev-certs.sh"
else
  ok "tls/cert.pem already present (skip; rerun gen-dev-certs.sh to renew)"
fi

# 3. bring the stack up
step "Starting Postgres + Redis + MinIO + CoreDNS via docker compose"
docker compose up -d
ok "compose up"

# 4. wait for postgres
step "Waiting for Postgres readiness"
for i in $(seq 1 30); do
  if docker compose exec -T postgres pg_isready -U xgg -d xgg >/dev/null 2>&1; then
    ok "postgres ready"
    break
  fi
  sleep 1
  [ "$i" -eq 30 ] && die "postgres did not become ready"
done

# 5. apply migrations
step "Applying migrations"
if command -v migrate >/dev/null 2>&1; then
  migrate -path migrations -database "postgres://xgg:xgg@localhost:5432/xgg?sslmode=disable" up
  ok "migrate up"
else
  warn "golang-migrate not installed; applying with psql instead"
  for f in $(ls migrations/*.sql | sort); do
    docker compose exec -T postgres psql -U xgg -d xgg < "$f" >/dev/null
    ok "applied $f"
  done
fi

# 6. fetch a small blocklist sample so the resolver has something to work with
step "Ingesting blocklists (one-shot, will take ~30s)"
if [ -d tools/blocklist-fetcher ]; then
  (
    cd tools/blocklist-fetcher
    pip install --quiet httpx redis >/dev/null 2>&1 || true
    OUT_DIR="$ROOT/data" REDIS_ADDR="localhost:6379" python fetch.py || warn "blocklist ingest failed; resolver will start empty"
  )
fi

# 7. seed a tiny brand registry (just 5 brands for quick start; full set takes longer)
step "Seeding a starter brand registry (5 brands)"
warn "Full 50-brand seed via 'make seed-brands' once sandbox-render + visual-match are running"
warn "Skipped here — needs services up first; run 'make seed-brands' after step 9"

# 8. summary
step "Building local Go services"
for svc in resolver verdict-api portal-api ct-monitor; do
  if [ -d "services/$svc" ]; then
    ( cd "services/$svc" && go build ./... >/dev/null 2>&1 ) \
      && ok "built $svc" \
      || warn "build failed for $svc — run 'go mod tidy' in services/$svc and rerun"
  fi
done

cat <<EOF

──────────────────────────────────────────────────────────────────
  ${c_green}Bring-up complete.${c_off}

  Next steps for internal testing:

  ${c_blue}1.${c_off} Trust the dev CA in your browser / OS:
        See top of scripts/gen-dev-certs.sh for per-OS commands.

  ${c_blue}2.${c_off} Start the backend services (in separate terminals or via tmux/Procfile):

        cd services/visual-match   && uvicorn app.main:app --port 8003
        cd services/sandbox-render && uvicorn app.main:app --port 8002
        cd services/verdict-api    && go run ./cmd/verdict-api
        cd services/portal-api     && go run ./cmd/portal-api
        cd services/resolver       && go run ./cmd/resolver
        cd services/ct-monitor     && go run ./cmd/ct-monitor

  ${c_blue}3.${c_off} Seed the brand registry once visual-match + sandbox-render are up:
        make seed-brands

  ${c_blue}4.${c_off} Start the portal:
        cd apps/portal && npm install && npm run dev

  ${c_blue}5.${c_off} Open the live activity feed:
        http://localhost:13000/live

  ${c_blue}6.${c_off} Point your browser at the DoH endpoint:
        Firefox → Settings → Network → Enable DoH →
          https://dns.local.test:8543/dns-query
        (or https://localhost:8543/dns-query if you skipped the hosts entry)

  ${c_blue}7.${c_off} Start clicking the worst of the web. Watch /live.
──────────────────────────────────────────────────────────────────
EOF
