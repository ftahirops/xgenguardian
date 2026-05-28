#!/usr/bin/env bash
# XGenGuardian — diagnostic. Run `make doctor` to find out why the stack
# isn't working. Each check ends with `OK` or `FAIL: <one-line fix>`.
#
# Designed to be safe to run mid-incident: read-only, no mutations.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

green=$'\033[32m'; red=$'\033[31m'; yellow=$'\033[33m'; off=$'\033[0m'
fails=0

ok()   { printf "  %sOK%s   %s\n" "$green" "$off" "$1"; }
fail() { printf "  %sFAIL%s %s\n       → %s\n" "$red" "$off" "$1" "$2"; fails=$((fails+1)); }
warn() { printf "  %sWARN%s %s\n       → %s\n" "$yellow" "$off" "$1" "$2"; }
sec()  { printf "\n%s%s%s\n" "$yellow" "── $1 ──" "$off"; }

http_ok() { curl -fsS --max-time 3 "$1" >/dev/null 2>&1; }

# ─────────────────────────────────────────────────────────────
sec "Toolchain"
command -v docker >/dev/null      && ok "docker"             || fail "docker"   "install Docker Desktop or docker-engine"
docker compose version >/dev/null 2>&1 && ok "compose plugin" || fail "docker compose" "install the compose plugin"
command -v go >/dev/null          && ok "go ($(go version | awk '{print $3}'))" || fail "go" "install Go 1.22+"
command -v node >/dev/null        && ok "node ($(node -v))" || fail "node"  "install Node 20+"
command -v python3 >/dev/null     && ok "python3 ($(python3 --version | awk '{print $2}'))" || fail "python3" "install Python 3.11+"
command -v openssl >/dev/null     && ok "openssl"           || fail "openssl" "install openssl"
command -v jq >/dev/null          && ok "jq"                || warn "jq" "optional but recommended for session-log inspection"

# ─────────────────────────────────────────────────────────────
sec "Local TLS"
if [ -f "$ROOT/tls/cert.pem" ] && [ -f "$ROOT/tls/key.pem" ] && [ -f "$ROOT/tls/ca.pem" ]; then
  ok "dev TLS certs present"
  notafter=$(openssl x509 -in "$ROOT/tls/cert.pem" -noout -enddate | cut -d= -f2)
  ok "leaf valid until: $notafter"
else
  fail "dev TLS certs" "run: make dev-certs"
fi

# ─────────────────────────────────────────────────────────────
sec "Docker infra"
for svc in postgres redis minio; do
  if docker compose ps --status running --quiet "$svc" 2>/dev/null | grep -q .; then
    ok "$svc container running"
  else
    fail "$svc not running" "run: docker compose up -d $svc"
  fi
done

# ─────────────────────────────────────────────────────────────
sec "Postgres"
if docker compose exec -T postgres pg_isready -U xgg -d xgg >/dev/null 2>&1; then
  ok "pg_isready"
  if docker compose exec -T postgres psql -U xgg -d xgg -tAc \
      "SELECT count(*) FROM pg_extension WHERE extname='vector';" 2>/dev/null | grep -q 1; then
    ok "pgvector extension installed"
  else
    fail "pgvector missing" "make migrate"
  fi
  brands=$(docker compose exec -T postgres psql -U xgg -d xgg -tAc "SELECT count(*) FROM brands;" 2>/dev/null || echo 0)
  if [ "$brands" -gt 0 ] 2>/dev/null; then
    ok "brand registry: $brands brands"
  else
    warn "brand registry empty" "run: make seed-brands (needs visual-match + sandbox-render up)"
  fi
else
  fail "postgres not accepting connections" "docker compose restart postgres"
fi

# ─────────────────────────────────────────────────────────────
sec "Redis"
if docker compose exec -T redis redis-cli ping 2>/dev/null | grep -q PONG; then
  ok "redis PONG"
  blocked=$(docker compose exec -T redis redis-cli SCARD blocklist:exact 2>/dev/null | tr -d '\r')
  if [ "${blocked:-0}" -gt 0 ] 2>/dev/null; then
    ok "blocklist: $blocked domains"
  else
    warn "blocklist empty" "run: make fetch-blocklists"
  fi
else
  fail "redis not responding" "docker compose restart redis"
fi

# ─────────────────────────────────────────────────────────────
sec "MinIO"
if http_ok http://localhost:9000/minio/health/live; then
  ok "minio live"
else
  fail "minio not reachable" "docker compose restart minio"
fi

# ─────────────────────────────────────────────────────────────
sec "Backend services"
http_ok http://localhost:8002/healthz && ok "sandbox-render (:8002)"  || fail "sandbox-render"  "cd services/sandbox-render && uvicorn app.main:app --port 8002"
http_ok http://localhost:8003/healthz && ok "visual-match (:8003)"    || fail "visual-match"   "cd services/visual-match && uvicorn app.main:app --port 8003 (first run downloads ~600MB)"
http_ok http://localhost:18080/healthz && ok "verdict-api (:18080)"     || fail "verdict-api"    "cd services/verdict-api && go run ./cmd/verdict-api"
http_ok http://localhost:18081/healthz && ok "portal-api (:18081)"      || fail "portal-api"     "cd services/portal-api && go run ./cmd/portal-api"

if curl -fksS --max-time 3 https://localhost:8543/healthz >/dev/null 2>&1; then
  ok "resolver DoH (:8543)"
else
  fail "resolver DoH not reachable" "cd services/resolver && go run ./cmd/resolver"
fi

http_ok http://localhost:13000 && ok "portal (:13000)" || warn "portal" "cd apps/portal && npm run dev"

# ─────────────────────────────────────────────────────────────
sec "End-to-end smoke"
if http_ok http://localhost:18080/healthz; then
  vr=$(curl -fsS --max-time 8 -X POST http://localhost:18080/v1/check \
        -H 'content-type: application/json' \
        -d '{"url":"https://example.com"}' 2>/dev/null || echo "")
  if echo "$vr" | grep -q '"verdict"'; then
    verdict=$(echo "$vr" | grep -o '"verdict":"[^"]*"' | head -1)
    ok "/v1/check returned $verdict"
  else
    fail "/v1/check did not respond with a verdict" "check verdict-api logs"
  fi
fi

# ─────────────────────────────────────────────────────────────
sec "Session log"
if [ -d "$ROOT/data/sessions" ]; then
  ok "data/sessions exists"
  today=$(date -u +%F)
  if [ -f "$ROOT/data/sessions/${today}.jsonl" ]; then
    lines=$(wc -l < "$ROOT/data/sessions/${today}.jsonl")
    ok "today's log: ${lines} verdict(s)"
  else
    warn "no log for today" "make a check call: curl -X POST :8080/v1/check -d '{\"url\":\"https://example.com\"}'"
  fi
else
  warn "data/sessions missing" "mkdir -p data/sessions; ensure SESSION_LOG_DIR is set in verdict-api"
fi

# ─────────────────────────────────────────────────────────────
echo
if [ "$fails" -eq 0 ]; then
  printf "%s✓ All checks passed.%s\n" "$green" "$off"
  exit 0
else
  printf "%s✗ %d check(s) failed.%s Fix the FAILs above and rerun.\n" "$red" "$fails" "$off"
  exit 1
fi
