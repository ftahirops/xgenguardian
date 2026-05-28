#!/usr/bin/env bash
# XGenGuardian — smoke test.
#
# Exercises every public endpoint after `docker compose up`. Pass = exit 0.
#
# Usage:
#   ./scripts/smoke.sh                          # against localhost
#   BASE_VERDICT=http://api.example ./scripts/smoke.sh
#
# Expects (defaults):
#   verdict-api HTTP  :8080
#   portal-api        :8081
#   sandbox-render    :8002
#   visual-match      :8003
#   portal            :3000
#   postgres          :5432 (xgg/xgg/xgg)
#   redis             :6379
#   minio             :9000 (xggadmin/xggadmin123, bucket xgg-evidence)
set -euo pipefail

BASE_VERDICT="${BASE_VERDICT:-http://localhost:18080}"
BASE_PORTAL_API="${BASE_PORTAL_API:-http://localhost:18081}"
BASE_SANDBOX="${BASE_SANDBOX:-http://localhost:8002}"
BASE_VISUAL="${BASE_VISUAL:-http://localhost:8003}"
BASE_PORTAL="${BASE_PORTAL:-http://localhost:13000}"
DOH_URL="${DOH_URL:-https://localhost:8543/dns-query}"

pass=0
fail=0

check() {
  local name="$1"; shift
  if "$@" >/dev/null 2>&1; then
    echo "  ✓ $name"
    pass=$((pass+1))
  else
    echo "  ✗ $name"
    fail=$((fail+1))
  fi
}

curl_json() {
  curl -fsS --max-time 5 "$@"
}

echo "── Health checks ──────────────────────────────────────"
check "verdict-api /healthz"     curl_json "$BASE_VERDICT/healthz"
check "portal-api /healthz"      curl_json "$BASE_PORTAL_API/healthz"
check "sandbox-render /healthz"  curl_json "$BASE_SANDBOX/healthz"
check "visual-match /healthz"    curl_json "$BASE_VISUAL/healthz"
check "portal index"             curl_json "$BASE_PORTAL/"

echo
echo "── Verdict API ────────────────────────────────────────"
# Clean known-good URL: should NOT be BLOCK.
resp_clean="$(curl_json -X POST "$BASE_VERDICT/v1/check" \
  -H 'content-type: application/json' \
  -d '{"url":"https://www.google.com"}')" || true
echo "  → $resp_clean"
if echo "$resp_clean" | grep -qE '"verdict":"(CLEAN|WARN|ANALYZING)"'; then
  echo "  ✓ clean URL returns non-BLOCK"; pass=$((pass+1))
else
  echo "  ✗ clean URL did not return non-BLOCK"; fail=$((fail+1))
fi

# Phishing-style URL: should be at minimum WARN.
resp_phish="$(curl_json -X POST "$BASE_VERDICT/v1/check" \
  -H 'content-type: application/json' \
  -d '{"url":"https://paypa1-secure-login.tk/signin"}')" || true
echo "  → $resp_phish"
if echo "$resp_phish" | grep -qE '"verdict":"(BLOCK|WARN)"'; then
  echo "  ✓ lookalike URL flagged"; pass=$((pass+1))
else
  echo "  ✗ lookalike URL not flagged"; fail=$((fail+1))
fi

echo
echo "── Portal API ─────────────────────────────────────────"
# /v1/recent should at least respond with JSON (may be empty).
resp_recent="$(curl_json "$BASE_PORTAL_API/v1/recent")" || true
if echo "$resp_recent" | head -c 1 | grep -qE '^\['; then
  echo "  ✓ /v1/recent returns JSON array"; pass=$((pass+1))
else
  echo "  ✗ /v1/recent did not return JSON array"; fail=$((fail+1))
fi

echo
echo "── Sandbox render (slow) ──────────────────────────────"
resp_render="$(curl -fsS --max-time 15 -X POST "$BASE_SANDBOX/render" \
  -H 'content-type: application/json' \
  -d '{"url":"https://example.com"}')" || true
if echo "$resp_render" | grep -q '"evidence_id"'; then
  echo "  ✓ render returns evidence_id"; pass=$((pass+1))
else
  echo "  ✗ render did not return evidence_id (sandbox-render may be cold)"
  fail=$((fail+1))
fi

echo
echo "── DoH endpoint ───────────────────────────────────────"
# RFC 8484 base64url-encoded query for example.com A record.
DNS_QUERY="$(printf '\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01' | base64 -w0 | tr '+/' '-_' | tr -d '=')"
if curl -fksS --max-time 5 -H 'accept: application/dns-message' \
      "$DOH_URL?dns=$DNS_QUERY" -o /tmp/xgg-doh.bin; then
  echo "  ✓ DoH endpoint responded"; pass=$((pass+1))
else
  echo "  ✗ DoH endpoint failed (resolver may not be running on $DOH_URL)"
  fail=$((fail+1))
fi

echo
echo "──────────────────────────────────────────────────────"
echo "Pass: $pass   Fail: $fail"
[ "$fail" -eq 0 ]
