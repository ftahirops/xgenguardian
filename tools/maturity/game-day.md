# Game-Day Runbook

Concrete shell scripts for the quarterly game-day exercises documented in
blueprint §18. Each exercise has an expected user-visible outcome and a
rollback step. Run on a non-production / staging environment unless the
exercise explicitly says "production-safe".

## Pre-flight

```bash
# Establish baselines.
make smoke                     # All services healthy
curl -s http://127.0.0.1:18080/metrics | grep ^xgg_ | wc -l   # ~53 series
docker ps | grep code-         # All dev deps up

# Record start timestamp for after-action review.
date -u +%FT%TZ > /tmp/gameday-start.txt
```

## Exercise 1 — Verdict-api hard stop

```bash
sudo systemctl stop xgg-verdict-api
```

**Expected (extension side):**
- New navigations show holding for 12s
- Manual-choice UI appears: Allow once / Allow 24h / Isolate / Go back
- Backend metrics: `xgg_verdict_total` rate drops to 0

**Rollback:**
```bash
sudo systemctl start xgg-verdict-api
sleep 3 && systemctl is-active xgg-verdict-api
curl -s http://127.0.0.1:18080/healthz
```

**Pass criteria:** zero indefinite spinners observed during outage.

## Exercise 2 — Sandbox-render hard stop

```bash
sudo systemctl stop xgg-sandbox-render
```

**Expected:**
- Sensitive pages (login/payment/oauth) → ISOLATE with
  `SENSITIVE_PAGE_VERIFICATION_UNAVAILABLE`
- Non-sensitive pages → Tier-1-only ALLOW/WARN
- No 45s timeout cascade

**Rollback:**
```bash
sudo systemctl start xgg-sandbox-render
sleep 6 && systemctl is-active xgg-sandbox-render
```

## Exercise 3 — Redis stop (Postgres survives)

```bash
docker compose -f docker-compose.yml stop redis
```

**Expected:**
- Verdict cache miss → every request runs full pipeline (slower)
- VendorDNS cache miss → 8-provider query runs each time
- No crash, no incorrect verdicts
- Metric: `xgg_verdict_cache_total{result="miss"}` 100% of requests

**Rollback:**
```bash
docker compose start redis
sleep 2
docker exec code-redis-1 redis-cli PING   # PONG
```

## Exercise 4 — Slow Redis (high latency injection)

```bash
docker exec code-redis-1 redis-cli DEBUG SLEEP 5 &
```

**Expected:**
- 200ms timeout on getVerdictCache fires
- Pipeline proceeds without cache hit
- No hang; verdicts return within p95 budget

**Rollback:** wait for sleep to expire (5s) or restart redis.

## Exercise 5 — MinIO hard stop (signed-URL fallout)

```bash
docker compose stop minio
```

**Expected:**
- New evidence renders fail upload → render result discarded → fallback to
  Tier-1-only verdict
- Existing block pages show evidence ID but broken screenshots (handled
  by `img.onerror` hiding)
- Portal-api re-sign fails silently; old presigned URLs may already be
  expired anyway

**Rollback:**
```bash
docker compose start minio
sleep 3
```

## Exercise 6 — Network partition (verdict-api ↔ sandbox-render)

```bash
sudo iptables -A INPUT -p tcp --dport 8002 -j DROP
```

**Expected:**
- Tier-2 calls in verdict-api timeout (45s + 30s retry)
- Final verdict falls through to Tier-1
- User sees ALLOW/WARN promptly (within 90s `/v1/check` budget)

**Rollback:**
```bash
sudo iptables -D INPUT -p tcp --dport 8002 -j DROP
```

## Exercise 7 — Verdict-api flap (restart 10× in 60s)

```bash
for i in {1..10}; do
  sudo systemctl restart xgg-verdict-api
  sleep 6
done
```

**Expected:**
- Extension shows manual-choice UI by 12s during each gap
- User picks; cache absorbs verdict on next attempt
- `xgg_verdict_total` rate noisy but converges after final restart

**Rollback:** none needed once restarts stop.

## Exercise 8 — Browser-side: extension reload mid-resolution

Run via Playwright:

```python
import asyncio
from playwright.async_api import async_playwright

async def reload_mid_flight():
    async with async_playwright() as p:
        ctx = await p.chromium.launch_persistent_context(
            user_data_dir="/tmp/gameday-ext",
            headless=False,
            args=[
                "--disable-extensions-except=/home/xgenguardian/code/apps/extension",
                "--load-extension=/home/xgenguardian/code/apps/extension",
            ],
        )
        page = await ctx.new_page()
        # Start a slow navigation
        task = asyncio.create_task(page.goto("https://signal.org/download/"))
        # Force extension reload while in flight
        await asyncio.sleep(2)
        # Trigger SW reload via chrome.runtime.reload from a privileged page
        # ... (extension-id-aware reload code)
        try:
            await asyncio.wait_for(task, timeout=15)
        except asyncio.TimeoutError:
            print("FAIL: navigation hung after extension reload")
            return False
        return True

asyncio.run(reload_mid_flight())
```

**Expected:** navigation either completes or shows manual-choice UI within 12s.

## After-action review

For each exercise:
1. `make smoke` passes
2. Prometheus metrics return to baseline within RTO (§11.4)
3. No orphan Chromium processes: `pgrep -c chromium` matches baseline
4. No leaked FDs: `lsof -p $(pgrep verdict-api) | wc -l` matches baseline
5. `journalctl --since "$(cat /tmp/gameday-start.txt)"` contains structured
   errors, not panic traces

Record findings in `docs/runbooks/incidents/gameday-YYYY-MM.md`.

A failed exercise blocks the quarter's release until the contract is
restored. Document the root cause + fix in the runbook so the next
game-day verifies the regression doesn't return.

## Cadence

| Activity | Frequency | Owner |
|---|---|---|
| Run all 8 exercises | quarterly | on-call |
| Add new exercise after every P0 incident | as-needed | incident lead |
| Audit RTOs against measured values | quarterly | SRE |
| Prune obsolete exercises (e.g. when a dependency is removed) | annually | tech lead |
