# Brand Registry Update

**TL;DR:** edit `brands.yaml` → re-run seeder → verify visual-match → eval.

## When to use

- A new brand needs protection (customer onboarding, growing phishing trend).
- A brand's infrastructure changed (new ASN, cert issuer rotation).
- False positives traced back to incomplete `canonical_domains`.
- False negatives traced back to a missing brand.

## Step 1 — Edit `tools/brand-seeder/brands.yaml`

Add or modify the brand entry. Each entry needs:

```yaml
- name: NewBrand
  canonical_domains: [newbrand.com, newbrand.io, newbrand.app]
  login_urls:
    - https://app.newbrand.com/login
    - https://www.newbrand.com/
  keywords: [newbrand, "new-brand"]
  expected_issuer: DigiCert
```

Rules:
- Use at least one login URL — without it the visual match doesn't have a credentials-page fingerprint.
- Keywords must be ≥4 chars (CT-monitor ignores shorter to avoid noise).
- Don't add brand keywords that overlap with common English words (e.g. don't make "box" a keyword — too many false matches).

## Step 2 — Re-run the seeder

```bash
make seed-brands
# or specifically:
cd tools/brand-seeder && python seed.py
```

Watch the output. Each brand should report `✓ <name>: N pages, M favicons`. If any brand fails (e.g. login URL requires CAPTCHA), capture the screenshot manually and use the alternate flow described in `tools/brand-seeder/MANUAL.md`.

## Step 3 — Verify in Postgres

```sql
SELECT brand_name, array_length(canonical_domains, 1) AS n_domains,
       array_length(favicon_hashes, 1) AS n_favicons,
       (SELECT count(*) FROM brand_screenshots WHERE brand_id = b.brand_id) AS n_screens
FROM brands b
WHERE brand_name = 'NewBrand';
```

Expect: `n_screens ≥ 1`, `n_favicons ≥ 1`.

## Step 4 — Verify visual-match recognises it

```bash
curl -X POST http://localhost:8003/match \
  -H 'content-type: application/json' \
  -d '{"image_url": "https://login.newbrand.com/static/login-screenshot.png"}'
```

Top match should be `NewBrand` with score ≥0.9.

## Step 5 — Trigger registry hydrator reload

The verdict-api caches the brand registry for 5 min. Force an immediate reload:

```bash
kubectl exec deploy/verdict-api -- /usr/local/bin/verdict-api --reload-brands
```

Or just wait 5 minutes.

## Step 6 — Eval

Run the eval harness with a focus on the new brand's known phishing samples (if any exist) and on Tranco entries that share keywords:

```bash
make eval --brand NewBrand
```

Confirm:
- Recall on the brand's known phishing samples ≥0.50 (Phase-1 bar).
- No new false positives against the canonical domains.

## Rollback

If a brand addition causes a regression:

```sql
DELETE FROM brand_screenshots WHERE brand_id = (SELECT brand_id FROM brands WHERE brand_name = 'NewBrand');
DELETE FROM brands WHERE brand_name = 'NewBrand';
```

Then trigger a hydrator reload.

## Verification

Done when:
- `SELECT * FROM brands WHERE brand_name = ...` shows expected fields populated.
- `/match` returns the brand for the canonical login page.
- Eval doesn't regress against the existing corpus.
