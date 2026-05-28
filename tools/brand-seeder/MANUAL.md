# Manual Screenshot Fallback

Some brands' login pages can't be rendered headlessly:

- **CAPTCHA-walled** (Chase, Wells Fargo, sometimes PayPal)
- **Geo-fenced** (HSBC HK from US IPs, regional bank dashboards)
- **Behind WAF** (Cloudflare's "Checking your browser" loop)
- **Auth-redirected** (SaaS apps that 302 to a tenant subdomain)
- **JS-broken in headless** (rare but happens)

For these, capture the canonical login screenshot manually (real browser, real session) and feed it directly to the seeder.

## How

1. Open the canonical login page in a real browser, full-screen at 1440×900.
2. Take a clean screenshot (no cookies banner, no autofill, no logged-in state).
3. Save as PNG to `tools/brand-seeder/manual/<brand-slug>/<page-label>.png`.
   - `brand-slug`: lowercase, hyphenated. Use the same form as `name` in `brands.yaml`.
   - `page-label`: `login`, `home`, `checkout`, etc. — matches what would have been auto-detected.
4. In `brands.yaml`, add a `manual_screenshots:` block to the brand:

```yaml
- name: Chase
  canonical_domains: [chase.com, jpmorganchase.com]
  login_urls:
    - https://secure01a.chase.com/web/auth/dashboard
  keywords: [chase, jpmorgan]
  expected_issuer: DigiCert
  manual_screenshots:
    - file: manual/chase/login.png
      page_label: login
      page_url: https://secure01a.chase.com/web/auth/dashboard
```

5. Re-run `make seed-brands`. The seeder will:
   - Try the URL via Playwright first.
   - On failure (timeout, CAPTCHA detected, blank page), fall back to the `manual_screenshots` entry for that page_label.
   - Compute the CLIP embedding from the local PNG identically to the auto path.

## Storage

`manual/` is gitignored by default. Real brand screenshots are visual IP — store them in private object storage (R2 / S3) under a versioned key per brand, and have the seeder fetch them at run time using `manual_screenshots[].url` instead of `file:` for non-dev environments.

## License / IP note

Storing a brand's login screenshot for *detecting impersonation of that brand* is generally fair use (transformative, non-commercial use-case, comparison rather than reproduction). When in doubt for a specific brand, ask the brand's security team — most welcome it.
