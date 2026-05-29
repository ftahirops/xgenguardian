# Personal 100-URL Acceptance Set

The single most important corpus for daily-life FP testing. Lists 100 sites
the tester ACTUALLY uses. If Safe mode flags any of these, it's a P1.

**This is a TEMPLATE.** Replace every example with URLs YOU visit. The
generic sites in here are placeholders, not the actual list.

## How to use

```bash
# Run the verdict-api against every URL in this file:
make ruat-personal-100

# Output: per-URL verdict + a summary block at the end.
```

The script reads URL lines (non-`#`) from this file and calls the
verdict-api in Safe mode. A column-aligned report prints PASS / WARN /
BLOCK / ISOLATE per URL. Anything other than PASS on a known-good URL
is a finding.

---

## Bucket 1 — Daily (20 sites)

Sites you open every day or near-every-day. Email, news, social, search.

```
https://www.google.com/
https://mail.google.com/
https://calendar.google.com/
https://outlook.office.com/
https://news.ycombinator.com/
https://www.reddit.com/
https://twitter.com/
https://www.linkedin.com/
# ... add 12 more
```

## Bucket 2 — Work / Dev (20 sites)

Source code, docs, package registries, dashboards, CI.

```
https://github.com/
https://gitlab.com/
https://stackoverflow.com/
https://www.npmjs.com/
https://pypi.org/
https://crates.io/
https://pkg.go.dev/
https://docs.python.org/3/
https://developer.mozilla.org/en-US/
https://kubernetes.io/docs/
# ... add 10 more (your specific tools)
```

## Bucket 3 — Login / Auth (20 sites)

Sites where you actually enter credentials. The most important bucket
for credential-sink false positives.

```
https://accounts.google.com/
https://login.microsoftonline.com/
https://appleid.apple.com/
https://github.com/login
https://www.dropbox.com/login
# ... add 15 more (your IDPs, SaaS logins)
```

## Bucket 4 — Payment / Billing (10 sites)

Pages where you enter a credit card. High-FP-risk zone (cross-origin POSTs to Stripe etc.).

```
https://billing.stripe.com/
https://www.paypal.com/
# ... add 8 more (your bank, your SaaS billing pages)
```

## Bucket 5 — Downloads (10 sites)

Install pages from trusted brands. High-FP-risk for SUSPICIOUS_DOWNLOAD_OFFERED.

```
https://signal.org/download/
https://www.mozilla.org/firefox/new/
https://www.python.org/downloads/
https://nodejs.org/en/download/
https://code.visualstudio.com/download
https://www.rust-lang.org/tools/install
https://go.dev/dl/
# ... add 3 more
```

## Bucket 6 — Email Wrapped Links (10 sites)

Open 10 real-world wrapped links from your inbox. Each one should pass
through to the destination without holding.

```
# Outlook SafeLinks examples (your actual links from email):
# https://nam04.safelinks.protection.outlook.com/?url=https%3A%2F%2F...
# Proofpoint examples:
# https://urldefense.com/v3/__https://...
# Mimecast examples:
# https://protect-us.mimecast.com/s/...
# (Paste real ones from your inbox)
```

## Bucket 7 — Self-hosted / Internal (10 sites)

Your operator infrastructure. Add to permanent allowlist in Options if needed.

```
# https://135.181.79.27:18443/...
# http://10.0.0.5:8080/admin
# https://internal.mycorp.com/
# (Replace with your actual self-hosted endpoints)
```

---

## How to seed the buckets

If you don't yet have 100 specific URLs, run this for one week:

1. Browse normally with the extension installed.
2. At the end of each day, open `chrome://history` and extract the top 20
   hosts you visited.
3. Add each host's most-visited path to the appropriate bucket here.
4. After 5 days you'll have your 100.

## Maintenance

- Refresh quarterly (your habits change)
- Add every URL that surprised you with a FP — that's the highest-signal corpus
- Remove URLs you no longer visit (keeps the run fast)
- Keep this file in version control; treat it as the operator's golden corpus
