# Phishing Report Triage

**TL;DR:** confirm → label → understand why we missed → add training sample → ship fix if patternable.

A user reported `https://evil-example.tk/` as a phishing site we didn't block (false negative).

## Step 1 — Confirm (≤10 min)

1. Open the URL in the Transparency Portal: `https://report.xgenguardian.com/?url=<url>`.
2. Force a fresh scan: `POST /v1/rescan` with the URL.
3. Review the evidence:
   - Screenshot — does it visually impersonate a known brand?
   - Form-action analysis — credentials posted cross-origin?
   - Domain age, ASN, cert age.
4. Cross-check with PhishTank, urlscan.io, VirusTotal. Note who else flagged it.

If after fresh scan we now BLOCK it: the verdict was cached as CLEAN. Note the cache TTL bug for follow-up.

If still CLEAN: real false negative. Continue.

## Step 2 — Label

In the analyst workbench (or directly in Postgres):

```sql
UPDATE urls
SET verdict = 'malicious', verdict_confidence = 1.0
WHERE url_hash = $1;

INSERT INTO false_negatives (url_hash, reported_by, reported_at, true_label, notes)
VALUES ($1, $2, NOW(), 'phishing', $3);
```

This adds the URL to the training set for the next nightly retrain (#38).

## Step 3 — Understand Why We Missed

Pick one (sometimes more than one):

| Reason | Action |
|---|---|
| **Brand not in registry** | Add brand entry; re-run seeder. Issue: ISS-NNN. |
| **Visual similarity below threshold** | Lower threshold for this brand in fusion config; record the screenshot embedding distance |
| **Cloaking — sandbox got clean page** | Add to multi-egress rotation; verify residential proxy still works |
| **Cert + WHOIS looked benign** | Note registrar + cert issuer; if pattern emerges, update intel |
| **Newly registered, but homoglyph missed it** | Audit the Unicode confusables map in `tier1/tier1.go` |
| **Hosted on a reputable ASN (e.g. Cloudflare)** | Reputation alone is not enough; fusion should still fire on visual+age |
| **Domain old, but page is new** | Need DOM/JS hash drift detection (#48). Open ticket. |
| **AI-generated novel page, no template match** | LLM page-understanding should catch it; check #32 invocation |

## Step 4 — Patternable Fix

If the same gap could affect other phishing pages right now:

1. Open a bug in `docs/bugs/BUGS.md` with the pattern (e.g. "homoglyph match misses single-char insertion variants").
2. If the fix is small and safe, ship it the same day with a regression test that uses this URL as a fixture.
3. If the fix is larger, file a ticket in `docs/tasks/TASKS.md` and add it to the current phase.

## Step 5 — Close the Loop with the Reporter

Reply within 24h:
- Acknowledge the report.
- Confirm we now block it.
- Share (if appropriate) the high-level reason we missed it.
- Thank them.

Public-facing reporters: optionally credit them on the next monthly transparency report.

## Step 6 — Update Eval Corpus

Add the URL to `tools/eval/corpus/recent-phish.txt` so the next `make eval` run will include it as a regression check.

## Verification

The triage is done when:
- The URL now returns BLOCK with confidence ≥0.85.
- A row exists in `false_negatives` with the reason.
- A test fixture exists.
- A `docs/bugs/BUGS.md` entry exists if the pattern was actually new.
