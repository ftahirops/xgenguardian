# False-Positive Triage

**TL;DR:** confirm clean → unblock immediately → find the rule that fired → tune or add allowlist exception → regression-test.

A user reports that a legitimate site is being blocked.

## Severity

| Trigger | Severity |
|---|---|
| Single user affected | S3 |
| Multiple users / customer escalation | S2 |
| FP rate >0.5% globally | **S1** — declare incident |

## Step 1 — Confirm Clean (≤15 min)

1. Open the URL in the Transparency Portal and view the evidence.
2. Independent verification:
   - Check `whois` for registration date and registrar reputation.
   - Cross-reference with Tranco top-1M.
   - Visit the site in a personal browser (not a sandbox) to confirm it's genuinely legitimate.
   - Check status page of the brand if applicable.
3. If confirmed legitimate, continue. If actually phishing, redirect to `phishing-report-triage.md` (false report).

## Step 2 — Unblock Immediately

```sql
-- Mark URL as clean in registry.
UPDATE urls SET verdict = 'clean', verdict_confidence = 1.0
WHERE url_hash = $1;
UPDATE domains SET verdict = 'clean'
WHERE domain = $2;

-- Add to allowlist to prevent re-block.
INSERT INTO allowlist_overrides (domain, reason, added_by, added_at)
VALUES ($2, $3, $4, NOW());
```

Invalidate Redis cache:

```bash
redis-cli DEL "verdict:$DOMAIN"
```

Confirm with `POST /v1/check` that the URL now returns CLEAN.

## Step 3 — Notify the Reporter

Within 1 hour: "Confirmed clean, unblocked globally. We're investigating the cause."

## Step 4 — Find Which Rule Fired

Open the evidence record. The `signals[]` array tells you which detector contributed to the BLOCK:

| Signal that fired | Likely root cause |
|---|---|
| `visual_brand_match` ≥0.92 | False match against a similar legitimate page (e.g. a partner co-brand). Action: refine the brand registry; this brand has overlapping visual identity. |
| `identity_mismatch` | The legitimate domain isn't in the brand's `canonical_domains`. Action: add it. |
| `homoglyph_match` | Brand keyword too short or too generic. Action: drop the keyword, or raise edit-distance threshold for it. |
| `domain_age` only | A young legitimate domain. Action: this signal alone shouldn't BLOCK; check fusion weights. |
| `cred_form_cross_origin` | Legitimate SSO/payment flow posts cross-origin. Action: maintain a known-good-SSO-target list. |
| `blocklist_hit` | A threat intel feed mis-listed it. Action: report upstream + add to our `intel_overrides`. |

## Step 5 — Tune

Options in increasing impact:

1. **Allowlist single domain** — fastest, least precise. Use when the FP is genuinely an outlier.
2. **Update brand registry** — add a canonical_domain or expected_issuer. Use when the registry was incomplete.
3. **Adjust fusion weight** — change a signal's weight or threshold. Use when the pattern would otherwise repeat.
4. **Re-train classifier** — for L4 visual model. Use when the model is genuinely fooled.

Whatever you change, add the URL to the eval harness's negative-set so it can't regress.

## Step 6 — Postmortem (if S1 or S2)

Same template as `incident-response.md` §6. Pay special attention to:
- How many users were affected?
- What was their experience? (e.g. unable to log into bank for 3 hours)
- Why didn't pre-deploy eval catch this?

## Verification

The FP is closed when:
- `POST /v1/check` returns CLEAN for the URL.
- The cause is documented in the evidence record's `notes` field.
- A regression entry exists in `tools/eval/corpus/should-be-clean.txt`.
- If it was S1/S2, postmortem is published.

## Cardinal Rule

**False positives kill the product faster than false negatives.** A user who gets phished once forgives. A user who can't reach their bank twice in a month uninstalls and warns their friends.
