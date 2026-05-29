<!--
  XGenGuardian PR template — enforced by `make maturity-test`.
  Read docs/maturity-testing-blueprint.md §15 + the
  three-tier trust policy below before opening this PR.
-->

## Summary

<!-- 1-3 sentences. What changed and why. Skip the "what" — the diff shows
     that. Focus on "why" and "what class of behavior changes." -->

## Definition of a Real Fix (6-bullet contract)

Tick every box. If any answer is "no" or "TBD," explain in the section
below. Untickable boxes are not necessarily blockers but require explicit
discussion in review.

- [ ] **Fixes the reported URL / case** — single URL or single case the issue mentioned
- [ ] **Fixes the entire class of similar URLs** — a structural change, not a one-off whitelist
- [ ] **Does NOT require a per-domain trustreg override** for the FP class addressed
- [ ] **Adds a regression test** — `policy_test.go`, `tier1_test.go`, corpus entry, or extension E2E case
- [ ] **Does NOT weaken malicious detection** — `make maturity-test-bench` shows 0 new FN
- [ ] **Explains which rule changed and why** in the Reason section below

## What rule / module changed?

<!-- Name the rule or module. Examples: HIDDEN_MALICIOUS_LINK threshold,
     orggraph.SameOrg behavior, policymap.go cross-origin counter,
     stage F.4 in policy.go, brandgraph scope. -->

## What class of bugs does this prevent?

<!-- Be specific. "False positive on moviesanywhere.com" is too narrow.
     "False positive on multi-brand corporate homepages with cross-origin
     hidden nav links" is the right level. -->

## Trust-registry policy

If this PR touches `internal/trustreg/`:

- [ ] **Tier 0** — A globally critical identity / payment / security provider (Google, Microsoft, Apple, GitHub, Stripe, PayPal, Cloudflare, a major OAuth provider). Justify why this brand is in this tier.
- [ ] **Tier 1** — A widely-impersonated phishing target (top 500 banks, governments, top SaaS, universities, crypto exchanges, marketplaces). Justify why this brand merits Tier 1.
- [ ] **Neither (DO NOT ADD)** — A site that a user reported as FP. Use the user allowlist (Options page) or fix the rule structurally. Do not add to trustreg.

If this PR is **not** adding a trustreg entry but instead refactors a rule to use orggraph, trustscore (when built), or context-aware logic — that's the preferred path.

## Corpus entries added

List every URL added to `tools/fp-bench/corpus/`:

- `tools/fp-bench/corpus/benign-real-world.txt`: <URLs>
- `tools/fp-bench/corpus/malicious-curated.txt`: <URLs>

## Test plan

```bash
make maturity-test                  # all gates pass
make ruat-personal-100              # if applicable
make ruat-known-bad                 # known-bad regression
```

Paste output summary (PASS counts, FP/FN rates, any new failures).

## Shadow-mode considerations

<!-- For changes to policy.Apply or feature extractors. Will old-engine
     vs new-engine produce different verdicts on a real-traffic sample?
     If yes, propose how to compare them. -->

## Rollback plan

<!-- One line. e.g. "Revert this commit; the new orggraph entries are
     additive and reverting drops them with no other behavior change." -->
