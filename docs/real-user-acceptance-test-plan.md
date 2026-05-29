# Real-User Acceptance Test Plan (RUAT)

This document is the human-driven counterpart to `make maturity-test`. The
automated suite proves "known cases still work." This plan proves "this is
usable as a daily browser." Both are required before a release ships.

## Goal

Run XGenGuardian like a normal person for several days and record every bad experience:

- wrong block
- wrong allow
- annoying warning
- hang
- slow page
- broken UI
- OAuth failure
- download failure
- DNS confusion
- evidence unclear

**Every issue becomes a corpus entry and regression test.** No exceptions —
patching without adding a test is how the same bug ships twice.

Companion documents:
- `tools/maturity/real-user-log-template.md` — fill-in-the-blank log per finding
- `tools/maturity/personal-100.md` — bucket structure for your personal 100-URL list
- `tools/maturity/status.md` — release-gate scoreboard updated after each run

---

## Phase 1: Clean Setup

Use one browser profile only for testing.

1. Install extension v0.3.2 from `/tmp/xgenguardian-extension-v0.3.2.zip` or unpacked from `/home/xgenguardian/code/apps/extension/`
2. Confirm Options page opens
3. Set mode to **Safe**
4. Empty the permanent allowlist
5. Clear any prior 24h overrides (Options → Active 24h overrides → Revoke all)
6. Keep extension service-worker console open (`chrome://extensions` → "Service worker" link → DevTools)
7. Keep a test log file open — use `make ruat-new-session` to create a dated copy of the template

**Log format per finding (see `tools/maturity/real-user-log-template.md`):**

```
Date:
Browser:
Mode:
URL:
Expected:
Actual:
Verdict:
Reason codes:
Evidence ID:
Screenshot:
Notes:
```

---

## Phase 2: Daily Browsing Test (2-4 hours)

Use the extension for normal browsing — your actual workflow, not synthetic.

| Category | Examples | Expected |
|---|---|---|
| Search | Google/Bing search results | no friction |
| Email | Outlook/Gmail links | SafeLinks/redirects work |
| Docs | GitHub docs, npm, Python, Go, Rust | no false command warning on legit docs |
| Developer tools | OpenAI, Claude, Cursor, opencode, GitHub, Vercel | normal |
| Payments | Stripe checkout, PayPal, billing pages | no false block |
| Social | YouTube, Reddit, X, LinkedIn | no annoying interstitials |
| News | ad-heavy news sites | no hang / broken UI |
| Banking | real bank login | no false block |
| Government | IRS/SSA/state/.gov portals | no false block |
| Downloads | Signal, Firefox, VS Code, Python | legit downloads allowed |
| Internal / self-hosted | IP/ports/admin panels | policy is understandable |

**Success criteria for Safe mode:**

- 0 infinite spinners
- 0 broken evidence pages
- 0 unexpected OAuth breakage
- 0 repeated prompts for the same trusted site
- ≤ 1-2 annoying false warnings

---

## Phase 3: Known-Good Checklist (your personal 100)

Create a list of 100 sites you personally use, bucketed as:

- 20 daily sites
- 20 work / dev sites
- 20 login / auth sites
- 10 payment / billing pages
- 10 download pages
- 10 email wrapped links
- 10 self-hosted / internal pages

Template lives at `tools/maturity/personal-100.md`. Copy and customize.

**Expected:** Safe mode mostly ALLOW. Any WARN / BLOCK / ISOLATE needs investigation.

Run via:
```bash
make ruat-personal-100
```

This script reads the list and reports verdict per URL so you can spot regressions over time.

---

## Phase 4: Known-Bad Checklist

Use safe controlled malicious test cases, not random live malware (unless you can isolate the VM properly).

Test cases:

- `thepiratebay.org` or any known-blocked piracy domain
- Public raw IP URL: `http://1.1.1.1/`
- Fake typosquat fixture (a string that resembles a brand but is benign — e.g. `paypall.example`)
- Local test page with popup storm (fixtures under `tools/fp-bench/fixtures/popup-storm.html` — TODO P1)
- Local test page with hidden credential sink
- Local test page with malicious command in `<pre><code>`
- Local test page with fake support phone overlay
- Local test page with mshta / PowerShell payload in code block

Run via:
```bash
make ruat-known-bad
```

**Expected:**

- bad domains BLOCK with `EXTERNAL_FEED_HIT` or `VENDOR_DNS_CONSENSUS_BLOCK`
- raw IP WARN/BLOCK unless allowlisted via `XGG_LOCAL_TRUSTED_HOSTS`
- malicious commands BLOCK with `MALICIOUS_INSTALL_COMMAND`
- popup storm BLOCK with `POPUP_STORM_DETECTED` or `FAKE_SUPPORT_SCAREWARE`
- fake support page BLOCK/WARN
- every block page explains why with the 8-layer transparency grid

---

## Phase 5: OAuth and Email Wrapper Testing (highest priority)

This is the failure mode users encounter constantly. We've shipped fixes through v0.3.2 but field-test every one.

Test matrix:

- Google login (`accounts.google.com`)
- Microsoft login (`login.microsoftonline.com`)
- GitHub login (`github.com/login`)
- Apple login (`appleid.apple.com`)
- Outlook SafeLinks (any regional prefix: `ind01`, `nam04`, `eur02`, etc.)
- Proofpoint wrapped link (`urldefense.com` / `urldefense.proofpoint.com`)
- Mimecast wrapped link (`protect-us.mimecast.com` etc.)
- Nested wrapper (SafeLinks → Proofpoint → real URL)
- OAuth from a popup window (provider window opened by JS)
- OAuth from a new tab (`target="_blank"`)

**Expected:**

- 0 holding-page hangs
- 0 blocks on real providers
- destination URL still gets checked (the wrapper bypass MUST forward to scanning of the real destination)
- login completes

---

## Phase 6: Timeout and Failure Testing

Prove the product fails nicely. Run the game-day exercises from `tools/maturity/game-day.md`.

### 6.1 Verdict-api stopped

```bash
sudo systemctl stop xgg-verdict-api
```

Browse to any unknown site → confirm **manual choice UI appears within 12 seconds** with: Allow once / Allow + remember 24h / Open in isolation / Go back.

Restore:
```bash
sudo systemctl start xgg-verdict-api
```

### 6.2 Sandbox-render stopped

```bash
sudo systemctl stop xgg-sandbox-render
```

Visit any `/login`, `/billing`, or `/oauth` URL on an unknown domain → confirm clear degraded behavior (ISOLATE with `SENSITIVE_PAGE_VERIFICATION_UNAVAILABLE`, not a hang).

Restore:
```bash
sudo systemctl start xgg-sandbox-render
```

### 6.3 DNS disabled

Disable internet/DNS at OS level, OR use a dead domain like `https://this-domain-does-not-exist-abc123.example/`.

Confirm **DNS-fail page** explicitly says "This is NOT an XGG block" with common-causes checklist.

**Success criteria:**

- No scenario leaves the user stuck on a spinner
- Every failure mode shows a clear choice or explanation

---

## Phase 7: Mode Testing

Run the same 20 URLs in each of 6 modes. **Important: do not judge Ultra like Safe.** Ultra is supposed to be noisy by design.

| Mode | What you check |
|---|---|
| Normal | very low friction; mostly cleanup-only blocks |
| Safe | balanced daily-use mode (your default) |
| Strict | more warnings on unknown / risky sites |
| Family | content/category blocks (adult/gambling/etc.) |
| Paranoid | unknown sensitive pages ISOLATE |
| Ultra | many unknowns ISOLATE by design; user uses 24h override |

Expected FP/FN rates per mode are documented in blueprint §19.

---

## Phase 8: Evidence Page Review

For every WARN / BLOCK / ISOLATE page encountered during testing, evaluate:

- Is the reason understandable to a non-technical user?
- Are screenshots loaded or hidden cleanly (no broken-image icons)?
- Does it say whether external feeds hit?
- Does it show raw IP clearly when applicable?
- Does it show domain age clearly?
- Does it distinguish "not malicious" from "could not verify"?
- Are buttons obvious and labelled correctly?
- Does "Go back" work?
- Does "Proceed anyway" work after the countdown?
- Does "Allow for 24h" work?
- Does the side-by-side screenshot comparison render?
- Is mobile layout (390×844) readable?
- Does the 8-layer transparency grid show pass/warn/fail per gate?

**If the user cannot understand why an interception happened from looking at the page alone, that is a P1 product bug.**

---

## Phase 9: Real-User Soak (3 days)

Use the extension as your default for 3 days. At end of each day, record:

- Total pages visited (approx, from browser history)
- Number of holding pages seen
- Number of warnings
- Number of blocks
- Number of isolates
- Number of manual overrides clicked
- Number of broken pages
- Number of hangs (should be 0)
- Number of OAuth failures (should be 0)

**Release targets for Safe mode:**

```
hangs: 0
OAuth failures: 0
broken evidence pages: 0
false blocks: 0
annoying false warnings: <1 per 100 pages
```

---

## Phase 10: Turn Findings Into Tests

Every finding gets classified and converted into permanent regression coverage:

| Type | Action | Where |
|---|---|---|
| False positive | add URL to benign corpus | `tools/fp-bench/corpus/benign-*.txt` |
| False negative | add URL to malicious corpus | `tools/fp-bench/corpus/malicious-*.txt` |
| Hang | add extension E2E test row | `tools/maturity/extension-e2e.py` corpus |
| Broken UI | add evidence UI test row | blueprint §7 + Playwright screenshot test |
| OAuth issue | add wrapper / auth test row | blueprint §6.2 + `WELL_KNOWN_AUTH_HOSTS` |
| DNS issue | add resolver / DNS-fail test row | blueprint §4 + `onErrorOccurred` handler |
| Raw IP issue | add raw-IP policy test row | blueprint §5.3 + `XGG_LOCAL_TRUSTED_HOSTS` |
| Confusing wording | fix UI copy | open PR with screenshot before/after |

**Do not just patch. Always add a permanent test.** A patch without a test means the bug will recur on the next refactor.

---

## Severity Classification

| Severity | Meaning | Release-blocking? |
|---|---|---|
| **P0** | Hang, login broken, all browsing broken, security bypass | YES — block the release |
| **P1** | False block on common-good site, bad site allowed, broken evidence UI | YES — block the release |
| **P2** | Annoying warning, unclear explanation, slow but recovers | Fix in next patch release |
| **P3** | Wording / layout polish | Fix when convenient |

---

## The Run Sheet — single page

Print or screen-pin this:

```
1. Build your personal 100-URL good list (Phase 3)
2. Run Safe mode for 2 hours (Phase 2)
3. Record every friction point in the template
4. Run known-bad controlled tests (Phase 4)
5. Run failure tests by stopping backend services (Phase 6)
6. Send the issue list
7. Add every issue to corpora/tests BEFORE fixing
```

That's how this becomes mature: not by saying "tests pass," but by turning real browsing pain into permanent regression coverage.
