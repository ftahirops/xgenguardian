# Real-User Test Session — `{SESSION_DATE}`

Copy this file with `make ruat-new-session` (creates `tools/maturity/sessions/<date>.md`)
or by hand: `cp tools/maturity/real-user-log-template.md tools/maturity/sessions/$(date +%F)-<your-name>.md`.

## Session info

```
Tester:
Date:
Browser + version:
Extension version:
Default mode:
Total duration:
Pages visited (estimate):
```

## Counters (fill at end of session)

```
Holds shown:         ___
Warnings shown:      ___
Blocks shown:        ___
Isolates shown:      ___
Manual overrides:    ___
Broken pages seen:   ___
Hangs seen:          ___
OAuth failures:      ___
```

## Findings

For each issue encountered, copy the block below and fill in.

---

### Finding #1

```
ID:                  RUAT-{date}-001
Date:
Mode:
URL:
Category:            (search | email | docs | dev-tool | payment | social |
                      news | banking | gov | download | self-hosted)

Expected:            (allow | warn | block | isolate)
Actual:              (allowed | warn | block | isolate | hung | error)
Verdict from API:
Reason codes:
Evidence ID:

Was there a hang?    yes / no
Did UI explain it?   yes / no
Did buttons work?    yes / no

Severity:            P0 / P1 / P2 / P3
Fix needed:          (one-line description)

Corpus file:         tools/fp-bench/corpus/{benign|malicious}-*.txt
Regression test:     (test file + test name, OR "TBD")
```

---

### Finding #2

```
ID:                  RUAT-{date}-002
...
```

---

## End-of-session checklist

- [ ] All P0 findings flagged in issue tracker
- [ ] Every URL with a wrong verdict added to the corresponding corpus file
- [ ] Counters totaled and recorded in `tools/maturity/status.md` (Real-User Soak Tracker section)
- [ ] Session file committed to `tools/maturity/sessions/`
- [ ] Game-day exercise from Phase 6 run at least once this session

## Notes

(Free-form observations: weird patterns, UI glitches you noticed but
couldn't pin to a specific URL, performance vibes, suggestions.)
