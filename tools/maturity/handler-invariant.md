# Handler Invariant Lint Rule

Specifies the lint check that enforces blueprint §2.5 — the always-respond
contract that kept v0.2.x extension hanging in production.

## The rule

A code path that registers a listener via:

```js
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => { ... });
chrome.webNavigation.onBeforeNavigate.addListener(...);
chrome.tabs.onUpdated.addListener(...);
```

and `return true` (signaling "I will call sendResponse later") MUST have a
corresponding `sendResponse(...)` call in EVERY reachable branch including
every `catch` clause.

## Enforcement layers

### Layer 1 — author-time (ESLint, blocking)

Custom rule `xgg/always-respond`. Add to `apps/extension/.eslintrc.json`:

```json
{
  "plugins": ["xgg"],
  "rules": {
    "xgg/always-respond": "error"
  }
}
```

Rule logic (pseudocode):

```
for each FunctionExpression / ArrowFunctionExpression passed to
  chrome.runtime.onMessage.addListener (or webNavigation.*, tabs.*):

  walk all return statements:
    if returns 'true' (async response intent):
      flag the enclosing function

  for each flagged function:
    walk all branches (if/else/switch/try/catch/finally):
      verify each branch ends in sendResponse(...) call OR throws OR returns

    flag any branch that does neither
```

Implementation file: `tools/maturity/eslint-rules/always-respond.js`.

### Layer 2 — test-time (CI, blocking)

`tests/extension/handler-invariant.spec.ts`:

For every registered listener, inject 5 synthetic failures:
1. `fetch` throws synchronous
2. `fetch` rejects async
3. `chrome.storage.local.set` throws (quota exceeded)
4. `crypto.subtle.digest` throws (unsupported input)
5. handler intentionally returns `undefined` without calling sendResponse

Each test asserts:
- exactly one response received within 9 seconds, AND
- the response is well-formed (not undefined, has expected shape)

### Layer 3 — run-time (telemetry, observational)

Every catch arm includes:

```js
console.warn("[xgg] <handler>: crashed:", e?.message || e);
```

A telemetry counter increments on each warn, exposed as
`xgg_handler_crashes_total{handler}`. Alert at >0.1/min over 5 min.

### Layer 4 — fail-safe (runtime default)

Every catch arm calls sendResponse with a fail-open verdict:

```js
sendResponse({
  verdict: {
    verdict: "ALLOW",
    reason: "verification_error",
    error: String(e?.message || e).slice(0, 200),
  },
});
```

Rationale: a hung user uninstalls; a wrong-ALLOW user reports via the
"I think this is wrong" button. The product survives the second outcome;
it does not survive the first.

## Verifying compliance manually

```bash
cd apps/extension
grep -n "return true" src/background.js
# For each line: look at the enclosing function. Trace all branches.
# Every catch arm must end in sendResponse.
```

## Known compliant handlers (as of v0.3.2)

- `kind === "resolve"` — try/catch with fail-open ALLOW (background.js:740)
- `kind === "apply"` — try/catch with err response (background.js:801)
- `kind === "allow_temp"` — synchronous validation + IIFE (background.js:706)
- `kind === "command-check"` — try/catch with fail-open ALLOW (background.js:560)

## Known non-compliant handlers (as of v0.3.2)

None known. Soak test passes 19/22 with zero hangs.

## Adding a new handler

1. Validate `sender.id` first (defense-in-depth)
2. Synchronous validation of `msg.target` URL scheme
3. If validation fails: `sendResponse(...); return false;` synchronously
4. If async work: `(async () => { try { ... sendResponse(); } catch (e) { sendResponse(failOpen); } })(); return true;`
5. Run `make maturity-test-extension`
6. Add a row to `tests/extension/handler-invariant.spec.ts` covering the 5 synthetic failures
