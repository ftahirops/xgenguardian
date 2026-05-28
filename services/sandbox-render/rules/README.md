# XGenGuardian YARA rules

Detection signatures applied to the **rendered DOM + inline JS** of every
sandbox scan. Run order is irrelevant; every rule runs against every page.

## Bundled rules

| File | Coverage | Severity | Reason code emitted |
|---|---|---|---|
| `clickfix.yar` | ClickFix / paste-to-run social engineering and matching clipboard payloads | high | `CLICKFIX_INSTRUCTION_PATTERN`, `CLIPBOARD_HIJACK_ATTEMPT` |
| `html_smuggling.yar` | Blob + `URL.createObjectURL` + programmatic anchor-click + big base64 blob | high | `HTML_SMUGGLING_PATTERN` |
| `cryptojacker.yar` | Known browser-miner libraries + generic WASM miner patterns | medium | `MINER_POOL_CONTACT` |
| `magecart_skimmer.yar` | Card-field listeners + cross-origin silent exfil | high | `FORM_POSTS_TO_UNRELATED_DOMAIN` |
| `phishing_kit.yar` | Generic phishing-kit anti-debug + Telegram exfil | medium/critical | `LOGIN_FORM_ON_UNAPPROVED_DOMAIN`, `KNOWN_PHISH_URL_MATCH` |

Each rule's `meta.reason_code` is what gets emitted as a fusion signal and,
ultimately, a user-visible reason on `blocked.html`. If a rule has no
`reason_code` we fall back to the generic `YARA_SIGNATURE_MATCH`.

## Extending — community rule sources

We deliberately ship only a small, original starter set. To improve recall
add rules from these sources to this directory (or a sibling dir referenced
via `YARA_RULES_DIR` env var):

- **Sansec free Magecart rules** — <https://sansec.io/free-magecart-detection>
- **YARA-Rules community repo** — <https://github.com/Yara-Rules/rules>
- **abuse.ch YARAify** — <https://yaraify.abuse.ch/yarahub/>
- **Florian Roth's signature-base** — <https://github.com/Neo23x0/signature-base>
- **Elastic protections-artifacts** — <https://github.com/elastic/protections-artifacts>

Licensing varies — keep an attributions file when copying upstream rules.

## Adding your own rule

1. Drop a `.yar` file in this directory (or `YARA_RULES_DIR`).
2. Each rule's `meta` block **must** include:
   - `author`
   - `description`
   - `severity` (`low` | `medium` | `high` | `critical`)
   - `reason_code` — one of the canonical codes in
     `services/verdict-api/internal/reasons/reasons.go`, or invent a new one
     and register it there in the same PR.
   - `rule_version` — bump on any logic change.
3. Restart sandbox-render. Rules are compiled at startup; failures are logged
   per-file and the rest still load.
4. Add a unit test in `services/sandbox-render/tests/test_yara.py`.

## Performance budget

YARA scanning runs synchronously after page render. Budget: < 100 ms per
page for our rule count. If we cross 500 ms total, move scanning to a
worker pool. `yara_ms` is reported in every render response.
