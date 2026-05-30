# Smoke corpus report

- API base: `http://127.0.0.1:18080`
- Cases: **100**
- Pass: **100**  /  Fail: **0**  /  Rate: **100.0%**
- Wall-clock: 93.0 s

## Per-category breakdown

| Category | Pass | Fail | Total | Rate |
| --- | ---: | ---: | ---: | ---: |
| crypto-drainer | 4 | 0 | 4 | 100% |
| edge-case | 3 | 0 | 3 | 100% |
| fake-banking | 4 | 0 | 4 | 100% |
| fake-oauth-host | 2 | 0 | 2 | 100% |
| fresh-payment | 2 | 0 | 2 | 100% |
| http-only | 1 | 0 | 1 | 100% |
| idn-homoglyph | 2 | 0 | 2 | 100% |
| install-lure | 2 | 0 | 2 | 100% |
| legit-banking | 3 | 0 | 3 | 100% |
| legit-cdn | 4 | 0 | 4 | 100% |
| legit-content | 4 | 0 | 4 | 100% |
| legit-dev | 2 | 0 | 2 | 100% |
| legit-major | 7 | 0 | 7 | 100% |
| legit-payment | 1 | 0 | 1 | 100% |
| legit-saas | 2 | 0 | 2 | 100% |
| legit-sensitive | 3 | 0 | 3 | 100% |
| malformed | 2 | 0 | 2 | 100% |
| oauth-legit | 2 | 0 | 2 | 100% |
| oauth-phish | 2 | 0 | 2 | 100% |
| payment-scam | 2 | 0 | 2 | 100% |
| piracy-tld | 6 | 0 | 6 | 100% |
| raw-ip | 2 | 0 | 2 | 100% |
| sensitive-unknown | 2 | 0 | 2 | 100% |
| shared-host | 3 | 0 | 3 | 100% |
| shortener | 2 | 0 | 2 | 100% |
| spoof-wrapper | 2 | 0 | 2 | 100% |
| support-scam | 3 | 0 | 3 | 100% |
| sus-tld | 3 | 0 | 3 | 100% |
| synth-phish | 5 | 0 | 5 | 100% |
| typosquat | 5 | 0 | 5 | 100% |
| wrapper-benign | 9 | 0 | 9 | 100% |
| wrapper-phish | 4 | 0 | 4 | 100% |

## Failing cases

_No failing cases._

## Detailed per-case results

| Case | Category | Expected | Actual | Latency | Pass |
| --- | --- | --- | --- | ---: | :---: |
| `drainer-fake-claim-airdrop` | crypto-drainer | `any-deny` | `BLOCK` | 898 ms | ✓ |
| `drainer-fake-opensea` | crypto-drainer | `any-deny` | `WARN` | 972 ms | ✓ |
| `drainer-fake-revoke` | crypto-drainer | `any-deny` | `ISOLATE` | 863 ms | ✓ |
| `drainer-metamask-update` | crypto-drainer | `any-deny` | `ISOLATE` | 690 ms | ✓ |
| `fqdn-trailing-dot` | edge-case | `any-allow` | `ALLOW` | 638 ms | ✓ |
| `hash-fragment-only` | edge-case | `any-allow` | `ALLOW` | 586 ms | ✓ |
| `nonstandard-port` | edge-case | `any-allow` | `ALLOW` | 573 ms | ✓ |
| `fake-boa-mobile` | fake-banking | `any-deny` | `ISOLATE` | 789 ms | ✓ |
| `fake-chase-login` | fake-banking | `any-deny` | `ISOLATE` | 768 ms | ✓ |
| `fake-citibank-secure` | fake-banking | `any-deny` | `ISOLATE` | 689 ms | ✓ |
| `fake-wellsfargo-update` | fake-banking | `any-deny` | `ISOLATE` | 798 ms | ✓ |
| `fake-google-accounts-host` | fake-oauth-host | `any-deny` | `ISOLATE` | 609 ms | ✓ |
| `fake-microsoft-oauth-host` | fake-oauth-host | `any-deny` | `ISOLATE` | 729 ms | ✓ |
| `payment-fresh-cart` | fresh-payment | `any-deny` | `ISOLATE` | 780 ms | ✓ |
| `payment-fresh-checkout` | fresh-payment | `any-deny` | `ISOLATE` | 681 ms | ✓ |
| `http-only-major` | http-only | `any-allow` | `ALLOW` | 708 ms | ✓ |
| `idn-google-cyrillic-o` | idn-homoglyph | `any-deny` | `WARN` | 856 ms | ✓ |
| `idn-paypal-cyrillic-a` | idn-homoglyph | `any-deny` | `BLOCK` | 577 ms | ✓ |
| `fake-anthropic-install` | install-lure | `any-deny` | `ISOLATE` | 1069 ms | ✓ |
| `fake-nodejs-install` | install-lure | `any-deny` | `ISOLATE` | 997 ms | ✓ |
| `bank-real-chase` | legit-banking | `any-allow` | `ALLOW` | 1025 ms | ✓ |
| `bank-real-citi` | legit-banking | `any-allow` | `ALLOW` | 947 ms | ✓ |
| `bank-real-wellsfargo` | legit-banking | `any-allow` | `ALLOW` | 915 ms | ✓ |
| `cloudflare-cdn-script` | legit-cdn | `any-allow` | `ALLOW` | 684 ms | ✓ |
| `google-fonts` | legit-cdn | `any-allow` | `ALLOW` | 627 ms | ✓ |
| `jsdelivr` | legit-cdn | `any-allow` | `ALLOW` | 666 ms | ✓ |
| `unpkg` | legit-cdn | `any-allow` | `ALLOW` | 648 ms | ✓ |
| `bbc-news` | legit-content | `any-allow` | `ALLOW` | 967 ms | ✓ |
| `mozilla-developer` | legit-content | `any-allow` | `ALLOW` | 804 ms | ✓ |
| `stackoverflow` | legit-content | `any-allow` | `ALLOW` | 803 ms | ✓ |
| `wikipedia` | legit-content | `any-allow` | `ALLOW` | 1023 ms | ✓ |
| `claude-quickstart` | legit-dev | `any-allow` | `ALLOW` | 682 ms | ✓ |
| `rustup` | legit-dev | `any-allow` | `ALLOW` | 985 ms | ✓ |
| `apple-id-host` | legit-major | `any-allow` | `ALLOW` | 968 ms | ✓ |
| `cloudflare-corporate` | legit-major | `any-allow` | `ALLOW` | 823 ms | ✓ |
| `github` | legit-major | `any-allow` | `ALLOW` | 24551 ms | ✓ |
| `google-homepage` | legit-major | `any-allow` | `ALLOW` | 785 ms | ✓ |
| `microsoft-login` | legit-major | `any-allow` | `ALLOW` | 703 ms | ✓ |
| `paypal-homepage` | legit-major | `any-allow` | `ALLOW` | 947 ms | ✓ |
| `stripe-checkout-host` | legit-major | `any-allow` | `ALLOW` | 739 ms | ✓ |
| `payment-real-stripe-docs` | legit-payment | `any-allow` | `ALLOW` | 647 ms | ✓ |
| `notion` | legit-saas | `any-allow` | `ALLOW` | 512 ms | ✓ |
| `slack-app` | legit-saas | `any-allow` | `ALLOW` | 796 ms | ✓ |
| `aws-console` | legit-sensitive | `any-allow` | `ALLOW` | 973 ms | ✓ |
| `github-settings` | legit-sensitive | `any-allow` | `ALLOW` | 17002 ms | ✓ |
| `gmail-inbox` | legit-sensitive | `any-allow` | `ALLOW` | 26987 ms | ✓ |
| `data-scheme` | malformed | `any` | `CLEAN` | 135 ms | ✓ |
| `javascript-scheme` | malformed | `any` | `CLEAN` | 211 ms | ✓ |
| `oauth-known-good-github-cli` | oauth-legit | `any-allow` | `ALLOW` | 18890 ms | ✓ |
| `oauth-known-good-vscode` | oauth-legit | `any-allow` | `ALLOW` | 23270 ms | ✓ |
| `oauth-google-unknown-client-drive-scope` | oauth-phish | `any-deny` | `BLOCK` | 620 ms | ✓ |
| `oauth-microsoft-unknown-client-high-scope` | oauth-phish | `any-deny` | `BLOCK` | 654 ms | ✓ |
| `gift-card-scam-1` | payment-scam | `any-deny` | `ISOLATE` | 739 ms | ✓ |
| `wire-fraud-irs` | payment-scam | `any-deny` | `WARN` | 747 ms | ✓ |
| `piracy-multiple-1` | piracy-tld | `any` | `ALLOW` | 1068 ms | ✓ |
| `piracy-multiple-2` | piracy-tld | `any` | `ALLOW` | 10773 ms | ✓ |
| `piracy-tld-cc` | piracy-tld | `any` | `ALLOW` | 25088 ms | ✓ |
| `piracy-tld-pw` | piracy-tld | `any` | `ALLOW` | 1233 ms | ✓ |
| `piracy-tld-to` | piracy-tld | `any` | `ALLOW` | 22154 ms | ✓ |
| `piracy-tld-ws` | piracy-tld | `any` | `ALLOW` | 1139 ms | ✓ |
| `raw-ip-bare` | raw-ip | `any-deny` | `BLOCK` | 10959 ms | ✓ |
| `raw-ip-binary-drop` | raw-ip | `block` | `BLOCK` | 10935 ms | ✓ |
| `login-on-fresh-unknown` | sensitive-unknown | `any-deny` | `ISOLATE` | 741 ms | ✓ |
| `payment-checkout-unknown` | sensitive-unknown | `any-deny` | `ISOLATE` | 743 ms | ✓ |
| `github-io-tenant` | shared-host | `any` | `ALLOW` | 13026 ms | ✓ |
| `netlify-tenant` | shared-host | `any` | `ALLOW` | 10332 ms | ✓ |
| `vercel-tenant` | shared-host | `any` | `ALLOW` | 15483 ms | ✓ |
| `bitly-home` | shortener | `any-allow` | `ALLOW` | 690 ms | ✓ |
| `tco-home` | shortener | `any-allow` | `ALLOW` | 804 ms | ✓ |
| `spoof-mimecast-host` | spoof-wrapper | `any-allow` | `ALLOW` | 914 ms | ✓ |
| `spoof-safelinks-host` | spoof-wrapper | `any-allow` | `ALLOW` | 973 ms | ✓ |
| `support-scam-apple-virus-alert` | support-scam | `any-deny` | `WARN` | 894 ms | ✓ |
| `support-scam-microsoft-helpline` | support-scam | `any-deny` | `WARN` | 1049 ms | ✓ |
| `support-scam-windows-defender` | support-scam | `any-deny` | `WARN` | 877 ms | ✓ |
| `tld-click` | sus-tld | `any` | `ALLOW` | 14925 ms | ✓ |
| `tld-tk` | sus-tld | `any` | `ALLOW` | 914 ms | ✓ |
| `tld-xyz` | sus-tld | `any` | `ALLOW` | 937 ms | ✓ |
| `brand-impersonation-google` | synth-phish | `any-deny` | `ISOLATE` | 764 ms | ✓ |
| `brand-impersonation-microsoft` | synth-phish | `any-deny` | `ISOLATE` | 810 ms | ✓ |
| `brand-impersonation-paypal` | synth-phish | `any-deny` | `ISOLATE` | 992 ms | ✓ |
| `homoglyph-google` | synth-phish | `any-deny` | `WARN` | 971 ms | ✓ |
| `random-host-login` | synth-phish | `any-deny` | `ISOLATE` | 669 ms | ✓ |
| `combosquat-paypal-account` | typosquat | `any-deny` | `ISOLATE` | 631 ms | ✓ |
| `homoglyph-amazon-zero-for-o` | typosquat | `any-deny` | `BLOCK` | 640 ms | ✓ |
| `homoglyph-microsoft-rn-for-m` | typosquat | `any-deny` | `BLOCK` | 769 ms | ✓ |
| `homoglyph-paypal-1-for-l` | typosquat | `any-deny` | `BLOCK` | 664 ms | ✓ |
| `typo-google-letter-swap` | typosquat | `any-deny` | `WARN` | 995 ms | ✓ |
| `barracuda-benign` | wrapper-benign | `any-allow` | `ALLOW` | 5591 ms | ✓ |
| `cisco-securemail-benign` | wrapper-benign | `any-allow` | `ALLOW` | 22992 ms | ✓ |
| `gmail-link-redirect-benign` | wrapper-benign | `any-allow` | `ALLOW` | 14565 ms | ✓ |
| `proofpoint-v2-benign` | wrapper-benign | `any-allow` | `ALLOW` | 22596 ms | ✓ |
| `proofpoint-v3-format-benign` | wrapper-benign | `any-allow` | `ALLOW` | 21669 ms | ✓ |
| `safelinks-benign` | wrapper-benign | `any-allow` | `ALLOW` | 25384 ms | ✓ |
| `safelinks-multi-region-india` | wrapper-benign | `any-allow` | `ALLOW` | 20911 ms | ✓ |
| `safelinks-multi-region-jp` | wrapper-benign | `any-allow` | `ALLOW` | 21541 ms | ✓ |
| `symantec-clicktime-benign` | wrapper-benign | `any-allow` | `ALLOW` | 21194 ms | ✓ |
| `cisco-pointing-to-homoglyph` | wrapper-phish | `any-deny` | `BLOCK` | 536 ms | ✓ |
| `mimecast-pointing-at-fresh-host` | wrapper-phish | `any-deny` | `ISOLATE` | 986 ms | ✓ |
| `proofpoint-pointing-to-fresh-host` | wrapper-phish | `any-deny` | `ISOLATE` | 744 ms | ✓ |
| `safelinks-spoof-phish-target` | wrapper-phish | `any-deny` | `ISOLATE` | 1268 ms | ✓ |
