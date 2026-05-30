# Smoke corpus report

- API base: `http://127.0.0.1:18080`
- Cases: **100**
- Pass: **94**  /  Fail: **6**  /  Rate: **94.0%**
- Wall-clock: 85.4 s

## Per-category breakdown

| Category | Pass | Fail | Total | Rate |
| --- | ---: | ---: | ---: | ---: |
| crypto-drainer | 3 | 1 | 4 | 75% |
| edge-case | 3 | 0 | 3 | 100% |
| fake-banking | 4 | 0 | 4 | 100% |
| fake-oauth-host | 2 | 0 | 2 | 100% |
| fresh-payment | 2 | 0 | 2 | 100% |
| http-only | 1 | 0 | 1 | 100% |
| idn-homoglyph | 2 | 0 | 2 | 100% |
| install-lure | 1 | 1 | 2 | 50% |
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
| payment-scam | 1 | 1 | 2 | 50% |
| piracy-tld | 6 | 0 | 6 | 100% |
| raw-ip | 2 | 0 | 2 | 100% |
| sensitive-unknown | 2 | 0 | 2 | 100% |
| shared-host | 3 | 0 | 3 | 100% |
| shortener | 2 | 0 | 2 | 100% |
| spoof-wrapper | 2 | 0 | 2 | 100% |
| support-scam | 0 | 3 | 3 | 0% |
| sus-tld | 3 | 0 | 3 | 100% |
| synth-phish | 5 | 0 | 5 | 100% |
| typosquat | 5 | 0 | 5 | 100% |
| wrapper-benign | 9 | 0 | 9 | 100% |
| wrapper-phish | 4 | 0 | 4 | 100% |

## Failing cases


| Case | Expected | Actual | Reason codes |
| --- | --- | --- | --- |
| `support-scam-apple-virus-alert` | `any-deny` | `ALLOW` | TIER2_DATA_UNAVAILABLE |
| `support-scam-microsoft-helpline` | `any-deny` | `ALLOW` | TIER2_DATA_UNAVAILABLE |
| `support-scam-windows-defender` | `any-deny` | `ALLOW` | — |
| `drainer-fake-opensea` | `any-deny` | `ALLOW` | TIER2_DATA_UNAVAILABLE |
| `wire-fraud-irs` | `any-deny` | `ALLOW` | — |
| `fake-nodejs-install` | `any-deny` | `ALLOW` | TIER2_DATA_UNAVAILABLE |

## Detailed per-case results

| Case | Category | Expected | Actual | Latency | Pass |
| --- | --- | --- | --- | ---: | :---: |
| `drainer-fake-claim-airdrop` | crypto-drainer | `any-deny` | `ISOLATE` | 699 ms | ✓ |
| `drainer-fake-opensea` | crypto-drainer | `any-deny` | `ALLOW` | 960 ms | ✗ |
| `drainer-fake-revoke` | crypto-drainer | `any-deny` | `ISOLATE` | 551 ms | ✓ |
| `drainer-metamask-update` | crypto-drainer | `any-deny` | `ISOLATE` | 547 ms | ✓ |
| `fqdn-trailing-dot` | edge-case | `any-allow` | `ALLOW` | 606 ms | ✓ |
| `hash-fragment-only` | edge-case | `any-allow` | `ALLOW` | 706 ms | ✓ |
| `nonstandard-port` | edge-case | `any-allow` | `ALLOW` | 737 ms | ✓ |
| `fake-boa-mobile` | fake-banking | `any-deny` | `ISOLATE` | 614 ms | ✓ |
| `fake-chase-login` | fake-banking | `any-deny` | `ISOLATE` | 881 ms | ✓ |
| `fake-citibank-secure` | fake-banking | `any-deny` | `ISOLATE` | 678 ms | ✓ |
| `fake-wellsfargo-update` | fake-banking | `any-deny` | `ISOLATE` | 818 ms | ✓ |
| `fake-google-accounts-host` | fake-oauth-host | `any-deny` | `ISOLATE` | 682 ms | ✓ |
| `fake-microsoft-oauth-host` | fake-oauth-host | `any-deny` | `ISOLATE` | 541 ms | ✓ |
| `payment-fresh-cart` | fresh-payment | `any-deny` | `ISOLATE` | 562 ms | ✓ |
| `payment-fresh-checkout` | fresh-payment | `any-deny` | `ISOLATE` | 546 ms | ✓ |
| `http-only-major` | http-only | `any-allow` | `ALLOW` | 704 ms | ✓ |
| `idn-google-cyrillic-o` | idn-homoglyph | `any-deny` | `WARN` | 753 ms | ✓ |
| `idn-paypal-cyrillic-a` | idn-homoglyph | `any-deny` | `BLOCK` | 591 ms | ✓ |
| `fake-anthropic-install` | install-lure | `any-deny` | `ISOLATE` | 773 ms | ✓ |
| `fake-nodejs-install` | install-lure | `any-deny` | `ALLOW` | 799 ms | ✗ |
| `bank-real-chase` | legit-banking | `any-allow` | `ALLOW` | 868 ms | ✓ |
| `bank-real-citi` | legit-banking | `any-allow` | `ALLOW` | 649 ms | ✓ |
| `bank-real-wellsfargo` | legit-banking | `any-allow` | `ALLOW` | 791 ms | ✓ |
| `cloudflare-cdn-script` | legit-cdn | `any-allow` | `ALLOW` | 594 ms | ✓ |
| `google-fonts` | legit-cdn | `any-allow` | `ALLOW` | 706 ms | ✓ |
| `jsdelivr` | legit-cdn | `any-allow` | `ALLOW` | 539 ms | ✓ |
| `unpkg` | legit-cdn | `any-allow` | `ALLOW` | 682 ms | ✓ |
| `bbc-news` | legit-content | `any-allow` | `ALLOW` | 786 ms | ✓ |
| `mozilla-developer` | legit-content | `any-allow` | `ALLOW` | 654 ms | ✓ |
| `stackoverflow` | legit-content | `any-allow` | `ALLOW` | 654 ms | ✓ |
| `wikipedia` | legit-content | `any-allow` | `ALLOW` | 794 ms | ✓ |
| `claude-quickstart` | legit-dev | `any-allow` | `ALLOW` | 534 ms | ✓ |
| `rustup` | legit-dev | `any-allow` | `ALLOW` | 872 ms | ✓ |
| `apple-id-host` | legit-major | `any-allow` | `ALLOW` | 983 ms | ✓ |
| `cloudflare-corporate` | legit-major | `any-allow` | `ALLOW` | 649 ms | ✓ |
| `github` | legit-major | `any-allow` | `ALLOW` | 25106 ms | ✓ |
| `google-homepage` | legit-major | `any-allow` | `ALLOW` | 742 ms | ✓ |
| `microsoft-login` | legit-major | `any-allow` | `ALLOW` | 646 ms | ✓ |
| `paypal-homepage` | legit-major | `any-allow` | `ALLOW` | 971 ms | ✓ |
| `stripe-checkout-host` | legit-major | `any-allow` | `ALLOW` | 725 ms | ✓ |
| `payment-real-stripe-docs` | legit-payment | `any-allow` | `ALLOW` | 721 ms | ✓ |
| `notion` | legit-saas | `any-allow` | `ALLOW` | 523 ms | ✓ |
| `slack-app` | legit-saas | `any-allow` | `ALLOW` | 820 ms | ✓ |
| `aws-console` | legit-sensitive | `any-allow` | `ALLOW` | 968 ms | ✓ |
| `github-settings` | legit-sensitive | `any-allow` | `ALLOW` | 17639 ms | ✓ |
| `gmail-inbox` | legit-sensitive | `any-allow` | `ALLOW` | 18303 ms | ✓ |
| `data-scheme` | malformed | `any` | `CLEAN` | 198 ms | ✓ |
| `javascript-scheme` | malformed | `any` | `CLEAN` | 198 ms | ✓ |
| `oauth-known-good-github-cli` | oauth-legit | `any-allow` | `ALLOW` | 16764 ms | ✓ |
| `oauth-known-good-vscode` | oauth-legit | `any-allow` | `ALLOW` | 25386 ms | ✓ |
| `oauth-google-unknown-client-drive-scope` | oauth-phish | `any-deny` | `BLOCK` | 513 ms | ✓ |
| `oauth-microsoft-unknown-client-high-scope` | oauth-phish | `any-deny` | `BLOCK` | 524 ms | ✓ |
| `gift-card-scam-1` | payment-scam | `any-deny` | `ISOLATE` | 738 ms | ✓ |
| `wire-fraud-irs` | payment-scam | `any-deny` | `ALLOW` | 859 ms | ✗ |
| `piracy-multiple-1` | piracy-tld | `any` | `ALLOW` | 926 ms | ✓ |
| `piracy-multiple-2` | piracy-tld | `any` | `ALLOW` | 10889 ms | ✓ |
| `piracy-tld-cc` | piracy-tld | `any` | `ALLOW` | 23864 ms | ✓ |
| `piracy-tld-pw` | piracy-tld | `any` | `ALLOW` | 1162 ms | ✓ |
| `piracy-tld-to` | piracy-tld | `any` | `ALLOW` | 26038 ms | ✓ |
| `piracy-tld-ws` | piracy-tld | `any` | `ALLOW` | 1237 ms | ✓ |
| `raw-ip-bare` | raw-ip | `any-deny` | `BLOCK` | 10969 ms | ✓ |
| `raw-ip-binary-drop` | raw-ip | `block` | `BLOCK` | 10961 ms | ✓ |
| `login-on-fresh-unknown` | sensitive-unknown | `any-deny` | `ISOLATE` | 530 ms | ✓ |
| `payment-checkout-unknown` | sensitive-unknown | `any-deny` | `ISOLATE` | 591 ms | ✓ |
| `github-io-tenant` | shared-host | `any` | `ALLOW` | 20001 ms | ✓ |
| `netlify-tenant` | shared-host | `any` | `ALLOW` | 23295 ms | ✓ |
| `vercel-tenant` | shared-host | `any` | `ALLOW` | 19897 ms | ✓ |
| `bitly-home` | shortener | `any-allow` | `ALLOW` | 741 ms | ✓ |
| `tco-home` | shortener | `any-allow` | `ALLOW` | 641 ms | ✓ |
| `spoof-mimecast-host` | spoof-wrapper | `any-allow` | `ALLOW` | 708 ms | ✓ |
| `spoof-safelinks-host` | spoof-wrapper | `any-allow` | `ALLOW` | 887 ms | ✓ |
| `support-scam-apple-virus-alert` | support-scam | `any-deny` | `ALLOW` | 887 ms | ✗ |
| `support-scam-microsoft-helpline` | support-scam | `any-deny` | `ALLOW` | 962 ms | ✗ |
| `support-scam-windows-defender` | support-scam | `any-deny` | `ALLOW` | 725 ms | ✗ |
| `tld-click` | sus-tld | `any` | `ALLOW` | 19988 ms | ✓ |
| `tld-tk` | sus-tld | `any` | `ALLOW` | 907 ms | ✓ |
| `tld-xyz` | sus-tld | `any` | `ALLOW` | 756 ms | ✓ |
| `brand-impersonation-google` | synth-phish | `any-deny` | `ISOLATE` | 668 ms | ✓ |
| `brand-impersonation-microsoft` | synth-phish | `any-deny` | `ISOLATE` | 757 ms | ✓ |
| `brand-impersonation-paypal` | synth-phish | `any-deny` | `ISOLATE` | 705 ms | ✓ |
| `homoglyph-google` | synth-phish | `any-deny` | `WARN` | 971 ms | ✓ |
| `random-host-login` | synth-phish | `any-deny` | `ISOLATE` | 652 ms | ✓ |
| `combosquat-paypal-account` | typosquat | `any-deny` | `ISOLATE` | 717 ms | ✓ |
| `homoglyph-amazon-zero-for-o` | typosquat | `any-deny` | `BLOCK` | 619 ms | ✓ |
| `homoglyph-microsoft-rn-for-m` | typosquat | `any-deny` | `BLOCK` | 624 ms | ✓ |
| `homoglyph-paypal-1-for-l` | typosquat | `any-deny` | `BLOCK` | 507 ms | ✓ |
| `typo-google-letter-swap` | typosquat | `any-deny` | `WARN` | 796 ms | ✓ |
| `barracuda-benign` | wrapper-benign | `any-allow` | `ALLOW` | 12895 ms | ✓ |
| `cisco-securemail-benign` | wrapper-benign | `any-allow` | `ALLOW` | 8275 ms | ✓ |
| `gmail-link-redirect-benign` | wrapper-benign | `any-allow` | `ALLOW` | 15885 ms | ✓ |
| `proofpoint-v2-benign` | wrapper-benign | `any-allow` | `ALLOW` | 22431 ms | ✓ |
| `proofpoint-v3-format-benign` | wrapper-benign | `any-allow` | `ALLOW` | 18946 ms | ✓ |
| `safelinks-benign` | wrapper-benign | `any-allow` | `ALLOW` | 15901 ms | ✓ |
| `safelinks-multi-region-india` | wrapper-benign | `any-allow` | `ALLOW` | 23814 ms | ✓ |
| `safelinks-multi-region-jp` | wrapper-benign | `any-allow` | `ALLOW` | 15203 ms | ✓ |
| `symantec-clicktime-benign` | wrapper-benign | `any-allow` | `ALLOW` | 11467 ms | ✓ |
| `cisco-pointing-to-homoglyph` | wrapper-phish | `any-deny` | `BLOCK` | 581 ms | ✓ |
| `mimecast-pointing-at-fresh-host` | wrapper-phish | `any-deny` | `ISOLATE` | 891 ms | ✓ |
| `proofpoint-pointing-to-fresh-host` | wrapper-phish | `any-deny` | `ISOLATE` | 574 ms | ✓ |
| `safelinks-spoof-phish-target` | wrapper-phish | `any-deny` | `ISOLATE` | 1057 ms | ✓ |
