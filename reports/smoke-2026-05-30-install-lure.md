# Smoke corpus report

- API base: `http://127.0.0.1:18080`
- Cases: **100**
- Pass: **95**  /  Fail: **5**  /  Rate: **95.0%**
- Wall-clock: 85.5 s

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
| `support-scam-microsoft-helpline` | `any-deny` | `ALLOW` | TIER2_DATA_UNAVAILABLE |
| `support-scam-apple-virus-alert` | `any-deny` | `ALLOW` | TIER2_DATA_UNAVAILABLE |
| `support-scam-windows-defender` | `any-deny` | `ALLOW` | — |
| `drainer-fake-opensea` | `any-deny` | `ALLOW` | TIER2_DATA_UNAVAILABLE |
| `wire-fraud-irs` | `any-deny` | `ALLOW` | — |

## Detailed per-case results

| Case | Category | Expected | Actual | Latency | Pass |
| --- | --- | --- | --- | ---: | :---: |
| `drainer-fake-claim-airdrop` | crypto-drainer | `any-deny` | `ISOLATE` | 705 ms | ✓ |
| `drainer-fake-opensea` | crypto-drainer | `any-deny` | `ALLOW` | 938 ms | ✗ |
| `drainer-fake-revoke` | crypto-drainer | `any-deny` | `ISOLATE` | 723 ms | ✓ |
| `drainer-metamask-update` | crypto-drainer | `any-deny` | `ISOLATE` | 695 ms | ✓ |
| `fqdn-trailing-dot` | edge-case | `any-allow` | `ALLOW` | 617 ms | ✓ |
| `hash-fragment-only` | edge-case | `any-allow` | `ALLOW` | 655 ms | ✓ |
| `nonstandard-port` | edge-case | `any-allow` | `ALLOW` | 533 ms | ✓ |
| `fake-boa-mobile` | fake-banking | `any-deny` | `ISOLATE` | 601 ms | ✓ |
| `fake-chase-login` | fake-banking | `any-deny` | `ISOLATE` | 642 ms | ✓ |
| `fake-citibank-secure` | fake-banking | `any-deny` | `ISOLATE` | 737 ms | ✓ |
| `fake-wellsfargo-update` | fake-banking | `any-deny` | `ISOLATE` | 647 ms | ✓ |
| `fake-google-accounts-host` | fake-oauth-host | `any-deny` | `ISOLATE` | 625 ms | ✓ |
| `fake-microsoft-oauth-host` | fake-oauth-host | `any-deny` | `ISOLATE` | 604 ms | ✓ |
| `payment-fresh-cart` | fresh-payment | `any-deny` | `ISOLATE` | 633 ms | ✓ |
| `payment-fresh-checkout` | fresh-payment | `any-deny` | `ISOLATE` | 735 ms | ✓ |
| `http-only-major` | http-only | `any-allow` | `ALLOW` | 804 ms | ✓ |
| `idn-google-cyrillic-o` | idn-homoglyph | `any-deny` | `WARN` | 823 ms | ✓ |
| `idn-paypal-cyrillic-a` | idn-homoglyph | `any-deny` | `BLOCK` | 698 ms | ✓ |
| `fake-anthropic-install` | install-lure | `any-deny` | `ISOLATE` | 984 ms | ✓ |
| `fake-nodejs-install` | install-lure | `any-deny` | `ISOLATE` | 857 ms | ✓ |
| `bank-real-chase` | legit-banking | `any-allow` | `ALLOW` | 1015 ms | ✓ |
| `bank-real-citi` | legit-banking | `any-allow` | `ALLOW` | 866 ms | ✓ |
| `bank-real-wellsfargo` | legit-banking | `any-allow` | `ALLOW` | 837 ms | ✓ |
| `cloudflare-cdn-script` | legit-cdn | `any-allow` | `ALLOW` | 633 ms | ✓ |
| `google-fonts` | legit-cdn | `any-allow` | `ALLOW` | 743 ms | ✓ |
| `jsdelivr` | legit-cdn | `any-allow` | `ALLOW` | 690 ms | ✓ |
| `unpkg` | legit-cdn | `any-allow` | `ALLOW` | 765 ms | ✓ |
| `bbc-news` | legit-content | `any-allow` | `ALLOW` | 954 ms | ✓ |
| `mozilla-developer` | legit-content | `any-allow` | `ALLOW` | 958 ms | ✓ |
| `stackoverflow` | legit-content | `any-allow` | `ALLOW` | 618 ms | ✓ |
| `wikipedia` | legit-content | `any-allow` | `ALLOW` | 950 ms | ✓ |
| `claude-quickstart` | legit-dev | `any-allow` | `ALLOW` | 681 ms | ✓ |
| `rustup` | legit-dev | `any-allow` | `ALLOW` | 855 ms | ✓ |
| `apple-id-host` | legit-major | `any-allow` | `ALLOW` | 812 ms | ✓ |
| `cloudflare-corporate` | legit-major | `any-allow` | `ALLOW` | 823 ms | ✓ |
| `github` | legit-major | `any-allow` | `ALLOW` | 21256 ms | ✓ |
| `google-homepage` | legit-major | `any-allow` | `ALLOW` | 854 ms | ✓ |
| `microsoft-login` | legit-major | `any-allow` | `ALLOW` | 846 ms | ✓ |
| `paypal-homepage` | legit-major | `any-allow` | `ALLOW` | 927 ms | ✓ |
| `stripe-checkout-host` | legit-major | `any-allow` | `ALLOW` | 933 ms | ✓ |
| `payment-real-stripe-docs` | legit-payment | `any-allow` | `ALLOW` | 625 ms | ✓ |
| `notion` | legit-saas | `any-allow` | `ALLOW` | 720 ms | ✓ |
| `slack-app` | legit-saas | `any-allow` | `ALLOW` | 766 ms | ✓ |
| `aws-console` | legit-sensitive | `any-allow` | `ALLOW` | 996 ms | ✓ |
| `github-settings` | legit-sensitive | `any-allow` | `ALLOW` | 19744 ms | ✓ |
| `gmail-inbox` | legit-sensitive | `any-allow` | `ALLOW` | 19797 ms | ✓ |
| `data-scheme` | malformed | `any` | `CLEAN` | 113 ms | ✓ |
| `javascript-scheme` | malformed | `any` | `CLEAN` | 222 ms | ✓ |
| `oauth-known-good-github-cli` | oauth-legit | `any-allow` | `ALLOW` | 16228 ms | ✓ |
| `oauth-known-good-vscode` | oauth-legit | `any-allow` | `ALLOW` | 22758 ms | ✓ |
| `oauth-google-unknown-client-drive-scope` | oauth-phish | `any-deny` | `BLOCK` | 463 ms | ✓ |
| `oauth-microsoft-unknown-client-high-scope` | oauth-phish | `any-deny` | `BLOCK` | 489 ms | ✓ |
| `gift-card-scam-1` | payment-scam | `any-deny` | `ISOLATE` | 683 ms | ✓ |
| `wire-fraud-irs` | payment-scam | `any-deny` | `ALLOW` | 858 ms | ✗ |
| `piracy-multiple-1` | piracy-tld | `any` | `ALLOW` | 1032 ms | ✓ |
| `piracy-multiple-2` | piracy-tld | `any` | `ALLOW` | 10971 ms | ✓ |
| `piracy-tld-cc` | piracy-tld | `any` | `ALLOW` | 27194 ms | ✓ |
| `piracy-tld-pw` | piracy-tld | `any` | `ALLOW` | 1144 ms | ✓ |
| `piracy-tld-to` | piracy-tld | `any` | `ALLOW` | 21720 ms | ✓ |
| `piracy-tld-ws` | piracy-tld | `any` | `ALLOW` | 756 ms | ✓ |
| `raw-ip-bare` | raw-ip | `any-deny` | `BLOCK` | 10919 ms | ✓ |
| `raw-ip-binary-drop` | raw-ip | `block` | `BLOCK` | 10928 ms | ✓ |
| `login-on-fresh-unknown` | sensitive-unknown | `any-deny` | `ISOLATE` | 621 ms | ✓ |
| `payment-checkout-unknown` | sensitive-unknown | `any-deny` | `ISOLATE` | 577 ms | ✓ |
| `github-io-tenant` | shared-host | `any` | `ALLOW` | 19718 ms | ✓ |
| `netlify-tenant` | shared-host | `any` | `ALLOW` | 16085 ms | ✓ |
| `vercel-tenant` | shared-host | `any` | `ALLOW` | 18063 ms | ✓ |
| `bitly-home` | shortener | `any-allow` | `ALLOW` | 738 ms | ✓ |
| `tco-home` | shortener | `any-allow` | `ALLOW` | 776 ms | ✓ |
| `spoof-mimecast-host` | spoof-wrapper | `any-allow` | `ALLOW` | 759 ms | ✓ |
| `spoof-safelinks-host` | spoof-wrapper | `any-allow` | `ALLOW` | 893 ms | ✓ |
| `support-scam-apple-virus-alert` | support-scam | `any-deny` | `ALLOW` | 889 ms | ✗ |
| `support-scam-microsoft-helpline` | support-scam | `any-deny` | `ALLOW` | 887 ms | ✗ |
| `support-scam-windows-defender` | support-scam | `any-deny` | `ALLOW` | 851 ms | ✗ |
| `tld-click` | sus-tld | `any` | `ALLOW` | 15308 ms | ✓ |
| `tld-tk` | sus-tld | `any` | `ALLOW` | 925 ms | ✓ |
| `tld-xyz` | sus-tld | `any` | `ALLOW` | 833 ms | ✓ |
| `brand-impersonation-google` | synth-phish | `any-deny` | `ISOLATE` | 692 ms | ✓ |
| `brand-impersonation-microsoft` | synth-phish | `any-deny` | `ISOLATE` | 515 ms | ✓ |
| `brand-impersonation-paypal` | synth-phish | `any-deny` | `ISOLATE` | 644 ms | ✓ |
| `homoglyph-google` | synth-phish | `any-deny` | `WARN` | 922 ms | ✓ |
| `random-host-login` | synth-phish | `any-deny` | `ISOLATE` | 619 ms | ✓ |
| `combosquat-paypal-account` | typosquat | `any-deny` | `ISOLATE` | 606 ms | ✓ |
| `homoglyph-amazon-zero-for-o` | typosquat | `any-deny` | `BLOCK` | 593 ms | ✓ |
| `homoglyph-microsoft-rn-for-m` | typosquat | `any-deny` | `BLOCK` | 554 ms | ✓ |
| `homoglyph-paypal-1-for-l` | typosquat | `any-deny` | `BLOCK` | 643 ms | ✓ |
| `typo-google-letter-swap` | typosquat | `any-deny` | `WARN` | 916 ms | ✓ |
| `barracuda-benign` | wrapper-benign | `any-allow` | `ALLOW` | 5514 ms | ✓ |
| `cisco-securemail-benign` | wrapper-benign | `any-allow` | `ALLOW` | 5023 ms | ✓ |
| `gmail-link-redirect-benign` | wrapper-benign | `any-allow` | `ALLOW` | 20060 ms | ✓ |
| `proofpoint-v2-benign` | wrapper-benign | `any-allow` | `ALLOW` | 20069 ms | ✓ |
| `proofpoint-v3-format-benign` | wrapper-benign | `any-allow` | `ALLOW` | 18540 ms | ✓ |
| `safelinks-benign` | wrapper-benign | `any-allow` | `ALLOW` | 21143 ms | ✓ |
| `safelinks-multi-region-india` | wrapper-benign | `any-allow` | `ALLOW` | 23992 ms | ✓ |
| `safelinks-multi-region-jp` | wrapper-benign | `any-allow` | `ALLOW` | 20878 ms | ✓ |
| `symantec-clicktime-benign` | wrapper-benign | `any-allow` | `ALLOW` | 13140 ms | ✓ |
| `cisco-pointing-to-homoglyph` | wrapper-phish | `any-deny` | `BLOCK` | 529 ms | ✓ |
| `mimecast-pointing-at-fresh-host` | wrapper-phish | `any-deny` | `ISOLATE` | 932 ms | ✓ |
| `proofpoint-pointing-to-fresh-host` | wrapper-phish | `any-deny` | `ISOLATE` | 617 ms | ✓ |
| `safelinks-spoof-phish-target` | wrapper-phish | `any-deny` | `ISOLATE` | 1065 ms | ✓ |
