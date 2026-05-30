# Smoke corpus report

- API base: `http://127.0.0.1:18080`
- Cases: **196**
- Pass: **184**  /  Fail: **12**  /  Rate: **93.9%**
- Wall-clock: 165.8 s

## Per-category breakdown

| Category | Pass | Fail | Total | Rate |
| --- | ---: | ---: | ---: | ---: |
| benign-trigger | 3 | 0 | 3 | 100% |
| crypto-drainer | 12 | 0 | 12 | 100% |
| direct-download | 3 | 0 | 3 | 100% |
| edge-case | 6 | 0 | 6 | 100% |
| fake-banking | 10 | 0 | 10 | 100% |
| fake-oauth-host | 2 | 0 | 2 | 100% |
| fresh-payment | 4 | 0 | 4 | 100% |
| http-only | 2 | 0 | 2 | 100% |
| idn-homoglyph | 6 | 0 | 6 | 100% |
| install-lure | 6 | 0 | 6 | 100% |
| legit-banking | 6 | 0 | 6 | 100% |
| legit-cdn | 5 | 0 | 5 | 100% |
| legit-content | 8 | 0 | 8 | 100% |
| legit-dev | 5 | 0 | 5 | 100% |
| legit-major | 11 | 1 | 12 | 92% |
| legit-payment | 1 | 0 | 1 | 100% |
| legit-saas | 6 | 0 | 6 | 100% |
| legit-sensitive | 1 | 2 | 3 | 33% |
| legit-tracker | 1 | 0 | 1 | 100% |
| malformed | 4 | 0 | 4 | 100% |
| mfa-bombing | 2 | 0 | 2 | 100% |
| oauth-legit | 3 | 1 | 4 | 75% |
| oauth-phish | 3 | 1 | 4 | 75% |
| payment-scam | 10 | 0 | 10 | 100% |
| piracy-tld | 6 | 0 | 6 | 100% |
| punycode | 1 | 0 | 1 | 100% |
| raw-ip | 3 | 1 | 4 | 75% |
| sensitive-unknown | 2 | 0 | 2 | 100% |
| session-hijack | 2 | 0 | 2 | 100% |
| shared-host | 5 | 1 | 6 | 83% |
| shortener | 3 | 0 | 3 | 100% |
| spoof-wrapper | 2 | 0 | 2 | 100% |
| subdomain-spoof | 3 | 0 | 3 | 100% |
| support-scam | 9 | 0 | 9 | 100% |
| sus-tld | 4 | 2 | 6 | 67% |
| synth-phish | 5 | 0 | 5 | 100% |
| typosquat | 9 | 0 | 9 | 100% |
| wrapper-benign | 6 | 3 | 9 | 67% |
| wrapper-phish | 4 | 0 | 4 | 100% |

## Failing cases


| Case | Expected | Actual | Reason codes |
| --- | --- | --- | --- |
| `github` | `any-allow` | `ERR: exception: timed out` | — |
| `tld-click` | `any` | `ERR: exception: timed out` | — |
| `safelinks-multi-region-india` | `any-allow` | `ERR: exception: timed out` | — |
| `safelinks-multi-region-jp` | `any-allow` | `ERR: exception: timed out` | — |
| `symantec-clicktime-benign` | `any-allow` | `ERR: exception: timed out` | — |
| `gmail-inbox` | `any-allow` | `ERR: exception: timed out` | — |
| `github-settings` | `any-allow` | `ERR: exception: timed out` | — |
| `oauth-phish-pretend-vscode` | `any-deny` | `ERR: exception: timed out` | — |
| `oauth-legit-github-mobile` | `any-allow` | `ERR: exception: timed out` | — |
| `cctld-ml` | `any` | `ERR: exception: timed out` | — |
| `shared-host-wordpress` | `any-allow` | `ERR: exception: timed out` | — |
| `raw-ip-cn-vps` | `block` | `ERR: exception: timed out` | — |

## Detailed per-case results

| Case | Category | Expected | Actual | Latency | Pass |
| --- | --- | --- | --- | ---: | :---: |
| `benign-news-irs-tax` | benign-trigger | `any-allow` | `ALLOW` | 923 ms | ✓ |
| `benign-wikipedia-gift-card` | benign-trigger | `any-allow` | `ALLOW` | 782 ms | ✓ |
| `benign-wikipedia-phishing` | benign-trigger | `any-allow` | `ALLOW` | 756 ms | ✓ |
| `drainer-arbitrum-mint` | crypto-drainer | `any-deny` | `WARN` | 839 ms | ✓ |
| `drainer-blur-airdrop` | crypto-drainer | `any-deny` | `WARN` | 2220 ms | ✓ |
| `drainer-fake-claim-airdrop` | crypto-drainer | `any-deny` | `BLOCK` | 1729 ms | ✓ |
| `drainer-fake-opensea` | crypto-drainer | `any-deny` | `WARN` | 1754 ms | ✓ |
| `drainer-fake-revoke` | crypto-drainer | `any-deny` | `ISOLATE` | 1407 ms | ✓ |
| `drainer-metamask-update` | crypto-drainer | `any-deny` | `ISOLATE` | 1368 ms | ✓ |
| `drainer-pancakeswap-airdrop` | crypto-drainer | `any-deny` | `BLOCK` | 4177 ms | ✓ |
| `drainer-phantom-wallet` | crypto-drainer | `any-deny` | `ISOLATE` | 2063 ms | ✓ |
| `drainer-revoke-cash-spoof` | crypto-drainer | `any-deny` | `ISOLATE` | 3635 ms | ✓ |
| `drainer-trustwallet` | crypto-drainer | `any-deny` | `ISOLATE` | 2234 ms | ✓ |
| `drainer-uniswap-claim` | crypto-drainer | `any-deny` | `WARN` | 2299 ms | ✓ |
| `drainer-wallet-validate` | crypto-drainer | `any-deny` | `ISOLATE` | 3143 ms | ✓ |
| `direct-download-exe` | direct-download | `any-deny` | `ISOLATE` | 1475 ms | ✓ |
| `direct-download-jar` | direct-download | `any-deny` | `ISOLATE` | 1494 ms | ✓ |
| `direct-download-msi` | direct-download | `any-deny` | `ISOLATE` | 1463 ms | ✓ |
| `edge-case-non-standard-tld` | edge-case | `any-allow` | `ALLOW` | 858 ms | ✓ |
| `edge-case-numeric-domain` | edge-case | `any` | `ALLOW` | 913 ms | ✓ |
| `edge-case-very-long-url` | edge-case | `any-allow` | `ALLOW` | 874 ms | ✓ |
| `fqdn-trailing-dot` | edge-case | `any-allow` | `ALLOW` | 720 ms | ✓ |
| `hash-fragment-only` | edge-case | `any-allow` | `ALLOW` | 728 ms | ✓ |
| `nonstandard-port` | edge-case | `any-allow` | `ALLOW` | 681 ms | ✓ |
| `fake-bank-barclays` | fake-banking | `any-deny` | `ISOLATE` | 1864 ms | ✓ |
| `fake-bank-deutsche` | fake-banking | `any-deny` | `ISOLATE` | 1743 ms | ✓ |
| `fake-bank-hsbc` | fake-banking | `any-deny` | `ISOLATE` | 1696 ms | ✓ |
| `fake-bank-natwest` | fake-banking | `any-deny` | `ISOLATE` | 1171 ms | ✓ |
| `fake-bank-rbc` | fake-banking | `any-deny` | `ISOLATE` | 1481 ms | ✓ |
| `fake-bank-santander` | fake-banking | `any-deny` | `ISOLATE` | 1844 ms | ✓ |
| `fake-boa-mobile` | fake-banking | `any-deny` | `ISOLATE` | 1818 ms | ✓ |
| `fake-chase-login` | fake-banking | `any-deny` | `ISOLATE` | 1578 ms | ✓ |
| `fake-citibank-secure` | fake-banking | `any-deny` | `ISOLATE` | 2050 ms | ✓ |
| `fake-wellsfargo-update` | fake-banking | `any-deny` | `ISOLATE` | 1791 ms | ✓ |
| `fake-google-accounts-host` | fake-oauth-host | `any-deny` | `ISOLATE` | 1863 ms | ✓ |
| `fake-microsoft-oauth-host` | fake-oauth-host | `any-deny` | `ISOLATE` | 2068 ms | ✓ |
| `fresh-payment-new-bank-login` | fresh-payment | `any-deny` | `ISOLATE` | 1695 ms | ✓ |
| `fresh-payment-wallet-connect` | fresh-payment | `any-deny` | `ISOLATE` | 1191 ms | ✓ |
| `payment-fresh-cart` | fresh-payment | `any-deny` | `ISOLATE` | 1500 ms | ✓ |
| `payment-fresh-checkout` | fresh-payment | `any-deny` | `ISOLATE` | 1876 ms | ✓ |
| `http-fresh-domain` | http-only | `any` | `ALLOW` | 821 ms | ✓ |
| `http-only-major` | http-only | `any-allow` | `ALLOW` | 589 ms | ✓ |
| `idn-amazon-cyrillic-a` | idn-homoglyph | `any-deny` | `WARN` | 1529 ms | ✓ |
| `idn-apple-cyrillic-p` | idn-homoglyph | `any-deny` | `BLOCK` | 1409 ms | ✓ |
| `idn-github-cyrillic-h` | idn-homoglyph | `any-deny` | `BLOCK` | 1597 ms | ✓ |
| `idn-google-cyrillic-o` | idn-homoglyph | `any-deny` | `WARN` | 2779 ms | ✓ |
| `idn-microsoft-cyrillic-o` | idn-homoglyph | `any-deny` | `WARN` | 1469 ms | ✓ |
| `idn-paypal-cyrillic-a` | idn-homoglyph | `any-deny` | `BLOCK` | 2570 ms | ✓ |
| `dev-install-fake-docker` | install-lure | `any-deny` | `ISOLATE` | 1500 ms | ✓ |
| `dev-install-fake-go` | install-lure | `any-deny` | `ISOLATE` | 1614 ms | ✓ |
| `dev-install-fake-rust` | install-lure | `any-deny` | `ISOLATE` | 1704 ms | ✓ |
| `dev-install-fake-terraform` | install-lure | `any-deny` | `ISOLATE` | 1702 ms | ✓ |
| `fake-anthropic-install` | install-lure | `any-deny` | `ISOLATE` | 2663 ms | ✓ |
| `fake-nodejs-install` | install-lure | `any-deny` | `ISOLATE` | 2550 ms | ✓ |
| `bank-real-chase` | legit-banking | `any-allow` | `ALLOW` | 898 ms | ✓ |
| `bank-real-citi` | legit-banking | `any-allow` | `ALLOW` | 684 ms | ✓ |
| `bank-real-deutsche` | legit-banking | `any-allow` | `ALLOW` | 767 ms | ✓ |
| `bank-real-hsbc` | legit-banking | `any-allow` | `ALLOW` | 886 ms | ✓ |
| `bank-real-rbc` | legit-banking | `any-allow` | `ALLOW` | 910 ms | ✓ |
| `bank-real-wellsfargo` | legit-banking | `any-allow` | `ALLOW` | 914 ms | ✓ |
| `cloudflare-cdn-script` | legit-cdn | `any-allow` | `ALLOW` | 577 ms | ✓ |
| `google-fonts` | legit-cdn | `any-allow` | `ALLOW` | 628 ms | ✓ |
| `jsdelivr` | legit-cdn | `any-allow` | `ALLOW` | 789 ms | ✓ |
| `legit-cdn-jquery` | legit-cdn | `any-allow` | `ALLOW` | 701 ms | ✓ |
| `unpkg` | legit-cdn | `any-allow` | `ALLOW` | 782 ms | ✓ |
| `bbc-news` | legit-content | `any-allow` | `ALLOW` | 840 ms | ✓ |
| `legit-content-medium` | legit-content | `any-allow` | `ALLOW` | 589 ms | ✓ |
| `legit-content-news-nytimes` | legit-content | `any-allow` | `ALLOW` | 912 ms | ✓ |
| `legit-content-reddit` | legit-content | `any-allow` | `ALLOW` | 878 ms | ✓ |
| `legit-content-substack` | legit-content | `any-allow` | `ALLOW` | 634 ms | ✓ |
| `mozilla-developer` | legit-content | `any-allow` | `ALLOW` | 574 ms | ✓ |
| `stackoverflow` | legit-content | `any-allow` | `ALLOW` | 820 ms | ✓ |
| `wikipedia` | legit-content | `any-allow` | `ALLOW` | 645 ms | ✓ |
| `claude-quickstart` | legit-dev | `any-allow` | `ALLOW` | 674 ms | ✓ |
| `legit-go-pkg` | legit-dev | `any-allow` | `ALLOW` | 722 ms | ✓ |
| `legit-python-docs` | legit-dev | `any-allow` | `ALLOW` | 826 ms | ✓ |
| `legit-rust-docs` | legit-dev | `any-allow` | `ALLOW` | 851 ms | ✓ |
| `rustup` | legit-dev | `any-allow` | `ALLOW` | 717 ms | ✓ |
| `apple-id-host` | legit-major | `any-allow` | `ALLOW` | 983 ms | ✓ |
| `cloudflare-corporate` | legit-major | `any-allow` | `ALLOW` | 665 ms | ✓ |
| `github` | legit-major | `any-allow` | `ERR: exception: timed out` | 30132 ms | ✗ |
| `google-homepage` | legit-major | `any-allow` | `ALLOW` | 729 ms | ✓ |
| `legit-anthropic` | legit-major | `any-allow` | `ALLOW` | 601 ms | ✓ |
| `legit-aws-docs` | legit-major | `any-allow` | `ALLOW` | 798 ms | ✓ |
| `legit-microsoft-learn` | legit-major | `any-allow` | `ALLOW` | 712 ms | ✓ |
| `legit-openai` | legit-major | `any-allow` | `ALLOW` | 663 ms | ✓ |
| `legit-vercel` | legit-major | `any-allow` | `ALLOW` | 747 ms | ✓ |
| `microsoft-login` | legit-major | `any-allow` | `ALLOW` | 686 ms | ✓ |
| `paypal-homepage` | legit-major | `any-allow` | `ALLOW` | 902 ms | ✓ |
| `stripe-checkout-host` | legit-major | `any-allow` | `ALLOW` | 845 ms | ✓ |
| `payment-real-stripe-docs` | legit-payment | `any-allow` | `ALLOW` | 550 ms | ✓ |
| `legit-saas-airtable` | legit-saas | `any-allow` | `ALLOW` | 726 ms | ✓ |
| `legit-saas-canva` | legit-saas | `any-allow` | `ALLOW` | 500 ms | ✓ |
| `legit-saas-figma` | legit-saas | `any-allow` | `ALLOW` | 597 ms | ✓ |
| `legit-saas-linear` | legit-saas | `any-allow` | `ALLOW` | 593 ms | ✓ |
| `notion` | legit-saas | `any-allow` | `ALLOW` | 644 ms | ✓ |
| `slack-app` | legit-saas | `any-allow` | `ALLOW` | 831 ms | ✓ |
| `aws-console` | legit-sensitive | `any-allow` | `ALLOW` | 950 ms | ✓ |
| `github-settings` | legit-sensitive | `any-allow` | `ERR: exception: timed out` | 30029 ms | ✗ |
| `gmail-inbox` | legit-sensitive | `any-allow` | `ERR: exception: timed out` | 30030 ms | ✗ |
| `benign-pixel-fb` | legit-tracker | `any-allow` | `ALLOW` | 783 ms | ✓ |
| `corrupt-protocol` | malformed | `any` | `ALLOW` | 570 ms | ✓ |
| `corrupt-spaces` | malformed | `any` | `ALLOW` | 538 ms | ✓ |
| `data-scheme` | malformed | `any` | `CLEAN` | 191 ms | ✓ |
| `javascript-scheme` | malformed | `any` | `CLEAN` | 176 ms | ✓ |
| `mfa-fake-duo` | mfa-bombing | `any-deny` | `ISOLATE` | 5312 ms | ✓ |
| `mfa-fake-okta-push` | mfa-bombing | `any-deny` | `ISOLATE` | 2729 ms | ✓ |
| `oauth-known-good-github-cli` | oauth-legit | `any-allow` | `ALLOW` | 25728 ms | ✓ |
| `oauth-known-good-vscode` | oauth-legit | `any-allow` | `ALLOW` | 19537 ms | ✓ |
| `oauth-legit-azure-cli` | oauth-legit | `any-allow` | `ALLOW` | 967 ms | ✓ |
| `oauth-legit-github-mobile` | oauth-legit | `any-allow` | `ERR: exception: timed out` | 30029 ms | ✗ |
| `oauth-google-unknown-client-drive-scope` | oauth-phish | `any-deny` | `BLOCK` | 474 ms | ✓ |
| `oauth-microsoft-unknown-client-high-scope` | oauth-phish | `any-deny` | `BLOCK` | 519 ms | ✓ |
| `oauth-phish-pretend-gcloud` | oauth-phish | `any-deny` | `BLOCK` | 660 ms | ✓ |
| `oauth-phish-pretend-vscode` | oauth-phish | `any-deny` | `ERR: exception: timed out` | 30029 ms | ✗ |
| `gift-card-scam-1` | payment-scam | `any-deny` | `ISOLATE` | 2967 ms | ✓ |
| `payment-scam-customs-fee` | payment-scam | `any-deny` | `WARN` | 1222 ms | ✓ |
| `payment-scam-fake-paypal-invoice` | payment-scam | `any-deny` | `BLOCK` | 1478 ms | ✓ |
| `payment-scam-geek-squad-invoice` | payment-scam | `any-deny` | `WARN` | 935 ms | ✓ |
| `payment-scam-inheritance` | payment-scam | `any-deny` | `WARN` | 846 ms | ✓ |
| `payment-scam-lottery` | payment-scam | `any-deny` | `WARN` | 837 ms | ✓ |
| `payment-scam-medicare-refund` | payment-scam | `any-deny` | `WARN` | 952 ms | ✓ |
| `payment-scam-ssn-suspended` | payment-scam | `any-deny` | `WARN` | 748 ms | ✓ |
| `payment-scam-tax-refund-uk` | payment-scam | `any-deny` | `WARN` | 1843 ms | ✓ |
| `wire-fraud-irs` | payment-scam | `any-deny` | `WARN` | 898 ms | ✓ |
| `piracy-multiple-1` | piracy-tld | `any` | `ALLOW` | 2497 ms | ✓ |
| `piracy-multiple-2` | piracy-tld | `any` | `ALLOW` | 13234 ms | ✓ |
| `piracy-tld-cc` | piracy-tld | `any` | `WARN` | 28952 ms | ✓ |
| `piracy-tld-pw` | piracy-tld | `any` | `ALLOW` | 1223 ms | ✓ |
| `piracy-tld-to` | piracy-tld | `any` | `ALLOW` | 20519 ms | ✓ |
| `piracy-tld-ws` | piracy-tld | `any` | `ALLOW` | 1636 ms | ✓ |
| `punycode-google` | punycode | `any` | `WARN` | 925 ms | ✓ |
| `raw-ip-bare` | raw-ip | `any-deny` | `BLOCK` | 11522 ms | ✓ |
| `raw-ip-binary-drop` | raw-ip | `block` | `BLOCK` | 11433 ms | ✓ |
| `raw-ip-cn-vps` | raw-ip | `block` | `ERR: exception: timed out` | 30029 ms | ✗ |
| `raw-ip-private-cgnat` | raw-ip | `any` | `BLOCK` | 11443 ms | ✓ |
| `login-on-fresh-unknown` | sensitive-unknown | `any-deny` | `ISOLATE` | 1250 ms | ✓ |
| `payment-checkout-unknown` | sensitive-unknown | `any-deny` | `ISOLATE` | 1186 ms | ✓ |
| `session-hijack-fake-signin` | session-hijack | `any-deny` | `ISOLATE` | 2041 ms | ✓ |
| `session-hijack-fake-token` | session-hijack | `any-deny` | `ISOLATE` | 1321 ms | ✓ |
| `github-io-tenant` | shared-host | `any` | `ALLOW` | 27338 ms | ✓ |
| `netlify-tenant` | shared-host | `any` | `ALLOW` | 27884 ms | ✓ |
| `shared-host-pages-dev` | shared-host | `any` | `ALLOW` | 1774 ms | ✓ |
| `shared-host-wordpress` | shared-host | `any-allow` | `ERR: exception: timed out` | 30029 ms | ✗ |
| `shared-host-workers-dev` | shared-host | `any` | `ALLOW` | 1621 ms | ✓ |
| `vercel-tenant` | shared-host | `any` | `ALLOW` | 15550 ms | ✓ |
| `bitly-home` | shortener | `any-allow` | `ALLOW` | 716 ms | ✓ |
| `shortener-bitly-corrupt` | shortener | `any` | `ALLOW` | 699 ms | ✓ |
| `tco-home` | shortener | `any-allow` | `ALLOW` | 681 ms | ✓ |
| `spoof-mimecast-host` | spoof-wrapper | `any-allow` | `ALLOW` | 841 ms | ✓ |
| `spoof-safelinks-host` | spoof-wrapper | `any-allow` | `ALLOW` | 785 ms | ✓ |
| `subdomain-spoof-google-accounts` | subdomain-spoof | `any-deny` | `ISOLATE` | 2930 ms | ✓ |
| `subdomain-spoof-microsoft-login` | subdomain-spoof | `any-deny` | `ISOLATE` | 2568 ms | ✓ |
| `subdomain-spoof-paypal` | subdomain-spoof | `any-deny` | `ISOLATE` | 5166 ms | ✓ |
| `scam-amazon-support` | support-scam | `any-deny` | `WARN` | 1874 ms | ✓ |
| `scam-google-virus-warning` | support-scam | `any-deny` | `WARN` | 1341 ms | ✓ |
| `scam-icloud-locked` | support-scam | `any-deny` | `ISOLATE` | 1406 ms | ✓ |
| `scam-mcafee-renewal` | support-scam | `any-deny` | `WARN` | 717 ms | ✓ |
| `scam-norton-support` | support-scam | `any-deny` | `WARN` | 875 ms | ✓ |
| `scam-windows-error` | support-scam | `any-deny` | `WARN` | 851 ms | ✓ |
| `support-scam-apple-virus-alert` | support-scam | `any-deny` | `WARN` | 1364 ms | ✓ |
| `support-scam-microsoft-helpline` | support-scam | `any-deny` | `WARN` | 1546 ms | ✓ |
| `support-scam-windows-defender` | support-scam | `any-deny` | `WARN` | 830 ms | ✓ |
| `cctld-cf` | sus-tld | `any` | `ALLOW` | 1728 ms | ✓ |
| `cctld-ga` | sus-tld | `any` | `ALLOW` | 1545 ms | ✓ |
| `cctld-ml` | sus-tld | `any` | `ERR: exception: timed out` | 30038 ms | ✗ |
| `tld-click` | sus-tld | `any` | `ERR: exception: timed out` | 30031 ms | ✗ |
| `tld-tk` | sus-tld | `any` | `ALLOW` | 1449 ms | ✓ |
| `tld-xyz` | sus-tld | `any` | `ALLOW` | 1606 ms | ✓ |
| `brand-impersonation-google` | synth-phish | `any-deny` | `ISOLATE` | 803 ms | ✓ |
| `brand-impersonation-microsoft` | synth-phish | `any-deny` | `ISOLATE` | 1102 ms | ✓ |
| `brand-impersonation-paypal` | synth-phish | `any-deny` | `ISOLATE` | 1286 ms | ✓ |
| `homoglyph-google` | synth-phish | `any-deny` | `WARN` | 1536 ms | ✓ |
| `random-host-login` | synth-phish | `any-deny` | `ISOLATE` | 1480 ms | ✓ |
| `combosquat-paypal-account` | typosquat | `any-deny` | `ISOLATE` | 1726 ms | ✓ |
| `homoglyph-amazon-zero-for-o` | typosquat | `any-deny` | `BLOCK` | 3601 ms | ✓ |
| `homoglyph-microsoft-rn-for-m` | typosquat | `any-deny` | `BLOCK` | 1594 ms | ✓ |
| `homoglyph-paypal-1-for-l` | typosquat | `any-deny` | `BLOCK` | 3201 ms | ✓ |
| `typo-amazon-shuffle` | typosquat | `any-deny` | `BLOCK` | 1516 ms | ✓ |
| `typo-google-h` | typosquat | `any-deny` | `WARN` | 1534 ms | ✓ |
| `typo-google-letter-swap` | typosquat | `any-deny` | `WARN` | 2306 ms | ✓ |
| `typo-microsoft-omission` | typosquat | `any-deny` | `BLOCK` | 1179 ms | ✓ |
| `typo-paypal-double` | typosquat | `any-deny` | `BLOCK` | 1420 ms | ✓ |
| `barracuda-benign` | wrapper-benign | `any-allow` | `ALLOW` | 15054 ms | ✓ |
| `cisco-securemail-benign` | wrapper-benign | `any-allow` | `ALLOW` | 18401 ms | ✓ |
| `gmail-link-redirect-benign` | wrapper-benign | `any-allow` | `ALLOW` | 6674 ms | ✓ |
| `proofpoint-v2-benign` | wrapper-benign | `any-allow` | `ALLOW` | 18009 ms | ✓ |
| `proofpoint-v3-format-benign` | wrapper-benign | `any-allow` | `ALLOW` | 24636 ms | ✓ |
| `safelinks-benign` | wrapper-benign | `any-allow` | `ALLOW` | 11740 ms | ✓ |
| `safelinks-multi-region-india` | wrapper-benign | `any-allow` | `ERR: exception: timed out` | 30029 ms | ✗ |
| `safelinks-multi-region-jp` | wrapper-benign | `any-allow` | `ERR: exception: timed out` | 30031 ms | ✗ |
| `symantec-clicktime-benign` | wrapper-benign | `any-allow` | `ERR: exception: timed out` | 30029 ms | ✗ |
| `cisco-pointing-to-homoglyph` | wrapper-phish | `any-deny` | `BLOCK` | 2318 ms | ✓ |
| `mimecast-pointing-at-fresh-host` | wrapper-phish | `any-deny` | `ISOLATE` | 801 ms | ✓ |
| `proofpoint-pointing-to-fresh-host` | wrapper-phish | `any-deny` | `ISOLATE` | 2461 ms | ✓ |
| `safelinks-spoof-phish-target` | wrapper-phish | `any-deny` | `ISOLATE` | 864 ms | ✓ |
