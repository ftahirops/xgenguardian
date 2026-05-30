# Smoke corpus report

- API base: `http://127.0.0.1:18080`
- Cases: **196**
- Pass: **182**  /  Fail: **14**  /  Rate: **92.9%**
- Wall-clock: 434.5 s

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
| legit-major | 12 | 0 | 12 | 100% |
| legit-payment | 1 | 0 | 1 | 100% |
| legit-saas | 6 | 0 | 6 | 100% |
| legit-sensitive | 1 | 2 | 3 | 33% |
| legit-tracker | 1 | 0 | 1 | 100% |
| malformed | 4 | 0 | 4 | 100% |
| mfa-bombing | 2 | 0 | 2 | 100% |
| oauth-legit | 4 | 0 | 4 | 100% |
| oauth-phish | 4 | 0 | 4 | 100% |
| payment-scam | 10 | 0 | 10 | 100% |
| piracy-tld | 4 | 2 | 6 | 67% |
| punycode | 1 | 0 | 1 | 100% |
| raw-ip | 3 | 1 | 4 | 75% |
| sensitive-unknown | 2 | 0 | 2 | 100% |
| session-hijack | 2 | 0 | 2 | 100% |
| shared-host | 2 | 4 | 6 | 33% |
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
| `piracy-tld-to` | `any` | `ERR: exception: timed out` | — |
| `piracy-tld-cc` | `any` | `ERR: exception: timed out` | — |
| `tld-click` | `any` | `ERR: exception: timed out` | — |
| `vercel-tenant` | `any` | `ERR: exception: timed out` | — |
| `netlify-tenant` | `any` | `ERR: exception: timed out` | — |
| `github-io-tenant` | `any` | `ERR: exception: timed out` | — |
| `proofpoint-v3-format-benign` | `any-allow` | `ERR: exception: timed out` | — |
| `symantec-clicktime-benign` | `any-allow` | `ERR: exception: timed out` | — |
| `cisco-securemail-benign` | `any-allow` | `ERR: exception: timed out` | — |
| `gmail-inbox` | `any-allow` | `ERR: exception: timed out` | — |
| `github-settings` | `any-allow` | `ERR: exception: timed out` | — |
| `cctld-ml` | `any` | `ERR: exception: timed out` | — |
| `shared-host-wordpress` | `any-allow` | `ERR: exception: timed out` | — |
| `raw-ip-cn-vps` | `block` | `ERR: exception: timed out` | — |

## Detailed per-case results

| Case | Category | Expected | Actual | Latency | Pass |
| --- | --- | --- | --- | ---: | :---: |
| `benign-news-irs-tax` | benign-trigger | `any-allow` | `ALLOW` | 928 ms | ✓ |
| `benign-wikipedia-gift-card` | benign-trigger | `any-allow` | `ALLOW` | 955 ms | ✓ |
| `benign-wikipedia-phishing` | benign-trigger | `any-allow` | `ALLOW` | 638 ms | ✓ |
| `drainer-arbitrum-mint` | crypto-drainer | `any-deny` | `WARN` | 902 ms | ✓ |
| `drainer-blur-airdrop` | crypto-drainer | `any-deny` | `WARN` | 1476 ms | ✓ |
| `drainer-fake-claim-airdrop` | crypto-drainer | `any-deny` | `BLOCK` | 1312 ms | ✓ |
| `drainer-fake-opensea` | crypto-drainer | `any-deny` | `WARN` | 1564 ms | ✓ |
| `drainer-fake-revoke` | crypto-drainer | `any-deny` | `ISOLATE` | 1354 ms | ✓ |
| `drainer-metamask-update` | crypto-drainer | `any-deny` | `ISOLATE` | 1411 ms | ✓ |
| `drainer-pancakeswap-airdrop` | crypto-drainer | `any-deny` | `BLOCK` | 1172 ms | ✓ |
| `drainer-phantom-wallet` | crypto-drainer | `any-deny` | `ISOLATE` | 1384 ms | ✓ |
| `drainer-revoke-cash-spoof` | crypto-drainer | `any-deny` | `ISOLATE` | 995 ms | ✓ |
| `drainer-trustwallet` | crypto-drainer | `any-deny` | `ISOLATE` | 1311 ms | ✓ |
| `drainer-uniswap-claim` | crypto-drainer | `any-deny` | `WARN` | 1424 ms | ✓ |
| `drainer-wallet-validate` | crypto-drainer | `any-deny` | `ISOLATE` | 1248 ms | ✓ |
| `direct-download-exe` | direct-download | `any-deny` | `ISOLATE` | 8042 ms | ✓ |
| `direct-download-jar` | direct-download | `any-deny` | `ISOLATE` | 1535 ms | ✓ |
| `direct-download-msi` | direct-download | `any-deny` | `ISOLATE` | 1895 ms | ✓ |
| `edge-case-non-standard-tld` | edge-case | `any-allow` | `ALLOW` | 876 ms | ✓ |
| `edge-case-numeric-domain` | edge-case | `any` | `ALLOW` | 762 ms | ✓ |
| `edge-case-very-long-url` | edge-case | `any-allow` | `ALLOW` | 702 ms | ✓ |
| `fqdn-trailing-dot` | edge-case | `any-allow` | `ALLOW` | 685 ms | ✓ |
| `hash-fragment-only` | edge-case | `any-allow` | `ALLOW` | 721 ms | ✓ |
| `nonstandard-port` | edge-case | `any-allow` | `ALLOW` | 677 ms | ✓ |
| `fake-bank-barclays` | fake-banking | `any-deny` | `ISOLATE` | 1302 ms | ✓ |
| `fake-bank-deutsche` | fake-banking | `any-deny` | `ISOLATE` | 1168 ms | ✓ |
| `fake-bank-hsbc` | fake-banking | `any-deny` | `ISOLATE` | 1515 ms | ✓ |
| `fake-bank-natwest` | fake-banking | `any-deny` | `ISOLATE` | 1090 ms | ✓ |
| `fake-bank-rbc` | fake-banking | `any-deny` | `ISOLATE` | 1083 ms | ✓ |
| `fake-bank-santander` | fake-banking | `any-deny` | `ISOLATE` | 1042 ms | ✓ |
| `fake-boa-mobile` | fake-banking | `any-deny` | `ISOLATE` | 1175 ms | ✓ |
| `fake-chase-login` | fake-banking | `any-deny` | `ISOLATE` | 1216 ms | ✓ |
| `fake-citibank-secure` | fake-banking | `any-deny` | `ISOLATE` | 1321 ms | ✓ |
| `fake-wellsfargo-update` | fake-banking | `any-deny` | `ISOLATE` | 945 ms | ✓ |
| `fake-google-accounts-host` | fake-oauth-host | `any-deny` | `ISOLATE` | 1092 ms | ✓ |
| `fake-microsoft-oauth-host` | fake-oauth-host | `any-deny` | `ISOLATE` | 1337 ms | ✓ |
| `fresh-payment-new-bank-login` | fresh-payment | `any-deny` | `ISOLATE` | 1340 ms | ✓ |
| `fresh-payment-wallet-connect` | fresh-payment | `any-deny` | `ISOLATE` | 1321 ms | ✓ |
| `payment-fresh-cart` | fresh-payment | `any-deny` | `ISOLATE` | 2862 ms | ✓ |
| `payment-fresh-checkout` | fresh-payment | `any-deny` | `ISOLATE` | 2824 ms | ✓ |
| `http-fresh-domain` | http-only | `any` | `ALLOW` | 832 ms | ✓ |
| `http-only-major` | http-only | `any-allow` | `ALLOW` | 667 ms | ✓ |
| `idn-amazon-cyrillic-a` | idn-homoglyph | `any-deny` | `WARN` | 1735 ms | ✓ |
| `idn-apple-cyrillic-p` | idn-homoglyph | `any-deny` | `BLOCK` | 1037 ms | ✓ |
| `idn-github-cyrillic-h` | idn-homoglyph | `any-deny` | `BLOCK` | 1599 ms | ✓ |
| `idn-google-cyrillic-o` | idn-homoglyph | `any-deny` | `WARN` | 2176 ms | ✓ |
| `idn-microsoft-cyrillic-o` | idn-homoglyph | `any-deny` | `WARN` | 1373 ms | ✓ |
| `idn-paypal-cyrillic-a` | idn-homoglyph | `any-deny` | `BLOCK` | 1110 ms | ✓ |
| `dev-install-fake-docker` | install-lure | `any-deny` | `ISOLATE` | 1564 ms | ✓ |
| `dev-install-fake-go` | install-lure | `any-deny` | `ISOLATE` | 1545 ms | ✓ |
| `dev-install-fake-rust` | install-lure | `any-deny` | `ISOLATE` | 1433 ms | ✓ |
| `dev-install-fake-terraform` | install-lure | `any-deny` | `ISOLATE` | 1584 ms | ✓ |
| `fake-anthropic-install` | install-lure | `any-deny` | `ISOLATE` | 1488 ms | ✓ |
| `fake-nodejs-install` | install-lure | `any-deny` | `ISOLATE` | 1443 ms | ✓ |
| `bank-real-chase` | legit-banking | `any-allow` | `ALLOW` | 971 ms | ✓ |
| `bank-real-citi` | legit-banking | `any-allow` | `ALLOW` | 926 ms | ✓ |
| `bank-real-deutsche` | legit-banking | `any-allow` | `ALLOW` | 960 ms | ✓ |
| `bank-real-hsbc` | legit-banking | `any-allow` | `ALLOW` | 993 ms | ✓ |
| `bank-real-rbc` | legit-banking | `any-allow` | `ALLOW` | 923 ms | ✓ |
| `bank-real-wellsfargo` | legit-banking | `any-allow` | `ALLOW` | 917 ms | ✓ |
| `cloudflare-cdn-script` | legit-cdn | `any-allow` | `ALLOW` | 631 ms | ✓ |
| `google-fonts` | legit-cdn | `any-allow` | `ALLOW` | 706 ms | ✓ |
| `jsdelivr` | legit-cdn | `any-allow` | `ALLOW` | 732 ms | ✓ |
| `legit-cdn-jquery` | legit-cdn | `any-allow` | `ALLOW` | 686 ms | ✓ |
| `unpkg` | legit-cdn | `any-allow` | `ALLOW` | 661 ms | ✓ |
| `bbc-news` | legit-content | `any-allow` | `ALLOW` | 954 ms | ✓ |
| `legit-content-medium` | legit-content | `any-allow` | `ALLOW` | 612 ms | ✓ |
| `legit-content-news-nytimes` | legit-content | `any-allow` | `ALLOW` | 830 ms | ✓ |
| `legit-content-reddit` | legit-content | `any-allow` | `ALLOW` | 691 ms | ✓ |
| `legit-content-substack` | legit-content | `any-allow` | `ALLOW` | 599 ms | ✓ |
| `mozilla-developer` | legit-content | `any-allow` | `ALLOW` | 707 ms | ✓ |
| `stackoverflow` | legit-content | `any-allow` | `ALLOW` | 713 ms | ✓ |
| `wikipedia` | legit-content | `any-allow` | `ALLOW` | 739 ms | ✓ |
| `claude-quickstart` | legit-dev | `any-allow` | `ALLOW` | 639 ms | ✓ |
| `legit-go-pkg` | legit-dev | `any-allow` | `ALLOW` | 809 ms | ✓ |
| `legit-python-docs` | legit-dev | `any-allow` | `ALLOW` | 940 ms | ✓ |
| `legit-rust-docs` | legit-dev | `any-allow` | `ALLOW` | 797 ms | ✓ |
| `rustup` | legit-dev | `any-allow` | `ALLOW` | 774 ms | ✓ |
| `apple-id-host` | legit-major | `any-allow` | `ALLOW` | 831 ms | ✓ |
| `cloudflare-corporate` | legit-major | `any-allow` | `ALLOW` | 503 ms | ✓ |
| `github` | legit-major | `any-allow` | `ALLOW` | 55786 ms | ✓ |
| `google-homepage` | legit-major | `any-allow` | `ALLOW` | 970 ms | ✓ |
| `legit-anthropic` | legit-major | `any-allow` | `ALLOW` | 791 ms | ✓ |
| `legit-aws-docs` | legit-major | `any-allow` | `ALLOW` | 965 ms | ✓ |
| `legit-microsoft-learn` | legit-major | `any-allow` | `ALLOW` | 893 ms | ✓ |
| `legit-openai` | legit-major | `any-allow` | `ALLOW` | 708 ms | ✓ |
| `legit-vercel` | legit-major | `any-allow` | `ALLOW` | 684 ms | ✓ |
| `microsoft-login` | legit-major | `any-allow` | `ALLOW` | 607 ms | ✓ |
| `paypal-homepage` | legit-major | `any-allow` | `ALLOW` | 879 ms | ✓ |
| `stripe-checkout-host` | legit-major | `any-allow` | `ALLOW` | 767 ms | ✓ |
| `payment-real-stripe-docs` | legit-payment | `any-allow` | `ALLOW` | 588 ms | ✓ |
| `legit-saas-airtable` | legit-saas | `any-allow` | `ALLOW` | 821 ms | ✓ |
| `legit-saas-canva` | legit-saas | `any-allow` | `ALLOW` | 821 ms | ✓ |
| `legit-saas-figma` | legit-saas | `any-allow` | `ALLOW` | 606 ms | ✓ |
| `legit-saas-linear` | legit-saas | `any-allow` | `ALLOW` | 696 ms | ✓ |
| `notion` | legit-saas | `any-allow` | `ALLOW` | 684 ms | ✓ |
| `slack-app` | legit-saas | `any-allow` | `ALLOW` | 991 ms | ✓ |
| `aws-console` | legit-sensitive | `any-allow` | `ALLOW` | 930 ms | ✓ |
| `github-settings` | legit-sensitive | `any-allow` | `ERR: exception: timed out` | 60059 ms | ✗ |
| `gmail-inbox` | legit-sensitive | `any-allow` | `ERR: exception: timed out` | 60060 ms | ✗ |
| `benign-pixel-fb` | legit-tracker | `any-allow` | `ALLOW` | 762 ms | ✓ |
| `corrupt-protocol` | malformed | `any` | `ALLOW` | 740 ms | ✓ |
| `corrupt-spaces` | malformed | `any` | `ALLOW` | 670 ms | ✓ |
| `data-scheme` | malformed | `any` | `CLEAN` | 166 ms | ✓ |
| `javascript-scheme` | malformed | `any` | `CLEAN` | 178 ms | ✓ |
| `mfa-fake-duo` | mfa-bombing | `any-deny` | `ISOLATE` | 1130 ms | ✓ |
| `mfa-fake-okta-push` | mfa-bombing | `any-deny` | `ISOLATE` | 1821 ms | ✓ |
| `oauth-known-good-github-cli` | oauth-legit | `any-allow` | `ALLOW` | 38156 ms | ✓ |
| `oauth-known-good-vscode` | oauth-legit | `any-allow` | `ALLOW` | 42420 ms | ✓ |
| `oauth-legit-azure-cli` | oauth-legit | `any-allow` | `ALLOW` | 608 ms | ✓ |
| `oauth-legit-github-mobile` | oauth-legit | `any-allow` | `ALLOW` | 46072 ms | ✓ |
| `oauth-google-unknown-client-drive-scope` | oauth-phish | `any-deny` | `BLOCK` | 523 ms | ✓ |
| `oauth-microsoft-unknown-client-high-scope` | oauth-phish | `any-deny` | `BLOCK` | 607 ms | ✓ |
| `oauth-phish-pretend-gcloud` | oauth-phish | `any-deny` | `BLOCK` | 465 ms | ✓ |
| `oauth-phish-pretend-vscode` | oauth-phish | `any-deny` | `BLOCK` | 47187 ms | ✓ |
| `gift-card-scam-1` | payment-scam | `any-deny` | `ISOLATE` | 1252 ms | ✓ |
| `payment-scam-customs-fee` | payment-scam | `any-deny` | `WARN` | 1569 ms | ✓ |
| `payment-scam-fake-paypal-invoice` | payment-scam | `any-deny` | `BLOCK` | 1234 ms | ✓ |
| `payment-scam-geek-squad-invoice` | payment-scam | `any-deny` | `WARN` | 825 ms | ✓ |
| `payment-scam-inheritance` | payment-scam | `any-deny` | `WARN` | 938 ms | ✓ |
| `payment-scam-lottery` | payment-scam | `any-deny` | `WARN` | 912 ms | ✓ |
| `payment-scam-medicare-refund` | payment-scam | `any-deny` | `WARN` | 699 ms | ✓ |
| `payment-scam-ssn-suspended` | payment-scam | `any-deny` | `WARN` | 873 ms | ✓ |
| `payment-scam-tax-refund-uk` | payment-scam | `any-deny` | `WARN` | 1281 ms | ✓ |
| `wire-fraud-irs` | payment-scam | `any-deny` | `WARN` | 896 ms | ✓ |
| `piracy-multiple-1` | piracy-tld | `any` | `ALLOW` | 1433 ms | ✓ |
| `piracy-multiple-2` | piracy-tld | `any` | `ALLOW` | 11718 ms | ✓ |
| `piracy-tld-cc` | piracy-tld | `any` | `ERR: exception: timed out` | 60060 ms | ✗ |
| `piracy-tld-pw` | piracy-tld | `any` | `ALLOW` | 2699 ms | ✓ |
| `piracy-tld-to` | piracy-tld | `any` | `ERR: exception: timed out` | 60059 ms | ✗ |
| `piracy-tld-ws` | piracy-tld | `any` | `ALLOW` | 8764 ms | ✓ |
| `punycode-google` | punycode | `any` | `WARN` | 890 ms | ✓ |
| `raw-ip-bare` | raw-ip | `any-deny` | `BLOCK` | 12072 ms | ✓ |
| `raw-ip-binary-drop` | raw-ip | `block` | `BLOCK` | 11317 ms | ✓ |
| `raw-ip-cn-vps` | raw-ip | `block` | `ERR: exception: timed out` | 60060 ms | ✗ |
| `raw-ip-private-cgnat` | raw-ip | `any` | `BLOCK` | 11363 ms | ✓ |
| `login-on-fresh-unknown` | sensitive-unknown | `any-deny` | `ISOLATE` | 18662 ms | ✓ |
| `payment-checkout-unknown` | sensitive-unknown | `any-deny` | `ISOLATE` | 19182 ms | ✓ |
| `session-hijack-fake-signin` | session-hijack | `any-deny` | `ISOLATE` | 1208 ms | ✓ |
| `session-hijack-fake-token` | session-hijack | `any-deny` | `ISOLATE` | 8074 ms | ✓ |
| `github-io-tenant` | shared-host | `any` | `ERR: exception: timed out` | 60059 ms | ✗ |
| `netlify-tenant` | shared-host | `any` | `ERR: exception: timed out` | 60059 ms | ✗ |
| `shared-host-pages-dev` | shared-host | `any` | `ALLOW` | 1696 ms | ✓ |
| `shared-host-wordpress` | shared-host | `any-allow` | `ERR: exception: timed out` | 60059 ms | ✗ |
| `shared-host-workers-dev` | shared-host | `any` | `ALLOW` | 1676 ms | ✓ |
| `vercel-tenant` | shared-host | `any` | `ERR: exception: timed out` | 60060 ms | ✗ |
| `bitly-home` | shortener | `any-allow` | `ALLOW` | 713 ms | ✓ |
| `shortener-bitly-corrupt` | shortener | `any` | `ALLOW` | 650 ms | ✓ |
| `tco-home` | shortener | `any-allow` | `ALLOW` | 699 ms | ✓ |
| `spoof-mimecast-host` | spoof-wrapper | `any-allow` | `ALLOW` | 736 ms | ✓ |
| `spoof-safelinks-host` | spoof-wrapper | `any-allow` | `ALLOW` | 807 ms | ✓ |
| `subdomain-spoof-google-accounts` | subdomain-spoof | `any-deny` | `ISOLATE` | 2094 ms | ✓ |
| `subdomain-spoof-microsoft-login` | subdomain-spoof | `any-deny` | `ISOLATE` | 1308 ms | ✓ |
| `subdomain-spoof-paypal` | subdomain-spoof | `any-deny` | `ISOLATE` | 2158 ms | ✓ |
| `scam-amazon-support` | support-scam | `any-deny` | `WARN` | 1468 ms | ✓ |
| `scam-google-virus-warning` | support-scam | `any-deny` | `WARN` | 1303 ms | ✓ |
| `scam-icloud-locked` | support-scam | `any-deny` | `ISOLATE` | 953 ms | ✓ |
| `scam-mcafee-renewal` | support-scam | `any-deny` | `WARN` | 925 ms | ✓ |
| `scam-norton-support` | support-scam | `any-deny` | `WARN` | 862 ms | ✓ |
| `scam-windows-error` | support-scam | `any-deny` | `WARN` | 867 ms | ✓ |
| `support-scam-apple-virus-alert` | support-scam | `any-deny` | `WARN` | 1736 ms | ✓ |
| `support-scam-microsoft-helpline` | support-scam | `any-deny` | `WARN` | 1752 ms | ✓ |
| `support-scam-windows-defender` | support-scam | `any-deny` | `WARN` | 696 ms | ✓ |
| `cctld-cf` | sus-tld | `any` | `ALLOW` | 1763 ms | ✓ |
| `cctld-ga` | sus-tld | `any` | `ALLOW` | 2095 ms | ✓ |
| `cctld-ml` | sus-tld | `any` | `ERR: exception: timed out` | 60071 ms | ✗ |
| `tld-click` | sus-tld | `any` | `ERR: exception: timed out` | 60059 ms | ✗ |
| `tld-tk` | sus-tld | `any` | `ALLOW` | 2181 ms | ✓ |
| `tld-xyz` | sus-tld | `any` | `ALLOW` | 1634 ms | ✓ |
| `brand-impersonation-google` | synth-phish | `any-deny` | `ISOLATE` | 1510 ms | ✓ |
| `brand-impersonation-microsoft` | synth-phish | `any-deny` | `ISOLATE` | 1371 ms | ✓ |
| `brand-impersonation-paypal` | synth-phish | `any-deny` | `ISOLATE` | 1383 ms | ✓ |
| `homoglyph-google` | synth-phish | `any-deny` | `WARN` | 1591 ms | ✓ |
| `random-host-login` | synth-phish | `any-deny` | `ISOLATE` | 1227 ms | ✓ |
| `combosquat-paypal-account` | typosquat | `any-deny` | `ISOLATE` | 1294 ms | ✓ |
| `homoglyph-amazon-zero-for-o` | typosquat | `any-deny` | `BLOCK` | 1217 ms | ✓ |
| `homoglyph-microsoft-rn-for-m` | typosquat | `any-deny` | `BLOCK` | 1698 ms | ✓ |
| `homoglyph-paypal-1-for-l` | typosquat | `any-deny` | `BLOCK` | 1221 ms | ✓ |
| `typo-amazon-shuffle` | typosquat | `any-deny` | `BLOCK` | 1374 ms | ✓ |
| `typo-google-h` | typosquat | `any-deny` | `WARN` | 1517 ms | ✓ |
| `typo-google-letter-swap` | typosquat | `any-deny` | `WARN` | 1790 ms | ✓ |
| `typo-microsoft-omission` | typosquat | `any-deny` | `BLOCK` | 1216 ms | ✓ |
| `typo-paypal-double` | typosquat | `any-deny` | `BLOCK` | 1261 ms | ✓ |
| `barracuda-benign` | wrapper-benign | `any-allow` | `ALLOW` | 50751 ms | ✓ |
| `cisco-securemail-benign` | wrapper-benign | `any-allow` | `ERR: exception: timed out` | 60061 ms | ✗ |
| `gmail-link-redirect-benign` | wrapper-benign | `any-allow` | `ALLOW` | 55715 ms | ✓ |
| `proofpoint-v2-benign` | wrapper-benign | `any-allow` | `ALLOW` | 20519 ms | ✓ |
| `proofpoint-v3-format-benign` | wrapper-benign | `any-allow` | `ERR: exception: timed out` | 60059 ms | ✗ |
| `safelinks-benign` | wrapper-benign | `any-allow` | `ALLOW` | 56148 ms | ✓ |
| `safelinks-multi-region-india` | wrapper-benign | `any-allow` | `ALLOW` | 37497 ms | ✓ |
| `safelinks-multi-region-jp` | wrapper-benign | `any-allow` | `ALLOW` | 37532 ms | ✓ |
| `symantec-clicktime-benign` | wrapper-benign | `any-allow` | `ERR: exception: timed out` | 60060 ms | ✗ |
| `cisco-pointing-to-homoglyph` | wrapper-phish | `any-deny` | `BLOCK` | 1733 ms | ✓ |
| `mimecast-pointing-at-fresh-host` | wrapper-phish | `any-deny` | `ISOLATE` | 21642 ms | ✓ |
| `proofpoint-pointing-to-fresh-host` | wrapper-phish | `any-deny` | `ISOLATE` | 1923 ms | ✓ |
| `safelinks-spoof-phish-target` | wrapper-phish | `any-deny` | `ISOLATE` | 20334 ms | ✓ |
