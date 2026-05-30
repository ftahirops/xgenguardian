# Smoke corpus report

- API base: `http://127.0.0.1:18080`
- Cases: **196**
- Pass: **189**  /  Fail: **7**  /  Rate: **96.4%**
- Wall-clock: 116.1 s

## Per-category breakdown

| Category | Pass | Fail | Total | Rate |
| --- | ---: | ---: | ---: | ---: |
| benign-trigger | 3 | 0 | 3 | 100% |
| crypto-drainer | 11 | 1 | 12 | 92% |
| direct-download | 2 | 1 | 3 | 67% |
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
| legit-sensitive | 3 | 0 | 3 | 100% |
| legit-tracker | 1 | 0 | 1 | 100% |
| malformed | 4 | 0 | 4 | 100% |
| mfa-bombing | 2 | 0 | 2 | 100% |
| oauth-legit | 4 | 0 | 4 | 100% |
| oauth-phish | 3 | 1 | 4 | 75% |
| payment-scam | 7 | 3 | 10 | 70% |
| piracy-tld | 6 | 0 | 6 | 100% |
| punycode | 1 | 0 | 1 | 100% |
| raw-ip | 4 | 0 | 4 | 100% |
| sensitive-unknown | 2 | 0 | 2 | 100% |
| session-hijack | 2 | 0 | 2 | 100% |
| shared-host | 6 | 0 | 6 | 100% |
| shortener | 3 | 0 | 3 | 100% |
| spoof-wrapper | 2 | 0 | 2 | 100% |
| subdomain-spoof | 3 | 0 | 3 | 100% |
| support-scam | 8 | 1 | 9 | 89% |
| sus-tld | 6 | 0 | 6 | 100% |
| synth-phish | 5 | 0 | 5 | 100% |
| typosquat | 9 | 0 | 9 | 100% |
| wrapper-benign | 9 | 0 | 9 | 100% |
| wrapper-phish | 4 | 0 | 4 | 100% |

## Failing cases


| Case | Expected | Actual | Reason codes |
| --- | --- | --- | --- |
| `drainer-arbitrum-mint` | `any-deny` | `ALLOW` | — |
| `scam-mcafee-renewal` | `any-deny` | `ALLOW` | — |
| `payment-scam-inheritance` | `any-deny` | `ALLOW` | — |
| `payment-scam-ssn-suspended` | `any-deny` | `ALLOW` | — |
| `payment-scam-geek-squad-invoice` | `any-deny` | `ALLOW` | — |
| `direct-download-jar` | `any-deny` | `ALLOW` | TIER2_DATA_UNAVAILABLE |
| `oauth-phish-pretend-vscode` | `any-deny` | `ALLOW` | TIER2_DATA_UNAVAILABLE |

## Detailed per-case results

| Case | Category | Expected | Actual | Latency | Pass |
| --- | --- | --- | --- | ---: | :---: |
| `benign-news-irs-tax` | benign-trigger | `any-allow` | `ALLOW` | 901 ms | ✓ |
| `benign-wikipedia-gift-card` | benign-trigger | `any-allow` | `ALLOW` | 646 ms | ✓ |
| `benign-wikipedia-phishing` | benign-trigger | `any-allow` | `ALLOW` | 988 ms | ✓ |
| `drainer-arbitrum-mint` | crypto-drainer | `any-deny` | `ALLOW` | 907 ms | ✗ |
| `drainer-blur-airdrop` | crypto-drainer | `any-deny` | `WARN` | 1075 ms | ✓ |
| `drainer-fake-claim-airdrop` | crypto-drainer | `any-deny` | `BLOCK` | 642 ms | ✓ |
| `drainer-fake-opensea` | crypto-drainer | `any-deny` | `WARN` | 962 ms | ✓ |
| `drainer-fake-revoke` | crypto-drainer | `any-deny` | `ISOLATE` | 615 ms | ✓ |
| `drainer-metamask-update` | crypto-drainer | `any-deny` | `ISOLATE` | 711 ms | ✓ |
| `drainer-pancakeswap-airdrop` | crypto-drainer | `any-deny` | `BLOCK` | 746 ms | ✓ |
| `drainer-phantom-wallet` | crypto-drainer | `any-deny` | `ISOLATE` | 757 ms | ✓ |
| `drainer-revoke-cash-spoof` | crypto-drainer | `any-deny` | `ISOLATE` | 693 ms | ✓ |
| `drainer-trustwallet` | crypto-drainer | `any-deny` | `ISOLATE` | 736 ms | ✓ |
| `drainer-uniswap-claim` | crypto-drainer | `any-deny` | `WARN` | 871 ms | ✓ |
| `drainer-wallet-validate` | crypto-drainer | `any-deny` | `ISOLATE` | 829 ms | ✓ |
| `direct-download-exe` | direct-download | `any-deny` | `ISOLATE` | 853 ms | ✓ |
| `direct-download-jar` | direct-download | `any-deny` | `ALLOW` | 874 ms | ✗ |
| `direct-download-msi` | direct-download | `any-deny` | `ISOLATE` | 732 ms | ✓ |
| `edge-case-non-standard-tld` | edge-case | `any-allow` | `ALLOW` | 1079 ms | ✓ |
| `edge-case-numeric-domain` | edge-case | `any` | `ALLOW` | 829 ms | ✓ |
| `edge-case-very-long-url` | edge-case | `any-allow` | `ALLOW` | 679 ms | ✓ |
| `fqdn-trailing-dot` | edge-case | `any-allow` | `ALLOW` | 597 ms | ✓ |
| `hash-fragment-only` | edge-case | `any-allow` | `ALLOW` | 657 ms | ✓ |
| `nonstandard-port` | edge-case | `any-allow` | `ALLOW` | 801 ms | ✓ |
| `fake-bank-barclays` | fake-banking | `any-deny` | `ISOLATE` | 655 ms | ✓ |
| `fake-bank-deutsche` | fake-banking | `any-deny` | `ISOLATE` | 796 ms | ✓ |
| `fake-bank-hsbc` | fake-banking | `any-deny` | `ISOLATE` | 696 ms | ✓ |
| `fake-bank-natwest` | fake-banking | `any-deny` | `ISOLATE` | 660 ms | ✓ |
| `fake-bank-rbc` | fake-banking | `any-deny` | `ISOLATE` | 748 ms | ✓ |
| `fake-bank-santander` | fake-banking | `any-deny` | `ISOLATE` | 720 ms | ✓ |
| `fake-boa-mobile` | fake-banking | `any-deny` | `ISOLATE` | 721 ms | ✓ |
| `fake-chase-login` | fake-banking | `any-deny` | `ISOLATE` | 779 ms | ✓ |
| `fake-citibank-secure` | fake-banking | `any-deny` | `ISOLATE` | 705 ms | ✓ |
| `fake-wellsfargo-update` | fake-banking | `any-deny` | `ISOLATE` | 885 ms | ✓ |
| `fake-google-accounts-host` | fake-oauth-host | `any-deny` | `ISOLATE` | 653 ms | ✓ |
| `fake-microsoft-oauth-host` | fake-oauth-host | `any-deny` | `ISOLATE` | 613 ms | ✓ |
| `fresh-payment-new-bank-login` | fresh-payment | `any-deny` | `ISOLATE` | 681 ms | ✓ |
| `fresh-payment-wallet-connect` | fresh-payment | `any-deny` | `ISOLATE` | 685 ms | ✓ |
| `payment-fresh-cart` | fresh-payment | `any-deny` | `ISOLATE` | 680 ms | ✓ |
| `payment-fresh-checkout` | fresh-payment | `any-deny` | `ISOLATE` | 639 ms | ✓ |
| `http-fresh-domain` | http-only | `any` | `ALLOW` | 920 ms | ✓ |
| `http-only-major` | http-only | `any-allow` | `ALLOW` | 827 ms | ✓ |
| `idn-amazon-cyrillic-a` | idn-homoglyph | `any-deny` | `WARN` | 848 ms | ✓ |
| `idn-apple-cyrillic-p` | idn-homoglyph | `any-deny` | `BLOCK` | 660 ms | ✓ |
| `idn-github-cyrillic-h` | idn-homoglyph | `any-deny` | `BLOCK` | 722 ms | ✓ |
| `idn-google-cyrillic-o` | idn-homoglyph | `any-deny` | `WARN` | 999 ms | ✓ |
| `idn-microsoft-cyrillic-o` | idn-homoglyph | `any-deny` | `WARN` | 878 ms | ✓ |
| `idn-paypal-cyrillic-a` | idn-homoglyph | `any-deny` | `BLOCK` | 625 ms | ✓ |
| `dev-install-fake-docker` | install-lure | `any-deny` | `ISOLATE` | 942 ms | ✓ |
| `dev-install-fake-go` | install-lure | `any-deny` | `ISOLATE` | 994 ms | ✓ |
| `dev-install-fake-rust` | install-lure | `any-deny` | `ISOLATE` | 1003 ms | ✓ |
| `dev-install-fake-terraform` | install-lure | `any-deny` | `ISOLATE` | 929 ms | ✓ |
| `fake-anthropic-install` | install-lure | `any-deny` | `ISOLATE` | 876 ms | ✓ |
| `fake-nodejs-install` | install-lure | `any-deny` | `ISOLATE` | 849 ms | ✓ |
| `bank-real-chase` | legit-banking | `any-allow` | `ALLOW` | 911 ms | ✓ |
| `bank-real-citi` | legit-banking | `any-allow` | `ALLOW` | 833 ms | ✓ |
| `bank-real-deutsche` | legit-banking | `any-allow` | `ALLOW` | 883 ms | ✓ |
| `bank-real-hsbc` | legit-banking | `any-allow` | `ALLOW` | 1003 ms | ✓ |
| `bank-real-rbc` | legit-banking | `any-allow` | `ALLOW` | 1082 ms | ✓ |
| `bank-real-wellsfargo` | legit-banking | `any-allow` | `ALLOW` | 823 ms | ✓ |
| `cloudflare-cdn-script` | legit-cdn | `any-allow` | `ALLOW` | 625 ms | ✓ |
| `google-fonts` | legit-cdn | `any-allow` | `ALLOW` | 702 ms | ✓ |
| `jsdelivr` | legit-cdn | `any-allow` | `ALLOW` | 701 ms | ✓ |
| `legit-cdn-jquery` | legit-cdn | `any-allow` | `ALLOW` | 690 ms | ✓ |
| `unpkg` | legit-cdn | `any-allow` | `ALLOW` | 644 ms | ✓ |
| `bbc-news` | legit-content | `any-allow` | `ALLOW` | 878 ms | ✓ |
| `legit-content-medium` | legit-content | `any-allow` | `ALLOW` | 605 ms | ✓ |
| `legit-content-news-nytimes` | legit-content | `any-allow` | `ALLOW` | 906 ms | ✓ |
| `legit-content-reddit` | legit-content | `any-allow` | `ALLOW` | 818 ms | ✓ |
| `legit-content-substack` | legit-content | `any-allow` | `ALLOW` | 666 ms | ✓ |
| `mozilla-developer` | legit-content | `any-allow` | `ALLOW` | 842 ms | ✓ |
| `stackoverflow` | legit-content | `any-allow` | `ALLOW` | 701 ms | ✓ |
| `wikipedia` | legit-content | `any-allow` | `ALLOW` | 1014 ms | ✓ |
| `claude-quickstart` | legit-dev | `any-allow` | `ALLOW` | 737 ms | ✓ |
| `legit-go-pkg` | legit-dev | `any-allow` | `ALLOW` | 891 ms | ✓ |
| `legit-python-docs` | legit-dev | `any-allow` | `ALLOW` | 935 ms | ✓ |
| `legit-rust-docs` | legit-dev | `any-allow` | `ALLOW` | 1089 ms | ✓ |
| `rustup` | legit-dev | `any-allow` | `ALLOW` | 1086 ms | ✓ |
| `apple-id-host` | legit-major | `any-allow` | `ALLOW` | 854 ms | ✓ |
| `cloudflare-corporate` | legit-major | `any-allow` | `ALLOW` | 591 ms | ✓ |
| `github` | legit-major | `any-allow` | `ALLOW` | 22656 ms | ✓ |
| `google-homepage` | legit-major | `any-allow` | `ALLOW` | 769 ms | ✓ |
| `legit-anthropic` | legit-major | `any-allow` | `ALLOW` | 670 ms | ✓ |
| `legit-aws-docs` | legit-major | `any-allow` | `ALLOW` | 1037 ms | ✓ |
| `legit-microsoft-learn` | legit-major | `any-allow` | `ALLOW` | 896 ms | ✓ |
| `legit-openai` | legit-major | `any-allow` | `ALLOW` | 704 ms | ✓ |
| `legit-vercel` | legit-major | `any-allow` | `ALLOW` | 797 ms | ✓ |
| `microsoft-login` | legit-major | `any-allow` | `ALLOW` | 700 ms | ✓ |
| `paypal-homepage` | legit-major | `any-allow` | `ALLOW` | 918 ms | ✓ |
| `stripe-checkout-host` | legit-major | `any-allow` | `ALLOW` | 844 ms | ✓ |
| `payment-real-stripe-docs` | legit-payment | `any-allow` | `ALLOW` | 583 ms | ✓ |
| `legit-saas-airtable` | legit-saas | `any-allow` | `ALLOW` | 1009 ms | ✓ |
| `legit-saas-canva` | legit-saas | `any-allow` | `ALLOW` | 946 ms | ✓ |
| `legit-saas-figma` | legit-saas | `any-allow` | `ALLOW` | 727 ms | ✓ |
| `legit-saas-linear` | legit-saas | `any-allow` | `ALLOW` | 762 ms | ✓ |
| `notion` | legit-saas | `any-allow` | `ALLOW` | 639 ms | ✓ |
| `slack-app` | legit-saas | `any-allow` | `ALLOW` | 834 ms | ✓ |
| `aws-console` | legit-sensitive | `any-allow` | `ALLOW` | 1002 ms | ✓ |
| `github-settings` | legit-sensitive | `any-allow` | `ALLOW` | 17973 ms | ✓ |
| `gmail-inbox` | legit-sensitive | `any-allow` | `ALLOW` | 12874 ms | ✓ |
| `benign-pixel-fb` | legit-tracker | `any-allow` | `ALLOW` | 734 ms | ✓ |
| `corrupt-protocol` | malformed | `any` | `ALLOW` | 653 ms | ✓ |
| `corrupt-spaces` | malformed | `any` | `ALLOW` | 592 ms | ✓ |
| `data-scheme` | malformed | `any` | `CLEAN` | 146 ms | ✓ |
| `javascript-scheme` | malformed | `any` | `CLEAN` | 197 ms | ✓ |
| `mfa-fake-duo` | mfa-bombing | `any-deny` | `ISOLATE` | 809 ms | ✓ |
| `mfa-fake-okta-push` | mfa-bombing | `any-deny` | `ISOLATE` | 739 ms | ✓ |
| `oauth-known-good-github-cli` | oauth-legit | `any-allow` | `ALLOW` | 13198 ms | ✓ |
| `oauth-known-good-vscode` | oauth-legit | `any-allow` | `ALLOW` | 19506 ms | ✓ |
| `oauth-legit-azure-cli` | oauth-legit | `any-allow` | `ALLOW` | 769 ms | ✓ |
| `oauth-legit-github-mobile` | oauth-legit | `any-allow` | `ALLOW` | 23367 ms | ✓ |
| `oauth-google-unknown-client-drive-scope` | oauth-phish | `any-deny` | `BLOCK` | 520 ms | ✓ |
| `oauth-microsoft-unknown-client-high-scope` | oauth-phish | `any-deny` | `BLOCK` | 592 ms | ✓ |
| `oauth-phish-pretend-gcloud` | oauth-phish | `any-deny` | `BLOCK` | 489 ms | ✓ |
| `oauth-phish-pretend-vscode` | oauth-phish | `any-deny` | `ALLOW` | 14782 ms | ✗ |
| `gift-card-scam-1` | payment-scam | `any-deny` | `ISOLATE` | 690 ms | ✓ |
| `payment-scam-customs-fee` | payment-scam | `any-deny` | `WARN` | 932 ms | ✓ |
| `payment-scam-fake-paypal-invoice` | payment-scam | `any-deny` | `ISOLATE` | 809 ms | ✓ |
| `payment-scam-geek-squad-invoice` | payment-scam | `any-deny` | `ALLOW` | 804 ms | ✗ |
| `payment-scam-inheritance` | payment-scam | `any-deny` | `ALLOW` | 894 ms | ✗ |
| `payment-scam-lottery` | payment-scam | `any-deny` | `WARN` | 930 ms | ✓ |
| `payment-scam-medicare-refund` | payment-scam | `any-deny` | `WARN` | 980 ms | ✓ |
| `payment-scam-ssn-suspended` | payment-scam | `any-deny` | `ALLOW` | 890 ms | ✗ |
| `payment-scam-tax-refund-uk` | payment-scam | `any-deny` | `WARN` | 868 ms | ✓ |
| `wire-fraud-irs` | payment-scam | `any-deny` | `WARN` | 886 ms | ✓ |
| `piracy-multiple-1` | piracy-tld | `any` | `ALLOW` | 1162 ms | ✓ |
| `piracy-multiple-2` | piracy-tld | `any` | `ALLOW` | 10897 ms | ✓ |
| `piracy-tld-cc` | piracy-tld | `any` | `ALLOW` | 24290 ms | ✓ |
| `piracy-tld-pw` | piracy-tld | `any` | `ALLOW` | 1343 ms | ✓ |
| `piracy-tld-to` | piracy-tld | `any` | `ALLOW` | 19260 ms | ✓ |
| `piracy-tld-ws` | piracy-tld | `any` | `ALLOW` | 1146 ms | ✓ |
| `punycode-google` | punycode | `any` | `WARN` | 874 ms | ✓ |
| `raw-ip-bare` | raw-ip | `any-deny` | `BLOCK` | 11001 ms | ✓ |
| `raw-ip-binary-drop` | raw-ip | `block` | `BLOCK` | 10905 ms | ✓ |
| `raw-ip-cn-vps` | raw-ip | `block` | `BLOCK` | 19292 ms | ✓ |
| `raw-ip-private-cgnat` | raw-ip | `any` | `BLOCK` | 11058 ms | ✓ |
| `login-on-fresh-unknown` | sensitive-unknown | `any-deny` | `ISOLATE` | 642 ms | ✓ |
| `payment-checkout-unknown` | sensitive-unknown | `any-deny` | `ISOLATE` | 676 ms | ✓ |
| `session-hijack-fake-signin` | session-hijack | `any-deny` | `ISOLATE` | 873 ms | ✓ |
| `session-hijack-fake-token` | session-hijack | `any-deny` | `ISOLATE` | 738 ms | ✓ |
| `github-io-tenant` | shared-host | `any` | `ALLOW` | 18255 ms | ✓ |
| `netlify-tenant` | shared-host | `any` | `ALLOW` | 19677 ms | ✓ |
| `shared-host-pages-dev` | shared-host | `any` | `ALLOW` | 1008 ms | ✓ |
| `shared-host-wordpress` | shared-host | `any-allow` | `ALLOW` | 14478 ms | ✓ |
| `shared-host-workers-dev` | shared-host | `any` | `ALLOW` | 1076 ms | ✓ |
| `vercel-tenant` | shared-host | `any` | `ALLOW` | 22707 ms | ✓ |
| `bitly-home` | shortener | `any-allow` | `ALLOW` | 752 ms | ✓ |
| `shortener-bitly-corrupt` | shortener | `any` | `ALLOW` | 1345 ms | ✓ |
| `tco-home` | shortener | `any-allow` | `ALLOW` | 807 ms | ✓ |
| `spoof-mimecast-host` | spoof-wrapper | `any-allow` | `ALLOW` | 829 ms | ✓ |
| `spoof-safelinks-host` | spoof-wrapper | `any-allow` | `ALLOW` | 853 ms | ✓ |
| `subdomain-spoof-google-accounts` | subdomain-spoof | `any-deny` | `ISOLATE` | 967 ms | ✓ |
| `subdomain-spoof-microsoft-login` | subdomain-spoof | `any-deny` | `ISOLATE` | 891 ms | ✓ |
| `subdomain-spoof-paypal` | subdomain-spoof | `any-deny` | `ISOLATE` | 958 ms | ✓ |
| `scam-amazon-support` | support-scam | `any-deny` | `WARN` | 956 ms | ✓ |
| `scam-google-virus-warning` | support-scam | `any-deny` | `WARN` | 955 ms | ✓ |
| `scam-icloud-locked` | support-scam | `any-deny` | `ISOLATE` | 751 ms | ✓ |
| `scam-mcafee-renewal` | support-scam | `any-deny` | `ALLOW` | 917 ms | ✗ |
| `scam-norton-support` | support-scam | `any-deny` | `WARN` | 880 ms | ✓ |
| `scam-windows-error` | support-scam | `any-deny` | `WARN` | 883 ms | ✓ |
| `support-scam-apple-virus-alert` | support-scam | `any-deny` | `WARN` | 885 ms | ✓ |
| `support-scam-microsoft-helpline` | support-scam | `any-deny` | `WARN` | 856 ms | ✓ |
| `support-scam-windows-defender` | support-scam | `any-deny` | `WARN` | 892 ms | ✓ |
| `cctld-cf` | sus-tld | `any` | `ALLOW` | 972 ms | ✓ |
| `cctld-ga` | sus-tld | `any` | `ALLOW` | 1024 ms | ✓ |
| `cctld-ml` | sus-tld | `any` | `ALLOW` | 17491 ms | ✓ |
| `tld-click` | sus-tld | `any` | `ALLOW` | 24702 ms | ✓ |
| `tld-tk` | sus-tld | `any` | `ALLOW` | 1050 ms | ✓ |
| `tld-xyz` | sus-tld | `any` | `ALLOW` | 941 ms | ✓ |
| `brand-impersonation-google` | synth-phish | `any-deny` | `ISOLATE` | 929 ms | ✓ |
| `brand-impersonation-microsoft` | synth-phish | `any-deny` | `ISOLATE` | 675 ms | ✓ |
| `brand-impersonation-paypal` | synth-phish | `any-deny` | `ISOLATE` | 814 ms | ✓ |
| `homoglyph-google` | synth-phish | `any-deny` | `WARN` | 1151 ms | ✓ |
| `random-host-login` | synth-phish | `any-deny` | `ISOLATE` | 898 ms | ✓ |
| `combosquat-paypal-account` | typosquat | `any-deny` | `ISOLATE` | 772 ms | ✓ |
| `homoglyph-amazon-zero-for-o` | typosquat | `any-deny` | `BLOCK` | 751 ms | ✓ |
| `homoglyph-microsoft-rn-for-m` | typosquat | `any-deny` | `BLOCK` | 754 ms | ✓ |
| `homoglyph-paypal-1-for-l` | typosquat | `any-deny` | `BLOCK` | 696 ms | ✓ |
| `typo-amazon-shuffle` | typosquat | `any-deny` | `BLOCK` | 728 ms | ✓ |
| `typo-google-h` | typosquat | `any-deny` | `WARN` | 953 ms | ✓ |
| `typo-google-letter-swap` | typosquat | `any-deny` | `WARN` | 886 ms | ✓ |
| `typo-microsoft-omission` | typosquat | `any-deny` | `BLOCK` | 729 ms | ✓ |
| `typo-paypal-double` | typosquat | `any-deny` | `BLOCK` | 680 ms | ✓ |
| `barracuda-benign` | wrapper-benign | `any-allow` | `ALLOW` | 13588 ms | ✓ |
| `cisco-securemail-benign` | wrapper-benign | `any-allow` | `ALLOW` | 6406 ms | ✓ |
| `gmail-link-redirect-benign` | wrapper-benign | `any-allow` | `ALLOW` | 12564 ms | ✓ |
| `proofpoint-v2-benign` | wrapper-benign | `any-allow` | `ALLOW` | 15594 ms | ✓ |
| `proofpoint-v3-format-benign` | wrapper-benign | `any-allow` | `ALLOW` | 18596 ms | ✓ |
| `safelinks-benign` | wrapper-benign | `any-allow` | `ALLOW` | 17256 ms | ✓ |
| `safelinks-multi-region-india` | wrapper-benign | `any-allow` | `ALLOW` | 18325 ms | ✓ |
| `safelinks-multi-region-jp` | wrapper-benign | `any-allow` | `ALLOW` | 22982 ms | ✓ |
| `symantec-clicktime-benign` | wrapper-benign | `any-allow` | `ALLOW` | 22225 ms | ✓ |
| `cisco-pointing-to-homoglyph` | wrapper-phish | `any-deny` | `BLOCK` | 698 ms | ✓ |
| `mimecast-pointing-at-fresh-host` | wrapper-phish | `any-deny` | `ISOLATE` | 836 ms | ✓ |
| `proofpoint-pointing-to-fresh-host` | wrapper-phish | `any-deny` | `ISOLATE` | 707 ms | ✓ |
| `safelinks-spoof-phish-target` | wrapper-phish | `any-deny` | `ISOLATE` | 1236 ms | ✓ |
