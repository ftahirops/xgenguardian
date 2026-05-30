# Smoke corpus report

- API base: `http://127.0.0.1:18080`
- Cases: **196**
- Pass: **191**  /  Fail: **5**  /  Rate: **97.4%**
- Wall-clock: 111.0 s

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
| `scam-mcafee-renewal` | `any-deny` | `ALLOW` | — |
| `payment-scam-inheritance` | `any-deny` | `ALLOW` | — |
| `payment-scam-ssn-suspended` | `any-deny` | `ALLOW` | — |
| `payment-scam-geek-squad-invoice` | `any-deny` | `ALLOW` | — |
| `oauth-phish-pretend-vscode` | `any-deny` | `ALLOW` | TIER2_DATA_UNAVAILABLE |

## Detailed per-case results

| Case | Category | Expected | Actual | Latency | Pass |
| --- | --- | --- | --- | ---: | :---: |
| `benign-news-irs-tax` | benign-trigger | `any-allow` | `ALLOW` | 870 ms | ✓ |
| `benign-wikipedia-gift-card` | benign-trigger | `any-allow` | `ALLOW` | 798 ms | ✓ |
| `benign-wikipedia-phishing` | benign-trigger | `any-allow` | `ALLOW` | 796 ms | ✓ |
| `drainer-arbitrum-mint` | crypto-drainer | `any-deny` | `WARN` | 947 ms | ✓ |
| `drainer-blur-airdrop` | crypto-drainer | `any-deny` | `WARN` | 896 ms | ✓ |
| `drainer-fake-claim-airdrop` | crypto-drainer | `any-deny` | `BLOCK` | 830 ms | ✓ |
| `drainer-fake-opensea` | crypto-drainer | `any-deny` | `WARN` | 1043 ms | ✓ |
| `drainer-fake-revoke` | crypto-drainer | `any-deny` | `ISOLATE` | 1035 ms | ✓ |
| `drainer-metamask-update` | crypto-drainer | `any-deny` | `ISOLATE` | 734 ms | ✓ |
| `drainer-pancakeswap-airdrop` | crypto-drainer | `any-deny` | `BLOCK` | 780 ms | ✓ |
| `drainer-phantom-wallet` | crypto-drainer | `any-deny` | `ISOLATE` | 813 ms | ✓ |
| `drainer-revoke-cash-spoof` | crypto-drainer | `any-deny` | `ISOLATE` | 821 ms | ✓ |
| `drainer-trustwallet` | crypto-drainer | `any-deny` | `ISOLATE` | 644 ms | ✓ |
| `drainer-uniswap-claim` | crypto-drainer | `any-deny` | `WARN` | 961 ms | ✓ |
| `drainer-wallet-validate` | crypto-drainer | `any-deny` | `ISOLATE` | 733 ms | ✓ |
| `direct-download-exe` | direct-download | `any-deny` | `ISOLATE` | 854 ms | ✓ |
| `direct-download-jar` | direct-download | `any-deny` | `ISOLATE` | 999 ms | ✓ |
| `direct-download-msi` | direct-download | `any-deny` | `ISOLATE` | 867 ms | ✓ |
| `edge-case-non-standard-tld` | edge-case | `any-allow` | `ALLOW` | 1136 ms | ✓ |
| `edge-case-numeric-domain` | edge-case | `any` | `ALLOW` | 948 ms | ✓ |
| `edge-case-very-long-url` | edge-case | `any-allow` | `ALLOW` | 673 ms | ✓ |
| `fqdn-trailing-dot` | edge-case | `any-allow` | `ALLOW` | 533 ms | ✓ |
| `hash-fragment-only` | edge-case | `any-allow` | `ALLOW` | 630 ms | ✓ |
| `nonstandard-port` | edge-case | `any-allow` | `ALLOW` | 763 ms | ✓ |
| `fake-bank-barclays` | fake-banking | `any-deny` | `ISOLATE` | 742 ms | ✓ |
| `fake-bank-deutsche` | fake-banking | `any-deny` | `ISOLATE` | 729 ms | ✓ |
| `fake-bank-hsbc` | fake-banking | `any-deny` | `ISOLATE` | 732 ms | ✓ |
| `fake-bank-natwest` | fake-banking | `any-deny` | `ISOLATE` | 754 ms | ✓ |
| `fake-bank-rbc` | fake-banking | `any-deny` | `ISOLATE` | 691 ms | ✓ |
| `fake-bank-santander` | fake-banking | `any-deny` | `ISOLATE` | 670 ms | ✓ |
| `fake-boa-mobile` | fake-banking | `any-deny` | `ISOLATE` | 704 ms | ✓ |
| `fake-chase-login` | fake-banking | `any-deny` | `ISOLATE` | 722 ms | ✓ |
| `fake-citibank-secure` | fake-banking | `any-deny` | `ISOLATE` | 797 ms | ✓ |
| `fake-wellsfargo-update` | fake-banking | `any-deny` | `ISOLATE` | 793 ms | ✓ |
| `fake-google-accounts-host` | fake-oauth-host | `any-deny` | `ISOLATE` | 758 ms | ✓ |
| `fake-microsoft-oauth-host` | fake-oauth-host | `any-deny` | `ISOLATE` | 796 ms | ✓ |
| `fresh-payment-new-bank-login` | fresh-payment | `any-deny` | `ISOLATE` | 663 ms | ✓ |
| `fresh-payment-wallet-connect` | fresh-payment | `any-deny` | `ISOLATE` | 708 ms | ✓ |
| `payment-fresh-cart` | fresh-payment | `any-deny` | `ISOLATE` | 775 ms | ✓ |
| `payment-fresh-checkout` | fresh-payment | `any-deny` | `ISOLATE` | 859 ms | ✓ |
| `http-fresh-domain` | http-only | `any` | `ALLOW` | 826 ms | ✓ |
| `http-only-major` | http-only | `any-allow` | `ALLOW` | 769 ms | ✓ |
| `idn-amazon-cyrillic-a` | idn-homoglyph | `any-deny` | `WARN` | 846 ms | ✓ |
| `idn-apple-cyrillic-p` | idn-homoglyph | `any-deny` | `BLOCK` | 598 ms | ✓ |
| `idn-github-cyrillic-h` | idn-homoglyph | `any-deny` | `BLOCK` | 711 ms | ✓ |
| `idn-google-cyrillic-o` | idn-homoglyph | `any-deny` | `WARN` | 944 ms | ✓ |
| `idn-microsoft-cyrillic-o` | idn-homoglyph | `any-deny` | `WARN` | 934 ms | ✓ |
| `idn-paypal-cyrillic-a` | idn-homoglyph | `any-deny` | `BLOCK` | 741 ms | ✓ |
| `dev-install-fake-docker` | install-lure | `any-deny` | `ISOLATE` | 936 ms | ✓ |
| `dev-install-fake-go` | install-lure | `any-deny` | `ISOLATE` | 909 ms | ✓ |
| `dev-install-fake-rust` | install-lure | `any-deny` | `ISOLATE` | 953 ms | ✓ |
| `dev-install-fake-terraform` | install-lure | `any-deny` | `ISOLATE` | 969 ms | ✓ |
| `fake-anthropic-install` | install-lure | `any-deny` | `ISOLATE` | 1010 ms | ✓ |
| `fake-nodejs-install` | install-lure | `any-deny` | `ISOLATE` | 1064 ms | ✓ |
| `bank-real-chase` | legit-banking | `any-allow` | `ALLOW` | 982 ms | ✓ |
| `bank-real-citi` | legit-banking | `any-allow` | `ALLOW` | 955 ms | ✓ |
| `bank-real-deutsche` | legit-banking | `any-allow` | `ALLOW` | 1024 ms | ✓ |
| `bank-real-hsbc` | legit-banking | `any-allow` | `ALLOW` | 1047 ms | ✓ |
| `bank-real-rbc` | legit-banking | `any-allow` | `ALLOW` | 1003 ms | ✓ |
| `bank-real-wellsfargo` | legit-banking | `any-allow` | `ALLOW` | 980 ms | ✓ |
| `cloudflare-cdn-script` | legit-cdn | `any-allow` | `ALLOW` | 700 ms | ✓ |
| `google-fonts` | legit-cdn | `any-allow` | `ALLOW` | 662 ms | ✓ |
| `jsdelivr` | legit-cdn | `any-allow` | `ALLOW` | 770 ms | ✓ |
| `legit-cdn-jquery` | legit-cdn | `any-allow` | `ALLOW` | 673 ms | ✓ |
| `unpkg` | legit-cdn | `any-allow` | `ALLOW` | 831 ms | ✓ |
| `bbc-news` | legit-content | `any-allow` | `ALLOW` | 780 ms | ✓ |
| `legit-content-medium` | legit-content | `any-allow` | `ALLOW` | 618 ms | ✓ |
| `legit-content-news-nytimes` | legit-content | `any-allow` | `ALLOW` | 913 ms | ✓ |
| `legit-content-reddit` | legit-content | `any-allow` | `ALLOW` | 838 ms | ✓ |
| `legit-content-substack` | legit-content | `any-allow` | `ALLOW` | 514 ms | ✓ |
| `mozilla-developer` | legit-content | `any-allow` | `ALLOW` | 718 ms | ✓ |
| `stackoverflow` | legit-content | `any-allow` | `ALLOW` | 821 ms | ✓ |
| `wikipedia` | legit-content | `any-allow` | `ALLOW` | 1079 ms | ✓ |
| `claude-quickstart` | legit-dev | `any-allow` | `ALLOW` | 602 ms | ✓ |
| `legit-go-pkg` | legit-dev | `any-allow` | `ALLOW` | 830 ms | ✓ |
| `legit-python-docs` | legit-dev | `any-allow` | `ALLOW` | 999 ms | ✓ |
| `legit-rust-docs` | legit-dev | `any-allow` | `ALLOW` | 1007 ms | ✓ |
| `rustup` | legit-dev | `any-allow` | `ALLOW` | 1022 ms | ✓ |
| `apple-id-host` | legit-major | `any-allow` | `ALLOW` | 970 ms | ✓ |
| `cloudflare-corporate` | legit-major | `any-allow` | `ALLOW` | 795 ms | ✓ |
| `github` | legit-major | `any-allow` | `ALLOW` | 24565 ms | ✓ |
| `google-homepage` | legit-major | `any-allow` | `ALLOW` | 875 ms | ✓ |
| `legit-anthropic` | legit-major | `any-allow` | `ALLOW` | 655 ms | ✓ |
| `legit-aws-docs` | legit-major | `any-allow` | `ALLOW` | 1012 ms | ✓ |
| `legit-microsoft-learn` | legit-major | `any-allow` | `ALLOW` | 909 ms | ✓ |
| `legit-openai` | legit-major | `any-allow` | `ALLOW` | 751 ms | ✓ |
| `legit-vercel` | legit-major | `any-allow` | `ALLOW` | 755 ms | ✓ |
| `microsoft-login` | legit-major | `any-allow` | `ALLOW` | 763 ms | ✓ |
| `paypal-homepage` | legit-major | `any-allow` | `ALLOW` | 903 ms | ✓ |
| `stripe-checkout-host` | legit-major | `any-allow` | `ALLOW` | 892 ms | ✓ |
| `payment-real-stripe-docs` | legit-payment | `any-allow` | `ALLOW` | 736 ms | ✓ |
| `legit-saas-airtable` | legit-saas | `any-allow` | `ALLOW` | 852 ms | ✓ |
| `legit-saas-canva` | legit-saas | `any-allow` | `ALLOW` | 637 ms | ✓ |
| `legit-saas-figma` | legit-saas | `any-allow` | `ALLOW` | 749 ms | ✓ |
| `legit-saas-linear` | legit-saas | `any-allow` | `ALLOW` | 676 ms | ✓ |
| `notion` | legit-saas | `any-allow` | `ALLOW` | 616 ms | ✓ |
| `slack-app` | legit-saas | `any-allow` | `ALLOW` | 753 ms | ✓ |
| `aws-console` | legit-sensitive | `any-allow` | `ALLOW` | 990 ms | ✓ |
| `github-settings` | legit-sensitive | `any-allow` | `ALLOW` | 20517 ms | ✓ |
| `gmail-inbox` | legit-sensitive | `any-allow` | `ALLOW` | 14444 ms | ✓ |
| `benign-pixel-fb` | legit-tracker | `any-allow` | `ALLOW` | 688 ms | ✓ |
| `corrupt-protocol` | malformed | `any` | `ALLOW` | 580 ms | ✓ |
| `corrupt-spaces` | malformed | `any` | `ALLOW` | 699 ms | ✓ |
| `data-scheme` | malformed | `any` | `CLEAN` | 173 ms | ✓ |
| `javascript-scheme` | malformed | `any` | `CLEAN` | 201 ms | ✓ |
| `mfa-fake-duo` | mfa-bombing | `any-deny` | `ISOLATE` | 893 ms | ✓ |
| `mfa-fake-okta-push` | mfa-bombing | `any-deny` | `ISOLATE` | 856 ms | ✓ |
| `oauth-known-good-github-cli` | oauth-legit | `any-allow` | `ALLOW` | 13910 ms | ✓ |
| `oauth-known-good-vscode` | oauth-legit | `any-allow` | `ALLOW` | 10994 ms | ✓ |
| `oauth-legit-azure-cli` | oauth-legit | `any-allow` | `ALLOW` | 459 ms | ✓ |
| `oauth-legit-github-mobile` | oauth-legit | `any-allow` | `ALLOW` | 23379 ms | ✓ |
| `oauth-google-unknown-client-drive-scope` | oauth-phish | `any-deny` | `BLOCK` | 569 ms | ✓ |
| `oauth-microsoft-unknown-client-high-scope` | oauth-phish | `any-deny` | `BLOCK` | 749 ms | ✓ |
| `oauth-phish-pretend-gcloud` | oauth-phish | `any-deny` | `BLOCK` | 449 ms | ✓ |
| `oauth-phish-pretend-vscode` | oauth-phish | `any-deny` | `ALLOW` | 26448 ms | ✗ |
| `gift-card-scam-1` | payment-scam | `any-deny` | `ISOLATE` | 851 ms | ✓ |
| `payment-scam-customs-fee` | payment-scam | `any-deny` | `WARN` | 959 ms | ✓ |
| `payment-scam-fake-paypal-invoice` | payment-scam | `any-deny` | `BLOCK` | 746 ms | ✓ |
| `payment-scam-geek-squad-invoice` | payment-scam | `any-deny` | `ALLOW` | 897 ms | ✗ |
| `payment-scam-inheritance` | payment-scam | `any-deny` | `ALLOW` | 861 ms | ✗ |
| `payment-scam-lottery` | payment-scam | `any-deny` | `WARN` | 1044 ms | ✓ |
| `payment-scam-medicare-refund` | payment-scam | `any-deny` | `WARN` | 809 ms | ✓ |
| `payment-scam-ssn-suspended` | payment-scam | `any-deny` | `ALLOW` | 787 ms | ✗ |
| `payment-scam-tax-refund-uk` | payment-scam | `any-deny` | `WARN` | 940 ms | ✓ |
| `wire-fraud-irs` | payment-scam | `any-deny` | `WARN` | 923 ms | ✓ |
| `piracy-multiple-1` | piracy-tld | `any` | `ALLOW` | 1127 ms | ✓ |
| `piracy-multiple-2` | piracy-tld | `any` | `ALLOW` | 10805 ms | ✓ |
| `piracy-tld-cc` | piracy-tld | `any` | `ALLOW` | 28273 ms | ✓ |
| `piracy-tld-pw` | piracy-tld | `any` | `ALLOW` | 960 ms | ✓ |
| `piracy-tld-to` | piracy-tld | `any` | `ALLOW` | 13509 ms | ✓ |
| `piracy-tld-ws` | piracy-tld | `any` | `ALLOW` | 1037 ms | ✓ |
| `punycode-google` | punycode | `any` | `WARN` | 736 ms | ✓ |
| `raw-ip-bare` | raw-ip | `any-deny` | `BLOCK` | 10936 ms | ✓ |
| `raw-ip-binary-drop` | raw-ip | `block` | `BLOCK` | 10894 ms | ✓ |
| `raw-ip-cn-vps` | raw-ip | `block` | `BLOCK` | 15204 ms | ✓ |
| `raw-ip-private-cgnat` | raw-ip | `any` | `BLOCK` | 11048 ms | ✓ |
| `login-on-fresh-unknown` | sensitive-unknown | `any-deny` | `ISOLATE` | 724 ms | ✓ |
| `payment-checkout-unknown` | sensitive-unknown | `any-deny` | `ISOLATE` | 720 ms | ✓ |
| `session-hijack-fake-signin` | session-hijack | `any-deny` | `ISOLATE` | 985 ms | ✓ |
| `session-hijack-fake-token` | session-hijack | `any-deny` | `ISOLATE` | 712 ms | ✓ |
| `github-io-tenant` | shared-host | `any` | `ALLOW` | 16063 ms | ✓ |
| `netlify-tenant` | shared-host | `any` | `ALLOW` | 13935 ms | ✓ |
| `shared-host-pages-dev` | shared-host | `any` | `ALLOW` | 1072 ms | ✓ |
| `shared-host-wordpress` | shared-host | `any-allow` | `ALLOW` | 21442 ms | ✓ |
| `shared-host-workers-dev` | shared-host | `any` | `ALLOW` | 1092 ms | ✓ |
| `vercel-tenant` | shared-host | `any` | `ALLOW` | 21146 ms | ✓ |
| `bitly-home` | shortener | `any-allow` | `ALLOW` | 821 ms | ✓ |
| `shortener-bitly-corrupt` | shortener | `any` | `ALLOW` | 1367 ms | ✓ |
| `tco-home` | shortener | `any-allow` | `ALLOW` | 550 ms | ✓ |
| `spoof-mimecast-host` | spoof-wrapper | `any-allow` | `ALLOW` | 897 ms | ✓ |
| `spoof-safelinks-host` | spoof-wrapper | `any-allow` | `ALLOW` | 1009 ms | ✓ |
| `subdomain-spoof-google-accounts` | subdomain-spoof | `any-deny` | `ISOLATE` | 857 ms | ✓ |
| `subdomain-spoof-microsoft-login` | subdomain-spoof | `any-deny` | `ISOLATE` | 994 ms | ✓ |
| `subdomain-spoof-paypal` | subdomain-spoof | `any-deny` | `ISOLATE` | 853 ms | ✓ |
| `scam-amazon-support` | support-scam | `any-deny` | `WARN` | 961 ms | ✓ |
| `scam-google-virus-warning` | support-scam | `any-deny` | `WARN` | 1005 ms | ✓ |
| `scam-icloud-locked` | support-scam | `any-deny` | `ISOLATE` | 740 ms | ✓ |
| `scam-mcafee-renewal` | support-scam | `any-deny` | `ALLOW` | 894 ms | ✗ |
| `scam-norton-support` | support-scam | `any-deny` | `WARN` | 809 ms | ✓ |
| `scam-windows-error` | support-scam | `any-deny` | `WARN` | 825 ms | ✓ |
| `support-scam-apple-virus-alert` | support-scam | `any-deny` | `WARN` | 1018 ms | ✓ |
| `support-scam-microsoft-helpline` | support-scam | `any-deny` | `WARN` | 1043 ms | ✓ |
| `support-scam-windows-defender` | support-scam | `any-deny` | `WARN` | 824 ms | ✓ |
| `cctld-cf` | sus-tld | `any` | `ALLOW` | 1053 ms | ✓ |
| `cctld-ga` | sus-tld | `any` | `ALLOW` | 1037 ms | ✓ |
| `cctld-ml` | sus-tld | `any` | `ALLOW` | 19667 ms | ✓ |
| `tld-click` | sus-tld | `any` | `ALLOW` | 16647 ms | ✓ |
| `tld-tk` | sus-tld | `any` | `ALLOW` | 977 ms | ✓ |
| `tld-xyz` | sus-tld | `any` | `ALLOW` | 997 ms | ✓ |
| `brand-impersonation-google` | synth-phish | `any-deny` | `ISOLATE` | 831 ms | ✓ |
| `brand-impersonation-microsoft` | synth-phish | `any-deny` | `ISOLATE` | 645 ms | ✓ |
| `brand-impersonation-paypal` | synth-phish | `any-deny` | `ISOLATE` | 866 ms | ✓ |
| `homoglyph-google` | synth-phish | `any-deny` | `WARN` | 1218 ms | ✓ |
| `random-host-login` | synth-phish | `any-deny` | `ISOLATE` | 924 ms | ✓ |
| `combosquat-paypal-account` | typosquat | `any-deny` | `ISOLATE` | 738 ms | ✓ |
| `homoglyph-amazon-zero-for-o` | typosquat | `any-deny` | `BLOCK` | 680 ms | ✓ |
| `homoglyph-microsoft-rn-for-m` | typosquat | `any-deny` | `BLOCK` | 711 ms | ✓ |
| `homoglyph-paypal-1-for-l` | typosquat | `any-deny` | `BLOCK` | 694 ms | ✓ |
| `typo-amazon-shuffle` | typosquat | `any-deny` | `BLOCK` | 823 ms | ✓ |
| `typo-google-h` | typosquat | `any-deny` | `WARN` | 902 ms | ✓ |
| `typo-google-letter-swap` | typosquat | `any-deny` | `WARN` | 874 ms | ✓ |
| `typo-microsoft-omission` | typosquat | `any-deny` | `BLOCK` | 741 ms | ✓ |
| `typo-paypal-double` | typosquat | `any-deny` | `BLOCK` | 670 ms | ✓ |
| `barracuda-benign` | wrapper-benign | `any-allow` | `ALLOW` | 11601 ms | ✓ |
| `cisco-securemail-benign` | wrapper-benign | `any-allow` | `ALLOW` | 12191 ms | ✓ |
| `gmail-link-redirect-benign` | wrapper-benign | `any-allow` | `ALLOW` | 11038 ms | ✓ |
| `proofpoint-v2-benign` | wrapper-benign | `any-allow` | `ALLOW` | 15747 ms | ✓ |
| `proofpoint-v3-format-benign` | wrapper-benign | `any-allow` | `ALLOW` | 18393 ms | ✓ |
| `safelinks-benign` | wrapper-benign | `any-allow` | `ALLOW` | 20531 ms | ✓ |
| `safelinks-multi-region-india` | wrapper-benign | `any-allow` | `ALLOW` | 22480 ms | ✓ |
| `safelinks-multi-region-jp` | wrapper-benign | `any-allow` | `ALLOW` | 20180 ms | ✓ |
| `symantec-clicktime-benign` | wrapper-benign | `any-allow` | `ALLOW` | 18118 ms | ✓ |
| `cisco-pointing-to-homoglyph` | wrapper-phish | `any-deny` | `BLOCK` | 707 ms | ✓ |
| `mimecast-pointing-at-fresh-host` | wrapper-phish | `any-deny` | `ISOLATE` | 1039 ms | ✓ |
| `proofpoint-pointing-to-fresh-host` | wrapper-phish | `any-deny` | `ISOLATE` | 722 ms | ✓ |
| `safelinks-spoof-phish-target` | wrapper-phish | `any-deny` | `ISOLATE` | 986 ms | ✓ |
