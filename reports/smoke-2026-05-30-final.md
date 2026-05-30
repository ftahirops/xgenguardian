# Smoke corpus report

- API base: `http://127.0.0.1:18080`
- Cases: **196**
- Pass: **194**  /  Fail: **2**  /  Rate: **99.0%**
- Wall-clock: 111.9 s

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
| legit-sensitive | 3 | 0 | 3 | 100% |
| legit-tracker | 1 | 0 | 1 | 100% |
| malformed | 4 | 0 | 4 | 100% |
| mfa-bombing | 2 | 0 | 2 | 100% |
| oauth-legit | 4 | 0 | 4 | 100% |
| oauth-phish | 3 | 1 | 4 | 75% |
| payment-scam | 10 | 0 | 10 | 100% |
| piracy-tld | 6 | 0 | 6 | 100% |
| punycode | 1 | 0 | 1 | 100% |
| raw-ip | 4 | 0 | 4 | 100% |
| sensitive-unknown | 2 | 0 | 2 | 100% |
| session-hijack | 2 | 0 | 2 | 100% |
| shared-host | 6 | 0 | 6 | 100% |
| shortener | 3 | 0 | 3 | 100% |
| spoof-wrapper | 2 | 0 | 2 | 100% |
| subdomain-spoof | 3 | 0 | 3 | 100% |
| support-scam | 9 | 0 | 9 | 100% |
| sus-tld | 6 | 0 | 6 | 100% |
| synth-phish | 5 | 0 | 5 | 100% |
| typosquat | 9 | 0 | 9 | 100% |
| wrapper-benign | 9 | 0 | 9 | 100% |
| wrapper-phish | 4 | 0 | 4 | 100% |

## Failing cases


| Case | Expected | Actual | Reason codes |
| --- | --- | --- | --- |
| `github` | `any-allow` | `ERR: exception: timed out` | — |
| `oauth-phish-pretend-vscode` | `any-deny` | `ALLOW` | TIER2_DATA_UNAVAILABLE |

## Detailed per-case results

| Case | Category | Expected | Actual | Latency | Pass |
| --- | --- | --- | --- | ---: | :---: |
| `benign-news-irs-tax` | benign-trigger | `any-allow` | `ALLOW` | 763 ms | ✓ |
| `benign-wikipedia-gift-card` | benign-trigger | `any-allow` | `ALLOW` | 763 ms | ✓ |
| `benign-wikipedia-phishing` | benign-trigger | `any-allow` | `ALLOW` | 712 ms | ✓ |
| `drainer-arbitrum-mint` | crypto-drainer | `any-deny` | `WARN` | 720 ms | ✓ |
| `drainer-blur-airdrop` | crypto-drainer | `any-deny` | `WARN` | 1079 ms | ✓ |
| `drainer-fake-claim-airdrop` | crypto-drainer | `any-deny` | `BLOCK` | 730 ms | ✓ |
| `drainer-fake-opensea` | crypto-drainer | `any-deny` | `WARN` | 806 ms | ✓ |
| `drainer-fake-revoke` | crypto-drainer | `any-deny` | `ISOLATE` | 767 ms | ✓ |
| `drainer-metamask-update` | crypto-drainer | `any-deny` | `ISOLATE` | 621 ms | ✓ |
| `drainer-pancakeswap-airdrop` | crypto-drainer | `any-deny` | `BLOCK` | 587 ms | ✓ |
| `drainer-phantom-wallet` | crypto-drainer | `any-deny` | `ISOLATE` | 724 ms | ✓ |
| `drainer-revoke-cash-spoof` | crypto-drainer | `any-deny` | `ISOLATE` | 707 ms | ✓ |
| `drainer-trustwallet` | crypto-drainer | `any-deny` | `ISOLATE` | 676 ms | ✓ |
| `drainer-uniswap-claim` | crypto-drainer | `any-deny` | `WARN` | 987 ms | ✓ |
| `drainer-wallet-validate` | crypto-drainer | `any-deny` | `ISOLATE` | 665 ms | ✓ |
| `direct-download-exe` | direct-download | `any-deny` | `ISOLATE` | 788 ms | ✓ |
| `direct-download-jar` | direct-download | `any-deny` | `ISOLATE` | 720 ms | ✓ |
| `direct-download-msi` | direct-download | `any-deny` | `ISOLATE` | 848 ms | ✓ |
| `edge-case-non-standard-tld` | edge-case | `any-allow` | `ALLOW` | 734 ms | ✓ |
| `edge-case-numeric-domain` | edge-case | `any` | `ALLOW` | 788 ms | ✓ |
| `edge-case-very-long-url` | edge-case | `any-allow` | `ALLOW` | 606 ms | ✓ |
| `fqdn-trailing-dot` | edge-case | `any-allow` | `ALLOW` | 540 ms | ✓ |
| `hash-fragment-only` | edge-case | `any-allow` | `ALLOW` | 541 ms | ✓ |
| `nonstandard-port` | edge-case | `any-allow` | `ALLOW` | 622 ms | ✓ |
| `fake-bank-barclays` | fake-banking | `any-deny` | `ISOLATE` | 687 ms | ✓ |
| `fake-bank-deutsche` | fake-banking | `any-deny` | `ISOLATE` | 755 ms | ✓ |
| `fake-bank-hsbc` | fake-banking | `any-deny` | `ISOLATE` | 666 ms | ✓ |
| `fake-bank-natwest` | fake-banking | `any-deny` | `ISOLATE` | 767 ms | ✓ |
| `fake-bank-rbc` | fake-banking | `any-deny` | `ISOLATE` | 779 ms | ✓ |
| `fake-bank-santander` | fake-banking | `any-deny` | `ISOLATE` | 684 ms | ✓ |
| `fake-boa-mobile` | fake-banking | `any-deny` | `ISOLATE` | 742 ms | ✓ |
| `fake-chase-login` | fake-banking | `any-deny` | `ISOLATE` | 572 ms | ✓ |
| `fake-citibank-secure` | fake-banking | `any-deny` | `ISOLATE` | 635 ms | ✓ |
| `fake-wellsfargo-update` | fake-banking | `any-deny` | `ISOLATE` | 739 ms | ✓ |
| `fake-google-accounts-host` | fake-oauth-host | `any-deny` | `ISOLATE` | 554 ms | ✓ |
| `fake-microsoft-oauth-host` | fake-oauth-host | `any-deny` | `ISOLATE` | 615 ms | ✓ |
| `fresh-payment-new-bank-login` | fresh-payment | `any-deny` | `ISOLATE` | 580 ms | ✓ |
| `fresh-payment-wallet-connect` | fresh-payment | `any-deny` | `ISOLATE` | 645 ms | ✓ |
| `payment-fresh-cart` | fresh-payment | `any-deny` | `ISOLATE` | 675 ms | ✓ |
| `payment-fresh-checkout` | fresh-payment | `any-deny` | `ISOLATE` | 678 ms | ✓ |
| `http-fresh-domain` | http-only | `any` | `ALLOW` | 805 ms | ✓ |
| `http-only-major` | http-only | `any-allow` | `ALLOW` | 739 ms | ✓ |
| `idn-amazon-cyrillic-a` | idn-homoglyph | `any-deny` | `WARN` | 806 ms | ✓ |
| `idn-apple-cyrillic-p` | idn-homoglyph | `any-deny` | `BLOCK` | 602 ms | ✓ |
| `idn-github-cyrillic-h` | idn-homoglyph | `any-deny` | `BLOCK` | 631 ms | ✓ |
| `idn-google-cyrillic-o` | idn-homoglyph | `any-deny` | `WARN` | 730 ms | ✓ |
| `idn-microsoft-cyrillic-o` | idn-homoglyph | `any-deny` | `WARN` | 811 ms | ✓ |
| `idn-paypal-cyrillic-a` | idn-homoglyph | `any-deny` | `BLOCK` | 758 ms | ✓ |
| `dev-install-fake-docker` | install-lure | `any-deny` | `ISOLATE` | 779 ms | ✓ |
| `dev-install-fake-go` | install-lure | `any-deny` | `ISOLATE` | 885 ms | ✓ |
| `dev-install-fake-rust` | install-lure | `any-deny` | `ISOLATE` | 844 ms | ✓ |
| `dev-install-fake-terraform` | install-lure | `any-deny` | `ISOLATE` | 847 ms | ✓ |
| `fake-anthropic-install` | install-lure | `any-deny` | `ISOLATE` | 828 ms | ✓ |
| `fake-nodejs-install` | install-lure | `any-deny` | `ISOLATE` | 970 ms | ✓ |
| `bank-real-chase` | legit-banking | `any-allow` | `ALLOW` | 1000 ms | ✓ |
| `bank-real-citi` | legit-banking | `any-allow` | `ALLOW` | 798 ms | ✓ |
| `bank-real-deutsche` | legit-banking | `any-allow` | `ALLOW` | 1054 ms | ✓ |
| `bank-real-hsbc` | legit-banking | `any-allow` | `ALLOW` | 986 ms | ✓ |
| `bank-real-rbc` | legit-banking | `any-allow` | `ALLOW` | 979 ms | ✓ |
| `bank-real-wellsfargo` | legit-banking | `any-allow` | `ALLOW` | 945 ms | ✓ |
| `cloudflare-cdn-script` | legit-cdn | `any-allow` | `ALLOW` | 628 ms | ✓ |
| `google-fonts` | legit-cdn | `any-allow` | `ALLOW` | 729 ms | ✓ |
| `jsdelivr` | legit-cdn | `any-allow` | `ALLOW` | 794 ms | ✓ |
| `legit-cdn-jquery` | legit-cdn | `any-allow` | `ALLOW` | 624 ms | ✓ |
| `unpkg` | legit-cdn | `any-allow` | `ALLOW` | 644 ms | ✓ |
| `bbc-news` | legit-content | `any-allow` | `ALLOW` | 1002 ms | ✓ |
| `legit-content-medium` | legit-content | `any-allow` | `ALLOW` | 764 ms | ✓ |
| `legit-content-news-nytimes` | legit-content | `any-allow` | `ALLOW` | 1031 ms | ✓ |
| `legit-content-reddit` | legit-content | `any-allow` | `ALLOW` | 658 ms | ✓ |
| `legit-content-substack` | legit-content | `any-allow` | `ALLOW` | 540 ms | ✓ |
| `mozilla-developer` | legit-content | `any-allow` | `ALLOW` | 871 ms | ✓ |
| `stackoverflow` | legit-content | `any-allow` | `ALLOW` | 751 ms | ✓ |
| `wikipedia` | legit-content | `any-allow` | `ALLOW` | 993 ms | ✓ |
| `claude-quickstart` | legit-dev | `any-allow` | `ALLOW` | 632 ms | ✓ |
| `legit-go-pkg` | legit-dev | `any-allow` | `ALLOW` | 877 ms | ✓ |
| `legit-python-docs` | legit-dev | `any-allow` | `ALLOW` | 887 ms | ✓ |
| `legit-rust-docs` | legit-dev | `any-allow` | `ALLOW` | 1101 ms | ✓ |
| `rustup` | legit-dev | `any-allow` | `ALLOW` | 852 ms | ✓ |
| `apple-id-host` | legit-major | `any-allow` | `ALLOW` | 877 ms | ✓ |
| `cloudflare-corporate` | legit-major | `any-allow` | `ALLOW` | 767 ms | ✓ |
| `github` | legit-major | `any-allow` | `ERR: exception: timed out` | 30123 ms | ✗ |
| `google-homepage` | legit-major | `any-allow` | `ALLOW` | 815 ms | ✓ |
| `legit-anthropic` | legit-major | `any-allow` | `ALLOW` | 669 ms | ✓ |
| `legit-aws-docs` | legit-major | `any-allow` | `ALLOW` | 1003 ms | ✓ |
| `legit-microsoft-learn` | legit-major | `any-allow` | `ALLOW` | 971 ms | ✓ |
| `legit-openai` | legit-major | `any-allow` | `ALLOW` | 804 ms | ✓ |
| `legit-vercel` | legit-major | `any-allow` | `ALLOW` | 679 ms | ✓ |
| `microsoft-login` | legit-major | `any-allow` | `ALLOW` | 724 ms | ✓ |
| `paypal-homepage` | legit-major | `any-allow` | `ALLOW` | 952 ms | ✓ |
| `stripe-checkout-host` | legit-major | `any-allow` | `ALLOW` | 827 ms | ✓ |
| `payment-real-stripe-docs` | legit-payment | `any-allow` | `ALLOW` | 678 ms | ✓ |
| `legit-saas-airtable` | legit-saas | `any-allow` | `ALLOW` | 906 ms | ✓ |
| `legit-saas-canva` | legit-saas | `any-allow` | `ALLOW` | 610 ms | ✓ |
| `legit-saas-figma` | legit-saas | `any-allow` | `ALLOW` | 698 ms | ✓ |
| `legit-saas-linear` | legit-saas | `any-allow` | `ALLOW` | 798 ms | ✓ |
| `notion` | legit-saas | `any-allow` | `ALLOW` | 610 ms | ✓ |
| `slack-app` | legit-saas | `any-allow` | `ALLOW` | 740 ms | ✓ |
| `aws-console` | legit-sensitive | `any-allow` | `ALLOW` | 1001 ms | ✓ |
| `github-settings` | legit-sensitive | `any-allow` | `ALLOW` | 18982 ms | ✓ |
| `gmail-inbox` | legit-sensitive | `any-allow` | `ALLOW` | 21270 ms | ✓ |
| `benign-pixel-fb` | legit-tracker | `any-allow` | `ALLOW` | 695 ms | ✓ |
| `corrupt-protocol` | malformed | `any` | `ALLOW` | 664 ms | ✓ |
| `corrupt-spaces` | malformed | `any` | `ALLOW` | 633 ms | ✓ |
| `data-scheme` | malformed | `any` | `CLEAN` | 190 ms | ✓ |
| `javascript-scheme` | malformed | `any` | `CLEAN` | 140 ms | ✓ |
| `mfa-fake-duo` | mfa-bombing | `any-deny` | `ISOLATE` | 950 ms | ✓ |
| `mfa-fake-okta-push` | mfa-bombing | `any-deny` | `ISOLATE` | 864 ms | ✓ |
| `oauth-known-good-github-cli` | oauth-legit | `any-allow` | `ALLOW` | 21729 ms | ✓ |
| `oauth-known-good-vscode` | oauth-legit | `any-allow` | `ALLOW` | 18618 ms | ✓ |
| `oauth-legit-azure-cli` | oauth-legit | `any-allow` | `ALLOW` | 602 ms | ✓ |
| `oauth-legit-github-mobile` | oauth-legit | `any-allow` | `ALLOW` | 16160 ms | ✓ |
| `oauth-google-unknown-client-drive-scope` | oauth-phish | `any-deny` | `BLOCK` | 681 ms | ✓ |
| `oauth-microsoft-unknown-client-high-scope` | oauth-phish | `any-deny` | `BLOCK` | 571 ms | ✓ |
| `oauth-phish-pretend-gcloud` | oauth-phish | `any-deny` | `BLOCK` | 472 ms | ✓ |
| `oauth-phish-pretend-vscode` | oauth-phish | `any-deny` | `ALLOW` | 17285 ms | ✗ |
| `gift-card-scam-1` | payment-scam | `any-deny` | `ISOLATE` | 654 ms | ✓ |
| `payment-scam-customs-fee` | payment-scam | `any-deny` | `WARN` | 823 ms | ✓ |
| `payment-scam-fake-paypal-invoice` | payment-scam | `any-deny` | `BLOCK` | 734 ms | ✓ |
| `payment-scam-geek-squad-invoice` | payment-scam | `any-deny` | `WARN` | 826 ms | ✓ |
| `payment-scam-inheritance` | payment-scam | `any-deny` | `WARN` | 916 ms | ✓ |
| `payment-scam-lottery` | payment-scam | `any-deny` | `WARN` | 843 ms | ✓ |
| `payment-scam-medicare-refund` | payment-scam | `any-deny` | `WARN` | 744 ms | ✓ |
| `payment-scam-ssn-suspended` | payment-scam | `any-deny` | `WARN` | 872 ms | ✓ |
| `payment-scam-tax-refund-uk` | payment-scam | `any-deny` | `WARN` | 873 ms | ✓ |
| `wire-fraud-irs` | payment-scam | `any-deny` | `WARN` | 915 ms | ✓ |
| `piracy-multiple-1` | piracy-tld | `any` | `ALLOW` | 1095 ms | ✓ |
| `piracy-multiple-2` | piracy-tld | `any` | `ALLOW` | 11046 ms | ✓ |
| `piracy-tld-cc` | piracy-tld | `any` | `ALLOW` | 18809 ms | ✓ |
| `piracy-tld-pw` | piracy-tld | `any` | `ALLOW` | 1051 ms | ✓ |
| `piracy-tld-to` | piracy-tld | `any` | `ALLOW` | 18907 ms | ✓ |
| `piracy-tld-ws` | piracy-tld | `any` | `ALLOW` | 879 ms | ✓ |
| `punycode-google` | punycode | `any` | `WARN` | 684 ms | ✓ |
| `raw-ip-bare` | raw-ip | `any-deny` | `BLOCK` | 10960 ms | ✓ |
| `raw-ip-binary-drop` | raw-ip | `block` | `BLOCK` | 10913 ms | ✓ |
| `raw-ip-cn-vps` | raw-ip | `block` | `BLOCK` | 12205 ms | ✓ |
| `raw-ip-private-cgnat` | raw-ip | `any` | `BLOCK` | 10937 ms | ✓ |
| `login-on-fresh-unknown` | sensitive-unknown | `any-deny` | `ISOLATE` | 624 ms | ✓ |
| `payment-checkout-unknown` | sensitive-unknown | `any-deny` | `ISOLATE` | 649 ms | ✓ |
| `session-hijack-fake-signin` | session-hijack | `any-deny` | `ISOLATE` | 628 ms | ✓ |
| `session-hijack-fake-token` | session-hijack | `any-deny` | `ISOLATE` | 592 ms | ✓ |
| `github-io-tenant` | shared-host | `any` | `ALLOW` | 14714 ms | ✓ |
| `netlify-tenant` | shared-host | `any` | `ALLOW` | 14107 ms | ✓ |
| `shared-host-pages-dev` | shared-host | `any` | `ALLOW` | 876 ms | ✓ |
| `shared-host-wordpress` | shared-host | `any-allow` | `ALLOW` | 19042 ms | ✓ |
| `shared-host-workers-dev` | shared-host | `any` | `ALLOW` | 879 ms | ✓ |
| `vercel-tenant` | shared-host | `any` | `ALLOW` | 17883 ms | ✓ |
| `bitly-home` | shortener | `any-allow` | `ALLOW` | 825 ms | ✓ |
| `shortener-bitly-corrupt` | shortener | `any` | `ALLOW` | 890 ms | ✓ |
| `tco-home` | shortener | `any-allow` | `ALLOW` | 598 ms | ✓ |
| `spoof-mimecast-host` | spoof-wrapper | `any-allow` | `ALLOW` | 911 ms | ✓ |
| `spoof-safelinks-host` | spoof-wrapper | `any-allow` | `ALLOW` | 939 ms | ✓ |
| `subdomain-spoof-google-accounts` | subdomain-spoof | `any-deny` | `ISOLATE` | 722 ms | ✓ |
| `subdomain-spoof-microsoft-login` | subdomain-spoof | `any-deny` | `ISOLATE` | 700 ms | ✓ |
| `subdomain-spoof-paypal` | subdomain-spoof | `any-deny` | `ISOLATE` | 807 ms | ✓ |
| `scam-amazon-support` | support-scam | `any-deny` | `WARN` | 998 ms | ✓ |
| `scam-google-virus-warning` | support-scam | `any-deny` | `WARN` | 888 ms | ✓ |
| `scam-icloud-locked` | support-scam | `any-deny` | `ISOLATE` | 604 ms | ✓ |
| `scam-mcafee-renewal` | support-scam | `any-deny` | `WARN` | 694 ms | ✓ |
| `scam-norton-support` | support-scam | `any-deny` | `WARN` | 908 ms | ✓ |
| `scam-windows-error` | support-scam | `any-deny` | `WARN` | 805 ms | ✓ |
| `support-scam-apple-virus-alert` | support-scam | `any-deny` | `WARN` | 849 ms | ✓ |
| `support-scam-microsoft-helpline` | support-scam | `any-deny` | `WARN` | 858 ms | ✓ |
| `support-scam-windows-defender` | support-scam | `any-deny` | `WARN` | 839 ms | ✓ |
| `cctld-cf` | sus-tld | `any` | `ALLOW` | 1013 ms | ✓ |
| `cctld-ga` | sus-tld | `any` | `ALLOW` | 927 ms | ✓ |
| `cctld-ml` | sus-tld | `any` | `ALLOW` | 19086 ms | ✓ |
| `tld-click` | sus-tld | `any` | `ALLOW` | 24692 ms | ✓ |
| `tld-tk` | sus-tld | `any` | `ALLOW` | 1020 ms | ✓ |
| `tld-xyz` | sus-tld | `any` | `ALLOW` | 858 ms | ✓ |
| `brand-impersonation-google` | synth-phish | `any-deny` | `ISOLATE` | 696 ms | ✓ |
| `brand-impersonation-microsoft` | synth-phish | `any-deny` | `ISOLATE` | 645 ms | ✓ |
| `brand-impersonation-paypal` | synth-phish | `any-deny` | `ISOLATE` | 789 ms | ✓ |
| `homoglyph-google` | synth-phish | `any-deny` | `WARN` | 1097 ms | ✓ |
| `random-host-login` | synth-phish | `any-deny` | `ISOLATE` | 775 ms | ✓ |
| `combosquat-paypal-account` | typosquat | `any-deny` | `ISOLATE` | 677 ms | ✓ |
| `homoglyph-amazon-zero-for-o` | typosquat | `any-deny` | `BLOCK` | 753 ms | ✓ |
| `homoglyph-microsoft-rn-for-m` | typosquat | `any-deny` | `BLOCK` | 758 ms | ✓ |
| `homoglyph-paypal-1-for-l` | typosquat | `any-deny` | `BLOCK` | 583 ms | ✓ |
| `typo-amazon-shuffle` | typosquat | `any-deny` | `BLOCK` | 721 ms | ✓ |
| `typo-google-h` | typosquat | `any-deny` | `WARN` | 908 ms | ✓ |
| `typo-google-letter-swap` | typosquat | `any-deny` | `WARN` | 837 ms | ✓ |
| `typo-microsoft-omission` | typosquat | `any-deny` | `BLOCK` | 759 ms | ✓ |
| `typo-paypal-double` | typosquat | `any-deny` | `BLOCK` | 701 ms | ✓ |
| `barracuda-benign` | wrapper-benign | `any-allow` | `ALLOW` | 6084 ms | ✓ |
| `cisco-securemail-benign` | wrapper-benign | `any-allow` | `ALLOW` | 22808 ms | ✓ |
| `gmail-link-redirect-benign` | wrapper-benign | `any-allow` | `ALLOW` | 18774 ms | ✓ |
| `proofpoint-v2-benign` | wrapper-benign | `any-allow` | `ALLOW` | 14190 ms | ✓ |
| `proofpoint-v3-format-benign` | wrapper-benign | `any-allow` | `ALLOW` | 19608 ms | ✓ |
| `safelinks-benign` | wrapper-benign | `any-allow` | `ALLOW` | 19452 ms | ✓ |
| `safelinks-multi-region-india` | wrapper-benign | `any-allow` | `ALLOW` | 17234 ms | ✓ |
| `safelinks-multi-region-jp` | wrapper-benign | `any-allow` | `ALLOW` | 25687 ms | ✓ |
| `symantec-clicktime-benign` | wrapper-benign | `any-allow` | `ALLOW` | 21518 ms | ✓ |
| `cisco-pointing-to-homoglyph` | wrapper-phish | `any-deny` | `BLOCK` | 710 ms | ✓ |
| `mimecast-pointing-at-fresh-host` | wrapper-phish | `any-deny` | `ISOLATE` | 701 ms | ✓ |
| `proofpoint-pointing-to-fresh-host` | wrapper-phish | `any-deny` | `ISOLATE` | 625 ms | ✓ |
| `safelinks-spoof-phish-target` | wrapper-phish | `any-deny` | `ISOLATE` | 738 ms | ✓ |
