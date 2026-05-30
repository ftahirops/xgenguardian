# Smoke corpus report

- API base: `http://127.0.0.1:18080`
- Cases: **196**
- Pass: **194**  /  Fail: **2**  /  Rate: **99.0%**
- Wall-clock: 110.7 s

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
| `oauth-phish-pretend-vscode` | `any-deny` | `ALLOW` | TIER2_DATA_UNAVAILABLE |

## Detailed per-case results

| Case | Category | Expected | Actual | Latency | Pass |
| --- | --- | --- | --- | ---: | :---: |
| `benign-news-irs-tax` | benign-trigger | `any-allow` | `ALLOW` | 885 ms | ✓ |
| `benign-wikipedia-gift-card` | benign-trigger | `any-allow` | `ALLOW` | 754 ms | ✓ |
| `benign-wikipedia-phishing` | benign-trigger | `any-allow` | `ALLOW` | 627 ms | ✓ |
| `drainer-arbitrum-mint` | crypto-drainer | `any-deny` | `WARN` | 912 ms | ✓ |
| `drainer-blur-airdrop` | crypto-drainer | `any-deny` | `WARN` | 773 ms | ✓ |
| `drainer-fake-claim-airdrop` | crypto-drainer | `any-deny` | `BLOCK` | 758 ms | ✓ |
| `drainer-fake-opensea` | crypto-drainer | `any-deny` | `WARN` | 852 ms | ✓ |
| `drainer-fake-revoke` | crypto-drainer | `any-deny` | `ISOLATE` | 798 ms | ✓ |
| `drainer-metamask-update` | crypto-drainer | `any-deny` | `ISOLATE` | 765 ms | ✓ |
| `drainer-pancakeswap-airdrop` | crypto-drainer | `any-deny` | `BLOCK` | 645 ms | ✓ |
| `drainer-phantom-wallet` | crypto-drainer | `any-deny` | `ISOLATE` | 635 ms | ✓ |
| `drainer-revoke-cash-spoof` | crypto-drainer | `any-deny` | `ISOLATE` | 713 ms | ✓ |
| `drainer-trustwallet` | crypto-drainer | `any-deny` | `ISOLATE` | 707 ms | ✓ |
| `drainer-uniswap-claim` | crypto-drainer | `any-deny` | `WARN` | 909 ms | ✓ |
| `drainer-wallet-validate` | crypto-drainer | `any-deny` | `ISOLATE` | 741 ms | ✓ |
| `direct-download-exe` | direct-download | `any-deny` | `ISOLATE` | 896 ms | ✓ |
| `direct-download-jar` | direct-download | `any-deny` | `ISOLATE` | 858 ms | ✓ |
| `direct-download-msi` | direct-download | `any-deny` | `ISOLATE` | 838 ms | ✓ |
| `edge-case-non-standard-tld` | edge-case | `any-allow` | `ALLOW` | 837 ms | ✓ |
| `edge-case-numeric-domain` | edge-case | `any` | `ALLOW` | 769 ms | ✓ |
| `edge-case-very-long-url` | edge-case | `any-allow` | `ALLOW` | 612 ms | ✓ |
| `fqdn-trailing-dot` | edge-case | `any-allow` | `ALLOW` | 595 ms | ✓ |
| `hash-fragment-only` | edge-case | `any-allow` | `ALLOW` | 543 ms | ✓ |
| `nonstandard-port` | edge-case | `any-allow` | `ALLOW` | 575 ms | ✓ |
| `fake-bank-barclays` | fake-banking | `any-deny` | `ISOLATE` | 686 ms | ✓ |
| `fake-bank-deutsche` | fake-banking | `any-deny` | `ISOLATE` | 819 ms | ✓ |
| `fake-bank-hsbc` | fake-banking | `any-deny` | `ISOLATE` | 725 ms | ✓ |
| `fake-bank-natwest` | fake-banking | `any-deny` | `ISOLATE` | 705 ms | ✓ |
| `fake-bank-rbc` | fake-banking | `any-deny` | `ISOLATE` | 586 ms | ✓ |
| `fake-bank-santander` | fake-banking | `any-deny` | `ISOLATE` | 701 ms | ✓ |
| `fake-boa-mobile` | fake-banking | `any-deny` | `ISOLATE` | 751 ms | ✓ |
| `fake-chase-login` | fake-banking | `any-deny` | `ISOLATE` | 725 ms | ✓ |
| `fake-citibank-secure` | fake-banking | `any-deny` | `ISOLATE` | 694 ms | ✓ |
| `fake-wellsfargo-update` | fake-banking | `any-deny` | `ISOLATE` | 769 ms | ✓ |
| `fake-google-accounts-host` | fake-oauth-host | `any-deny` | `ISOLATE` | 596 ms | ✓ |
| `fake-microsoft-oauth-host` | fake-oauth-host | `any-deny` | `ISOLATE` | 789 ms | ✓ |
| `fresh-payment-new-bank-login` | fresh-payment | `any-deny` | `ISOLATE` | 681 ms | ✓ |
| `fresh-payment-wallet-connect` | fresh-payment | `any-deny` | `ISOLATE` | 712 ms | ✓ |
| `payment-fresh-cart` | fresh-payment | `any-deny` | `ISOLATE` | 668 ms | ✓ |
| `payment-fresh-checkout` | fresh-payment | `any-deny` | `ISOLATE` | 757 ms | ✓ |
| `http-fresh-domain` | http-only | `any` | `ALLOW` | 759 ms | ✓ |
| `http-only-major` | http-only | `any-allow` | `ALLOW` | 686 ms | ✓ |
| `idn-amazon-cyrillic-a` | idn-homoglyph | `any-deny` | `WARN` | 849 ms | ✓ |
| `idn-apple-cyrillic-p` | idn-homoglyph | `any-deny` | `BLOCK` | 653 ms | ✓ |
| `idn-github-cyrillic-h` | idn-homoglyph | `any-deny` | `BLOCK` | 633 ms | ✓ |
| `idn-google-cyrillic-o` | idn-homoglyph | `any-deny` | `WARN` | 898 ms | ✓ |
| `idn-microsoft-cyrillic-o` | idn-homoglyph | `any-deny` | `WARN` | 840 ms | ✓ |
| `idn-paypal-cyrillic-a` | idn-homoglyph | `any-deny` | `BLOCK` | 686 ms | ✓ |
| `dev-install-fake-docker` | install-lure | `any-deny` | `ISOLATE` | 792 ms | ✓ |
| `dev-install-fake-go` | install-lure | `any-deny` | `ISOLATE` | 860 ms | ✓ |
| `dev-install-fake-rust` | install-lure | `any-deny` | `ISOLATE` | 945 ms | ✓ |
| `dev-install-fake-terraform` | install-lure | `any-deny` | `ISOLATE` | 848 ms | ✓ |
| `fake-anthropic-install` | install-lure | `any-deny` | `ISOLATE` | 867 ms | ✓ |
| `fake-nodejs-install` | install-lure | `any-deny` | `ISOLATE` | 914 ms | ✓ |
| `bank-real-chase` | legit-banking | `any-allow` | `ALLOW` | 785 ms | ✓ |
| `bank-real-citi` | legit-banking | `any-allow` | `ALLOW` | 699 ms | ✓ |
| `bank-real-deutsche` | legit-banking | `any-allow` | `ALLOW` | 929 ms | ✓ |
| `bank-real-hsbc` | legit-banking | `any-allow` | `ALLOW` | 851 ms | ✓ |
| `bank-real-rbc` | legit-banking | `any-allow` | `ALLOW` | 842 ms | ✓ |
| `bank-real-wellsfargo` | legit-banking | `any-allow` | `ALLOW` | 771 ms | ✓ |
| `cloudflare-cdn-script` | legit-cdn | `any-allow` | `ALLOW` | 628 ms | ✓ |
| `google-fonts` | legit-cdn | `any-allow` | `ALLOW` | 607 ms | ✓ |
| `jsdelivr` | legit-cdn | `any-allow` | `ALLOW` | 639 ms | ✓ |
| `legit-cdn-jquery` | legit-cdn | `any-allow` | `ALLOW` | 645 ms | ✓ |
| `unpkg` | legit-cdn | `any-allow` | `ALLOW` | 676 ms | ✓ |
| `bbc-news` | legit-content | `any-allow` | `ALLOW` | 1042 ms | ✓ |
| `legit-content-medium` | legit-content | `any-allow` | `ALLOW` | 547 ms | ✓ |
| `legit-content-news-nytimes` | legit-content | `any-allow` | `ALLOW` | 925 ms | ✓ |
| `legit-content-reddit` | legit-content | `any-allow` | `ALLOW` | 645 ms | ✓ |
| `legit-content-substack` | legit-content | `any-allow` | `ALLOW` | 641 ms | ✓ |
| `mozilla-developer` | legit-content | `any-allow` | `ALLOW` | 634 ms | ✓ |
| `stackoverflow` | legit-content | `any-allow` | `ALLOW` | 812 ms | ✓ |
| `wikipedia` | legit-content | `any-allow` | `ALLOW` | 737 ms | ✓ |
| `claude-quickstart` | legit-dev | `any-allow` | `ALLOW` | 614 ms | ✓ |
| `legit-go-pkg` | legit-dev | `any-allow` | `ALLOW` | 833 ms | ✓ |
| `legit-python-docs` | legit-dev | `any-allow` | `ALLOW` | 869 ms | ✓ |
| `legit-rust-docs` | legit-dev | `any-allow` | `ALLOW` | 682 ms | ✓ |
| `rustup` | legit-dev | `any-allow` | `ALLOW` | 800 ms | ✓ |
| `apple-id-host` | legit-major | `any-allow` | `ALLOW` | 895 ms | ✓ |
| `cloudflare-corporate` | legit-major | `any-allow` | `ALLOW` | 658 ms | ✓ |
| `github` | legit-major | `any-allow` | `ALLOW` | 21237 ms | ✓ |
| `google-homepage` | legit-major | `any-allow` | `ALLOW` | 795 ms | ✓ |
| `legit-anthropic` | legit-major | `any-allow` | `ALLOW` | 586 ms | ✓ |
| `legit-aws-docs` | legit-major | `any-allow` | `ALLOW` | 711 ms | ✓ |
| `legit-microsoft-learn` | legit-major | `any-allow` | `ALLOW` | 694 ms | ✓ |
| `legit-openai` | legit-major | `any-allow` | `ALLOW` | 701 ms | ✓ |
| `legit-vercel` | legit-major | `any-allow` | `ALLOW` | 746 ms | ✓ |
| `microsoft-login` | legit-major | `any-allow` | `ALLOW` | 634 ms | ✓ |
| `paypal-homepage` | legit-major | `any-allow` | `ALLOW` | 902 ms | ✓ |
| `stripe-checkout-host` | legit-major | `any-allow` | `ALLOW` | 764 ms | ✓ |
| `payment-real-stripe-docs` | legit-payment | `any-allow` | `ALLOW` | 641 ms | ✓ |
| `legit-saas-airtable` | legit-saas | `any-allow` | `ALLOW` | 724 ms | ✓ |
| `legit-saas-canva` | legit-saas | `any-allow` | `ALLOW` | 538 ms | ✓ |
| `legit-saas-figma` | legit-saas | `any-allow` | `ALLOW` | 714 ms | ✓ |
| `legit-saas-linear` | legit-saas | `any-allow` | `ALLOW` | 628 ms | ✓ |
| `notion` | legit-saas | `any-allow` | `ALLOW` | 712 ms | ✓ |
| `slack-app` | legit-saas | `any-allow` | `ALLOW` | 807 ms | ✓ |
| `aws-console` | legit-sensitive | `any-allow` | `ALLOW` | 1025 ms | ✓ |
| `github-settings` | legit-sensitive | `any-allow` | `ALLOW` | 14466 ms | ✓ |
| `gmail-inbox` | legit-sensitive | `any-allow` | `ALLOW` | 14796 ms | ✓ |
| `benign-pixel-fb` | legit-tracker | `any-allow` | `ALLOW` | 658 ms | ✓ |
| `corrupt-protocol` | malformed | `any` | `ALLOW` | 643 ms | ✓ |
| `corrupt-spaces` | malformed | `any` | `ALLOW` | 634 ms | ✓ |
| `data-scheme` | malformed | `any` | `CLEAN` | 241 ms | ✓ |
| `javascript-scheme` | malformed | `any` | `CLEAN` | 180 ms | ✓ |
| `mfa-fake-duo` | mfa-bombing | `any-deny` | `ISOLATE` | 733 ms | ✓ |
| `mfa-fake-okta-push` | mfa-bombing | `any-deny` | `ISOLATE` | 688 ms | ✓ |
| `oauth-known-good-github-cli` | oauth-legit | `any-allow` | `ALLOW` | 25498 ms | ✓ |
| `oauth-known-good-vscode` | oauth-legit | `any-allow` | `ALLOW` | 18010 ms | ✓ |
| `oauth-legit-azure-cli` | oauth-legit | `any-allow` | `ALLOW` | 801 ms | ✓ |
| `oauth-legit-github-mobile` | oauth-legit | `any-allow` | `ALLOW` | 26907 ms | ✓ |
| `oauth-google-unknown-client-drive-scope` | oauth-phish | `any-deny` | `BLOCK` | 535 ms | ✓ |
| `oauth-microsoft-unknown-client-high-scope` | oauth-phish | `any-deny` | `BLOCK` | 535 ms | ✓ |
| `oauth-phish-pretend-gcloud` | oauth-phish | `any-deny` | `BLOCK` | 422 ms | ✓ |
| `oauth-phish-pretend-vscode` | oauth-phish | `any-deny` | `ALLOW` | 22576 ms | ✗ |
| `gift-card-scam-1` | payment-scam | `any-deny` | `ISOLATE` | 734 ms | ✓ |
| `payment-scam-customs-fee` | payment-scam | `any-deny` | `WARN` | 915 ms | ✓ |
| `payment-scam-fake-paypal-invoice` | payment-scam | `any-deny` | `BLOCK` | 751 ms | ✓ |
| `payment-scam-geek-squad-invoice` | payment-scam | `any-deny` | `WARN` | 924 ms | ✓ |
| `payment-scam-inheritance` | payment-scam | `any-deny` | `WARN` | 800 ms | ✓ |
| `payment-scam-lottery` | payment-scam | `any-deny` | `WARN` | 934 ms | ✓ |
| `payment-scam-medicare-refund` | payment-scam | `any-deny` | `WARN` | 766 ms | ✓ |
| `payment-scam-ssn-suspended` | payment-scam | `any-deny` | `WARN` | 861 ms | ✓ |
| `payment-scam-tax-refund-uk` | payment-scam | `any-deny` | `WARN` | 903 ms | ✓ |
| `wire-fraud-irs` | payment-scam | `any-deny` | `WARN` | 746 ms | ✓ |
| `piracy-multiple-1` | piracy-tld | `any` | `ALLOW` | 1099 ms | ✓ |
| `piracy-multiple-2` | piracy-tld | `any` | `ALLOW` | 11022 ms | ✓ |
| `piracy-tld-cc` | piracy-tld | `any` | `ALLOW` | 21794 ms | ✓ |
| `piracy-tld-pw` | piracy-tld | `any` | `ALLOW` | 873 ms | ✓ |
| `piracy-tld-to` | piracy-tld | `any` | `ALLOW` | 20764 ms | ✓ |
| `piracy-tld-ws` | piracy-tld | `any` | `ALLOW` | 1083 ms | ✓ |
| `punycode-google` | punycode | `any` | `WARN` | 656 ms | ✓ |
| `raw-ip-bare` | raw-ip | `any-deny` | `BLOCK` | 10924 ms | ✓ |
| `raw-ip-binary-drop` | raw-ip | `block` | `BLOCK` | 10937 ms | ✓ |
| `raw-ip-cn-vps` | raw-ip | `block` | `BLOCK` | 12886 ms | ✓ |
| `raw-ip-private-cgnat` | raw-ip | `any` | `BLOCK` | 10870 ms | ✓ |
| `login-on-fresh-unknown` | sensitive-unknown | `any-deny` | `ISOLATE` | 728 ms | ✓ |
| `payment-checkout-unknown` | sensitive-unknown | `any-deny` | `ISOLATE` | 679 ms | ✓ |
| `session-hijack-fake-signin` | session-hijack | `any-deny` | `ISOLATE` | 868 ms | ✓ |
| `session-hijack-fake-token` | session-hijack | `any-deny` | `ISOLATE` | 692 ms | ✓ |
| `github-io-tenant` | shared-host | `any` | `ALLOW` | 13841 ms | ✓ |
| `netlify-tenant` | shared-host | `any` | `ALLOW` | 20814 ms | ✓ |
| `shared-host-pages-dev` | shared-host | `any` | `ALLOW` | 849 ms | ✓ |
| `shared-host-wordpress` | shared-host | `any-allow` | `ALLOW` | 16090 ms | ✓ |
| `shared-host-workers-dev` | shared-host | `any` | `ALLOW` | 1043 ms | ✓ |
| `vercel-tenant` | shared-host | `any` | `ALLOW` | 13757 ms | ✓ |
| `bitly-home` | shortener | `any-allow` | `ALLOW` | 733 ms | ✓ |
| `shortener-bitly-corrupt` | shortener | `any` | `ALLOW` | 879 ms | ✓ |
| `tco-home` | shortener | `any-allow` | `ALLOW` | 608 ms | ✓ |
| `spoof-mimecast-host` | spoof-wrapper | `any-allow` | `ALLOW` | 811 ms | ✓ |
| `spoof-safelinks-host` | spoof-wrapper | `any-allow` | `ALLOW` | 929 ms | ✓ |
| `subdomain-spoof-google-accounts` | subdomain-spoof | `any-deny` | `ISOLATE` | 973 ms | ✓ |
| `subdomain-spoof-microsoft-login` | subdomain-spoof | `any-deny` | `ISOLATE` | 866 ms | ✓ |
| `subdomain-spoof-paypal` | subdomain-spoof | `any-deny` | `ISOLATE` | 854 ms | ✓ |
| `scam-amazon-support` | support-scam | `any-deny` | `WARN` | 993 ms | ✓ |
| `scam-google-virus-warning` | support-scam | `any-deny` | `WARN` | 1044 ms | ✓ |
| `scam-icloud-locked` | support-scam | `any-deny` | `ISOLATE` | 831 ms | ✓ |
| `scam-mcafee-renewal` | support-scam | `any-deny` | `ALLOW` | 804 ms | ✗ |
| `scam-norton-support` | support-scam | `any-deny` | `WARN` | 890 ms | ✓ |
| `scam-windows-error` | support-scam | `any-deny` | `WARN` | 754 ms | ✓ |
| `support-scam-apple-virus-alert` | support-scam | `any-deny` | `WARN` | 963 ms | ✓ |
| `support-scam-microsoft-helpline` | support-scam | `any-deny` | `WARN` | 895 ms | ✓ |
| `support-scam-windows-defender` | support-scam | `any-deny` | `WARN` | 867 ms | ✓ |
| `cctld-cf` | sus-tld | `any` | `ALLOW` | 983 ms | ✓ |
| `cctld-ga` | sus-tld | `any` | `ALLOW` | 886 ms | ✓ |
| `cctld-ml` | sus-tld | `any` | `ALLOW` | 11752 ms | ✓ |
| `tld-click` | sus-tld | `any` | `ALLOW` | 18996 ms | ✓ |
| `tld-tk` | sus-tld | `any` | `ALLOW` | 804 ms | ✓ |
| `tld-xyz` | sus-tld | `any` | `ALLOW` | 759 ms | ✓ |
| `brand-impersonation-google` | synth-phish | `any-deny` | `ISOLATE` | 941 ms | ✓ |
| `brand-impersonation-microsoft` | synth-phish | `any-deny` | `ISOLATE` | 671 ms | ✓ |
| `brand-impersonation-paypal` | synth-phish | `any-deny` | `ISOLATE` | 777 ms | ✓ |
| `homoglyph-google` | synth-phish | `any-deny` | `WARN` | 802 ms | ✓ |
| `random-host-login` | synth-phish | `any-deny` | `ISOLATE` | 607 ms | ✓ |
| `combosquat-paypal-account` | typosquat | `any-deny` | `ISOLATE` | 587 ms | ✓ |
| `homoglyph-amazon-zero-for-o` | typosquat | `any-deny` | `BLOCK` | 662 ms | ✓ |
| `homoglyph-microsoft-rn-for-m` | typosquat | `any-deny` | `BLOCK` | 729 ms | ✓ |
| `homoglyph-paypal-1-for-l` | typosquat | `any-deny` | `BLOCK` | 679 ms | ✓ |
| `typo-amazon-shuffle` | typosquat | `any-deny` | `BLOCK` | 767 ms | ✓ |
| `typo-google-h` | typosquat | `any-deny` | `WARN` | 982 ms | ✓ |
| `typo-google-letter-swap` | typosquat | `any-deny` | `WARN` | 877 ms | ✓ |
| `typo-microsoft-omission` | typosquat | `any-deny` | `BLOCK` | 689 ms | ✓ |
| `typo-paypal-double` | typosquat | `any-deny` | `BLOCK` | 706 ms | ✓ |
| `barracuda-benign` | wrapper-benign | `any-allow` | `ALLOW` | 12301 ms | ✓ |
| `cisco-securemail-benign` | wrapper-benign | `any-allow` | `ALLOW` | 9805 ms | ✓ |
| `gmail-link-redirect-benign` | wrapper-benign | `any-allow` | `ALLOW` | 12623 ms | ✓ |
| `proofpoint-v2-benign` | wrapper-benign | `any-allow` | `ALLOW` | 27652 ms | ✓ |
| `proofpoint-v3-format-benign` | wrapper-benign | `any-allow` | `ALLOW` | 13028 ms | ✓ |
| `safelinks-benign` | wrapper-benign | `any-allow` | `ALLOW` | 21021 ms | ✓ |
| `safelinks-multi-region-india` | wrapper-benign | `any-allow` | `ALLOW` | 23681 ms | ✓ |
| `safelinks-multi-region-jp` | wrapper-benign | `any-allow` | `ALLOW` | 28773 ms | ✓ |
| `symantec-clicktime-benign` | wrapper-benign | `any-allow` | `ALLOW` | 25491 ms | ✓ |
| `cisco-pointing-to-homoglyph` | wrapper-phish | `any-deny` | `BLOCK` | 724 ms | ✓ |
| `mimecast-pointing-at-fresh-host` | wrapper-phish | `any-deny` | `ISOLATE` | 784 ms | ✓ |
| `proofpoint-pointing-to-fresh-host` | wrapper-phish | `any-deny` | `ISOLATE` | 584 ms | ✓ |
| `safelinks-spoof-phish-target` | wrapper-phish | `any-deny` | `ISOLATE` | 940 ms | ✓ |
