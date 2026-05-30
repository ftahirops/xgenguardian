# Smoke corpus report

- API base: `http://127.0.0.1:18080`
- Cases: **196**
- Pass: **195**  /  Fail: **1**  /  Rate: **99.5%**
- Wall-clock: 78.2 s

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
| support-scam | 9 | 0 | 9 | 100% |
| sus-tld | 6 | 0 | 6 | 100% |
| synth-phish | 5 | 0 | 5 | 100% |
| typosquat | 9 | 0 | 9 | 100% |
| wrapper-benign | 9 | 0 | 9 | 100% |
| wrapper-phish | 4 | 0 | 4 | 100% |

## Failing cases


| Case | Expected | Actual | Reason codes |
| --- | --- | --- | --- |
| `oauth-phish-pretend-vscode` | `any-deny` | `ALLOW` | — |

## Detailed per-case results

| Case | Category | Expected | Actual | Latency | Pass |
| --- | --- | --- | --- | ---: | :---: |
| `benign-news-irs-tax` | benign-trigger | `any-allow` | `ALLOW` | 960 ms | ✓ |
| `benign-wikipedia-gift-card` | benign-trigger | `any-allow` | `ALLOW` | 685 ms | ✓ |
| `benign-wikipedia-phishing` | benign-trigger | `any-allow` | `ALLOW` | 890 ms | ✓ |
| `drainer-arbitrum-mint` | crypto-drainer | `any-deny` | `WARN` | 792 ms | ✓ |
| `drainer-blur-airdrop` | crypto-drainer | `any-deny` | `WARN` | 999 ms | ✓ |
| `drainer-fake-claim-airdrop` | crypto-drainer | `any-deny` | `BLOCK` | 714 ms | ✓ |
| `drainer-fake-opensea` | crypto-drainer | `any-deny` | `WARN` | 972 ms | ✓ |
| `drainer-fake-revoke` | crypto-drainer | `any-deny` | `ISOLATE` | 803 ms | ✓ |
| `drainer-metamask-update` | crypto-drainer | `any-deny` | `ISOLATE` | 769 ms | ✓ |
| `drainer-pancakeswap-airdrop` | crypto-drainer | `any-deny` | `BLOCK` | 715 ms | ✓ |
| `drainer-phantom-wallet` | crypto-drainer | `any-deny` | `ISOLATE` | 774 ms | ✓ |
| `drainer-revoke-cash-spoof` | crypto-drainer | `any-deny` | `ISOLATE` | 973 ms | ✓ |
| `drainer-trustwallet` | crypto-drainer | `any-deny` | `ISOLATE` | 816 ms | ✓ |
| `drainer-uniswap-claim` | crypto-drainer | `any-deny` | `WARN` | 1488 ms | ✓ |
| `drainer-wallet-validate` | crypto-drainer | `any-deny` | `ISOLATE` | 844 ms | ✓ |
| `direct-download-exe` | direct-download | `any-deny` | `ISOLATE` | 1023 ms | ✓ |
| `direct-download-jar` | direct-download | `any-deny` | `ISOLATE` | 1021 ms | ✓ |
| `direct-download-msi` | direct-download | `any-deny` | `ISOLATE` | 1038 ms | ✓ |
| `edge-case-non-standard-tld` | edge-case | `any-allow` | `ALLOW` | 1138 ms | ✓ |
| `edge-case-numeric-domain` | edge-case | `any` | `ALLOW` | 885 ms | ✓ |
| `edge-case-very-long-url` | edge-case | `any-allow` | `ALLOW` | 633 ms | ✓ |
| `fqdn-trailing-dot` | edge-case | `any-allow` | `ALLOW` | 618 ms | ✓ |
| `hash-fragment-only` | edge-case | `any-allow` | `ALLOW` | 760 ms | ✓ |
| `nonstandard-port` | edge-case | `any-allow` | `ALLOW` | 613 ms | ✓ |
| `fake-bank-barclays` | fake-banking | `any-deny` | `ISOLATE` | 719 ms | ✓ |
| `fake-bank-deutsche` | fake-banking | `any-deny` | `ISOLATE` | 696 ms | ✓ |
| `fake-bank-hsbc` | fake-banking | `any-deny` | `ISOLATE` | 726 ms | ✓ |
| `fake-bank-natwest` | fake-banking | `any-deny` | `ISOLATE` | 680 ms | ✓ |
| `fake-bank-rbc` | fake-banking | `any-deny` | `ISOLATE` | 722 ms | ✓ |
| `fake-bank-santander` | fake-banking | `any-deny` | `ISOLATE` | 676 ms | ✓ |
| `fake-boa-mobile` | fake-banking | `any-deny` | `ISOLATE` | 695 ms | ✓ |
| `fake-chase-login` | fake-banking | `any-deny` | `ISOLATE` | 702 ms | ✓ |
| `fake-citibank-secure` | fake-banking | `any-deny` | `ISOLATE` | 692 ms | ✓ |
| `fake-wellsfargo-update` | fake-banking | `any-deny` | `ISOLATE` | 702 ms | ✓ |
| `fake-google-accounts-host` | fake-oauth-host | `any-deny` | `ISOLATE` | 622 ms | ✓ |
| `fake-microsoft-oauth-host` | fake-oauth-host | `any-deny` | `ISOLATE` | 967 ms | ✓ |
| `fresh-payment-new-bank-login` | fresh-payment | `any-deny` | `ISOLATE` | 781 ms | ✓ |
| `fresh-payment-wallet-connect` | fresh-payment | `any-deny` | `ISOLATE` | 774 ms | ✓ |
| `payment-fresh-cart` | fresh-payment | `any-deny` | `ISOLATE` | 685 ms | ✓ |
| `payment-fresh-checkout` | fresh-payment | `any-deny` | `ISOLATE` | 716 ms | ✓ |
| `http-fresh-domain` | http-only | `any` | `ALLOW` | 894 ms | ✓ |
| `http-only-major` | http-only | `any-allow` | `ALLOW` | 771 ms | ✓ |
| `idn-amazon-cyrillic-a` | idn-homoglyph | `any-deny` | `WARN` | 863 ms | ✓ |
| `idn-apple-cyrillic-p` | idn-homoglyph | `any-deny` | `BLOCK` | 585 ms | ✓ |
| `idn-github-cyrillic-h` | idn-homoglyph | `any-deny` | `BLOCK` | 789 ms | ✓ |
| `idn-google-cyrillic-o` | idn-homoglyph | `any-deny` | `WARN` | 776 ms | ✓ |
| `idn-microsoft-cyrillic-o` | idn-homoglyph | `any-deny` | `WARN` | 915 ms | ✓ |
| `idn-paypal-cyrillic-a` | idn-homoglyph | `any-deny` | `BLOCK` | 618 ms | ✓ |
| `dev-install-fake-docker` | install-lure | `any-deny` | `ISOLATE` | 942 ms | ✓ |
| `dev-install-fake-go` | install-lure | `any-deny` | `ISOLATE` | 897 ms | ✓ |
| `dev-install-fake-rust` | install-lure | `any-deny` | `ISOLATE` | 866 ms | ✓ |
| `dev-install-fake-terraform` | install-lure | `any-deny` | `ISOLATE` | 857 ms | ✓ |
| `fake-anthropic-install` | install-lure | `any-deny` | `ISOLATE` | 885 ms | ✓ |
| `fake-nodejs-install` | install-lure | `any-deny` | `ISOLATE` | 1265 ms | ✓ |
| `bank-real-chase` | legit-banking | `any-allow` | `ALLOW` | 1027 ms | ✓ |
| `bank-real-citi` | legit-banking | `any-allow` | `ALLOW` | 775 ms | ✓ |
| `bank-real-deutsche` | legit-banking | `any-allow` | `ALLOW` | 946 ms | ✓ |
| `bank-real-hsbc` | legit-banking | `any-allow` | `ALLOW` | 952 ms | ✓ |
| `bank-real-rbc` | legit-banking | `any-allow` | `ALLOW` | 1022 ms | ✓ |
| `bank-real-wellsfargo` | legit-banking | `any-allow` | `ALLOW` | 940 ms | ✓ |
| `cloudflare-cdn-script` | legit-cdn | `any-allow` | `ALLOW` | 512 ms | ✓ |
| `google-fonts` | legit-cdn | `any-allow` | `ALLOW` | 696 ms | ✓ |
| `jsdelivr` | legit-cdn | `any-allow` | `ALLOW` | 741 ms | ✓ |
| `legit-cdn-jquery` | legit-cdn | `any-allow` | `ALLOW` | 677 ms | ✓ |
| `unpkg` | legit-cdn | `any-allow` | `ALLOW` | 616 ms | ✓ |
| `bbc-news` | legit-content | `any-allow` | `ALLOW` | 817 ms | ✓ |
| `legit-content-medium` | legit-content | `any-allow` | `ALLOW` | 587 ms | ✓ |
| `legit-content-news-nytimes` | legit-content | `any-allow` | `ALLOW` | 897 ms | ✓ |
| `legit-content-reddit` | legit-content | `any-allow` | `ALLOW` | 660 ms | ✓ |
| `legit-content-substack` | legit-content | `any-allow` | `ALLOW` | 659 ms | ✓ |
| `mozilla-developer` | legit-content | `any-allow` | `ALLOW` | 1008 ms | ✓ |
| `stackoverflow` | legit-content | `any-allow` | `ALLOW` | 795 ms | ✓ |
| `wikipedia` | legit-content | `any-allow` | `ALLOW` | 1002 ms | ✓ |
| `claude-quickstart` | legit-dev | `any-allow` | `ALLOW` | 679 ms | ✓ |
| `legit-go-pkg` | legit-dev | `any-allow` | `ALLOW` | 806 ms | ✓ |
| `legit-python-docs` | legit-dev | `any-allow` | `ALLOW` | 884 ms | ✓ |
| `legit-rust-docs` | legit-dev | `any-allow` | `ALLOW` | 848 ms | ✓ |
| `rustup` | legit-dev | `any-allow` | `ALLOW` | 1000 ms | ✓ |
| `apple-id-host` | legit-major | `any-allow` | `ALLOW` | 958 ms | ✓ |
| `cloudflare-corporate` | legit-major | `any-allow` | `ALLOW` | 778 ms | ✓ |
| `github` | legit-major | `any-allow` | `ALLOW` | 21905 ms | ✓ |
| `google-homepage` | legit-major | `any-allow` | `ALLOW` | 734 ms | ✓ |
| `legit-anthropic` | legit-major | `any-allow` | `ALLOW` | 727 ms | ✓ |
| `legit-aws-docs` | legit-major | `any-allow` | `ALLOW` | 963 ms | ✓ |
| `legit-microsoft-learn` | legit-major | `any-allow` | `ALLOW` | 884 ms | ✓ |
| `legit-openai` | legit-major | `any-allow` | `ALLOW` | 741 ms | ✓ |
| `legit-vercel` | legit-major | `any-allow` | `ALLOW` | 693 ms | ✓ |
| `microsoft-login` | legit-major | `any-allow` | `ALLOW` | 751 ms | ✓ |
| `paypal-homepage` | legit-major | `any-allow` | `ALLOW` | 940 ms | ✓ |
| `stripe-checkout-host` | legit-major | `any-allow` | `ALLOW` | 821 ms | ✓ |
| `payment-real-stripe-docs` | legit-payment | `any-allow` | `ALLOW` | 700 ms | ✓ |
| `legit-saas-airtable` | legit-saas | `any-allow` | `ALLOW` | 954 ms | ✓ |
| `legit-saas-canva` | legit-saas | `any-allow` | `ALLOW` | 804 ms | ✓ |
| `legit-saas-figma` | legit-saas | `any-allow` | `ALLOW` | 818 ms | ✓ |
| `legit-saas-linear` | legit-saas | `any-allow` | `ALLOW` | 760 ms | ✓ |
| `notion` | legit-saas | `any-allow` | `ALLOW` | 602 ms | ✓ |
| `slack-app` | legit-saas | `any-allow` | `ALLOW` | 829 ms | ✓ |
| `aws-console` | legit-sensitive | `any-allow` | `ALLOW` | 947 ms | ✓ |
| `github-settings` | legit-sensitive | `any-allow` | `ALLOW` | 5902 ms | ✓ |
| `gmail-inbox` | legit-sensitive | `any-allow` | `ALLOW` | 6148 ms | ✓ |
| `benign-pixel-fb` | legit-tracker | `any-allow` | `ALLOW` | 800 ms | ✓ |
| `corrupt-protocol` | malformed | `any` | `ALLOW` | 869 ms | ✓ |
| `corrupt-spaces` | malformed | `any` | `ALLOW` | 595 ms | ✓ |
| `data-scheme` | malformed | `any` | `CLEAN` | 160 ms | ✓ |
| `javascript-scheme` | malformed | `any` | `CLEAN` | 179 ms | ✓ |
| `mfa-fake-duo` | mfa-bombing | `any-deny` | `ISOLATE` | 830 ms | ✓ |
| `mfa-fake-okta-push` | mfa-bombing | `any-deny` | `ISOLATE` | 638 ms | ✓ |
| `oauth-known-good-github-cli` | oauth-legit | `any-allow` | `ALLOW` | 6918 ms | ✓ |
| `oauth-known-good-vscode` | oauth-legit | `any-allow` | `ALLOW` | 11040 ms | ✓ |
| `oauth-legit-azure-cli` | oauth-legit | `any-allow` | `ALLOW` | 584 ms | ✓ |
| `oauth-legit-github-mobile` | oauth-legit | `any-allow` | `ALLOW` | 4384 ms | ✓ |
| `oauth-google-unknown-client-drive-scope` | oauth-phish | `any-deny` | `BLOCK` | 724 ms | ✓ |
| `oauth-microsoft-unknown-client-high-scope` | oauth-phish | `any-deny` | `BLOCK` | 752 ms | ✓ |
| `oauth-phish-pretend-gcloud` | oauth-phish | `any-deny` | `BLOCK` | 674 ms | ✓ |
| `oauth-phish-pretend-vscode` | oauth-phish | `any-deny` | `ALLOW` | 4298 ms | ✗ |
| `gift-card-scam-1` | payment-scam | `any-deny` | `ISOLATE` | 680 ms | ✓ |
| `payment-scam-customs-fee` | payment-scam | `any-deny` | `WARN` | 756 ms | ✓ |
| `payment-scam-fake-paypal-invoice` | payment-scam | `any-deny` | `BLOCK` | 720 ms | ✓ |
| `payment-scam-geek-squad-invoice` | payment-scam | `any-deny` | `WARN` | 814 ms | ✓ |
| `payment-scam-inheritance` | payment-scam | `any-deny` | `WARN` | 862 ms | ✓ |
| `payment-scam-lottery` | payment-scam | `any-deny` | `WARN` | 930 ms | ✓ |
| `payment-scam-medicare-refund` | payment-scam | `any-deny` | `WARN` | 902 ms | ✓ |
| `payment-scam-ssn-suspended` | payment-scam | `any-deny` | `WARN` | 808 ms | ✓ |
| `payment-scam-tax-refund-uk` | payment-scam | `any-deny` | `WARN` | 953 ms | ✓ |
| `wire-fraud-irs` | payment-scam | `any-deny` | `WARN` | 884 ms | ✓ |
| `piracy-multiple-1` | piracy-tld | `any` | `ALLOW` | 1301 ms | ✓ |
| `piracy-multiple-2` | piracy-tld | `any` | `ALLOW` | 10985 ms | ✓ |
| `piracy-tld-cc` | piracy-tld | `any` | `WARN` | 16882 ms | ✓ |
| `piracy-tld-pw` | piracy-tld | `any` | `ALLOW` | 1382 ms | ✓ |
| `piracy-tld-to` | piracy-tld | `any` | `ALLOW` | 15139 ms | ✓ |
| `piracy-tld-ws` | piracy-tld | `any` | `ALLOW` | 1311 ms | ✓ |
| `punycode-google` | punycode | `any` | `WARN` | 691 ms | ✓ |
| `raw-ip-bare` | raw-ip | `any-deny` | `BLOCK` | 11271 ms | ✓ |
| `raw-ip-binary-drop` | raw-ip | `block` | `BLOCK` | 11415 ms | ✓ |
| `raw-ip-cn-vps` | raw-ip | `block` | `BLOCK` | 2786 ms | ✓ |
| `raw-ip-private-cgnat` | raw-ip | `any` | `BLOCK` | 10879 ms | ✓ |
| `login-on-fresh-unknown` | sensitive-unknown | `any-deny` | `ISOLATE` | 855 ms | ✓ |
| `payment-checkout-unknown` | sensitive-unknown | `any-deny` | `ISOLATE` | 548 ms | ✓ |
| `session-hijack-fake-signin` | session-hijack | `any-deny` | `ISOLATE` | 756 ms | ✓ |
| `session-hijack-fake-token` | session-hijack | `any-deny` | `ISOLATE` | 757 ms | ✓ |
| `github-io-tenant` | shared-host | `any` | `ALLOW` | 5782 ms | ✓ |
| `netlify-tenant` | shared-host | `any` | `ALLOW` | 5753 ms | ✓ |
| `shared-host-pages-dev` | shared-host | `any` | `ALLOW` | 961 ms | ✓ |
| `shared-host-wordpress` | shared-host | `any-allow` | `ALLOW` | 3969 ms | ✓ |
| `shared-host-workers-dev` | shared-host | `any` | `ALLOW` | 939 ms | ✓ |
| `vercel-tenant` | shared-host | `any` | `ALLOW` | 3809 ms | ✓ |
| `bitly-home` | shortener | `any-allow` | `ALLOW` | 741 ms | ✓ |
| `shortener-bitly-corrupt` | shortener | `any` | `ALLOW` | 954 ms | ✓ |
| `tco-home` | shortener | `any-allow` | `ALLOW` | 591 ms | ✓ |
| `spoof-mimecast-host` | spoof-wrapper | `any-allow` | `ALLOW` | 848 ms | ✓ |
| `spoof-safelinks-host` | spoof-wrapper | `any-allow` | `ALLOW` | 917 ms | ✓ |
| `subdomain-spoof-google-accounts` | subdomain-spoof | `any-deny` | `ISOLATE` | 713 ms | ✓ |
| `subdomain-spoof-microsoft-login` | subdomain-spoof | `any-deny` | `ISOLATE` | 680 ms | ✓ |
| `subdomain-spoof-paypal` | subdomain-spoof | `any-deny` | `ISOLATE` | 845 ms | ✓ |
| `scam-amazon-support` | support-scam | `any-deny` | `WARN` | 874 ms | ✓ |
| `scam-google-virus-warning` | support-scam | `any-deny` | `WARN` | 1069 ms | ✓ |
| `scam-icloud-locked` | support-scam | `any-deny` | `ISOLATE` | 771 ms | ✓ |
| `scam-mcafee-renewal` | support-scam | `any-deny` | `WARN` | 870 ms | ✓ |
| `scam-norton-support` | support-scam | `any-deny` | `WARN` | 779 ms | ✓ |
| `scam-windows-error` | support-scam | `any-deny` | `WARN` | 778 ms | ✓ |
| `support-scam-apple-virus-alert` | support-scam | `any-deny` | `WARN` | 852 ms | ✓ |
| `support-scam-microsoft-helpline` | support-scam | `any-deny` | `WARN` | 804 ms | ✓ |
| `support-scam-windows-defender` | support-scam | `any-deny` | `WARN` | 783 ms | ✓ |
| `cctld-cf` | sus-tld | `any` | `ALLOW` | 837 ms | ✓ |
| `cctld-ga` | sus-tld | `any` | `ALLOW` | 936 ms | ✓ |
| `cctld-ml` | sus-tld | `any` | `ALLOW` | 4720 ms | ✓ |
| `tld-click` | sus-tld | `any` | `ALLOW` | 7195 ms | ✓ |
| `tld-tk` | sus-tld | `any` | `ALLOW` | 1166 ms | ✓ |
| `tld-xyz` | sus-tld | `any` | `ALLOW` | 835 ms | ✓ |
| `brand-impersonation-google` | synth-phish | `any-deny` | `ISOLATE` | 1194 ms | ✓ |
| `brand-impersonation-microsoft` | synth-phish | `any-deny` | `ISOLATE` | 904 ms | ✓ |
| `brand-impersonation-paypal` | synth-phish | `any-deny` | `ISOLATE` | 1159 ms | ✓ |
| `homoglyph-google` | synth-phish | `any-deny` | `WARN` | 1339 ms | ✓ |
| `random-host-login` | synth-phish | `any-deny` | `ISOLATE` | 910 ms | ✓ |
| `combosquat-paypal-account` | typosquat | `any-deny` | `ISOLATE` | 798 ms | ✓ |
| `homoglyph-amazon-zero-for-o` | typosquat | `any-deny` | `BLOCK` | 599 ms | ✓ |
| `homoglyph-microsoft-rn-for-m` | typosquat | `any-deny` | `BLOCK` | 740 ms | ✓ |
| `homoglyph-paypal-1-for-l` | typosquat | `any-deny` | `BLOCK` | 662 ms | ✓ |
| `typo-amazon-shuffle` | typosquat | `any-deny` | `BLOCK` | 645 ms | ✓ |
| `typo-google-h` | typosquat | `any-deny` | `WARN` | 953 ms | ✓ |
| `typo-google-letter-swap` | typosquat | `any-deny` | `WARN` | 925 ms | ✓ |
| `typo-microsoft-omission` | typosquat | `any-deny` | `BLOCK` | 686 ms | ✓ |
| `typo-paypal-double` | typosquat | `any-deny` | `BLOCK` | 648 ms | ✓ |
| `barracuda-benign` | wrapper-benign | `any-allow` | `ALLOW` | 7492 ms | ✓ |
| `cisco-securemail-benign` | wrapper-benign | `any-allow` | `ALLOW` | 5648 ms | ✓ |
| `gmail-link-redirect-benign` | wrapper-benign | `any-allow` | `ALLOW` | 9524 ms | ✓ |
| `proofpoint-v2-benign` | wrapper-benign | `any-allow` | `ALLOW` | 13499 ms | ✓ |
| `proofpoint-v3-format-benign` | wrapper-benign | `any-allow` | `ALLOW` | 12280 ms | ✓ |
| `safelinks-benign` | wrapper-benign | `any-allow` | `ALLOW` | 20166 ms | ✓ |
| `safelinks-multi-region-india` | wrapper-benign | `any-allow` | `ALLOW` | 15275 ms | ✓ |
| `safelinks-multi-region-jp` | wrapper-benign | `any-allow` | `ALLOW` | 15141 ms | ✓ |
| `symantec-clicktime-benign` | wrapper-benign | `any-allow` | `ALLOW` | 14934 ms | ✓ |
| `cisco-pointing-to-homoglyph` | wrapper-phish | `any-deny` | `BLOCK` | 668 ms | ✓ |
| `mimecast-pointing-at-fresh-host` | wrapper-phish | `any-deny` | `ISOLATE` | 842 ms | ✓ |
| `proofpoint-pointing-to-fresh-host` | wrapper-phish | `any-deny` | `ISOLATE` | 753 ms | ✓ |
| `safelinks-spoof-phish-target` | wrapper-phish | `any-deny` | `ISOLATE` | 919 ms | ✓ |
