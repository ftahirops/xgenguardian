# Smoke corpus report

- API base: `http://127.0.0.1:18080`
- Cases: **196**
- Pass: **196**  /  Fail: **0**  /  Rate: **100.0%**
- Wall-clock: 77.7 s

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
| oauth-phish | 4 | 0 | 4 | 100% |
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

_No failing cases._

## Detailed per-case results

| Case | Category | Expected | Actual | Latency | Pass |
| --- | --- | --- | --- | ---: | :---: |
| `benign-news-irs-tax` | benign-trigger | `any-allow` | `ALLOW` | 874 ms | ✓ |
| `benign-wikipedia-gift-card` | benign-trigger | `any-allow` | `ALLOW` | 874 ms | ✓ |
| `benign-wikipedia-phishing` | benign-trigger | `any-allow` | `ALLOW` | 927 ms | ✓ |
| `drainer-arbitrum-mint` | crypto-drainer | `any-deny` | `WARN` | 863 ms | ✓ |
| `drainer-blur-airdrop` | crypto-drainer | `any-deny` | `WARN` | 1017 ms | ✓ |
| `drainer-fake-claim-airdrop` | crypto-drainer | `any-deny` | `BLOCK` | 825 ms | ✓ |
| `drainer-fake-opensea` | crypto-drainer | `any-deny` | `WARN` | 1428 ms | ✓ |
| `drainer-fake-revoke` | crypto-drainer | `any-deny` | `ISOLATE` | 716 ms | ✓ |
| `drainer-metamask-update` | crypto-drainer | `any-deny` | `ISOLATE` | 849 ms | ✓ |
| `drainer-pancakeswap-airdrop` | crypto-drainer | `any-deny` | `BLOCK` | 818 ms | ✓ |
| `drainer-phantom-wallet` | crypto-drainer | `any-deny` | `ISOLATE` | 954 ms | ✓ |
| `drainer-revoke-cash-spoof` | crypto-drainer | `any-deny` | `ISOLATE` | 902 ms | ✓ |
| `drainer-trustwallet` | crypto-drainer | `any-deny` | `ISOLATE` | 1011 ms | ✓ |
| `drainer-uniswap-claim` | crypto-drainer | `any-deny` | `WARN` | 1110 ms | ✓ |
| `drainer-wallet-validate` | crypto-drainer | `any-deny` | `ISOLATE` | 1072 ms | ✓ |
| `direct-download-exe` | direct-download | `any-deny` | `ISOLATE` | 1022 ms | ✓ |
| `direct-download-jar` | direct-download | `any-deny` | `ISOLATE` | 981 ms | ✓ |
| `direct-download-msi` | direct-download | `any-deny` | `ISOLATE` | 1227 ms | ✓ |
| `edge-case-non-standard-tld` | edge-case | `any-allow` | `ALLOW` | 1016 ms | ✓ |
| `edge-case-numeric-domain` | edge-case | `any` | `ALLOW` | 857 ms | ✓ |
| `edge-case-very-long-url` | edge-case | `any-allow` | `ALLOW` | 720 ms | ✓ |
| `fqdn-trailing-dot` | edge-case | `any-allow` | `ALLOW` | 650 ms | ✓ |
| `hash-fragment-only` | edge-case | `any-allow` | `ALLOW` | 574 ms | ✓ |
| `nonstandard-port` | edge-case | `any-allow` | `ALLOW` | 711 ms | ✓ |
| `fake-bank-barclays` | fake-banking | `any-deny` | `ISOLATE` | 663 ms | ✓ |
| `fake-bank-deutsche` | fake-banking | `any-deny` | `ISOLATE` | 681 ms | ✓ |
| `fake-bank-hsbc` | fake-banking | `any-deny` | `ISOLATE` | 765 ms | ✓ |
| `fake-bank-natwest` | fake-banking | `any-deny` | `ISOLATE` | 749 ms | ✓ |
| `fake-bank-rbc` | fake-banking | `any-deny` | `ISOLATE` | 727 ms | ✓ |
| `fake-bank-santander` | fake-banking | `any-deny` | `ISOLATE` | 723 ms | ✓ |
| `fake-boa-mobile` | fake-banking | `any-deny` | `ISOLATE` | 830 ms | ✓ |
| `fake-chase-login` | fake-banking | `any-deny` | `ISOLATE` | 724 ms | ✓ |
| `fake-citibank-secure` | fake-banking | `any-deny` | `ISOLATE` | 681 ms | ✓ |
| `fake-wellsfargo-update` | fake-banking | `any-deny` | `ISOLATE` | 697 ms | ✓ |
| `fake-google-accounts-host` | fake-oauth-host | `any-deny` | `ISOLATE` | 745 ms | ✓ |
| `fake-microsoft-oauth-host` | fake-oauth-host | `any-deny` | `ISOLATE` | 748 ms | ✓ |
| `fresh-payment-new-bank-login` | fresh-payment | `any-deny` | `ISOLATE` | 874 ms | ✓ |
| `fresh-payment-wallet-connect` | fresh-payment | `any-deny` | `ISOLATE` | 769 ms | ✓ |
| `payment-fresh-cart` | fresh-payment | `any-deny` | `ISOLATE` | 1012 ms | ✓ |
| `payment-fresh-checkout` | fresh-payment | `any-deny` | `ISOLATE` | 770 ms | ✓ |
| `http-fresh-domain` | http-only | `any` | `ALLOW` | 761 ms | ✓ |
| `http-only-major` | http-only | `any-allow` | `ALLOW` | 712 ms | ✓ |
| `idn-amazon-cyrillic-a` | idn-homoglyph | `any-deny` | `WARN` | 847 ms | ✓ |
| `idn-apple-cyrillic-p` | idn-homoglyph | `any-deny` | `BLOCK` | 578 ms | ✓ |
| `idn-github-cyrillic-h` | idn-homoglyph | `any-deny` | `BLOCK` | 708 ms | ✓ |
| `idn-google-cyrillic-o` | idn-homoglyph | `any-deny` | `WARN` | 1000 ms | ✓ |
| `idn-microsoft-cyrillic-o` | idn-homoglyph | `any-deny` | `WARN` | 779 ms | ✓ |
| `idn-paypal-cyrillic-a` | idn-homoglyph | `any-deny` | `BLOCK` | 555 ms | ✓ |
| `dev-install-fake-docker` | install-lure | `any-deny` | `ISOLATE` | 1097 ms | ✓ |
| `dev-install-fake-go` | install-lure | `any-deny` | `ISOLATE` | 820 ms | ✓ |
| `dev-install-fake-rust` | install-lure | `any-deny` | `ISOLATE` | 995 ms | ✓ |
| `dev-install-fake-terraform` | install-lure | `any-deny` | `ISOLATE` | 943 ms | ✓ |
| `fake-anthropic-install` | install-lure | `any-deny` | `ISOLATE` | 1070 ms | ✓ |
| `fake-nodejs-install` | install-lure | `any-deny` | `ISOLATE` | 916 ms | ✓ |
| `bank-real-chase` | legit-banking | `any-allow` | `ALLOW` | 951 ms | ✓ |
| `bank-real-citi` | legit-banking | `any-allow` | `ALLOW` | 984 ms | ✓ |
| `bank-real-deutsche` | legit-banking | `any-allow` | `ALLOW` | 1010 ms | ✓ |
| `bank-real-hsbc` | legit-banking | `any-allow` | `ALLOW` | 968 ms | ✓ |
| `bank-real-rbc` | legit-banking | `any-allow` | `ALLOW` | 961 ms | ✓ |
| `bank-real-wellsfargo` | legit-banking | `any-allow` | `ALLOW` | 864 ms | ✓ |
| `cloudflare-cdn-script` | legit-cdn | `any-allow` | `ALLOW` | 671 ms | ✓ |
| `google-fonts` | legit-cdn | `any-allow` | `ALLOW` | 583 ms | ✓ |
| `jsdelivr` | legit-cdn | `any-allow` | `ALLOW` | 736 ms | ✓ |
| `legit-cdn-jquery` | legit-cdn | `any-allow` | `ALLOW` | 606 ms | ✓ |
| `unpkg` | legit-cdn | `any-allow` | `ALLOW` | 732 ms | ✓ |
| `bbc-news` | legit-content | `any-allow` | `ALLOW` | 990 ms | ✓ |
| `legit-content-medium` | legit-content | `any-allow` | `ALLOW` | 608 ms | ✓ |
| `legit-content-news-nytimes` | legit-content | `any-allow` | `ALLOW` | 801 ms | ✓ |
| `legit-content-reddit` | legit-content | `any-allow` | `ALLOW` | 826 ms | ✓ |
| `legit-content-substack` | legit-content | `any-allow` | `ALLOW` | 628 ms | ✓ |
| `mozilla-developer` | legit-content | `any-allow` | `ALLOW` | 744 ms | ✓ |
| `stackoverflow` | legit-content | `any-allow` | `ALLOW` | 580 ms | ✓ |
| `wikipedia` | legit-content | `any-allow` | `ALLOW` | 1026 ms | ✓ |
| `claude-quickstart` | legit-dev | `any-allow` | `ALLOW` | 817 ms | ✓ |
| `legit-go-pkg` | legit-dev | `any-allow` | `ALLOW` | 814 ms | ✓ |
| `legit-python-docs` | legit-dev | `any-allow` | `ALLOW` | 935 ms | ✓ |
| `legit-rust-docs` | legit-dev | `any-allow` | `ALLOW` | 896 ms | ✓ |
| `rustup` | legit-dev | `any-allow` | `ALLOW` | 990 ms | ✓ |
| `apple-id-host` | legit-major | `any-allow` | `ALLOW` | 968 ms | ✓ |
| `cloudflare-corporate` | legit-major | `any-allow` | `ALLOW` | 720 ms | ✓ |
| `github` | legit-major | `any-allow` | `ALLOW` | 17858 ms | ✓ |
| `google-homepage` | legit-major | `any-allow` | `ALLOW` | 768 ms | ✓ |
| `legit-anthropic` | legit-major | `any-allow` | `ALLOW` | 789 ms | ✓ |
| `legit-aws-docs` | legit-major | `any-allow` | `ALLOW` | 992 ms | ✓ |
| `legit-microsoft-learn` | legit-major | `any-allow` | `ALLOW` | 928 ms | ✓ |
| `legit-openai` | legit-major | `any-allow` | `ALLOW` | 693 ms | ✓ |
| `legit-vercel` | legit-major | `any-allow` | `ALLOW` | 756 ms | ✓ |
| `microsoft-login` | legit-major | `any-allow` | `ALLOW` | 779 ms | ✓ |
| `paypal-homepage` | legit-major | `any-allow` | `ALLOW` | 908 ms | ✓ |
| `stripe-checkout-host` | legit-major | `any-allow` | `ALLOW` | 860 ms | ✓ |
| `payment-real-stripe-docs` | legit-payment | `any-allow` | `ALLOW` | 688 ms | ✓ |
| `legit-saas-airtable` | legit-saas | `any-allow` | `ALLOW` | 926 ms | ✓ |
| `legit-saas-canva` | legit-saas | `any-allow` | `ALLOW` | 732 ms | ✓ |
| `legit-saas-figma` | legit-saas | `any-allow` | `ALLOW` | 700 ms | ✓ |
| `legit-saas-linear` | legit-saas | `any-allow` | `ALLOW` | 787 ms | ✓ |
| `notion` | legit-saas | `any-allow` | `ALLOW` | 565 ms | ✓ |
| `slack-app` | legit-saas | `any-allow` | `ALLOW` | 757 ms | ✓ |
| `aws-console` | legit-sensitive | `any-allow` | `ALLOW` | 1061 ms | ✓ |
| `github-settings` | legit-sensitive | `any-allow` | `ALLOW` | 6171 ms | ✓ |
| `gmail-inbox` | legit-sensitive | `any-allow` | `ALLOW` | 5557 ms | ✓ |
| `benign-pixel-fb` | legit-tracker | `any-allow` | `ALLOW` | 811 ms | ✓ |
| `corrupt-protocol` | malformed | `any` | `ALLOW` | 745 ms | ✓ |
| `corrupt-spaces` | malformed | `any` | `ALLOW` | 689 ms | ✓ |
| `data-scheme` | malformed | `any` | `CLEAN` | 169 ms | ✓ |
| `javascript-scheme` | malformed | `any` | `CLEAN` | 193 ms | ✓ |
| `mfa-fake-duo` | mfa-bombing | `any-deny` | `ISOLATE` | 694 ms | ✓ |
| `mfa-fake-okta-push` | mfa-bombing | `any-deny` | `ISOLATE` | 845 ms | ✓ |
| `oauth-known-good-github-cli` | oauth-legit | `any-allow` | `ALLOW` | 11765 ms | ✓ |
| `oauth-known-good-vscode` | oauth-legit | `any-allow` | `ALLOW` | 7545 ms | ✓ |
| `oauth-legit-azure-cli` | oauth-legit | `any-allow` | `ALLOW` | 721 ms | ✓ |
| `oauth-legit-github-mobile` | oauth-legit | `any-allow` | `ALLOW` | 4654 ms | ✓ |
| `oauth-google-unknown-client-drive-scope` | oauth-phish | `any-deny` | `BLOCK` | 667 ms | ✓ |
| `oauth-microsoft-unknown-client-high-scope` | oauth-phish | `any-deny` | `BLOCK` | 619 ms | ✓ |
| `oauth-phish-pretend-gcloud` | oauth-phish | `any-deny` | `BLOCK` | 671 ms | ✓ |
| `oauth-phish-pretend-vscode` | oauth-phish | `any-deny` | `BLOCK` | 4508 ms | ✓ |
| `gift-card-scam-1` | payment-scam | `any-deny` | `ISOLATE` | 1355 ms | ✓ |
| `payment-scam-customs-fee` | payment-scam | `any-deny` | `WARN` | 917 ms | ✓ |
| `payment-scam-fake-paypal-invoice` | payment-scam | `any-deny` | `BLOCK` | 712 ms | ✓ |
| `payment-scam-geek-squad-invoice` | payment-scam | `any-deny` | `WARN` | 887 ms | ✓ |
| `payment-scam-inheritance` | payment-scam | `any-deny` | `WARN` | 700 ms | ✓ |
| `payment-scam-lottery` | payment-scam | `any-deny` | `WARN` | 905 ms | ✓ |
| `payment-scam-medicare-refund` | payment-scam | `any-deny` | `WARN` | 785 ms | ✓ |
| `payment-scam-ssn-suspended` | payment-scam | `any-deny` | `WARN` | 893 ms | ✓ |
| `payment-scam-tax-refund-uk` | payment-scam | `any-deny` | `WARN` | 1026 ms | ✓ |
| `wire-fraud-irs` | payment-scam | `any-deny` | `WARN` | 905 ms | ✓ |
| `piracy-multiple-1` | piracy-tld | `any` | `ALLOW` | 1055 ms | ✓ |
| `piracy-multiple-2` | piracy-tld | `any` | `ALLOW` | 11020 ms | ✓ |
| `piracy-tld-cc` | piracy-tld | `any` | `WARN` | 15283 ms | ✓ |
| `piracy-tld-pw` | piracy-tld | `any` | `ALLOW` | 1597 ms | ✓ |
| `piracy-tld-to` | piracy-tld | `any` | `ALLOW` | 13595 ms | ✓ |
| `piracy-tld-ws` | piracy-tld | `any` | `ALLOW` | 1359 ms | ✓ |
| `punycode-google` | punycode | `any` | `WARN` | 869 ms | ✓ |
| `raw-ip-bare` | raw-ip | `any-deny` | `BLOCK` | 11082 ms | ✓ |
| `raw-ip-binary-drop` | raw-ip | `block` | `BLOCK` | 11144 ms | ✓ |
| `raw-ip-cn-vps` | raw-ip | `block` | `BLOCK` | 2672 ms | ✓ |
| `raw-ip-private-cgnat` | raw-ip | `any` | `BLOCK` | 10991 ms | ✓ |
| `login-on-fresh-unknown` | sensitive-unknown | `any-deny` | `ISOLATE` | 776 ms | ✓ |
| `payment-checkout-unknown` | sensitive-unknown | `any-deny` | `ISOLATE` | 760 ms | ✓ |
| `session-hijack-fake-signin` | session-hijack | `any-deny` | `ISOLATE` | 903 ms | ✓ |
| `session-hijack-fake-token` | session-hijack | `any-deny` | `ISOLATE` | 867 ms | ✓ |
| `github-io-tenant` | shared-host | `any` | `ALLOW` | 4121 ms | ✓ |
| `netlify-tenant` | shared-host | `any` | `ALLOW` | 5105 ms | ✓ |
| `shared-host-pages-dev` | shared-host | `any` | `ALLOW` | 986 ms | ✓ |
| `shared-host-wordpress` | shared-host | `any-allow` | `ALLOW` | 3757 ms | ✓ |
| `shared-host-workers-dev` | shared-host | `any` | `ALLOW` | 1025 ms | ✓ |
| `vercel-tenant` | shared-host | `any` | `ALLOW` | 3724 ms | ✓ |
| `bitly-home` | shortener | `any-allow` | `ALLOW` | 819 ms | ✓ |
| `shortener-bitly-corrupt` | shortener | `any` | `ALLOW` | 1263 ms | ✓ |
| `tco-home` | shortener | `any-allow` | `ALLOW` | 625 ms | ✓ |
| `spoof-mimecast-host` | spoof-wrapper | `any-allow` | `ALLOW` | 969 ms | ✓ |
| `spoof-safelinks-host` | spoof-wrapper | `any-allow` | `ALLOW` | 844 ms | ✓ |
| `subdomain-spoof-google-accounts` | subdomain-spoof | `any-deny` | `ISOLATE` | 809 ms | ✓ |
| `subdomain-spoof-microsoft-login` | subdomain-spoof | `any-deny` | `ISOLATE` | 748 ms | ✓ |
| `subdomain-spoof-paypal` | subdomain-spoof | `any-deny` | `ISOLATE` | 789 ms | ✓ |
| `scam-amazon-support` | support-scam | `any-deny` | `WARN` | 1001 ms | ✓ |
| `scam-google-virus-warning` | support-scam | `any-deny` | `WARN` | 962 ms | ✓ |
| `scam-icloud-locked` | support-scam | `any-deny` | `ISOLATE` | 783 ms | ✓ |
| `scam-mcafee-renewal` | support-scam | `any-deny` | `WARN` | 878 ms | ✓ |
| `scam-norton-support` | support-scam | `any-deny` | `WARN` | 931 ms | ✓ |
| `scam-windows-error` | support-scam | `any-deny` | `WARN` | 884 ms | ✓ |
| `support-scam-apple-virus-alert` | support-scam | `any-deny` | `WARN` | 915 ms | ✓ |
| `support-scam-microsoft-helpline` | support-scam | `any-deny` | `WARN` | 834 ms | ✓ |
| `support-scam-windows-defender` | support-scam | `any-deny` | `WARN` | 818 ms | ✓ |
| `cctld-cf` | sus-tld | `any` | `ALLOW` | 1073 ms | ✓ |
| `cctld-ga` | sus-tld | `any` | `ALLOW` | 1005 ms | ✓ |
| `cctld-ml` | sus-tld | `any` | `ALLOW` | 3540 ms | ✓ |
| `tld-click` | sus-tld | `any` | `ALLOW` | 13337 ms | ✓ |
| `tld-tk` | sus-tld | `any` | `ALLOW` | 985 ms | ✓ |
| `tld-xyz` | sus-tld | `any` | `ALLOW` | 1114 ms | ✓ |
| `brand-impersonation-google` | synth-phish | `any-deny` | `ISOLATE` | 924 ms | ✓ |
| `brand-impersonation-microsoft` | synth-phish | `any-deny` | `ISOLATE` | 884 ms | ✓ |
| `brand-impersonation-paypal` | synth-phish | `any-deny` | `ISOLATE` | 1073 ms | ✓ |
| `homoglyph-google` | synth-phish | `any-deny` | `WARN` | 1362 ms | ✓ |
| `random-host-login` | synth-phish | `any-deny` | `ISOLATE` | 903 ms | ✓ |
| `combosquat-paypal-account` | typosquat | `any-deny` | `ISOLATE` | 596 ms | ✓ |
| `homoglyph-amazon-zero-for-o` | typosquat | `any-deny` | `BLOCK` | 679 ms | ✓ |
| `homoglyph-microsoft-rn-for-m` | typosquat | `any-deny` | `BLOCK` | 763 ms | ✓ |
| `homoglyph-paypal-1-for-l` | typosquat | `any-deny` | `BLOCK` | 640 ms | ✓ |
| `typo-amazon-shuffle` | typosquat | `any-deny` | `BLOCK` | 888 ms | ✓ |
| `typo-google-h` | typosquat | `any-deny` | `WARN` | 910 ms | ✓ |
| `typo-google-letter-swap` | typosquat | `any-deny` | `WARN` | 1077 ms | ✓ |
| `typo-microsoft-omission` | typosquat | `any-deny` | `BLOCK` | 767 ms | ✓ |
| `typo-paypal-double` | typosquat | `any-deny` | `BLOCK` | 750 ms | ✓ |
| `barracuda-benign` | wrapper-benign | `any-allow` | `ALLOW` | 7015 ms | ✓ |
| `cisco-securemail-benign` | wrapper-benign | `any-allow` | `ALLOW` | 5541 ms | ✓ |
| `gmail-link-redirect-benign` | wrapper-benign | `any-allow` | `ALLOW` | 9001 ms | ✓ |
| `proofpoint-v2-benign` | wrapper-benign | `any-allow` | `ALLOW` | 12768 ms | ✓ |
| `proofpoint-v3-format-benign` | wrapper-benign | `any-allow` | `ALLOW` | 11754 ms | ✓ |
| `safelinks-benign` | wrapper-benign | `any-allow` | `ALLOW` | 18677 ms | ✓ |
| `safelinks-multi-region-india` | wrapper-benign | `any-allow` | `ALLOW` | 14890 ms | ✓ |
| `safelinks-multi-region-jp` | wrapper-benign | `any-allow` | `ALLOW` | 14473 ms | ✓ |
| `symantec-clicktime-benign` | wrapper-benign | `any-allow` | `ALLOW` | 13868 ms | ✓ |
| `cisco-pointing-to-homoglyph` | wrapper-phish | `any-deny` | `BLOCK` | 718 ms | ✓ |
| `mimecast-pointing-at-fresh-host` | wrapper-phish | `any-deny` | `ISOLATE` | 1064 ms | ✓ |
| `proofpoint-pointing-to-fresh-host` | wrapper-phish | `any-deny` | `ISOLATE` | 705 ms | ✓ |
| `safelinks-spoof-phish-target` | wrapper-phish | `any-deny` | `ISOLATE` | 1176 ms | ✓ |
