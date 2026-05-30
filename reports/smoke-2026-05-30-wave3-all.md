# Smoke corpus report

- API base: `http://127.0.0.1:18080`
- Cases: **196**
- Pass: **192**  /  Fail: **4**  /  Rate: **98.0%**
- Wall-clock: 81.4 s

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
| wrapper-benign | 6 | 3 | 9 | 67% |
| wrapper-phish | 4 | 0 | 4 | 100% |

## Failing cases


| Case | Expected | Actual | Reason codes |
| --- | --- | --- | --- |
| `proofpoint-v2-benign` | `any-allow` | `WARN` | HIDDEN_IFRAME_CROSS_ORIGIN, HIDDEN_MALICIOUS_LINK |
| `safelinks-multi-region-jp` | `any-allow` | `WARN` | HIDDEN_IFRAME_CROSS_ORIGIN, HIDDEN_MALICIOUS_LINK |
| `symantec-clicktime-benign` | `any-allow` | `WARN` | HIDDEN_IFRAME_CROSS_ORIGIN, HIDDEN_MALICIOUS_LINK |
| `oauth-phish-pretend-vscode` | `any-deny` | `ALLOW` | — |

## Detailed per-case results

| Case | Category | Expected | Actual | Latency | Pass |
| --- | --- | --- | --- | ---: | :---: |
| `benign-news-irs-tax` | benign-trigger | `any-allow` | `ALLOW` | 857 ms | ✓ |
| `benign-wikipedia-gift-card` | benign-trigger | `any-allow` | `ALLOW` | 812 ms | ✓ |
| `benign-wikipedia-phishing` | benign-trigger | `any-allow` | `ALLOW` | 822 ms | ✓ |
| `drainer-arbitrum-mint` | crypto-drainer | `any-deny` | `WARN` | 870 ms | ✓ |
| `drainer-blur-airdrop` | crypto-drainer | `any-deny` | `WARN` | 913 ms | ✓ |
| `drainer-fake-claim-airdrop` | crypto-drainer | `any-deny` | `BLOCK` | 665 ms | ✓ |
| `drainer-fake-opensea` | crypto-drainer | `any-deny` | `WARN` | 982 ms | ✓ |
| `drainer-fake-revoke` | crypto-drainer | `any-deny` | `ISOLATE` | 803 ms | ✓ |
| `drainer-metamask-update` | crypto-drainer | `any-deny` | `ISOLATE` | 752 ms | ✓ |
| `drainer-pancakeswap-airdrop` | crypto-drainer | `any-deny` | `BLOCK` | 996 ms | ✓ |
| `drainer-phantom-wallet` | crypto-drainer | `any-deny` | `ISOLATE` | 775 ms | ✓ |
| `drainer-revoke-cash-spoof` | crypto-drainer | `any-deny` | `ISOLATE` | 911 ms | ✓ |
| `drainer-trustwallet` | crypto-drainer | `any-deny` | `ISOLATE` | 848 ms | ✓ |
| `drainer-uniswap-claim` | crypto-drainer | `any-deny` | `WARN` | 1199 ms | ✓ |
| `drainer-wallet-validate` | crypto-drainer | `any-deny` | `ISOLATE` | 723 ms | ✓ |
| `direct-download-exe` | direct-download | `any-deny` | `ISOLATE` | 1116 ms | ✓ |
| `direct-download-jar` | direct-download | `any-deny` | `ISOLATE` | 1077 ms | ✓ |
| `direct-download-msi` | direct-download | `any-deny` | `ISOLATE` | 1248 ms | ✓ |
| `edge-case-non-standard-tld` | edge-case | `any-allow` | `ALLOW` | 1139 ms | ✓ |
| `edge-case-numeric-domain` | edge-case | `any` | `ALLOW` | 942 ms | ✓ |
| `edge-case-very-long-url` | edge-case | `any-allow` | `ALLOW` | 632 ms | ✓ |
| `fqdn-trailing-dot` | edge-case | `any-allow` | `ALLOW` | 634 ms | ✓ |
| `hash-fragment-only` | edge-case | `any-allow` | `ALLOW` | 500 ms | ✓ |
| `nonstandard-port` | edge-case | `any-allow` | `ALLOW` | 636 ms | ✓ |
| `fake-bank-barclays` | fake-banking | `any-deny` | `ISOLATE` | 629 ms | ✓ |
| `fake-bank-deutsche` | fake-banking | `any-deny` | `ISOLATE` | 682 ms | ✓ |
| `fake-bank-hsbc` | fake-banking | `any-deny` | `ISOLATE` | 705 ms | ✓ |
| `fake-bank-natwest` | fake-banking | `any-deny` | `ISOLATE` | 676 ms | ✓ |
| `fake-bank-rbc` | fake-banking | `any-deny` | `ISOLATE` | 819 ms | ✓ |
| `fake-bank-santander` | fake-banking | `any-deny` | `ISOLATE` | 752 ms | ✓ |
| `fake-boa-mobile` | fake-banking | `any-deny` | `ISOLATE` | 709 ms | ✓ |
| `fake-chase-login` | fake-banking | `any-deny` | `ISOLATE` | 742 ms | ✓ |
| `fake-citibank-secure` | fake-banking | `any-deny` | `ISOLATE` | 698 ms | ✓ |
| `fake-wellsfargo-update` | fake-banking | `any-deny` | `ISOLATE` | 675 ms | ✓ |
| `fake-google-accounts-host` | fake-oauth-host | `any-deny` | `ISOLATE` | 716 ms | ✓ |
| `fake-microsoft-oauth-host` | fake-oauth-host | `any-deny` | `ISOLATE` | 736 ms | ✓ |
| `fresh-payment-new-bank-login` | fresh-payment | `any-deny` | `ISOLATE` | 808 ms | ✓ |
| `fresh-payment-wallet-connect` | fresh-payment | `any-deny` | `ISOLATE` | 765 ms | ✓ |
| `payment-fresh-cart` | fresh-payment | `any-deny` | `ISOLATE` | 643 ms | ✓ |
| `payment-fresh-checkout` | fresh-payment | `any-deny` | `ISOLATE` | 710 ms | ✓ |
| `http-fresh-domain` | http-only | `any` | `ALLOW` | 865 ms | ✓ |
| `http-only-major` | http-only | `any-allow` | `ALLOW` | 615 ms | ✓ |
| `idn-amazon-cyrillic-a` | idn-homoglyph | `any-deny` | `WARN` | 774 ms | ✓ |
| `idn-apple-cyrillic-p` | idn-homoglyph | `any-deny` | `BLOCK` | 618 ms | ✓ |
| `idn-github-cyrillic-h` | idn-homoglyph | `any-deny` | `BLOCK` | 667 ms | ✓ |
| `idn-google-cyrillic-o` | idn-homoglyph | `any-deny` | `WARN` | 902 ms | ✓ |
| `idn-microsoft-cyrillic-o` | idn-homoglyph | `any-deny` | `WARN` | 808 ms | ✓ |
| `idn-paypal-cyrillic-a` | idn-homoglyph | `any-deny` | `BLOCK` | 629 ms | ✓ |
| `dev-install-fake-docker` | install-lure | `any-deny` | `ISOLATE` | 1222 ms | ✓ |
| `dev-install-fake-go` | install-lure | `any-deny` | `ISOLATE` | 1014 ms | ✓ |
| `dev-install-fake-rust` | install-lure | `any-deny` | `ISOLATE` | 1152 ms | ✓ |
| `dev-install-fake-terraform` | install-lure | `any-deny` | `ISOLATE` | 1261 ms | ✓ |
| `fake-anthropic-install` | install-lure | `any-deny` | `ISOLATE` | 1214 ms | ✓ |
| `fake-nodejs-install` | install-lure | `any-deny` | `ISOLATE` | 1079 ms | ✓ |
| `bank-real-chase` | legit-banking | `any-allow` | `ALLOW` | 961 ms | ✓ |
| `bank-real-citi` | legit-banking | `any-allow` | `ALLOW` | 919 ms | ✓ |
| `bank-real-deutsche` | legit-banking | `any-allow` | `ALLOW` | 1054 ms | ✓ |
| `bank-real-hsbc` | legit-banking | `any-allow` | `ALLOW` | 868 ms | ✓ |
| `bank-real-rbc` | legit-banking | `any-allow` | `ALLOW` | 930 ms | ✓ |
| `bank-real-wellsfargo` | legit-banking | `any-allow` | `ALLOW` | 914 ms | ✓ |
| `cloudflare-cdn-script` | legit-cdn | `any-allow` | `ALLOW` | 593 ms | ✓ |
| `google-fonts` | legit-cdn | `any-allow` | `ALLOW` | 709 ms | ✓ |
| `jsdelivr` | legit-cdn | `any-allow` | `ALLOW` | 770 ms | ✓ |
| `legit-cdn-jquery` | legit-cdn | `any-allow` | `ALLOW` | 658 ms | ✓ |
| `unpkg` | legit-cdn | `any-allow` | `ALLOW` | 693 ms | ✓ |
| `bbc-news` | legit-content | `any-allow` | `ALLOW` | 747 ms | ✓ |
| `legit-content-medium` | legit-content | `any-allow` | `ALLOW` | 688 ms | ✓ |
| `legit-content-news-nytimes` | legit-content | `any-allow` | `ALLOW` | 871 ms | ✓ |
| `legit-content-reddit` | legit-content | `any-allow` | `ALLOW` | 740 ms | ✓ |
| `legit-content-substack` | legit-content | `any-allow` | `ALLOW` | 836 ms | ✓ |
| `mozilla-developer` | legit-content | `any-allow` | `ALLOW` | 722 ms | ✓ |
| `stackoverflow` | legit-content | `any-allow` | `ALLOW` | 787 ms | ✓ |
| `wikipedia` | legit-content | `any-allow` | `ALLOW` | 1006 ms | ✓ |
| `claude-quickstart` | legit-dev | `any-allow` | `ALLOW` | 679 ms | ✓ |
| `legit-go-pkg` | legit-dev | `any-allow` | `ALLOW` | 755 ms | ✓ |
| `legit-python-docs` | legit-dev | `any-allow` | `ALLOW` | 878 ms | ✓ |
| `legit-rust-docs` | legit-dev | `any-allow` | `ALLOW` | 1021 ms | ✓ |
| `rustup` | legit-dev | `any-allow` | `ALLOW` | 873 ms | ✓ |
| `apple-id-host` | legit-major | `any-allow` | `ALLOW` | 1061 ms | ✓ |
| `cloudflare-corporate` | legit-major | `any-allow` | `ALLOW` | 826 ms | ✓ |
| `github` | legit-major | `any-allow` | `ALLOW` | 25314 ms | ✓ |
| `google-homepage` | legit-major | `any-allow` | `ALLOW` | 873 ms | ✓ |
| `legit-anthropic` | legit-major | `any-allow` | `ALLOW` | 642 ms | ✓ |
| `legit-aws-docs` | legit-major | `any-allow` | `ALLOW` | 962 ms | ✓ |
| `legit-microsoft-learn` | legit-major | `any-allow` | `ALLOW` | 876 ms | ✓ |
| `legit-openai` | legit-major | `any-allow` | `ALLOW` | 709 ms | ✓ |
| `legit-vercel` | legit-major | `any-allow` | `ALLOW` | 784 ms | ✓ |
| `microsoft-login` | legit-major | `any-allow` | `ALLOW` | 754 ms | ✓ |
| `paypal-homepage` | legit-major | `any-allow` | `ALLOW` | 1009 ms | ✓ |
| `stripe-checkout-host` | legit-major | `any-allow` | `ALLOW` | 868 ms | ✓ |
| `payment-real-stripe-docs` | legit-payment | `any-allow` | `ALLOW` | 665 ms | ✓ |
| `legit-saas-airtable` | legit-saas | `any-allow` | `ALLOW` | 871 ms | ✓ |
| `legit-saas-canva` | legit-saas | `any-allow` | `ALLOW` | 787 ms | ✓ |
| `legit-saas-figma` | legit-saas | `any-allow` | `ALLOW` | 704 ms | ✓ |
| `legit-saas-linear` | legit-saas | `any-allow` | `ALLOW` | 810 ms | ✓ |
| `notion` | legit-saas | `any-allow` | `ALLOW` | 671 ms | ✓ |
| `slack-app` | legit-saas | `any-allow` | `ALLOW` | 835 ms | ✓ |
| `aws-console` | legit-sensitive | `any-allow` | `ALLOW` | 1000 ms | ✓ |
| `github-settings` | legit-sensitive | `any-allow` | `ALLOW` | 5488 ms | ✓ |
| `gmail-inbox` | legit-sensitive | `any-allow` | `ALLOW` | 5697 ms | ✓ |
| `benign-pixel-fb` | legit-tracker | `any-allow` | `ALLOW` | 687 ms | ✓ |
| `corrupt-protocol` | malformed | `any` | `ALLOW` | 671 ms | ✓ |
| `corrupt-spaces` | malformed | `any` | `ALLOW` | 642 ms | ✓ |
| `data-scheme` | malformed | `any` | `CLEAN` | 188 ms | ✓ |
| `javascript-scheme` | malformed | `any` | `CLEAN` | 182 ms | ✓ |
| `mfa-fake-duo` | mfa-bombing | `any-deny` | `ISOLATE` | 805 ms | ✓ |
| `mfa-fake-okta-push` | mfa-bombing | `any-deny` | `ISOLATE` | 884 ms | ✓ |
| `oauth-known-good-github-cli` | oauth-legit | `any-allow` | `ALLOW` | 10174 ms | ✓ |
| `oauth-known-good-vscode` | oauth-legit | `any-allow` | `ALLOW` | 10061 ms | ✓ |
| `oauth-legit-azure-cli` | oauth-legit | `any-allow` | `ALLOW` | 516 ms | ✓ |
| `oauth-legit-github-mobile` | oauth-legit | `any-allow` | `ALLOW` | 4502 ms | ✓ |
| `oauth-google-unknown-client-drive-scope` | oauth-phish | `any-deny` | `BLOCK` | 735 ms | ✓ |
| `oauth-microsoft-unknown-client-high-scope` | oauth-phish | `any-deny` | `BLOCK` | 568 ms | ✓ |
| `oauth-phish-pretend-gcloud` | oauth-phish | `any-deny` | `BLOCK` | 417 ms | ✓ |
| `oauth-phish-pretend-vscode` | oauth-phish | `any-deny` | `ALLOW` | 4173 ms | ✗ |
| `gift-card-scam-1` | payment-scam | `any-deny` | `ISOLATE` | 727 ms | ✓ |
| `payment-scam-customs-fee` | payment-scam | `any-deny` | `WARN` | 854 ms | ✓ |
| `payment-scam-fake-paypal-invoice` | payment-scam | `any-deny` | `BLOCK` | 722 ms | ✓ |
| `payment-scam-geek-squad-invoice` | payment-scam | `any-deny` | `WARN` | 867 ms | ✓ |
| `payment-scam-inheritance` | payment-scam | `any-deny` | `WARN` | 807 ms | ✓ |
| `payment-scam-lottery` | payment-scam | `any-deny` | `WARN` | 831 ms | ✓ |
| `payment-scam-medicare-refund` | payment-scam | `any-deny` | `WARN` | 868 ms | ✓ |
| `payment-scam-ssn-suspended` | payment-scam | `any-deny` | `WARN` | 902 ms | ✓ |
| `payment-scam-tax-refund-uk` | payment-scam | `any-deny` | `WARN` | 889 ms | ✓ |
| `wire-fraud-irs` | payment-scam | `any-deny` | `WARN` | 829 ms | ✓ |
| `piracy-multiple-1` | piracy-tld | `any` | `ALLOW` | 1032 ms | ✓ |
| `piracy-multiple-2` | piracy-tld | `any` | `ALLOW` | 10992 ms | ✓ |
| `piracy-tld-cc` | piracy-tld | `any` | `WARN` | 20387 ms | ✓ |
| `piracy-tld-pw` | piracy-tld | `any` | `ALLOW` | 1310 ms | ✓ |
| `piracy-tld-to` | piracy-tld | `any` | `ALLOW` | 20727 ms | ✓ |
| `piracy-tld-ws` | piracy-tld | `any` | `ALLOW` | 1081 ms | ✓ |
| `punycode-google` | punycode | `any` | `WARN` | 811 ms | ✓ |
| `raw-ip-bare` | raw-ip | `any-deny` | `BLOCK` | 10963 ms | ✓ |
| `raw-ip-binary-drop` | raw-ip | `block` | `BLOCK` | 10951 ms | ✓ |
| `raw-ip-cn-vps` | raw-ip | `block` | `BLOCK` | 2961 ms | ✓ |
| `raw-ip-private-cgnat` | raw-ip | `any` | `BLOCK` | 10836 ms | ✓ |
| `login-on-fresh-unknown` | sensitive-unknown | `any-deny` | `ISOLATE` | 850 ms | ✓ |
| `payment-checkout-unknown` | sensitive-unknown | `any-deny` | `ISOLATE` | 830 ms | ✓ |
| `session-hijack-fake-signin` | session-hijack | `any-deny` | `ISOLATE` | 751 ms | ✓ |
| `session-hijack-fake-token` | session-hijack | `any-deny` | `ISOLATE` | 852 ms | ✓ |
| `github-io-tenant` | shared-host | `any` | `ALLOW` | 4986 ms | ✓ |
| `netlify-tenant` | shared-host | `any` | `ALLOW` | 5305 ms | ✓ |
| `shared-host-pages-dev` | shared-host | `any` | `ALLOW` | 867 ms | ✓ |
| `shared-host-wordpress` | shared-host | `any-allow` | `ALLOW` | 4437 ms | ✓ |
| `shared-host-workers-dev` | shared-host | `any` | `ALLOW` | 787 ms | ✓ |
| `vercel-tenant` | shared-host | `any` | `ALLOW` | 3163 ms | ✓ |
| `bitly-home` | shortener | `any-allow` | `ALLOW` | 767 ms | ✓ |
| `shortener-bitly-corrupt` | shortener | `any` | `ALLOW` | 981 ms | ✓ |
| `tco-home` | shortener | `any-allow` | `ALLOW` | 750 ms | ✓ |
| `spoof-mimecast-host` | spoof-wrapper | `any-allow` | `ALLOW` | 775 ms | ✓ |
| `spoof-safelinks-host` | spoof-wrapper | `any-allow` | `ALLOW` | 873 ms | ✓ |
| `subdomain-spoof-google-accounts` | subdomain-spoof | `any-deny` | `ISOLATE` | 721 ms | ✓ |
| `subdomain-spoof-microsoft-login` | subdomain-spoof | `any-deny` | `ISOLATE` | 715 ms | ✓ |
| `subdomain-spoof-paypal` | subdomain-spoof | `any-deny` | `ISOLATE` | 813 ms | ✓ |
| `scam-amazon-support` | support-scam | `any-deny` | `WARN` | 892 ms | ✓ |
| `scam-google-virus-warning` | support-scam | `any-deny` | `WARN` | 890 ms | ✓ |
| `scam-icloud-locked` | support-scam | `any-deny` | `ISOLATE` | 761 ms | ✓ |
| `scam-mcafee-renewal` | support-scam | `any-deny` | `WARN` | 773 ms | ✓ |
| `scam-norton-support` | support-scam | `any-deny` | `WARN` | 828 ms | ✓ |
| `scam-windows-error` | support-scam | `any-deny` | `WARN` | 756 ms | ✓ |
| `support-scam-apple-virus-alert` | support-scam | `any-deny` | `WARN` | 797 ms | ✓ |
| `support-scam-microsoft-helpline` | support-scam | `any-deny` | `WARN` | 927 ms | ✓ |
| `support-scam-windows-defender` | support-scam | `any-deny` | `WARN` | 875 ms | ✓ |
| `cctld-cf` | sus-tld | `any` | `ALLOW` | 841 ms | ✓ |
| `cctld-ga` | sus-tld | `any` | `ALLOW` | 969 ms | ✓ |
| `cctld-ml` | sus-tld | `any` | `ALLOW` | 3888 ms | ✓ |
| `tld-click` | sus-tld | `any` | `ALLOW` | 7120 ms | ✓ |
| `tld-tk` | sus-tld | `any` | `ALLOW` | 1238 ms | ✓ |
| `tld-xyz` | sus-tld | `any` | `ALLOW` | 1105 ms | ✓ |
| `brand-impersonation-google` | synth-phish | `any-deny` | `ISOLATE` | 1289 ms | ✓ |
| `brand-impersonation-microsoft` | synth-phish | `any-deny` | `ISOLATE` | 1373 ms | ✓ |
| `brand-impersonation-paypal` | synth-phish | `any-deny` | `ISOLATE` | 882 ms | ✓ |
| `homoglyph-google` | synth-phish | `any-deny` | `WARN` | 1506 ms | ✓ |
| `random-host-login` | synth-phish | `any-deny` | `ISOLATE` | 907 ms | ✓ |
| `combosquat-paypal-account` | typosquat | `any-deny` | `ISOLATE` | 768 ms | ✓ |
| `homoglyph-amazon-zero-for-o` | typosquat | `any-deny` | `BLOCK` | 788 ms | ✓ |
| `homoglyph-microsoft-rn-for-m` | typosquat | `any-deny` | `BLOCK` | 766 ms | ✓ |
| `homoglyph-paypal-1-for-l` | typosquat | `any-deny` | `BLOCK` | 721 ms | ✓ |
| `typo-amazon-shuffle` | typosquat | `any-deny` | `BLOCK` | 658 ms | ✓ |
| `typo-google-h` | typosquat | `any-deny` | `WARN` | 823 ms | ✓ |
| `typo-google-letter-swap` | typosquat | `any-deny` | `WARN` | 1000 ms | ✓ |
| `typo-microsoft-omission` | typosquat | `any-deny` | `BLOCK` | 798 ms | ✓ |
| `typo-paypal-double` | typosquat | `any-deny` | `BLOCK` | 681 ms | ✓ |
| `barracuda-benign` | wrapper-benign | `any-allow` | `ALLOW` | 3801 ms | ✓ |
| `cisco-securemail-benign` | wrapper-benign | `any-allow` | `ALLOW` | 6382 ms | ✓ |
| `gmail-link-redirect-benign` | wrapper-benign | `any-allow` | `ALLOW` | 8942 ms | ✓ |
| `proofpoint-v2-benign` | wrapper-benign | `any-allow` | `WARN` | 19167 ms | ✗ |
| `proofpoint-v3-format-benign` | wrapper-benign | `any-allow` | `ALLOW` | 11892 ms | ✓ |
| `safelinks-benign` | wrapper-benign | `any-allow` | `ALLOW` | 24956 ms | ✓ |
| `safelinks-multi-region-india` | wrapper-benign | `any-allow` | `ALLOW` | 14998 ms | ✓ |
| `safelinks-multi-region-jp` | wrapper-benign | `any-allow` | `WARN` | 14788 ms | ✗ |
| `symantec-clicktime-benign` | wrapper-benign | `any-allow` | `WARN` | 14477 ms | ✗ |
| `cisco-pointing-to-homoglyph` | wrapper-phish | `any-deny` | `BLOCK` | 797 ms | ✓ |
| `mimecast-pointing-at-fresh-host` | wrapper-phish | `any-deny` | `ISOLATE` | 801 ms | ✓ |
| `proofpoint-pointing-to-fresh-host` | wrapper-phish | `any-deny` | `ISOLATE` | 839 ms | ✓ |
| `safelinks-spoof-phish-target` | wrapper-phish | `any-deny` | `ISOLATE` | 730 ms | ✓ |
