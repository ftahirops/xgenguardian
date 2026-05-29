# FP / FN Corpus Directory

Curated URL corpora that drive the maturity-test FP-rate and FN-rate
measurements. Each file is plain text, one URL per line, comment lines
starting with `#`. Categories match blueprint §8/§9.

## Structure

```
corpus/
├── benign-real-world.txt          # general browsing
├── benign-sensitive.txt           # login/payment/oauth pages on legit hosts
├── benign-downloads.txt           # install pages on trusted brands
├── benign-wrappers.txt            # SafeLinks/Proofpoint/Mimecast samples
├── benign-raw-ip-operator.txt     # operator self-hosted IP URLs
├── benign-ultra-friendly-set.txt  # 200 mainstream URLs that should pass Ultra
├── malicious-phishing.txt         # login clones, MFA pages, bank clones
├── malicious-scam.txt             # tech support, refund, gift card
├── malicious-command-copy.txt     # fake docs with mshta/rundll32/PS encoded
├── malicious-raw-ip.txt           # botnet arch paths, IP+exe
├── malicious-oauth.txt            # unknown high-scope OAuth clients
├── malicious-downloads.txt        # malware drops
├── malicious-popup.txt            # alert loops, fullscreen traps
├── malicious-qr.txt               # quishing landing pages
└── adversarial-inputs.txt         # NFC/emoji/mixed-script/IDN tricks
```

## Format

```
# Category: benign-real-world
# Last refreshed: 2026-05-29
https://www.google.com/
https://www.youtube.com/
https://github.com/
```

## Adding entries

Every real user-reported false positive MUST be added to the matching benign
file with this metadata as a comment line above the URL:

```
# v0.3.2 FP, found 2026-05-29, fixed by 8f19db2 (added processing.org to trustreg)
https://processing.org/download/
```

Every real user-reported false negative MUST be added to the matching
malicious file with the discovery / catch metadata:

```
# v0.3.0 FN — caught by VENDOR_DNS_CONSENSUS_BLOCK after Phase 6
https://thepiratebay.org/
```

This creates an auditable trail from incident → corpus entry → release
gate that prevents the regression.

## Running

```bash
make maturity-test-bench
```

Output reports per-category FP/FN rates and identifies any URL that
changed verdict between releases.
