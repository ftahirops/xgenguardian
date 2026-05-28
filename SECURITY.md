# Security Policy

XGenGuardian is a security product. We take vulnerability reports very seriously.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Email: `security@xgenguardian.com` (PGP key fingerprint published on the website).

Please include:
- Affected component (resolver, verdict-api, sandbox-render, visual-match, portal, browser extension, endpoint client).
- Affected version(s) — commit SHA or release tag.
- Steps to reproduce.
- Impact: who can do what to whom?
- Proof-of-concept code if available.

## Our Commitment

- **Acknowledgement** within 2 business days.
- **Triage + severity assessment** within 5 business days.
- **Fix timeline communicated** within 10 business days.
- **Coordinated disclosure** — we'll work with you on a CVE if appropriate. Credit given in release notes unless you prefer otherwise.

## Scope

In scope:
- Any service code under `services/`.
- Browser extension / endpoint client.
- The DoH resolver and its sinkhole/interstitial behavior.
- Verdict-API authentication and tenant isolation.
- Evidence-store access controls.
- Brand Registry tampering paths.

Out of scope:
- Phishing/malware *that we fail to detect*. That's a detection-gap report (see "Detection Gaps" below), not a security vulnerability.
- Issues in third-party threat-intel feeds we ingest.
- Findings against staging environments without prior arrangement.
- Self-DoS on free-tier endpoints (rate limits are intentional).

## Detection Gaps

If XGenGuardian misclassified a URL — false positive or false negative — file it via:

- The "Report" button on the verdict page in the Transparency Portal, or
- A GitHub issue with the `detection-gap` label.

These are publicly trackable and not security-sensitive.

## Bug Bounty

We do not currently run a paid bug bounty. We do offer public acknowledgement and (where applicable) free Pro/Business tier credit.

## Cryptographic Details

- Verdict signing keys, brand-registry signing, and tenant-data isolation are documented in `docs/architecture.md` §6 (Continuous Intelligence Plane) and §29 (SaaS Multi-Tenancy).
- TLS configuration on the public endpoints follows Mozilla "Modern" profile.

## Supply Chain

- Dependencies are pinned via `go.sum`, `package-lock.json`, and `pyproject.toml`/`uv.lock`.
- Container images are built from minimal bases (distroless / Alpine / Playwright official).
- We do not currently sign release artifacts; this is a known gap tracked in `docs/issues/ISSUES.md`.
