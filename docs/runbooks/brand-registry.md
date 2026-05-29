# Brand Registry Runbook

The Brand Registry is the ground-truth list of legitimate brands that XGenGuardian
monitors for impersonation. It lives in `tools/brand-seeder/brands.yaml` and is
seeded into the `brands` and `brand_screenshots` Postgres tables via `make seed-brands`.

---

## Table of contents

1. [Adding a new brand](#1-adding-a-new-brand)
2. [Editing an existing brand](#2-editing-an-existing-brand)
3. [Running the seeder](#3-running-the-seeder)
4. [How the CI gate works](#4-how-the-ci-gate-works)
5. [Threat model: brand-yaml access](#5-threat-model-brand-yaml-access)
6. [Troubleshooting](#6-troubleshooting)

---

## 1. Adding a new brand

Edit `tools/brand-seeder/brands.yaml`. Each entry is a YAML mapping with the
following fields:

| Field | Required | Type | Description |
|---|---|---|---|
| `name` | yes | string | Primary key — must be unique. |
| `canonical_domains` | yes | string[] | Domains the brand owns. Any lookalike outside this set triggers an impersonation signal. |
| `login_urls` | no | string[] | URLs the seeder will auto-render to capture reference screenshots. |
| `keywords` | no | string[] | Lowercased substrings used in domain fuzzy-matching (typo-squatting). |
| `expected_issuer` | no | string | Short-name of the expected TLS certificate CA (e.g. `DigiCert`, `Let's Encrypt`). |
| `legitimate_asns` | no | integer[] | ASNs the brand legitimately uses for hosting. |
| `legitimate_issuers` | no | string[] | Multi-issuer variant of `expected_issuer`. |
| `manual_screenshots` | no | object[] | Fallback screenshots for login pages that block headless rendering (see below). |

Minimal example:

```yaml
- name: Acme Bank
  canonical_domains:
    - acmebank.com
    - acmebank.co.uk
  login_urls:
    - https://online.acmebank.com/login
    - https://www.acmebank.com/
  keywords:
    - acmebank
    - acme bank
  expected_issuer: DigiCert
```

### Manual screenshot fallback

If `sandbox-render` cannot capture a page (WAF block, CAPTCHA, etc.) add a
manual screenshot:

1. Capture a screenshot of the login page and save it as a PNG under
   `tools/brand-seeder/manual/<brand-slug>-login.png`.
2. Add a `manual_screenshots` block:

```yaml
  manual_screenshots:
    - page_label: login
      page_url: https://online.acmebank.com/login
      file: manual/acme-bank-login.png
```

`page_label` must be one of: `login`, `home`, `checkout`.

---

## 2. Editing an existing brand

Locate the entry by `name`. You can edit any field freely. The seeder uses
`ON CONFLICT (brand_name) DO UPDATE` so re-running after an edit is idempotent.

Do **not** rename the `name` field — it is the database primary key. To rename a
brand, delete the old entry and add a new one, then run the seeder twice or
run `make seed-brands` and manually delete the orphaned row.

---

## 3. Running the seeder

```bash
# Full seed (all brands)
make seed-brands

# Single brand (faster for iteration)
cd tools/brand-seeder && python seed.py --brand "Acme Bank"

# Dry-run (no DB writes, validates YAML + render pipeline)
cd tools/brand-seeder && python seed.py --dry-run
```

The seeder requires:
- Postgres reachable at `DATABASE_URL` (default `postgres://xgg:xgg@localhost:15432/xgg`)
- `sandbox-render` running at `SANDBOX_RENDER_URL` (default `http://localhost:8002`)
- `visual-match` running at `VISUAL_MATCH_URL` (default `http://localhost:8003`)

In CI these services are not present; the schema gate validates structure only.
Full embedding is gated behind the integration test suite.

---

## 4. How the CI gate works

Every pull request that modifies `tools/brand-seeder/brands.yaml` runs the
`brand-yaml-validate` job in `.github/workflows/ci.yml`. The job:

1. Checks out the repository.
2. Installs `check-jsonschema`.
3. Runs:
   ```
   check-jsonschema \
     --schemafile tools/brand-seeder/brands.schema.json \
     tools/brand-seeder/brands.yaml
   ```
4. Fails the CI run if the YAML does not conform to the schema.

The schema (`tools/brand-seeder/brands.schema.json`) enforces:
- `brands` top-level key is required.
- Each brand entry has a non-empty `name` and at least one `canonical_domain`.
- All login URLs start with `https://` or `http://`.
- `manual_screenshots[].page_label` is one of `login`, `home`, `checkout`.
- `manual_screenshots[].file` matches `manual/*.png`.
- No unrecognized fields are allowed (`additionalProperties: false`).

To intentionally extend the schema (e.g. add a new field), update
`brands.schema.json` in the same PR as the `brands.yaml` change.

### Bypassing the gate

The gate can be skipped by a repository admin using GitHub's "bypass required
status checks" feature. This bypass is logged and should only be used in
genuine operational emergencies. Any bypass must be followed by a retroactive
PR to fix the YAML and schema.

---

## 5. Threat model: brand-yaml access

`brands.yaml` is a security-sensitive file. An attacker with write access to it
(via a compromised developer account, a malicious PR, or a supply-chain attack)
could:

| Attack | Effect |
|---|---|
| Remove a brand entry | Eliminates impersonation detection for that brand. Phishing pages for that brand would pass undetected. |
| Replace `canonical_domains` with attacker-controlled domains | Inverts detection: the attacker's domain becomes "legitimate" and the real brand's domain triggers alerts. |
| Empty or corrupt `keywords` | Disables fuzzy domain matching (typo-squatting detection) for the brand. |
| Swap `expected_issuer` | Suppresses TLS mis-issuance signals. A phishing site with a Let's Encrypt cert impersonating a DigiCert brand would not be flagged. |
| Inject a `manual_screenshots` entry pointing to a crafted PNG | Could poison the CLIP visual embedding space, causing the visual matcher to recognise attacker-controlled pages as legitimate. |

The CI schema gate does **not** prevent all of these attacks — it only prevents
malformed YAML from being merged. The main mitigations are:

- **Branch protection**: require at least one reviewer for PRs that touch
  `tools/brand-seeder/brands.yaml`.
- **CODEOWNERS**: add a `CODEOWNERS` entry so the security team is
  auto-requested on brand changes.
- **Audit log**: the seeder logs every brand update with a timestamp in
  `brands.updated_at`. Monitor for unexpected updates.
- **Eval gate**: any change that accidentally degrades brand coverage will be
  caught by the `make eval` / `fp-bench` harnesses.

Recommended `CODEOWNERS` entry:

```
tools/brand-seeder/brands.yaml  @xgenguardian/security-team
```

---

## 6. Troubleshooting

**`check-jsonschema` fails with "Additional properties are not allowed"**

A field name in `brands.yaml` is not in the schema. Either fix the YAML typo or
add the field to `brands.schema.json` if it is intentional.

**`check-jsonschema` fails with "is not valid under any of the given schemas"**

A brand entry is missing a required field (`name` or `canonical_domains`), or a
field value has the wrong type (e.g. `canonical_domains` is a string instead of
an array).

**Seeder exits with `[ERR] BrandName: ...`**

The seeder is resilient — it logs errors and continues. Check:
- Is `sandbox-render` running? (`make dev-backend`)
- Is `visual-match` running?
- Does the URL return a non-200? The seeder will skip it and try the manual fallback.

**Seeder produces no embeddings**

The CLIP model (~600 MB) needs to be downloaded on first run. Allow several
minutes. Check `visual-match` logs for download progress.
