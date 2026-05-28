# Rotate Secrets

**TL;DR:** generate new → deploy both old+new → cut over → revoke old → audit.

Secrets rotated regularly: every 90 days. Secrets rotated on incident: immediately.

## Inventory

| Secret | Location | Rotation cadence |
|---|---|---|
| Postgres password | `DATABASE_URL` | 90d |
| Redis password | `REDIS_ADDR` | 90d |
| S3/Spaces access keys | `S3_ACCESS_KEY` / `S3_SECRET_KEY` | 90d |
| Cloudflare API token | `CF_API_TOKEN` | 180d |
| DigitalOcean token | `DO_TOKEN` | 180d |
| Stripe keys | `STRIPE_SECRET` | 365d (or on staff change) |
| Verdict signing key (Ed25519) | `VERDICT_SIGNING_KEY` | 365d |
| TLS certs for `dns.xgenguardian.com` | ACM / Let's Encrypt | auto (Certbot) |
| GitHub deploy keys | repo settings | 365d |
| PagerDuty integration keys | `pd_routing_key` | on incident |

## Step 1 — Generate New

For random secrets:
```bash
openssl rand -base64 48
```

For service-specific tokens, use the provider's console (Cloudflare, DO, Stripe). Always create the **new** token first; do not revoke the old yet.

## Step 2 — Deploy Both

Add the new secret alongside the old in the secret manager (Kubernetes Secret, AWS Secrets Manager, etc.). For symmetric secrets like DB passwords this requires multi-credential support:

- **Postgres**: create a second user with the same privileges before retiring the first.
- **S3**: both old and new access-key IDs valid simultaneously is the default.

Deploy code that reads the **new** secret. Keep services able to fall back to the old until cutover is verified.

## Step 3 — Cut Over

Roll out the new secret to all services via `kubectl rollout restart deploy/...`. Watch:
- `error_rate_5m` should not change.
- All `/healthz` endpoints return 200.

## Step 4 — Revoke Old

After 24h of stable operation on the new secret:
- Delete the old secret from the secret manager.
- Revoke at the provider (Cloudflare dashboard, DO dashboard, etc.).
- For Postgres: `DROP USER old_xgg_user;`

## Step 5 — Audit

- Confirm via provider audit log that the old credential is not used anywhere unexpected.
- Update `docs/runbooks/secrets-inventory.md` (private, off-repo) with rotation date.

## Emergency Rotation (compromise suspected)

Skip the gradual cutover. Generate new secret, deploy, **revoke old immediately**. Tolerate a brief outage rather than leave a compromised credential active.

After revoke:
- Audit logs of every system the old credential could access for the last 90 days.
- Open a security incident in `docs/runbooks/incidents/` if any unauthorized access is found.
- Disclose to customers within 72 hours if customer data may have been exposed (GDPR Art. 33).

## Verification

Rotation complete when:
- All services running on the new secret.
- Old secret is provably revoked at the provider.
- Audit log shows no access attempts using old credential in last 24h.
- Inventory updated.
