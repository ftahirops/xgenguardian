# Staging Terraform

Spins up the Phase-1 staging stack: 1 droplet running services via docker-compose, managed Postgres + Redis, S3-compatible bucket, DNS records.

## Use

```bash
export TF_VAR_do_token=...
export TF_VAR_cloudflare_api_token=...
export TF_VAR_cf_zone_id=...

terraform init
terraform plan
terraform apply
```

## What you get
- `dns.staging.xgenguardian.io` → A record to droplet IP (DoH endpoint)
- `report.staging.xgenguardian.io` → A record to droplet IP (Transparency Portal)
- Managed PG + Redis with connection URIs in outputs
- DigitalOcean Space `xgg-staging-evidence` for screenshots/DOM/HAR

## Cost
~$70/month with the chosen sizes; halve by co-locating PG/Redis in the droplet for early testing.

## Next steps after `terraform apply`
1. SSH to droplet IP.
2. Clone repo.
3. Set env vars from terraform output (PG DSN, Redis URI, S3 keys).
4. `docker compose up -d`.
5. Run `make migrate` and `make seed-brands`.
6. Point your browser DoH to `https://dns.staging.xgenguardian.io/dns-query`.
