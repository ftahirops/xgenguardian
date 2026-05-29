# Evidence Retention Runbook

## What gets deleted and when

The weekly cleanup job (Sunday 04:00 UTC) purges:

| Target | Condition | Default retention |
|---|---|---|
| `scan_history` rows | `evidence_id` references a nonexistent evidence row (orphan) | immediate |
| `evidence` rows | `retention_until < NOW()` | set per-row at insert time |
| `dns_queries` rows | `created_at` older than retention window | 30 days |
| `prescan_queue` rows | `completed_at` older than 7 days | 7 days |
| MinIO objects | key not referenced by any `evidence` URL column | immediate |

---

## How to override retention windows

Set environment variables before running the cleanup scripts, or add them to
`/etc/xgenguardian/cleanup.env`:

| Variable | Default | Effect |
|---|---|---|
| `DNS_QUERIES_RETENTION_DAYS` | `30` | How many days of DNS query history to keep |
| `CLEANUP_CONFIRM` | _(unset)_ | Must be `yes` to commit SQL deletes and MinIO deletes |

Example — extend DNS retention to 90 days:

```bash
DNS_QUERIES_RETENTION_DAYS=90 CLEANUP_CONFIRM=yes \
  /home/xgenguardian/code/scripts/cleanup-expired.sh
```

---

## How to set `retention_until` when persisting evidence

Evidence rows should have `retention_until` set at insert time so that the
weekly cleanup can expire them automatically. Example SQL:

```sql
INSERT INTO evidence (url, ..., retention_until)
VALUES (..., NOW() + INTERVAL '90 days');
```

**Follow-up required:** `verdict-api` currently does not set `retention_until`
when writing evidence rows. Until that is fixed, evidence rows will not be
expired by the cleanup job (the column will be NULL, which the cleanup skips).
Track this in the verdict-api backlog.

---

## Install the systemd timer

```bash
sudo cp /home/xgenguardian/code/deploy/systemd/xgg-cleanup.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now xgg-cleanup.timer

# Verify
systemctl list-timers xgg-cleanup.timer
```

## Configure credentials

Create `/etc/xgenguardian/cleanup.env` (mode 0600, owned root):

```ini
PGPASSWORD=your_postgres_password
DATABASE_URL=postgres://xgg:xgg@localhost:15432/xgg
DNS_QUERIES_RETENTION_DAYS=30
CLEANUP_CONFIRM=yes
MINIO_ENDPOINT=http://127.0.0.1:19000
MINIO_ACCESS_KEY=xggadmin
MINIO_SECRET_KEY=xggadmin123
MINIO_BUCKET=xgg-evidence
```

---

## Run cleanup manually

```bash
# Dry run (default — just reports counts, no deletes)
PGPASSWORD=xgg /home/xgenguardian/code/scripts/cleanup-expired.sh

# Live run
CLEANUP_CONFIRM=yes PGPASSWORD=xgg /home/xgenguardian/code/scripts/cleanup-expired.sh

# MinIO dry run
MINIO_ENDPOINT=http://127.0.0.1:19000 \
MINIO_ACCESS_KEY=xggadmin \
MINIO_SECRET_KEY=xggadmin123 \
MINIO_BUCKET=xgg-evidence \
DATABASE_URL=postgres://xgg:xgg@localhost:15432/xgg \
PGPASSWORD=xgg \
python3 /home/xgenguardian/code/scripts/cleanup-minio.py

# MinIO live run (add CLEANUP_CONFIRM=yes)
```

Or via make:

```bash
make cleanup
```

---

## When cleanup fails partway through

The SQL cleanup runs inside a single transaction. If any statement fails the
entire transaction rolls back — no partial deletes occur.

**MinIO cleanup** is not transactional. If it fails mid-run:
- Already-deleted objects are gone (they were orphans, so safe)
- Re-running is idempotent: objects already deleted simply won't appear in the
  next listing

**Common failures:**

| Symptom | Fix |
|---|---|
| `psql: error: connection to server failed` | Check DB credentials, ensure Postgres is running |
| `psql: ERROR: relation "prescan_queue" does not exist` | Run `make migrate` to apply pending migrations |
| `botocore.exceptions.EndpointResolutionError` | Check `MINIO_ENDPOINT`; ensure MinIO is running |
| `NoSuchBucket` | Bucket name wrong or MinIO init did not run; check `MINIO_BUCKET` |

---

## Troubleshoot the timer

```bash
systemctl status xgg-cleanup.timer
systemctl status xgg-cleanup.service
journalctl -u xgg-cleanup.service --since "1 week ago"
```
