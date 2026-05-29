# Postgres Backup Runbook

## Overview

Daily `pg_dump` (custom format, gzip-compressed) written to `/var/backups/xgg-postgres/`.
Dumps are kept for 14 days (overridable). A systemd timer fires at 03:00 UTC daily.

---

## Install the systemd timer

```bash
sudo cp /home/xgenguardian/code/deploy/systemd/xgg-backup.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now xgg-backup.timer

# Verify timer is active
systemctl list-timers xgg-backup.timer
```

## Configure credentials

Create `/etc/xgenguardian/backup.env` (mode 0600, owned root):

```ini
PGPASSWORD=your_postgres_password
DATABASE_URL=postgres://xgg:your_password@localhost:15432/xgg
BACKUP_RETENTION_DAYS=14
```

```bash
sudo mkdir -p /etc/xgenguardian
sudo install -m 0600 /dev/null /etc/xgenguardian/backup.env
# then edit with your values
```

---

## Run a manual backup

```bash
sudo PGPASSWORD=xgg \
  DATABASE_URL=postgres://xgg:xgg@localhost:15432/xgg \
  /home/xgenguardian/code/scripts/pg-backup.sh
```

Or via make:

```bash
make backup
```

Check that a file appeared:

```bash
ls -lh /var/backups/xgg-postgres/
```

---

## Restore from a backup

**This is destructive. The target database will be overwritten.**

```bash
XGG_RESTORE_CONFIRM=yes \
PGPASSWORD=xgg \
DATABASE_URL=postgres://xgg:xgg@localhost:15432/xgg \
  /home/xgenguardian/code/scripts/pg-restore.sh \
  /var/backups/xgg-postgres/xgg-postgres-YYYYMMDD-HHMMSS.dump.gz
```

Or via make (pass the full path):

```bash
make restore FILE=/var/backups/xgg-postgres/xgg-postgres-20260528-030000.dump.gz
```

### What `pg_restore --clean --if-exists` does

Drops each object (`DROP TABLE IF EXISTS`, etc.) before recreating it.
This means active connections to the DB may be interrupted.
Stop dependent services first:

```bash
docker compose stop verdict-api resolver scheduler
# restore
docker compose start verdict-api resolver scheduler
```

---

## Copy backups to remote / S3

Use rsync to push to a remote host:

```bash
rsync -avz /var/backups/xgg-postgres/ backup-host:/mnt/xgg-backups/
```

For S3-compatible storage (e.g. AWS S3, MinIO):

```bash
aws s3 sync /var/backups/xgg-postgres/ s3://your-bucket/xgg-postgres/
```

---

## When restore fails partway through

`pg_restore` exits non-zero if any object could not be dropped or recreated.
The most common causes and fixes:

| Symptom | Fix |
|---|---|
| `ERROR: database "xgg" does not exist` | `createdb xgg` then re-run restore |
| `ERROR: role "xgg" does not exist` | `createuser xgg` then re-run restore |
| `pg_restore: error: connection to server failed` | Check PGHOST, PGPORT, PGPASSWORD; ensure Postgres is running |
| Restore completes but tables are empty | Dump may be from a schema-only run; verify dump size > few KB |
| "could not execute query: ERROR: tuple concurrently updated" | Stop all services that write to the DB, then retry |

After any failed restore the DB may be in a partial state. The safest recovery is:

```bash
# drop and recreate the database, then restore
psql -U xgg -h localhost -p 15432 postgres -c "DROP DATABASE IF EXISTS xgg; CREATE DATABASE xgg OWNER xgg;"
XGG_RESTORE_CONFIRM=yes PGPASSWORD=xgg ./scripts/pg-restore.sh <dump-file>
```

---

## Troubleshoot the timer

```bash
systemctl status xgg-backup.timer
systemctl status xgg-backup.service
journalctl -u xgg-backup.service --since "1 hour ago"
```
