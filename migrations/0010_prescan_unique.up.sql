BEGIN;
-- Drop pre-existing duplicates so the UNIQUE constraint can be added.
-- ON CONFLICT DO NOTHING was a no-op without this constraint (Finding #6);
-- unbounded duplicate (domain, reason) pairs accumulated per CT log cycle.
DELETE FROM prescan_queue WHERE id IN (
  SELECT id FROM (
    SELECT id, ROW_NUMBER() OVER (PARTITION BY domain, reason ORDER BY id) AS rn
    FROM prescan_queue
  ) t WHERE t.rn > 1
);
ALTER TABLE prescan_queue
  ADD CONSTRAINT uq_prescan_domain_reason UNIQUE (domain, reason);
COMMIT;
