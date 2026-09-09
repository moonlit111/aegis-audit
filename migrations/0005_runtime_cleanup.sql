ALTER TABLE work_items ADD COLUMN cleanup_confirmed INTEGER NOT NULL DEFAULT 0;
UPDATE work_items
SET cleanup_confirmed = 1
WHERE kind != 'RUNTIME'
   OR state IN ('CANCELLED', 'COMPLETED', 'FAILED');
CREATE INDEX work_runtime_cleanup ON work_items(kind, state, cleanup_confirmed, created_at);
