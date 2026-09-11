-- Active-run lookup happens under BEGIN IMMEDIATE. Keep legacy histories intact.
CREATE INDEX runs_snapshot_state ON audit_runs(snapshot_id, state, created_at);
