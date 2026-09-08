CREATE TABLE runtime_records (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL UNIQUE REFERENCES audit_runs(id),
    source_run_id TEXT NOT NULL REFERENCES audit_runs(id),
    finding_id TEXT REFERENCES findings(id),
    created_at TEXT NOT NULL,
    data TEXT NOT NULL
);
CREATE INDEX runtime_source ON runtime_records(source_run_id, created_at, id);
