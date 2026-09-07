CREATE TABLE projects (id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL, data TEXT NOT NULL);
CREATE TABLE snapshots (id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id), kind TEXT NOT NULL, state TEXT NOT NULL, created_at TEXT NOT NULL, data TEXT NOT NULL);
CREATE INDEX snapshots_project ON snapshots(project_id, created_at);
CREATE TABLE audit_runs (id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id), snapshot_id TEXT NOT NULL REFERENCES snapshots(id), state TEXT NOT NULL, created_at TEXT NOT NULL, data TEXT NOT NULL);
CREATE INDEX runs_project ON audit_runs(project_id, created_at);
CREATE TABLE executors (id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE, last_seen INTEGER NOT NULL, data TEXT NOT NULL);
CREATE TABLE work_items (
    id TEXT PRIMARY KEY, snapshot_id TEXT NOT NULL REFERENCES snapshots(id), run_id TEXT REFERENCES audit_runs(id),
    kind TEXT NOT NULL, capability TEXT NOT NULL, state TEXT NOT NULL, created_at TEXT NOT NULL,
    input_artifact_id TEXT NOT NULL, payload TEXT NOT NULL, executor_id TEXT REFERENCES executors(id),
    attempt_id TEXT NOT NULL DEFAULT '', lease_hash TEXT NOT NULL DEFAULT '', lease_expires INTEGER NOT NULL DEFAULT 0,
    cancel_requested INTEGER NOT NULL DEFAULT 0, completion_hash TEXT NOT NULL DEFAULT ''
);
CREATE INDEX work_queue ON work_items(state, created_at);
CREATE TABLE work_attempts (attempt_id TEXT PRIMARY KEY, work_item_id TEXT NOT NULL REFERENCES work_items(id), executor_id TEXT NOT NULL REFERENCES executors(id), lease_hash TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT, outcome TEXT, detail TEXT);
CREATE TABLE artifacts (id TEXT PRIMARY KEY, sha256 TEXT NOT NULL CHECK(length(sha256)=64), size INTEGER NOT NULL CHECK(size>=0), name TEXT NOT NULL, media_type TEXT NOT NULL, snapshot_id TEXT REFERENCES snapshots(id), work_item_id TEXT REFERENCES work_items(id), attempt_id TEXT, data TEXT NOT NULL);
CREATE INDEX artifacts_work ON artifacts(work_item_id, attempt_id);
CREATE TABLE program_units (id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES audit_runs(id), snapshot_id TEXT NOT NULL REFERENCES snapshots(id), name TEXT NOT NULL, path TEXT NOT NULL, language TEXT NOT NULL, data TEXT NOT NULL);
CREATE INDEX units_run ON program_units(run_id, path, name);
CREATE TABLE program_edges (id INTEGER PRIMARY KEY, run_id TEXT NOT NULL REFERENCES audit_runs(id), source_id TEXT NOT NULL REFERENCES program_units(id), target_id TEXT, data TEXT NOT NULL);
CREATE INDEX edges_source ON program_edges(source_id);
CREATE INDEX edges_target ON program_edges(target_id);
CREATE TABLE tool_runs (id TEXT PRIMARY KEY, work_item_id TEXT NOT NULL REFERENCES work_items(id), run_id TEXT REFERENCES audit_runs(id), data TEXT NOT NULL);
CREATE TABLE run_events (run_id TEXT NOT NULL REFERENCES audit_runs(id), seq INTEGER NOT NULL, data TEXT NOT NULL, PRIMARY KEY(run_id, seq));
CREATE TABLE report_exports (id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES audit_runs(id), artifact_id TEXT NOT NULL REFERENCES artifacts(id), created_at TEXT NOT NULL, data TEXT NOT NULL);
CREATE TABLE requests (method TEXT NOT NULL, request_id TEXT NOT NULL, body_hash TEXT NOT NULL, object_id TEXT NOT NULL, PRIMARY KEY(method, request_id));
