ALTER TABLE model_calls ADD COLUMN run_id TEXT REFERENCES audit_runs(id);
ALTER TABLE model_calls ADD COLUMN task_id TEXT;
CREATE INDEX model_calls_run ON model_calls(run_id, created_at, id);
CREATE TABLE audit_workflows (
    run_id TEXT PRIMARY KEY REFERENCES audit_runs(id),
    state TEXT NOT NULL,
    config TEXT NOT NULL,
    model TEXT NOT NULL,
    config_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE agent_tasks (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES audit_runs(id),
    role TEXT NOT NULL,
    item_key TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    data TEXT NOT NULL,
    UNIQUE(run_id, role, item_key)
);
CREATE TABLE findings (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES audit_runs(id),
    unit_id TEXT NOT NULL REFERENCES program_units(id),
    fingerprint TEXT NOT NULL,
    review_status TEXT NOT NULL,
    verification_status TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision > 0),
    created_at TEXT NOT NULL,
    data TEXT NOT NULL,
    UNIQUE(run_id, fingerprint)
);
CREATE TABLE reviews (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings(id),
    revision INTEGER NOT NULL,
    actor TEXT NOT NULL,
    created_at TEXT NOT NULL,
    data TEXT NOT NULL,
    UNIQUE(finding_id, revision)
);
CREATE TABLE logic_annotations (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES audit_runs(id),
    unit_id TEXT NOT NULL REFERENCES program_units(id),
    tag TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision > 0),
    data TEXT NOT NULL,
    UNIQUE(run_id, unit_id, tag)
);
CREATE TABLE annotation_revisions (
    annotation_id TEXT NOT NULL REFERENCES logic_annotations(id),
    revision INTEGER NOT NULL,
    data TEXT NOT NULL,
    PRIMARY KEY(annotation_id, revision)
);
CREATE INDEX findings_run ON findings(run_id, created_at, id);
CREATE INDEX annotations_run ON logic_annotations(run_id);
