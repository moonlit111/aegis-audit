CREATE TABLE model_calls (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    config_hash TEXT NOT NULL,
    artifact_id TEXT REFERENCES artifacts(id),
    data TEXT NOT NULL
);
