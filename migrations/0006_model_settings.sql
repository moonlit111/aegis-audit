-- Only DPAPI ciphertext is persisted; raw keys never enter requests or artifacts.
CREATE TABLE model_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    data TEXT NOT NULL
);
