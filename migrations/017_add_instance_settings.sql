-- Instance settings table
CREATE TABLE instance_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1), -- Singleton table - only one row allowed
    name TEXT NOT NULL DEFAULT 'Vault',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Insert default instance settings
INSERT INTO instance_settings (id, name) VALUES (1, 'Vault');
