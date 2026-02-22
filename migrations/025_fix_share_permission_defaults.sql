-- Fix insecure defaults for share permissions
-- Change can_download default from TRUE to FALSE for security

-- For SQLite, we need to recreate the tables to change column defaults
-- But first, let's check and fix any existing rows that might have wrong permissions

-- Backup existing data
CREATE TABLE user_project_shares_backup AS SELECT * FROM user_project_shares;
CREATE TABLE user_track_shares_backup AS SELECT * FROM user_track_shares;

-- Drop old tables
DROP TABLE user_project_shares;
DROP TABLE user_track_shares;

-- Recreate with secure defaults
CREATE TABLE user_project_shares (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    shared_by INTEGER NOT NULL,
    shared_to INTEGER NOT NULL,
    can_edit BOOLEAN NOT NULL DEFAULT 0,
    can_download BOOLEAN NOT NULL DEFAULT 0,  -- Changed from DEFAULT 1 to DEFAULT 0
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (shared_by) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (shared_to) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(project_id, shared_to)
);

CREATE TABLE user_track_shares (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    track_id INTEGER NOT NULL,
    shared_by INTEGER NOT NULL,
    shared_to INTEGER NOT NULL,
    can_edit BOOLEAN NOT NULL DEFAULT 0,
    can_download BOOLEAN NOT NULL DEFAULT 0,  -- Changed from DEFAULT 1 to DEFAULT 0
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (track_id) REFERENCES tracks(id) ON DELETE CASCADE,
    FOREIGN KEY (shared_by) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (shared_to) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(track_id, shared_to)
);

-- Restore data from backup
INSERT INTO user_project_shares (id, project_id, shared_by, shared_to, can_edit, can_download, created_at, updated_at)
SELECT id, project_id, shared_by, shared_to, can_edit, can_download, created_at, updated_at
FROM user_project_shares_backup;

INSERT INTO user_track_shares (id, track_id, shared_by, shared_to, can_edit, can_download, created_at, updated_at)
SELECT id, track_id, shared_by, shared_to, can_edit, can_download, created_at, updated_at
FROM user_track_shares_backup;

-- Drop backup tables
DROP TABLE user_project_shares_backup;
DROP TABLE user_track_shares_backup;

-- Recreate indexes
CREATE INDEX idx_user_project_shares_project_id ON user_project_shares(project_id);
CREATE INDEX idx_user_project_shares_shared_to ON user_project_shares(shared_to);

CREATE INDEX idx_user_track_shares_track_id ON user_track_shares(track_id);
CREATE INDEX idx_user_track_shares_shared_to ON user_track_shares(shared_to);
