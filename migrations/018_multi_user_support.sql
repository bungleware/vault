-- Add admin role support
ALTER TABLE users ADD COLUMN is_admin BOOLEAN NOT NULL DEFAULT 0;

-- Set the first (oldest) user as admin
UPDATE users SET is_admin = 1 WHERE id = (SELECT MIN(id) FROM users LIMIT 1);

-- Invite tokens for user creation and password resets
CREATE TABLE invite_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT NOT NULL UNIQUE,
    token_type TEXT NOT NULL CHECK(token_type IN ('invite', 'reset')),
    user_id INTEGER,
    created_by INTEGER NOT NULL,
    email TEXT NOT NULL,
    used BOOLEAN NOT NULL DEFAULT 0,
    used_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_invite_tokens_token ON invite_tokens(token);
CREATE INDEX idx_invite_tokens_user_id ON invite_tokens(user_id);
CREATE INDEX idx_invite_tokens_created_by ON invite_tokens(created_by);
CREATE INDEX idx_invite_tokens_expires_at ON invite_tokens(expires_at);

-- User-to-user project sharing
CREATE TABLE user_project_shares (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    shared_by INTEGER NOT NULL,
    shared_to INTEGER NOT NULL,
    can_edit BOOLEAN NOT NULL DEFAULT 0,
    can_download BOOLEAN NOT NULL DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (shared_by) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (shared_to) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(project_id, shared_to)
);

CREATE INDEX idx_user_project_shares_project_id ON user_project_shares(project_id);
CREATE INDEX idx_user_project_shares_shared_to ON user_project_shares(shared_to);
CREATE INDEX idx_user_project_shares_shared_by ON user_project_shares(shared_by);

-- User-to-user track sharing
CREATE TABLE user_track_shares (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    track_id INTEGER NOT NULL,
    shared_by INTEGER NOT NULL,
    shared_to INTEGER NOT NULL,
    can_edit BOOLEAN NOT NULL DEFAULT 0,
    can_download BOOLEAN NOT NULL DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (track_id) REFERENCES tracks(id) ON DELETE CASCADE,
    FOREIGN KEY (shared_by) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (shared_to) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(track_id, shared_to)
);

CREATE INDEX idx_user_track_shares_track_id ON user_track_shares(track_id);
CREATE INDEX idx_user_track_shares_shared_to ON user_track_shares(shared_to);
CREATE INDEX idx_user_track_shares_shared_by ON user_track_shares(shared_by);

-- Cleanup: Update visibility_status to handle deprecation of federation
-- Keep 'private', 'public', and 'invite_only' options, remove federation-specific tracking
ALTER TABLE projects ADD COLUMN shared_with_instance_users BOOLEAN DEFAULT 0;
ALTER TABLE tracks ADD COLUMN shared_with_instance_users BOOLEAN DEFAULT 0;
