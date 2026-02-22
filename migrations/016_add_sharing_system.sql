-- Migration: Add comprehensive sharing system with federation support
-- This migration adds:
-- 1. Visibility status (private/invite_only/public) replacing is_private
-- 2. Permission fields for editing, downloads, and password protection
-- 3. Federation support for cross-instance sharing
-- 4. Share access tracking
-- 5. Real-time collaboration support

PRAGMA foreign_keys = OFF;

-- ==============================================================================
-- STEP 0: Create project_share_tokens if it doesn't exist (for SQLC)
-- ==============================================================================

-- This table was previously added manually, now formalizing it in migrations
CREATE TABLE IF NOT EXISTS project_share_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT NOT NULL UNIQUE,
    user_id INTEGER NOT NULL,
    project_id INTEGER NOT NULL,
    expires_at DATETIME,
    max_access_count INTEGER,
    current_access_count INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_project_share_tokens_token ON project_share_tokens(token);
CREATE INDEX IF NOT EXISTS idx_project_share_tokens_project_id ON project_share_tokens(project_id);

-- ==============================================================================
-- STEP 1: Migrate Projects Table
-- ==============================================================================

-- Create new projects table with updated schema
CREATE TABLE projects_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    quality_override TEXT CHECK(quality_override IN ('source', 'lossless', 'lossy') OR quality_override IS NULL),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    public_id TEXT NOT NULL,
    cover_art_path TEXT,
    cover_art_mime TEXT,
    cover_art_updated_at DATETIME,
    author_override TEXT,
    folder_id INTEGER,
    folder_added_at DATETIME,
    notes TEXT,
    notes_author_name TEXT,
    notes_updated_at TIMESTAMP,

    -- NEW: Visibility and permissions
    visibility_status TEXT NOT NULL DEFAULT 'private' CHECK(visibility_status IN ('private', 'invite_only', 'public')),
    allow_editing BOOLEAN NOT NULL DEFAULT 0,
    allow_downloads BOOLEAN NOT NULL DEFAULT 1,
    password_hash TEXT,
    origin_instance_url TEXT, -- NULL for local projects, set for remote shared projects

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE SET NULL
);

-- Migrate data from old projects table
INSERT INTO projects_new (
    id, user_id, name, description, quality_override, created_at, updated_at,
    public_id, cover_art_path, cover_art_mime, cover_art_updated_at,
    author_override, folder_id, folder_added_at, notes, notes_author_name,
    notes_updated_at, visibility_status, allow_editing, allow_downloads, password_hash, origin_instance_url
)
SELECT
    id, user_id, name, description, quality_override, created_at, updated_at,
    public_id, cover_art_path, cover_art_mime, cover_art_updated_at,
    author_override, folder_id, folder_added_at, notes, notes_author_name,
    notes_updated_at,
    'private', -- All existing projects default to private
    0, -- allow_editing defaults to false
    1, -- allow_downloads defaults to true
    NULL, -- no password hash
    NULL -- local projects
FROM projects;

-- Drop old table and rename
DROP TABLE projects;
ALTER TABLE projects_new RENAME TO projects;

-- Recreate indexes
CREATE INDEX idx_projects_user_id ON projects(user_id);
CREATE UNIQUE INDEX idx_projects_public_id ON projects(public_id);
CREATE INDEX idx_projects_folder_id ON projects(folder_id);
CREATE INDEX idx_projects_visibility_status ON projects(visibility_status);
CREATE INDEX idx_projects_origin_instance ON projects(origin_instance_url);

-- ==============================================================================
-- STEP 2: Migrate Tracks Table
-- ==============================================================================

-- Create new tracks table with updated schema
CREATE TABLE tracks_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    project_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    artist TEXT,
    album TEXT,
    active_version_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    track_order INTEGER NOT NULL DEFAULT 0,
    key TEXT,
    bpm INTEGER,
    public_id TEXT NOT NULL,
    notes TEXT,
    notes_author_name TEXT,
    notes_updated_at TIMESTAMP,

    -- NEW: Visibility and permissions
    visibility_status TEXT NOT NULL DEFAULT 'private' CHECK(visibility_status IN ('private', 'invite_only', 'public')),
    allow_editing BOOLEAN NOT NULL DEFAULT 0,
    allow_downloads BOOLEAN NOT NULL DEFAULT 1,
    password_hash TEXT,
    origin_instance_url TEXT, -- NULL for local tracks, set for remote shared tracks

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (active_version_id) REFERENCES track_versions(id) ON DELETE SET NULL
);

-- Migrate data from old tracks table
INSERT INTO tracks_new (
    id, user_id, project_id, title, artist, album, active_version_id,
    created_at, updated_at, track_order, key, bpm, public_id,
    notes, notes_author_name, notes_updated_at,
    visibility_status, allow_editing, allow_downloads, password_hash, origin_instance_url
)
SELECT
    id, user_id, project_id, title, artist, album, active_version_id,
    created_at, updated_at, track_order, key, bpm, public_id,
    notes, notes_author_name, notes_updated_at,
    'private', -- All existing tracks default to private
    0, -- allow_editing defaults to false
    1, -- allow_downloads defaults to true
    NULL, -- no password hash
    NULL -- local tracks
FROM tracks;

-- Drop old table and rename
DROP TABLE tracks;
ALTER TABLE tracks_new RENAME TO tracks;

-- Recreate indexes
CREATE INDEX idx_tracks_user_id ON tracks(user_id);
CREATE INDEX idx_tracks_project_id ON tracks(project_id);
CREATE INDEX idx_tracks_active_version_id ON tracks(active_version_id);
CREATE UNIQUE INDEX idx_tracks_public_id ON tracks(public_id);
CREATE INDEX idx_tracks_visibility_status ON tracks(visibility_status);
CREATE INDEX idx_tracks_origin_instance ON tracks(origin_instance_url);

-- ==============================================================================
-- STEP 3: Update Share Tokens Tables
-- ==============================================================================

-- Migrate share_tokens (track sharing)
CREATE TABLE share_tokens_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT NOT NULL UNIQUE,
    user_id INTEGER NOT NULL,
    track_id INTEGER NOT NULL,
    version_id INTEGER, -- NULL = always use active version

    -- Expiration settings
    expires_at DATETIME,
    max_access_count INTEGER,
    current_access_count INTEGER DEFAULT 0,

    -- NEW: Additional permissions and metadata
    allow_editing BOOLEAN NOT NULL DEFAULT 0,
    allow_downloads BOOLEAN NOT NULL DEFAULT 1,
    password_hash TEXT,
    visibility_type TEXT NOT NULL DEFAULT 'invite_only' CHECK(visibility_type IN ('invite_only', 'public')),

    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (track_id) REFERENCES tracks(id) ON DELETE CASCADE,
    FOREIGN KEY (version_id) REFERENCES track_versions(id) ON DELETE CASCADE
);

-- Migrate existing share tokens
INSERT INTO share_tokens_new (
    id, token, user_id, track_id, version_id, expires_at, max_access_count,
    current_access_count, created_at, allow_editing, allow_downloads, password_hash, visibility_type, updated_at
)
SELECT
    id, token, user_id, track_id, version_id, expires_at, max_access_count,
    current_access_count, created_at,
    0, -- allow_editing defaults to false
    1, -- allow_downloads defaults to true
    NULL, -- no password
    'invite_only', -- existing tokens are invite-only
    created_at -- use created_at as updated_at
FROM share_tokens;

DROP TABLE share_tokens;
ALTER TABLE share_tokens_new RENAME TO share_tokens;

CREATE INDEX idx_share_tokens_token ON share_tokens(token);
CREATE INDEX idx_share_tokens_track_id ON share_tokens(track_id);
CREATE INDEX idx_share_tokens_user_id ON share_tokens(user_id);

-- Migrate project_share_tokens
CREATE TABLE project_share_tokens_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT NOT NULL UNIQUE,
    user_id INTEGER NOT NULL,
    project_id INTEGER NOT NULL,

    -- Expiration settings
    expires_at DATETIME,
    max_access_count INTEGER,
    current_access_count INTEGER DEFAULT 0,

    -- NEW: Additional permissions and metadata
    allow_editing BOOLEAN NOT NULL DEFAULT 0,
    allow_downloads BOOLEAN NOT NULL DEFAULT 1,
    password_hash TEXT,
    visibility_type TEXT NOT NULL DEFAULT 'invite_only' CHECK(visibility_type IN ('invite_only', 'public')),

    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

-- Migrate existing project share tokens
INSERT INTO project_share_tokens_new (
    id, token, user_id, project_id, expires_at, max_access_count,
    current_access_count, created_at, allow_editing, allow_downloads, password_hash, visibility_type, updated_at
)
SELECT
    id, token, user_id, project_id, expires_at, max_access_count,
    current_access_count, created_at,
    0, -- allow_editing defaults to false
    1, -- allow_downloads defaults to true
    NULL, -- no password
    'invite_only', -- existing tokens are invite-only
    created_at -- use created_at as updated_at
FROM project_share_tokens;

DROP TABLE project_share_tokens;
ALTER TABLE project_share_tokens_new RENAME TO project_share_tokens;

CREATE INDEX idx_project_share_tokens_token ON project_share_tokens(token);
CREATE INDEX idx_project_share_tokens_project_id ON project_share_tokens(project_id);
CREATE INDEX idx_project_share_tokens_user_id ON project_share_tokens(user_id);

-- ==============================================================================
-- STEP 4: Create Federation Tables
-- ==============================================================================

-- Federation tokens: Allows remote instances to access shared content
CREATE TABLE federation_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT NOT NULL UNIQUE,

    -- Origin instance info
    origin_instance_url TEXT NOT NULL,
    origin_share_token TEXT NOT NULL,

    -- Local user who accepted the share
    local_user_id INTEGER NOT NULL,

    -- Resource being accessed
    resource_type TEXT NOT NULL CHECK(resource_type IN ('track', 'project')),
    resource_id INTEGER NOT NULL, -- ID on the origin instance

    -- Remote user info (from origin instance)
    remote_user_id INTEGER,
    remote_username TEXT,

    -- Token lifecycle
    expires_at DATETIME,
    last_used_at DATETIME,

    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (local_user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_federation_tokens_token ON federation_tokens(token);
CREATE INDEX idx_federation_tokens_local_user ON federation_tokens(local_user_id);
CREATE INDEX idx_federation_tokens_origin ON federation_tokens(origin_instance_url);
CREATE INDEX idx_federation_tokens_resource ON federation_tokens(resource_type, resource_id);

-- Share access: Tracks who has accepted access to shared content
CREATE TABLE share_access (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Share info
    share_type TEXT NOT NULL CHECK(share_type IN ('track', 'project')),
    share_token_id INTEGER NOT NULL, -- ID in share_tokens or project_share_tokens

    -- User who accepted
    user_id INTEGER NOT NULL,
    user_instance_url TEXT, -- NULL for same instance, set for remote instance

    -- Federation token if remote
    federation_token_id INTEGER,

    -- Access info
    accepted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_accessed_at DATETIME,
    access_count INTEGER DEFAULT 0,

    -- Permissions at time of acceptance (can differ from current share settings)
    can_edit BOOLEAN NOT NULL DEFAULT 0,
    can_download BOOLEAN NOT NULL DEFAULT 1,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (federation_token_id) REFERENCES federation_tokens(id) ON DELETE CASCADE,

    -- Unique: One user can only accept a share once
    UNIQUE(share_type, share_token_id, user_id, user_instance_url)
);

CREATE INDEX idx_share_access_user ON share_access(user_id);
CREATE INDEX idx_share_access_share ON share_access(share_type, share_token_id);
CREATE INDEX idx_share_access_federation ON share_access(federation_token_id);

-- ==============================================================================
-- STEP 5: Create WebSocket Session Tracking
-- ==============================================================================

-- WebSocket sessions: Tracks active real-time connections for collaboration
CREATE TABLE websocket_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL UNIQUE,

    -- User connection info
    user_id INTEGER NOT NULL,
    user_instance_url TEXT, -- NULL for local, set for remote

    -- Resource being collaborated on
    resource_type TEXT NOT NULL CHECK(resource_type IN ('track', 'project')),
    resource_id TEXT NOT NULL, -- public_id of the resource

    -- Connection metadata
    connected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_heartbeat_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_websocket_sessions_user ON websocket_sessions(user_id);
CREATE INDEX idx_websocket_sessions_resource ON websocket_sessions(resource_type, resource_id);
CREATE INDEX idx_websocket_sessions_session ON websocket_sessions(session_id);

-- ==============================================================================
-- STEP 6: Instance Configuration
-- ==============================================================================

-- Instance info: Stores this instance's configuration
CREATE TABLE instance_config (
    id INTEGER PRIMARY KEY CHECK (id = 1), -- Only one row
    instance_url TEXT NOT NULL, -- This instance's public URL
    instance_name TEXT NOT NULL,
    allow_federation BOOLEAN NOT NULL DEFAULT 1,
    allow_public_shares BOOLEAN NOT NULL DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Insert default instance config (will need to be updated by user)
INSERT INTO instance_config (id, instance_url, instance_name)
VALUES (1, 'http://localhost:8080', 'My Vault Instance');

PRAGMA foreign_keys = ON;
