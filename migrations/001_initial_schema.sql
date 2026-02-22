-- Enable foreign keys
PRAGMA foreign_keys = ON;

-- Users table
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);

-- User preferences
CREATE TABLE user_preferences (
    user_id INTEGER PRIMARY KEY,
    default_quality TEXT NOT NULL DEFAULT 'lossy' CHECK(default_quality IN ('source', 'lossless', 'lossy')),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Projects table
CREATE TABLE projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    quality_override TEXT CHECK(quality_override IN ('source', 'lossless', 'lossy') OR quality_override IS NULL),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_projects_user_id ON projects(user_id);

-- Tracks table
CREATE TABLE tracks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    project_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    artist TEXT,
    album TEXT,
    active_version_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE INDEX idx_tracks_user_id ON tracks(user_id);
CREATE INDEX idx_tracks_project_id ON tracks(project_id);

-- Track versions
CREATE TABLE track_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    track_id INTEGER NOT NULL,
    version_name TEXT NOT NULL,
    notes TEXT,
    duration_seconds REAL,
    version_order INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (track_id) REFERENCES tracks(id) ON DELETE CASCADE
);

CREATE INDEX idx_track_versions_track_id ON track_versions(track_id);

-- Track files (quality variants)
CREATE TABLE track_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    version_id INTEGER NOT NULL,
    quality TEXT NOT NULL CHECK(quality IN ('source', 'lossless', 'lossy')),
    file_path TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    format TEXT NOT NULL,
    bitrate INTEGER,
    content_hash TEXT,
    transcoding_status TEXT DEFAULT 'completed' CHECK(transcoding_status IN ('pending', 'processing', 'completed', 'failed')),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (version_id) REFERENCES track_versions(id) ON DELETE CASCADE,
    UNIQUE(version_id, quality)
);

CREATE INDEX idx_track_files_version_id ON track_files(version_id);
CREATE INDEX idx_track_files_content_hash ON track_files(content_hash);

-- Share tokens
CREATE TABLE share_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT NOT NULL UNIQUE,
    user_id INTEGER NOT NULL,
    track_id INTEGER NOT NULL,
    version_id INTEGER,
    expires_at DATETIME,
    max_access_count INTEGER,
    current_access_count INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (track_id) REFERENCES tracks(id) ON DELETE CASCADE,
    FOREIGN KEY (version_id) REFERENCES track_versions(id) ON DELETE CASCADE
);

CREATE INDEX idx_share_tokens_token ON share_tokens(token);
CREATE INDEX idx_share_tokens_track_id ON share_tokens(track_id);

-- Remote tracks (federated)
CREATE TABLE remote_tracks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    local_user_id INTEGER NOT NULL,
    local_project_id INTEGER NOT NULL,
    remote_instance_url TEXT NOT NULL,
    remote_track_id INTEGER NOT NULL,
    share_token TEXT NOT NULL,
    title TEXT NOT NULL,
    artist TEXT,
    album TEXT,
    cached_metadata TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (local_user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (local_project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE INDEX idx_remote_tracks_user_id ON remote_tracks(local_user_id);
CREATE INDEX idx_remote_tracks_project_id ON remote_tracks(local_project_id);
