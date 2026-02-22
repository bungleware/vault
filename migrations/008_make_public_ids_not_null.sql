-- Make public_id columns NOT NULL since they're always populated

-- For projects: Create new table with NOT NULL constraint, copy data, replace table
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
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

INSERT INTO projects_new SELECT * FROM projects;
DROP TABLE projects;
ALTER TABLE projects_new RENAME TO projects;

CREATE INDEX idx_projects_user_id ON projects(user_id);
CREATE UNIQUE INDEX idx_projects_public_id ON projects(public_id);

-- For tracks: Create new table with NOT NULL constraint, copy data, replace table
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
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (active_version_id) REFERENCES track_versions(id) ON DELETE SET NULL
);

INSERT INTO tracks_new SELECT * FROM tracks;
DROP TABLE tracks;
ALTER TABLE tracks_new RENAME TO tracks;

CREATE INDEX idx_tracks_user_id ON tracks(user_id);
CREATE INDEX idx_tracks_project_id ON tracks(project_id);
CREATE INDEX idx_tracks_active_version_id ON tracks(active_version_id);
CREATE UNIQUE INDEX idx_tracks_public_id ON tracks(public_id);
