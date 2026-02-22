-- Create a separate notes table for multi-user notes
-- Each user can have their own note for each track or project

CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Either track_id or project_id should be set, but not both
    track_id INTEGER REFERENCES tracks(id) ON DELETE CASCADE,
    project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
    content TEXT NOT NULL DEFAULT '',
    author_name TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    -- Ensure either track_id or project_id is set, but not both
    CHECK ((track_id IS NOT NULL AND project_id IS NULL) OR (track_id IS NULL AND project_id IS NOT NULL)),
    -- Ensure one note per user per track/project
    UNIQUE (user_id, track_id),
    UNIQUE (user_id, project_id)
);

-- Create indexes for efficient lookups
CREATE INDEX IF NOT EXISTS idx_notes_track_id ON notes(track_id);
CREATE INDEX IF NOT EXISTS idx_notes_project_id ON notes(project_id);
CREATE INDEX IF NOT EXISTS idx_notes_user_id ON notes(user_id);

-- Migrate existing notes from tracks table to notes table
INSERT INTO notes (user_id, track_id, content, author_name, created_at, updated_at)
SELECT
    user_id,
    id,
    notes,
    COALESCE(notes_author_name, (SELECT username FROM users WHERE users.id = tracks.user_id)),
    COALESCE(notes_updated_at, updated_at),
    COALESCE(notes_updated_at, updated_at)
FROM tracks
WHERE notes IS NOT NULL AND notes != '';

-- Migrate existing notes from projects table to notes table
INSERT INTO notes (user_id, project_id, content, author_name, created_at, updated_at)
SELECT
    user_id,
    id,
    notes,
    COALESCE(notes_author_name, (SELECT username FROM users WHERE users.id = projects.user_id)),
    COALESCE(notes_updated_at, updated_at),
    COALESCE(notes_updated_at, updated_at)
FROM projects
WHERE notes IS NOT NULL AND notes != '';
