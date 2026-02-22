-- Add note author tracking to tracks and projects
ALTER TABLE tracks ADD COLUMN notes_author_name TEXT;
ALTER TABLE tracks ADD COLUMN notes_updated_at TIMESTAMP;

ALTER TABLE projects ADD COLUMN notes_author_name TEXT;
ALTER TABLE projects ADD COLUMN notes_updated_at TIMESTAMP;
