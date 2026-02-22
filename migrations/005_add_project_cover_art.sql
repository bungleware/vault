-- Cover art metadata for projects
ALTER TABLE projects ADD COLUMN cover_art_path TEXT;
ALTER TABLE projects ADD COLUMN cover_art_mime TEXT;
ALTER TABLE projects ADD COLUMN cover_art_updated_at DATETIME;


