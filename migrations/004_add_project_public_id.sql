-- Add public IDs to projects for opaque routing/storage keys
ALTER TABLE projects ADD COLUMN public_id TEXT;

-- Backfill existing rows with random identifiers (21 hex chars)
UPDATE projects
SET public_id = SUBSTR(LOWER(HEX(RANDOMBLOB(16))), 1, 21)
WHERE public_id IS NULL OR public_id = '';

-- Ensure uniqueness for lookups
CREATE UNIQUE INDEX IF NOT EXISTS idx_projects_public_id ON projects(public_id);


