-- Track whether cover art has been processed into multiple sizes
ALTER TABLE projects ADD COLUMN cover_processed BOOLEAN DEFAULT FALSE;

-- Mark existing covers as unprocessed (will be migrated on server startup)
UPDATE projects SET cover_processed = FALSE WHERE cover_art_path IS NOT NULL;
