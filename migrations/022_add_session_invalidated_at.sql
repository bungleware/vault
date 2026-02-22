-- Add session_invalidated_at to instance_settings for session invalidation after reset/import
ALTER TABLE instance_settings ADD COLUMN session_invalidated_at DATETIME DEFAULT NULL;
