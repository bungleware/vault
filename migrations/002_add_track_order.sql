-- Add track_order column to tracks table
ALTER TABLE tracks ADD COLUMN track_order INTEGER NOT NULL DEFAULT 0;

-- Set initial order based on created_at
UPDATE tracks
SET track_order = (
    SELECT COUNT(*)
    FROM tracks t2
    WHERE t2.project_id = tracks.project_id
    AND t2.created_at <= tracks.created_at
);

-- Create index for efficient ordering
CREATE INDEX idx_tracks_project_order ON tracks(project_id, track_order);
